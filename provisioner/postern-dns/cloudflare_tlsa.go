// Cloudflare-specific TLSA fallback.
//
// `libdns/cloudflare` v0.2.2 has no `r.(type)` case for TLSA in its
// `cloudflareRecord(libdns.Record)` marshaling: a generic libdns.RR{Type:"TLSA"}
// falls through with only `Content: rr.Data` populated. Cloudflare's REST API
// rejects that with HTTP 400 "usage / selector / matching_type / certificate
// is a required data field" (see #127). Until libdns/cloudflare grows
// structured TLSA support, postern-dns bypasses libdns for `tlsa-set` /
// `tlsa-delete` against Cloudflare and POSTs to the Cloudflare API directly
// with the structured payload.
//
// Reuses CLOUDFLARE_API_TOKEN (already required by the libdns provider).

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// cloudflareDuplicateCode is what the Cloudflare API returns when AppendRecords
// tries to create an exact-match record that already exists (RFC: 81058).
const cloudflareDuplicateCode = 81058

// cfClient is a thin Cloudflare-API wrapper used only by the TLSA fallback.
// Field is exported so tests can substitute a httptest.Server URL.
type cfClient struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func newCFClient(token string) *cfClient {
	return &cfClient{
		BaseURL: cloudflareAPIBase,
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e cfError) Error() string {
	return fmt.Sprintf("cloudflare API error %d: %s", e.Code, e.Message)
}

type cfResponse struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result,omitempty"`
	Errors  []cfError       `json:"errors,omitempty"`
}

type cfTLSAData struct {
	Usage        int    `json:"usage"`
	Selector     int    `json:"selector"`
	MatchingType int    `json:"matching_type"`
	Certificate  string `json:"certificate"`
}

type cfTLSARecord struct {
	ID   string     `json:"id,omitempty"`
	Type string     `json:"type"`
	Name string     `json:"name"`
	TTL  int        `json:"ttl,omitempty"`
	Data cfTLSAData `json:"data"`
}

// do performs a request against the Cloudflare API and decodes the envelope.
// Returns the wrapped error chain on `success=false`.
func (c *cfClient) do(ctx context.Context, method, path string, body interface{}) (*cfResponse, int, error) {
	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("encode request: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("transport: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read body: %w", err)
	}
	var env cfResponse
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode envelope (HTTP %d): %w; body=%s", resp.StatusCode, err, string(raw))
	}
	return &env, resp.StatusCode, nil
}

// zoneID resolves a Cloudflare zone name to its API ID. The CF list endpoint
// returns at most one match for an exact name (zone names are globally unique).
func (c *cfClient) zoneID(ctx context.Context, zone string) (string, error) {
	env, status, err := c.do(ctx, http.MethodGet, "/zones?name="+strings.TrimSuffix(zone, "."), nil)
	if err != nil {
		return "", err
	}
	if !env.Success {
		return "", fmt.Errorf("zone lookup failed (HTTP %d): %s", status, formatCFErrors(env.Errors))
	}
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(env.Result, &zones); err != nil {
		return "", fmt.Errorf("decode zones: %w", err)
	}
	if len(zones) == 0 {
		return "", fmt.Errorf("zone %q not found in Cloudflare account", zone)
	}
	return zones[0].ID, nil
}

// listTLSA returns every TLSA record at `name` (FQDN). Cloudflare allows
// multiple TLSA RRs at one name; the caller is responsible for matching the
// specific record by content.
func (c *cfClient) listTLSA(ctx context.Context, zoneID, fqdn string) ([]cfTLSARecord, error) {
	env, status, err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/zones/%s/dns_records?type=TLSA&name=%s", zoneID, strings.TrimSuffix(fqdn, ".")), nil)
	if err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("list TLSA failed (HTTP %d): %s", status, formatCFErrors(env.Errors))
	}
	var out []cfTLSARecord
	if err := json.Unmarshal(env.Result, &out); err != nil {
		return nil, fmt.Errorf("decode TLSA list: %w", err)
	}
	return out, nil
}

// createTLSA POSTs a new TLSA record. Treats Cloudflare error 81058
// ("identical record already exists") as idempotent success.
func (c *cfClient) createTLSA(ctx context.Context, zoneID string, rec cfTLSARecord) error {
	env, status, err := c.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", rec)
	if err != nil {
		return err
	}
	if env.Success {
		return nil
	}
	for _, e := range env.Errors {
		if e.Code == cloudflareDuplicateCode {
			// Confirm the duplicate actually matches our intended payload.
			existing, listErr := c.listTLSA(ctx, zoneID, rec.Name)
			if listErr != nil {
				return fmt.Errorf("provider reported duplicate but could not verify (HTTP %d): %w", status, listErr)
			}
			for _, ex := range existing {
				if tlsaContentEqual(ex.Data, rec.Data) {
					return nil
				}
			}
			return fmt.Errorf("provider reported duplicate but no matching record visible: %s", formatCFErrors(env.Errors))
		}
	}
	return fmt.Errorf("create TLSA failed (HTTP %d): %s", status, formatCFErrors(env.Errors))
}

// deleteTLSA removes the first TLSA record at `name` whose data matches `data`.
// Missing record is treated as idempotent success.
func (c *cfClient) deleteTLSA(ctx context.Context, zoneID, fqdn string, data cfTLSAData) error {
	existing, err := c.listTLSA(ctx, zoneID, fqdn)
	if err != nil {
		return err
	}
	for _, ex := range existing {
		if tlsaContentEqual(ex.Data, data) {
			env, status, err := c.do(ctx, http.MethodDelete,
				fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, ex.ID), nil)
			if err != nil {
				return err
			}
			if !env.Success {
				return fmt.Errorf("delete TLSA failed (HTTP %d): %s", status, formatCFErrors(env.Errors))
			}
			return nil
		}
	}
	return nil // already absent
}

// tlsaContentEqual compares Cloudflare-side TLSA data with the desired data.
// Hex compare is case-insensitive (Cloudflare normalizes to lowercase but other
// rendering paths preserve whatever was sent).
func tlsaContentEqual(a, b cfTLSAData) bool {
	return a.Usage == b.Usage && a.Selector == b.Selector && a.MatchingType == b.MatchingType &&
		strings.EqualFold(a.Certificate, b.Certificate)
}

func formatCFErrors(errs []cfError) string {
	if len(errs) == 0 {
		return "(no error detail)"
	}
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, e.Error())
	}
	return strings.Join(parts, "; ")
}

// Entry points ===========================================================================================================

// cloudflareTLSASet publishes `rec` via the Cloudflare REST API. Called when
// DNS_PROVIDER=cloudflare and the libdns generic-RR path would otherwise
// produce HTTP 400 missing-fields errors (#127).
func cloudflareTLSASet(ctx context.Context, client *cfClient, zone string, rec libdns.RR) error {
	data, err := tlsaDataFromRR(rec)
	if err != nil {
		return err
	}
	zoneID, err := client.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	return client.createTLSA(ctx, zoneID, cfTLSARecord{
		Type: "TLSA",
		Name: strings.TrimSuffix(rec.Name+"."+zone, "."),
		TTL:  int(rec.TTL.Seconds()),
		Data: data,
	})
}

// cloudflareTLSADelete removes the matching TLSA record via the Cloudflare REST API.
func cloudflareTLSADelete(ctx context.Context, client *cfClient, zone string, rec libdns.RR) error {
	data, err := tlsaDataFromRR(rec)
	if err != nil {
		return err
	}
	zoneID, err := client.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	return client.deleteTLSA(ctx, zoneID, strings.TrimSuffix(rec.Name+"."+zone, "."), data)
}

// tlsaDataFromRR re-parses the `"u s m hex"` Data field that parseTLSAArgs
// produced. The duplicate parsing keeps cloudflareTLSASet a thin wrapper
// over the generic libdns.RR shape that the rest of postern-dns uses; the
// fields have already been validated by parseTLSAArgs at this point.
func tlsaDataFromRR(rec libdns.RR) (cfTLSAData, error) {
	parts := strings.Fields(rec.Data)
	if len(parts) != 4 {
		return cfTLSAData{}, fmt.Errorf("cloudflare TLSA: malformed RR.Data %q (want 4 fields)", rec.Data)
	}
	usage, err := strconv.Atoi(parts[0])
	if err != nil {
		return cfTLSAData{}, fmt.Errorf("cloudflare TLSA: usage: %w", err)
	}
	selector, err := strconv.Atoi(parts[1])
	if err != nil {
		return cfTLSAData{}, fmt.Errorf("cloudflare TLSA: selector: %w", err)
	}
	matchType, err := strconv.Atoi(parts[2])
	if err != nil {
		return cfTLSAData{}, fmt.Errorf("cloudflare TLSA: matching_type: %w", err)
	}
	certHex := strings.ToLower(parts[3])
	if _, err := hex.DecodeString(certHex); err != nil {
		return cfTLSAData{}, fmt.Errorf("cloudflare TLSA: certificate hex: %w", err)
	}
	return cfTLSAData{
		Usage:        usage,
		Selector:     selector,
		MatchingType: matchType,
		Certificate:  certHex,
	}, nil
}
