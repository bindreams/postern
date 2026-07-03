// Cloudflare-specific A/AAAA proxied-flag support for the edge profile.
//
// libdns/cloudflare v0.2.2's AppendRecords does not expose Cloudflare's
// `proxied` (orange-cloud) flag -- it always creates gray-clouded records. The
// edge profile needs the apex A/AAAA orange-clouded so Cloudflare fronts the
// tunnel, and needs to flip them back to gray when edge is disabled. So, exactly
// like the TLSA fallback (#127), postern-dns bypasses libdns for the proxied
// A/AAAA writes and talks to the Cloudflare REST API directly, reusing the
// cfClient defined in cloudflare_tlsa.go and CLOUDFLARE_API_TOKEN.
//
// Direction (see cloudflareAddrSetProxied):
//
//	--proxied=true  : POST-then-PATCH. POST creates the record (ttl=1, which
//	                  Cloudflare requires for proxied records); on an 81058
//	                  duplicate the record already exists (possibly gray), so we
//	                  look it up and PATCH proxied=true.
//	--proxied=false : GET-then-PATCH. Look the record up and PATCH proxied=false
//	                  (restoring a normal ttl); if it is absent, POST-create it
//	                  gray. GET-first avoids a guaranteed-81058 POST when the
//	                  record already exists orange.
//
// CONTRACT ASSUMPTION: Cloudflare's duplicate-detection key behind error 81058
// is (zone, type, name, content) and does NOT include `proxied`. Flipping only
// the proxied bit is therefore always a PATCH, never a create -- a POST of the
// same (name, content) with a different proxied value still 81058s. This is
// verified against a self-authored fake only; the real-zone contract check is
// verified against a real Cloudflare zone by the maintainer real-zone e2e added
// in the edge fast-follow PR (not in this change).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/libdns/libdns"
)

// Cloudflare requires ttl=1 ("automatic") for proxied records and rejects any
// other value; gray records use our usual short TTL (matches recordTTL in main.go).
const (
	cfProxiedTTL   = 1
	cfUnproxiedTTL = 300
)

// errCFDuplicate is the sentinel createAddr returns when Cloudflare rejects a
// POST with code 81058 (identical record already exists).
var errCFDuplicate = errors.New("cloudflare: identical record already exists (81058)")

// cfAddrRecord is the Cloudflare REST shape for an A/AAAA record. Proxied has no
// omitempty: a false value must survive JSON marshalling on the un-proxy path.
type cfAddrRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
	Proxied bool   `json:"proxied"`
}

// cloudflareAddrSetProxied publishes rec (an A or AAAA) via the Cloudflare REST
// API and forces its proxied flag to `proxied`. Called from runCmd when
// DNS_PROVIDER=cloudflare and the caller passed --proxied.
func cloudflareAddrSetProxied(ctx context.Context, client *cfClient, zone string, rec libdns.Address, proxied bool) error {
	rr := rec.RR()
	fqdn := strings.TrimSuffix(displayFQDN(rr.Name, zone), ".")
	zoneID, err := client.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	if proxied {
		return client.setAddrProxiedTrue(ctx, zoneID, rr.Type, fqdn, rec.IP)
	}
	return client.setAddrProxiedFalse(ctx, zoneID, rr.Type, fqdn, rec.IP)
}

// listAddr returns every recType (A/AAAA) record at fqdn.
func (c *cfClient) listAddr(ctx context.Context, zoneID, recType, fqdn string) ([]cfAddrRecord, error) {
	env, status, err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/zones/%s/dns_records?type=%s&name=%s", zoneID, recType, fqdn), nil)
	if err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("list %s failed (HTTP %d): %s", recType, status, formatCFErrors(env.Errors))
	}
	var out []cfAddrRecord
	if err := json.Unmarshal(env.Result, &out); err != nil {
		return nil, fmt.Errorf("decode %s list: %w", recType, err)
	}
	return out, nil
}

// createAddr POSTs a new A/AAAA record and returns its Cloudflare ID. A code
// 81058 rejection maps to errCFDuplicate so callers can fall back to
// look-up-then-PATCH.
func (c *cfClient) createAddr(ctx context.Context, zoneID string, rec cfAddrRecord) (string, error) {
	env, status, err := c.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", rec)
	if err != nil {
		return "", err
	}
	if env.Success {
		var created cfAddrRecord
		if err := json.Unmarshal(env.Result, &created); err != nil {
			return "", fmt.Errorf("decode created %s: %w", rec.Type, err)
		}
		return created.ID, nil
	}
	for _, e := range env.Errors {
		if e.Code == cloudflareDuplicateCode {
			return "", errCFDuplicate
		}
	}
	return "", fmt.Errorf("create %s %s failed (HTTP %d): %s", rec.Type, rec.Name, status, formatCFErrors(env.Errors))
}

// patchProxied flips proxied (and sets ttl) on an existing record by ID.
func (c *cfClient) patchProxied(ctx context.Context, zoneID, recordID string, proxied bool, ttl int) error {
	payload := struct {
		Proxied bool `json:"proxied"`
		TTL     int  `json:"ttl"`
	}{Proxied: proxied, TTL: ttl}
	env, status, err := c.do(ctx, http.MethodPatch,
		fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), payload)
	if err != nil {
		return err
	}
	if !env.Success {
		return fmt.Errorf("patch proxied=%t (HTTP %d): %s", proxied, status, formatCFErrors(env.Errors))
	}
	return nil
}

// setAddrProxiedTrue implements the --proxied=true POST-then-PATCH direction.
func (c *cfClient) setAddrProxiedTrue(ctx context.Context, zoneID, recType, fqdn string, ip netip.Addr) error {
	_, err := c.createAddr(ctx, zoneID, cfAddrRecord{
		Type: recType, Name: fqdn, Content: ip.String(), TTL: cfProxiedTTL, Proxied: true,
	})
	if err == nil {
		return nil // created fresh, already orange.
	}
	if !errors.Is(err, errCFDuplicate) {
		return err
	}
	existing, err := c.listAddr(ctx, zoneID, recType, fqdn)
	if err != nil {
		return err
	}
	id, ok := firstAddrMatch(existing, ip)
	if !ok {
		return fmt.Errorf("cloudflare %s-set %s: 81058 duplicate but no record with content %q to flip proxied on",
			strings.ToLower(recType), fqdn, ip.String())
	}
	return c.patchProxied(ctx, zoneID, id, true, cfProxiedTTL)
}

// setAddrProxiedFalse implements the --proxied=false GET-then-PATCH direction,
// creating the record gray if it is absent (first publish with edge disabled).
func (c *cfClient) setAddrProxiedFalse(ctx context.Context, zoneID, recType, fqdn string, ip netip.Addr) error {
	existing, err := c.listAddr(ctx, zoneID, recType, fqdn)
	if err != nil {
		return err
	}
	if id, ok := firstAddrMatch(existing, ip); ok {
		return c.patchProxied(ctx, zoneID, id, false, cfUnproxiedTTL)
	}
	_, err = c.createAddr(ctx, zoneID, cfAddrRecord{
		Type: recType, Name: fqdn, Content: ip.String(), TTL: cfUnproxiedTTL, Proxied: false,
	})
	if errors.Is(err, errCFDuplicate) {
		return nil // raced or list-missed; the gray record exists -> desired state reached.
	}
	return err
}

// firstAddrMatch returns the ID of the first record whose content parses to ip.
// Parsing (not string compare) makes IPv6 matching robust to Cloudflare
// re-rendering the address in a different-but-equivalent textual form.
func firstAddrMatch(recs []cfAddrRecord, ip netip.Addr) (string, bool) {
	for _, r := range recs {
		if got, err := netip.ParseAddr(r.Content); err == nil && got == ip {
			return r.ID, true
		}
	}
	return "", false
}
