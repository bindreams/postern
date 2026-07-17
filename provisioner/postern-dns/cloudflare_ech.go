// Cloudflare zone-level ECH (Encrypted ClientHello) setting support for the edge
// profile's "batteries-included ECH front".
//
// ECH only conceals the SNI when Cloudflare's zone-level ECH setting is ON, so CF
// publishes the ech= SvcParam in each proxied hostname's HTTPS/SVCB record. That
// toggle is a zone SETTING, not a DNS record, and has no libdns model -- so,
// exactly like the proxied flag (cloudflare_proxied.go) and TLSA
// (cloudflare_tlsa.go), postern-dns bypasses libdns and talks to the Cloudflare
// zone-settings REST endpoint directly, reusing cfClient + CLOUDFLARE_API_TOKEN.
//
// GET-then-PATCH, idempotent: read the current value and PATCH only when it
// differs, so a re-run when ECH is already on is a no-op. The setting is
// zone-WIDE; the reconciler only ever calls this with on=true (converge-to-ON,
// never auto-OFF). on=false exists for manual operator use and the real-zone
// contract test's restore step.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// cfZoneSetting is the Cloudflare REST shape for a single zone setting. For "ech"
// the value is the string "on" or "off".
type cfZoneSetting struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

// getZoneSetting reads one zone setting's value (e.g. "ech" -> "on"/"off").
func (c *cfClient) getZoneSetting(ctx context.Context, zoneID, setting string) (string, error) {
	env, status, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/zones/%s/settings/%s", zoneID, setting), nil)
	if err != nil {
		return "", err
	}
	if !env.Success {
		return "", fmt.Errorf("get zone setting %q failed (HTTP %d): %s", setting, status, formatCFErrors(env.Errors))
	}
	var s cfZoneSetting
	if err := json.Unmarshal(env.Result, &s); err != nil {
		return "", fmt.Errorf("decode zone setting %q: %w", setting, err)
	}
	return s.Value, nil
}

func (c *cfClient) patchZoneSetting(ctx context.Context, zoneID, setting, value string) error {
	payload := struct {
		Value string `json:"value"`
	}{Value: value}
	env, status, err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/zones/%s/settings/%s", zoneID, setting), payload)
	if err != nil {
		return err
	}
	if !env.Success {
		return fmt.Errorf("set zone setting %q=%q failed (HTTP %d): %s", setting, value, status, formatCFErrors(env.Errors))
	}
	return nil
}

// cloudflareZoneEchSet forces the zone's ECH setting to on/off, idempotently.
func cloudflareZoneEchSet(ctx context.Context, client *cfClient, zone string, on bool) error {
	zoneID, err := client.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	desired := "off"
	if on {
		desired = "on"
	}
	current, err := client.getZoneSetting(ctx, zoneID, "ech")
	if err != nil {
		return err
	}
	if current == desired {
		return nil
	}
	return client.patchZoneSetting(ctx, zoneID, "ech", desired)
}
