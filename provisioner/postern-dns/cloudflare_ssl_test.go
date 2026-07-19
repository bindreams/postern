package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeCFSSL is a minimal in-memory Cloudflare API for the zone-settings ssl slice
// (GET /zones, GET/PATCH /zones/{id}/settings/ssl), mirroring fakeCFEch.
type fakeCFSSL struct {
	zoneID      string
	zoneName    string
	sslValue    string
	failPatch   bool
	failZoneGet bool // /zones lookup returns a CF error (zoneID resolution fails)
	failSettGet bool // GET settings/ssl returns a CF error
	requestLog  []string
}

func newFakeCFSSL(zoneName, initial string) *fakeCFSSL {
	return &fakeCFSSL{zoneID: "ZONE_" + zoneName, zoneName: zoneName, sslValue: initial}
}

func (f *fakeCFSSL) writeJSON(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeCFSSL) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requestLog = append(f.requestLog, fmt.Sprintf("%s %s", r.Method, r.URL.Path))
		settingPath := "/zones/" + f.zoneID + "/settings/ssl"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			if f.failZoneGet {
				f.writeJSON(w, 403, cfResponse{Errors: []cfError{{Code: 9109, Message: "Invalid access token"}}})
				return
			}
			if r.URL.Query().Get("name") == f.zoneName {
				f.writeJSON(w, 200, cfResponse{Success: true,
					Result: json.RawMessage(fmt.Sprintf(`[{"id":%q,"name":%q}]`, f.zoneID, f.zoneName))})
				return
			}
			f.writeJSON(w, 200, cfResponse{Success: true, Result: json.RawMessage(`[]`)})
		case r.Method == http.MethodGet && r.URL.Path == settingPath:
			if f.failSettGet {
				f.writeJSON(w, 500, cfResponse{Errors: []cfError{{Code: 1000, Message: "internal error"}}})
				return
			}
			f.writeJSON(w, 200, cfResponse{Success: true,
				Result: json.RawMessage(fmt.Sprintf(`{"id":"ssl","value":%q}`, f.sslValue))})
		case r.Method == http.MethodPatch && r.URL.Path == settingPath:
			if f.failPatch {
				f.writeJSON(w, 403, cfResponse{Errors: []cfError{{Code: 1006, Message: "SSL/TLS mode not available on this plan"}}})
				return
			}
			var s struct {
				Value string `json:"value"`
			}
			_ = json.NewDecoder(r.Body).Decode(&s)
			f.sslValue = s.Value
			f.writeJSON(w, 200, cfResponse{Success: true,
				Result: json.RawMessage(fmt.Sprintf(`{"id":"ssl","value":%q}`, f.sslValue))})
		default:
			f.writeJSON(w, 404, cfResponse{Errors: []cfError{{Message: "unexpected " + r.Method + " " + r.URL.Path}}})
		}
	})
}

func sslTestClient(t *testing.T, f *fakeCFSSL) *cfClient {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return &cfClient{BaseURL: srv.URL, Token: "test-token", HTTP: srv.Client()}
}

func TestZoneSSLRaisesFlexibleToStrict(t *testing.T) {
	f := newFakeCFSSL("example.com", "flexible")
	mode, err := cloudflareZoneSSLSet(context.Background(), sslTestClient(t, f), "example.com.", "strict")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if mode != "strict" {
		t.Errorf("observed mode = %q, want strict (raised)", mode)
	}
	if f.sslValue != "strict" {
		t.Errorf("ssl = %q, want strict", f.sslValue)
	}
	if countMethod(f.requestLog, "PATCH") != 1 {
		t.Errorf("expected exactly 1 PATCH, log=%v", f.requestLog)
	}
}

func TestZoneSSLRaisesOffToFull(t *testing.T) {
	f := newFakeCFSSL("example.com", "off")
	mode, err := cloudflareZoneSSLSet(context.Background(), sslTestClient(t, f), "example.com.", "full")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if mode != "full" || f.sslValue != "full" {
		t.Errorf("observed=%q sslValue=%q, want full/full", mode, f.sslValue)
	}
}

func TestZoneSSLAlreadyFullIsNoopEvenWithStrictTarget(t *testing.T) {
	// The returned mode is the ACTUAL "full" (not the "strict" target) -- this is what makes
	// the target-vs-actual gap visible to `edge ssl-status`.
	f := newFakeCFSSL("example.com", "full")
	mode, err := cloudflareZoneSSLSet(context.Background(), sslTestClient(t, f), "example.com.", "strict")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if mode != "full" {
		t.Errorf("observed mode = %q, want full (left as-is, below the strict target)", mode)
	}
	if f.sslValue != "full" {
		t.Errorf("ssl = %q, want full (unchanged)", f.sslValue)
	}
	if countMethod(f.requestLog, "PATCH") != 0 {
		t.Errorf("expected 0 PATCH (already sufficient), log=%v", f.requestLog)
	}
}

func TestZoneSSLAlreadyStrictIsNoopWithFullTarget(t *testing.T) {
	f := newFakeCFSSL("example.com", "strict")
	mode, err := cloudflareZoneSSLSet(context.Background(), sslTestClient(t, f), "example.com.", "full")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if mode != "strict" {
		t.Errorf("observed mode = %q, want strict (no downgrade)", mode)
	}
	if f.sslValue != "strict" {
		t.Errorf("ssl = %q, want strict (no downgrade)", f.sslValue)
	}
	if countMethod(f.requestLog, "PATCH") != 0 {
		t.Errorf("expected 0 PATCH (no downgrade), log=%v", f.requestLog)
	}
}

func TestZoneSSLSurfacesCFError(t *testing.T) {
	f := newFakeCFSSL("example.com", "flexible")
	f.failPatch = true
	_, err := cloudflareZoneSSLSet(context.Background(), sslTestClient(t, f), "example.com.", "strict")
	if err == nil || !strings.Contains(err.Error(), "SSL/TLS mode not available on this plan") {
		t.Fatalf("error should surface CF's message, got: %v", err)
	}
}

func TestZoneSSLUnknownCurrentModeErrors(t *testing.T) {
	f := newFakeCFSSL("example.com", "bogus")
	_, err := cloudflareZoneSSLSet(context.Background(), sslTestClient(t, f), "example.com.", "strict")
	if err == nil || !strings.Contains(err.Error(), "unknown ssl mode") {
		t.Fatalf("expected unknown-mode error, got: %v", err)
	}
	if countMethod(f.requestLog, "PATCH") != 0 {
		t.Errorf("must not PATCH on unknown current mode, log=%v", f.requestLog)
	}
}

func TestZoneSSLSurfacesZoneResolveError(t *testing.T) {
	// zoneID lookup fails -> error propagated, no settings GET/PATCH attempted.
	f := newFakeCFSSL("example.com", "flexible")
	f.failZoneGet = true
	_, err := cloudflareZoneSSLSet(context.Background(), sslTestClient(t, f), "example.com.", "strict")
	if err == nil {
		t.Fatal("expected zone-resolve error to propagate")
	}
	if countMethod(f.requestLog, "PATCH") != 0 {
		t.Errorf("must not PATCH when zone resolution fails, log=%v", f.requestLog)
	}
}

func TestZoneSSLSurfacesGetSettingError(t *testing.T) {
	// The settings GET fails -> error propagated, no PATCH attempted.
	f := newFakeCFSSL("example.com", "flexible")
	f.failSettGet = true
	_, err := cloudflareZoneSSLSet(context.Background(), sslTestClient(t, f), "example.com.", "strict")
	if err == nil {
		t.Fatal("expected get-setting error to propagate")
	}
	if countMethod(f.requestLog, "PATCH") != 0 {
		t.Errorf("must not PATCH when the settings GET fails, log=%v", f.requestLog)
	}
}

func TestZoneSSLRejectsBadTarget(t *testing.T) {
	f := newFakeCFSSL("example.com", "flexible")
	_, err := cloudflareZoneSSLSet(context.Background(), sslTestClient(t, f), "example.com.", "flexible")
	if err == nil || !strings.Contains(err.Error(), "target must be 'full' or 'strict'") {
		t.Fatalf("expected bad-target error, got: %v", err)
	}
}

func TestZoneSSLRejectsUnknownTarget(t *testing.T) {
	// Hits the `!ok` branch of the target guard (an unrecognized string), distinct from
	// the known-but-too-low `flexible` case above.
	f := newFakeCFSSL("example.com", "flexible")
	_, err := cloudflareZoneSSLSet(context.Background(), sslTestClient(t, f), "example.com.", "bogus")
	if err == nil || !strings.Contains(err.Error(), "target must be 'full' or 'strict'") {
		t.Fatalf("expected bad-target error for unknown target, got: %v", err)
	}
	if countMethod(f.requestLog, "PATCH") != 0 {
		t.Errorf("must not PATCH on an unknown target, log=%v", f.requestLog)
	}
}
