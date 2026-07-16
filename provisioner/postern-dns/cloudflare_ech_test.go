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

// fakeCFEch is a minimal in-memory Cloudflare API for the zone-settings ECH slice
// (GET /zones, GET/PATCH /zones/{id}/settings/ech). requestLog records method+path
// so tests can assert the GET-then-PATCH shape and the idempotent no-PATCH path.
type fakeCFEch struct {
	zoneID     string
	zoneName   string
	echValue   string
	failPatch  bool
	requestLog []string
}

func newFakeCFEch(zoneName, initial string) *fakeCFEch {
	return &fakeCFEch{zoneID: "ZONE_" + zoneName, zoneName: zoneName, echValue: initial}
}

func (f *fakeCFEch) writeJSON(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeCFEch) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requestLog = append(f.requestLog, fmt.Sprintf("%s %s", r.Method, r.URL.Path))
		settingPath := "/zones/" + f.zoneID + "/settings/ech"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			if r.URL.Query().Get("name") == f.zoneName {
				f.writeJSON(w, 200, cfResponse{Success: true,
					Result: json.RawMessage(fmt.Sprintf(`[{"id":%q,"name":%q}]`, f.zoneID, f.zoneName))})
				return
			}
			f.writeJSON(w, 200, cfResponse{Success: true, Result: json.RawMessage(`[]`)})
		case r.Method == http.MethodGet && r.URL.Path == settingPath:
			f.writeJSON(w, 200, cfResponse{Success: true,
				Result: json.RawMessage(fmt.Sprintf(`{"id":"ech","value":%q}`, f.echValue))})
		case r.Method == http.MethodPatch && r.URL.Path == settingPath:
			if f.failPatch {
				f.writeJSON(w, 403, cfResponse{Errors: []cfError{{Code: 1006, Message: "ECH is not available on this plan"}}})
				return
			}
			var s struct {
				Value string `json:"value"`
			}
			_ = json.NewDecoder(r.Body).Decode(&s)
			f.echValue = s.Value
			f.writeJSON(w, 200, cfResponse{Success: true,
				Result: json.RawMessage(fmt.Sprintf(`{"id":"ech","value":%q}`, f.echValue))})
		default:
			f.writeJSON(w, 404, cfResponse{Errors: []cfError{{Message: "unexpected " + r.Method + " " + r.URL.Path}}})
		}
	})
}

func echTestClient(t *testing.T, f *fakeCFEch) *cfClient {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return &cfClient{BaseURL: srv.URL, Token: "test-token", HTTP: srv.Client()}
}

func countMethod(log []string, method string) int {
	n := 0
	for _, e := range log {
		if strings.HasPrefix(e, method+" ") {
			n++
		}
	}
	return n
}

func TestZoneEchSetOnFromOff(t *testing.T) {
	f := newFakeCFEch("example.com", "off")
	client := echTestClient(t, f)
	if err := cloudflareZoneEchSet(context.Background(), client, "example.com.", true); err != nil {
		t.Fatalf("set on: %v", err)
	}
	if f.echValue != "on" {
		t.Errorf("ech value = %q, want on", f.echValue)
	}
	if countMethod(f.requestLog, "PATCH") != 1 {
		t.Errorf("expected exactly 1 PATCH, log=%v", f.requestLog)
	}
}

func TestZoneEchSetOnWhenAlreadyOnIsNoop(t *testing.T) {
	f := newFakeCFEch("example.com", "on")
	client := echTestClient(t, f)
	if err := cloudflareZoneEchSet(context.Background(), client, "example.com.", true); err != nil {
		t.Fatalf("set on: %v", err)
	}
	if countMethod(f.requestLog, "PATCH") != 0 {
		t.Errorf("expected 0 PATCH (idempotent no-op), log=%v", f.requestLog)
	}
}

func TestZoneEchSetOff(t *testing.T) {
	f := newFakeCFEch("example.com", "on")
	client := echTestClient(t, f)
	if err := cloudflareZoneEchSet(context.Background(), client, "example.com.", false); err != nil {
		t.Fatalf("set off: %v", err)
	}
	if f.echValue != "off" {
		t.Errorf("ech value = %q, want off", f.echValue)
	}
}

func TestZoneEchSetSurfacesCFError(t *testing.T) {
	f := newFakeCFEch("example.com", "off")
	f.failPatch = true
	client := echTestClient(t, f)
	err := cloudflareZoneEchSet(context.Background(), client, "example.com.", true)
	if err == nil {
		t.Fatal("expected an error when CF PATCH fails")
	}
	if !strings.Contains(err.Error(), "ECH is not available on this plan") {
		t.Errorf("error should surface CF's message, got: %v", err)
	}
}
