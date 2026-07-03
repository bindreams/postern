package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// fakeCFAddr is a minimal in-memory Cloudflare API for A/AAAA records, covering
// the GET-zones / GET-list / POST-create / PATCH-proxied slice that
// cloudflare_proxied.go uses. requestLog records every method+path for
// request-shape assertions.
type fakeCFAddr struct {
	zoneID     string
	zoneName   string
	next       int
	recs       map[string]cfAddrRecord
	requestLog []string
}

func newFakeCFAddr(zoneName string) *fakeCFAddr {
	return &fakeCFAddr{zoneID: "ZONE_" + zoneName, zoneName: zoneName, recs: map[string]cfAddrRecord{}}
}

func (f *fakeCFAddr) writeJSON(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// addrContentEqual compares record contents by parsed IP (mirrors firstAddrMatch)
// so IPv6 re-rendering never causes a spurious mismatch. NOTE: Cloudflare's real
// 81058 duplicate key is the content STRING, not a parsed IP; parsed-IP equality
// is a deliberate SUPERSET that coincides for the canonical IPs Postern always
// sends. The authoritative content-string semantics are pinned by the maintainer
// real-zone contract test (fast-follow PR), not this fake.
func addrContentEqual(a, b string) bool {
	ia, ea := netip.ParseAddr(a)
	ib, eb := netip.ParseAddr(b)
	return ea == nil && eb == nil && ia == ib
}

func (f *fakeCFAddr) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requestLog = append(f.requestLog, fmt.Sprintf("%s %s", r.Method, r.URL.Path))
		dnsPath := "/zones/" + f.zoneID + "/dns_records"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			if r.URL.Query().Get("name") == f.zoneName {
				f.writeJSON(w, 200, cfResponse{Success: true,
					Result: json.RawMessage(fmt.Sprintf(`[{"id":%q,"name":%q}]`, f.zoneID, f.zoneName))})
				return
			}
			f.writeJSON(w, 200, cfResponse{Success: true, Result: json.RawMessage(`[]`)})
		case r.Method == http.MethodGet && r.URL.Path == dnsPath:
			typ, name := r.URL.Query().Get("type"), r.URL.Query().Get("name")
			out := []cfAddrRecord{}
			for _, rec := range f.recs {
				if rec.Type == typ && rec.Name == name {
					out = append(out, rec)
				}
			}
			raw, _ := json.Marshal(out)
			f.writeJSON(w, 200, cfResponse{Success: true, Result: raw})
		case r.Method == http.MethodPost && r.URL.Path == dnsPath:
			var rec cfAddrRecord
			if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
				f.writeJSON(w, 400, cfResponse{Errors: []cfError{{Message: err.Error()}}})
				return
			}
			// Real CF: 81058 keys on (type,name,content), EXCLUDING proxied.
			for _, ex := range f.recs {
				if ex.Type == rec.Type && ex.Name == rec.Name && addrContentEqual(ex.Content, rec.Content) {
					f.writeJSON(w, 400, cfResponse{Errors: []cfError{{
						Code: cloudflareDuplicateCode, Message: "An identical record already exists"}}})
					return
				}
			}
			f.next++
			rec.ID = fmt.Sprintf("rec-%d", f.next)
			f.recs[rec.ID] = rec
			raw, _ := json.Marshal(rec)
			f.writeJSON(w, 200, cfResponse{Success: true, Result: raw})
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, dnsPath+"/"):
			id := strings.TrimPrefix(r.URL.Path, dnsPath+"/")
			rec, ok := f.recs[id]
			if !ok {
				f.writeJSON(w, 404, cfResponse{Errors: []cfError{{Code: 81044, Message: "Record not found"}}})
				return
			}
			var patch struct {
				Proxied bool `json:"proxied"`
				TTL     int  `json:"ttl"`
			}
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				f.writeJSON(w, 400, cfResponse{Errors: []cfError{{Message: err.Error()}}})
				return
			}
			rec.Proxied, rec.TTL = patch.Proxied, patch.TTL
			f.recs[id] = rec
			raw, _ := json.Marshal(rec)
			f.writeJSON(w, 200, cfResponse{Success: true, Result: raw})
		default:
			http.Error(w, "unrouted: "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	})
}

func (f *fakeCFAddr) only() cfAddrRecord {
	for _, r := range f.recs {
		return r
	}
	return cfAddrRecord{}
}

func (f *fakeCFAddr) methods() []string {
	var m []string
	for _, e := range f.requestLog {
		m = append(m, strings.Fields(e)[0])
	}
	return m
}

// containsInOrder reports whether want appears as an ordered subsequence of seq.
func containsInOrder(seq []string, want ...string) bool {
	i := 0
	for _, s := range seq {
		if i < len(want) && s == want[i] {
			i++
		}
	}
	return i == len(want)
}

func newAddrTestClient(srv *httptest.Server) *cfClient {
	return &cfClient{BaseURL: srv.URL, Token: "fake-token", HTTP: &http.Client{Timeout: 5 * time.Second}}
}

func addrRR(name, ip string) libdns.Address {
	return libdns.Address{Name: name, IP: netip.MustParseAddr(ip), TTL: 5 * time.Minute}
}

func TestCFAddrSetProxied_True_FreshCreate(t *testing.T) {
	cf := newFakeCFAddr("example.com")
	srv := httptest.NewServer(cf.handler())
	defer srv.Close()
	if err := cloudflareAddrSetProxied(context.Background(), newAddrTestClient(srv), "example.com", addrRR("@", "203.0.113.7"), true); err != nil {
		t.Fatalf("cloudflareAddrSetProxied: %v", err)
	}
	if len(cf.recs) != 1 {
		t.Fatalf("recs=%d, want 1", len(cf.recs))
	}
	rec := cf.only()
	if rec.Type != "A" || rec.Name != "example.com" || rec.Content != "203.0.113.7" {
		t.Errorf("unexpected record %+v", rec)
	}
	if !rec.Proxied || rec.TTL != cfProxiedTTL {
		t.Errorf("want proxied ttl=1, got proxied=%t ttl=%d", rec.Proxied, rec.TTL)
	}
	for _, m := range cf.methods() {
		if m == http.MethodPatch {
			t.Errorf("unexpected PATCH on fresh create; log=%v", cf.requestLog)
		}
	}
}

func TestCFAddrSetProxied_True_FlipsExistingGray(t *testing.T) {
	cf := newFakeCFAddr("example.com")
	cf.next = 1
	cf.recs["rec-1"] = cfAddrRecord{ID: "rec-1", Type: "A", Name: "example.com", Content: "203.0.113.7", TTL: 300, Proxied: false}
	srv := httptest.NewServer(cf.handler())
	defer srv.Close()
	if err := cloudflareAddrSetProxied(context.Background(), newAddrTestClient(srv), "example.com", addrRR("@", "203.0.113.7"), true); err != nil {
		t.Fatalf("cloudflareAddrSetProxied: %v", err)
	}
	if len(cf.recs) != 1 {
		t.Fatalf("recs=%d, want 1 (no duplicate created)", len(cf.recs))
	}
	if rec := cf.recs["rec-1"]; !rec.Proxied || rec.TTL != cfProxiedTTL {
		t.Errorf("want flipped to proxied ttl=1, got %+v", rec)
	}
	if !containsInOrder(cf.methods(), http.MethodPost, http.MethodGet, http.MethodPatch) {
		t.Errorf("want POST->GET->PATCH, got %v", cf.requestLog)
	}
}

func TestCFAddrSetProxied_False_FlipsExistingOrange(t *testing.T) {
	cf := newFakeCFAddr("example.com")
	cf.next = 1
	cf.recs["rec-1"] = cfAddrRecord{ID: "rec-1", Type: "A", Name: "example.com", Content: "203.0.113.7", TTL: 1, Proxied: true}
	srv := httptest.NewServer(cf.handler())
	defer srv.Close()
	if err := cloudflareAddrSetProxied(context.Background(), newAddrTestClient(srv), "example.com", addrRR("@", "203.0.113.7"), false); err != nil {
		t.Fatalf("cloudflareAddrSetProxied: %v", err)
	}
	if rec := cf.recs["rec-1"]; rec.Proxied || rec.TTL != cfUnproxiedTTL {
		t.Errorf("want flipped to gray ttl=300, got %+v", rec)
	}
	for _, m := range cf.methods() {
		if m == http.MethodPost {
			t.Errorf("un-proxy must not POST; log=%v", cf.requestLog)
		}
	}
	if !containsInOrder(cf.methods(), http.MethodGet, http.MethodPatch) {
		t.Errorf("want GET->PATCH, got %v", cf.requestLog)
	}
}

func TestCFAddrSetProxied_False_AbsentCreatesGray(t *testing.T) {
	cf := newFakeCFAddr("example.com")
	srv := httptest.NewServer(cf.handler())
	defer srv.Close()
	if err := cloudflareAddrSetProxied(context.Background(), newAddrTestClient(srv), "example.com", addrRR("@", "203.0.113.7"), false); err != nil {
		t.Fatalf("cloudflareAddrSetProxied: %v", err)
	}
	if len(cf.recs) != 1 {
		t.Fatalf("recs=%d, want 1 (created gray)", len(cf.recs))
	}
	if rec := cf.only(); rec.Proxied || rec.TTL != cfUnproxiedTTL {
		t.Errorf("want gray ttl=300, got %+v", rec)
	}
	if !containsInOrder(cf.methods(), http.MethodGet, http.MethodPost) {
		t.Errorf("want GET(list)->POST(create), got %v", cf.requestLog)
	}
}

func TestCFAddrSetProxied_AAAA_Proxied(t *testing.T) {
	cf := newFakeCFAddr("example.com")
	srv := httptest.NewServer(cf.handler())
	defer srv.Close()
	if err := cloudflareAddrSetProxied(context.Background(), newAddrTestClient(srv), "example.com", addrRR("@", "2001:db8::1"), true); err != nil {
		t.Fatalf("cloudflareAddrSetProxied AAAA: %v", err)
	}
	rec := cf.only()
	if rec.Type != "AAAA" || !rec.Proxied {
		t.Errorf("want proxied AAAA, got %+v", rec)
	}
	if got, err := netip.ParseAddr(rec.Content); err != nil || got != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("content %q not the canonical IPv6", rec.Content)
	}
}

func TestCFAddrSetProxied_ZoneMissing(t *testing.T) {
	cf := newFakeCFAddr("other.example")
	srv := httptest.NewServer(cf.handler())
	defer srv.Close()
	err := cloudflareAddrSetProxied(context.Background(), newAddrTestClient(srv), "example.com", addrRR("@", "203.0.113.7"), true)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want zone-not-found error, got %v", err)
	}
}
