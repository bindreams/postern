// Unit tests for the Cloudflare-API direct TLSA fallback (#127). Each test
// stands up an httptest server that mirrors the small slice of the Cloudflare
// REST API the fallback uses: GET /zones, GET/POST/DELETE
// /zones/{id}/dns_records.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// fakeCF is a minimal in-memory Cloudflare API. Records are indexed by an
// auto-incrementing ID; only TLSA is implemented (and only the subset
// cloudflare_tlsa.go uses).
type fakeCF struct {
	zoneID   string
	zoneName string
	mu       struct {
		next int
		recs map[string]cfTLSARecord
	}
	// dedupeOnPost makes POST /dns_records return Cloudflare's 81058 error
	// when an exact-content match already exists (matches real Cloudflare
	// behavior; see issue #122 and the duplicate-detection logic upstream).
	dedupeOnPost bool
	// requestLog captures every method+path the test exercised, for shape
	// assertions.
	requestLog []string
}

func newFakeCF(zoneName string) *fakeCF {
	f := &fakeCF{zoneID: "ZONE_ID_" + zoneName, zoneName: zoneName}
	f.mu.recs = map[string]cfTLSARecord{}
	return f
}

func (f *fakeCF) writeJSON(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeCF) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requestLog = append(f.requestLog, fmt.Sprintf("%s %s", r.Method, r.URL.RequestURI()))

		if r.Method == http.MethodGet && r.URL.Path == "/zones" {
			name := r.URL.Query().Get("name")
			if name == f.zoneName {
				f.writeJSON(w, 200, cfResponse{Success: true, Result: json.RawMessage(fmt.Sprintf(
					`[{"id":%q,"name":%q}]`, f.zoneID, f.zoneName,
				))})
				return
			}
			f.writeJSON(w, 200, cfResponse{Success: true, Result: json.RawMessage(`[]`)})
			return
		}

		dnsPath := "/zones/" + f.zoneID + "/dns_records"
		if r.Method == http.MethodGet && r.URL.Path == dnsPath {
			name := r.URL.Query().Get("name")
			out := []cfTLSARecord{}
			for _, rec := range f.mu.recs {
				if rec.Name == name && rec.Type == "TLSA" {
					out = append(out, rec)
				}
			}
			raw, _ := json.Marshal(out)
			f.writeJSON(w, 200, cfResponse{Success: true, Result: raw})
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == dnsPath {
			var rec cfTLSARecord
			if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
				f.writeJSON(w, 400, cfResponse{Errors: []cfError{{Code: 0, Message: err.Error()}}})
				return
			}
			if f.dedupeOnPost {
				for _, ex := range f.mu.recs {
					if ex.Type == "TLSA" && ex.Name == rec.Name && tlsaContentEqual(ex.Data, rec.Data) {
						f.writeJSON(w, 400, cfResponse{Errors: []cfError{{
							Code: cloudflareDuplicateCode, Message: "An identical record already exists",
						}}})
						return
					}
				}
			}
			f.mu.next++
			id := fmt.Sprintf("rec-%d", f.mu.next)
			rec.ID = id
			f.mu.recs[id] = rec
			raw, _ := json.Marshal(rec)
			f.writeJSON(w, 200, cfResponse{Success: true, Result: raw})
			return
		}
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, dnsPath+"/") {
			id := strings.TrimPrefix(r.URL.Path, dnsPath+"/")
			if _, ok := f.mu.recs[id]; !ok {
				f.writeJSON(w, 404, cfResponse{Errors: []cfError{{Code: 81044, Message: "Record not found"}}})
				return
			}
			delete(f.mu.recs, id)
			f.writeJSON(w, 200, cfResponse{Success: true, Result: json.RawMessage(fmt.Sprintf(`{"id":%q}`, id))})
			return
		}

		http.Error(w, "unrouted: "+r.Method+" "+r.URL.Path, http.StatusNotFound)
	})
}

func newTestClient(srv *httptest.Server) *cfClient {
	return &cfClient{
		BaseURL: srv.URL,
		Token:   "fake-token",
		HTTP:    &http.Client{Timeout: 5 * time.Second},
	}
}

func sampleRR() libdns.RR {
	return libdns.RR{
		Name: "_25._tcp.mail",
		Type: "TLSA",
		Data: "3 1 1 " + strings.Repeat("ab", 32),
		TTL:  300 * time.Second,
	}
}

func TestCFTLSASet_PublishesRecordWithStructuredFields(t *testing.T) {
	cf := newFakeCF("example.com")
	srv := httptest.NewServer(cf.handler())
	defer srv.Close()

	if err := cloudflareTLSASet(context.Background(), newTestClient(srv), "example.com", sampleRR()); err != nil {
		t.Fatalf("cloudflareTLSASet: %v", err)
	}
	if len(cf.mu.recs) != 1 {
		t.Fatalf("recs after publish = %d, want 1", len(cf.mu.recs))
	}
	var got cfTLSARecord
	for _, r := range cf.mu.recs {
		got = r
	}
	if got.Type != "TLSA" {
		t.Errorf("got.Type=%q, want TLSA", got.Type)
	}
	if got.Name != "_25._tcp.mail.example.com" {
		t.Errorf("got.Name=%q, want fully-qualified", got.Name)
	}
	// Structured fields populated -- the whole reason this fallback exists.
	if got.Data.Usage != 3 || got.Data.Selector != 1 || got.Data.MatchingType != 1 {
		t.Errorf("Data structured fields = %+v, want {3,1,1}", got.Data)
	}
	if got.Data.Certificate != strings.Repeat("ab", 32) {
		t.Errorf("Data.Certificate = %q, want lowercase hex", got.Data.Certificate)
	}
}

func TestCFTLSASet_IdempotentOnDuplicate(t *testing.T) {
	cf := newFakeCF("example.com")
	cf.dedupeOnPost = true
	srv := httptest.NewServer(cf.handler())
	defer srv.Close()

	client := newTestClient(srv)
	if err := cloudflareTLSASet(context.Background(), client, "example.com", sampleRR()); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	// Second publish must succeed (Cloudflare returns 81058; client confirms via list and treats as no-op).
	if err := cloudflareTLSASet(context.Background(), client, "example.com", sampleRR()); err != nil {
		t.Fatalf("idempotent publish: %v", err)
	}
	if len(cf.mu.recs) != 1 {
		t.Errorf("recs = %d, want 1 (no duplicate)", len(cf.mu.recs))
	}
}

func TestCFTLSADelete_RemovesMatchingRecord(t *testing.T) {
	cf := newFakeCF("example.com")
	srv := httptest.NewServer(cf.handler())
	defer srv.Close()

	client := newTestClient(srv)
	if err := cloudflareTLSASet(context.Background(), client, "example.com", sampleRR()); err != nil {
		t.Fatalf("seed publish: %v", err)
	}
	if err := cloudflareTLSADelete(context.Background(), client, "example.com", sampleRR()); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(cf.mu.recs) != 0 {
		t.Errorf("recs after delete = %d, want 0", len(cf.mu.recs))
	}
}

func TestCFTLSADelete_NoMatchIsIdempotent(t *testing.T) {
	cf := newFakeCF("example.com")
	srv := httptest.NewServer(cf.handler())
	defer srv.Close()

	if err := cloudflareTLSADelete(context.Background(), newTestClient(srv), "example.com", sampleRR()); err != nil {
		t.Fatalf("delete on empty zone: %v", err)
	}
}

func TestCFTLSADelete_LeavesNonMatchingRecord(t *testing.T) {
	cf := newFakeCF("example.com")
	srv := httptest.NewServer(cf.handler())
	defer srv.Close()

	client := newTestClient(srv)
	other := sampleRR()
	other.Data = "3 1 1 " + strings.Repeat("cd", 32)
	if err := cloudflareTLSASet(context.Background(), client, "example.com", other); err != nil {
		t.Fatalf("seed publish: %v", err)
	}
	// Delete a different cert hex -- the seeded record must remain.
	if err := cloudflareTLSADelete(context.Background(), client, "example.com", sampleRR()); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(cf.mu.recs) != 1 {
		t.Errorf("recs after non-matching delete = %d, want 1", len(cf.mu.recs))
	}
}

func TestCFTLSASet_ReturnsAPIErrorWhenZoneMissing(t *testing.T) {
	cf := newFakeCF("other.example")
	srv := httptest.NewServer(cf.handler())
	defer srv.Close()

	err := cloudflareTLSASet(context.Background(), newTestClient(srv), "example.com", sampleRR())
	if err == nil {
		t.Fatalf("expected error when zone is not in the account, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got %q", err.Error())
	}
}

func TestCFTLSASet_AuthorizationHeaderSent(t *testing.T) {
	var seen string
	cf := newFakeCF("example.com")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get("Authorization"); seen == "" {
			seen = v
		}
		cf.handler().ServeHTTP(w, r)
	}))
	defer srv.Close()

	_ = cloudflareTLSASet(context.Background(), newTestClient(srv), "example.com", sampleRR())
	if seen != "Bearer fake-token" {
		t.Errorf("Authorization = %q, want %q", seen, "Bearer fake-token")
	}
}

func TestTLSADataFromRR_RejectsBadInput(t *testing.T) {
	bad := libdns.RR{Name: "_25._tcp.mail", Type: "TLSA", Data: "3 1 1"}
	if _, err := tlsaDataFromRR(bad); err == nil {
		t.Errorf("expected error on 3-field data, got nil")
	}
	bad2 := libdns.RR{Name: "_25._tcp.mail", Type: "TLSA", Data: "3 1 1 not-hex!"}
	if _, err := tlsaDataFromRR(bad2); err == nil {
		t.Errorf("expected error on non-hex cert, got nil")
	}
}

// Sanity: net/http error path is preserved as a plain Go error (not silently swallowed).
func TestCFClientDo_TransportError(t *testing.T) {
	c := &cfClient{BaseURL: "http://127.0.0.1:1", Token: "t", HTTP: &http.Client{Timeout: 100 * time.Millisecond}}
	_, _, err := c.do(context.Background(), http.MethodGet, "/zones", nil)
	if err == nil {
		t.Fatalf("expected transport error, got nil")
	}
	// Either dial-refused, dial-timeout, or i/o-timeout -- depends on the host's TCP stack.
	if !strings.Contains(err.Error(), "transport") {
		t.Errorf("expected 'transport' in error, got %q", err.Error())
	}
}

// Compile-time assertion that the helpers play with the libdns types we use.
var _ = errors.New
