package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/libdns/cloudflare"
	"github.com/libdns/digitalocean"
	"github.com/libdns/gandi"
	"github.com/libdns/hetzner/v2"
	"github.com/libdns/libdns"
	"github.com/libdns/linode"
	"github.com/libdns/namecheap"
	"github.com/libdns/ovh"
	"github.com/libdns/route53"
)

func TestSplitFQDN(t *testing.T) {
	cases := []struct {
		in       string
		wantZone string
		wantName string
	}{
		{"host.example.com", "example.com.", "host"},
		{"_acme-challenge.example.com", "example.com.", "_acme-challenge"},
		{"postern-2026-04._domainkey.example.com", "example.com.", "postern-2026-04._domainkey"},
		{"sub.host.example.com", "example.com.", "sub.host"},
		{"example.com", "example.com.", "@"},
		{"example.com.", "example.com.", "@"},
		{"localhost", "localhost.", "@"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			zone, name := splitFQDN(c.in)
			if zone != c.wantZone || name != c.wantName {
				t.Errorf("splitFQDN(%q) = (%q, %q); want (%q, %q)", c.in, zone, name, c.wantZone, c.wantName)
			}
		})
	}
}

func TestNewProvider_KnownNames(t *testing.T) {
	cases := []struct {
		name string
		// assertType returns true when p has the expected concrete type for
		// that provider name. We use a closure rather than reflect so any
		// silent change to the concrete type breaks compilation.
		assertType func(p providerOps) bool
	}{
		{"cloudflare", func(p providerOps) bool { _, ok := p.(*cloudflare.Provider); return ok }},
		{"route53", func(p providerOps) bool { _, ok := p.(*route53.Provider); return ok }},
		{"gandi", func(p providerOps) bool { _, ok := p.(*gandi.Provider); return ok }},
		{"digitalocean", func(p providerOps) bool { _, ok := p.(*digitalocean.Provider); return ok }},
		{"ovh", func(p providerOps) bool { _, ok := p.(*ovh.Provider); return ok }},
		{"hetzner", func(p providerOps) bool { _, ok := p.(*hetzner.Provider); return ok }},
		{"linode", func(p providerOps) bool { _, ok := p.(*linode.Provider); return ok }},
		{"namecheap", func(p providerOps) bool { _, ok := p.(*namecheap.Provider); return ok }},
		// case-insensitive lookup
		{"CloudFlare", func(p providerOps) bool { _, ok := p.(*cloudflare.Provider); return ok }},
		{"HETZNER", func(p providerOps) bool { _, ok := p.(*hetzner.Provider); return ok }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := newProvider(c.name)
			if err != nil {
				t.Fatalf("newProvider(%q) returned error: %v", c.name, err)
			}
			if p == nil {
				t.Fatalf("newProvider(%q) returned nil provider", c.name)
			}
			if !c.assertType(p) {
				t.Errorf("newProvider(%q) returned wrong concrete type: %T", c.name, p)
			}
		})
	}
}

func TestNewProvider_UnknownName(t *testing.T) {
	p, err := newProvider("nonexistent-provider-xyz")
	if err == nil {
		t.Fatalf("newProvider(unknown) succeeded; want error, got %T", p)
	}
	// Error message should name the supported providers so an operator can
	// see the contract. We check for a couple anchors rather than the full
	// list to stay robust to ordering.
	for _, want := range []string{"cloudflare", "hetzner", "namecheap"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention supported provider %q", err.Error(), want)
		}
	}
}

func TestNewProvider_FieldWiring(t *testing.T) {
	// Each case sets one provider's documented env vars to sentinel values
	// and asserts the relevant field on the constructed Provider carries
	// the sentinel. This is the regression guard for the gandi
	// APIToken->BearerToken and hetzner AuthAPIToken->APIToken renames.
	cases := []struct {
		providerName string
		env          map[string]string
		check        func(t *testing.T, p providerOps)
	}{
		{
			providerName: "cloudflare",
			env:          map[string]string{"CLOUDFLARE_API_TOKEN": "cf-sentinel"},
			check: func(t *testing.T, p providerOps) {
				cf := p.(*cloudflare.Provider)
				if cf.APIToken != "cf-sentinel" {
					t.Errorf("cloudflare APIToken = %q; want cf-sentinel", cf.APIToken)
				}
			},
		},
		{
			providerName: "gandi",
			env:          map[string]string{"GANDI_API_TOKEN": "gandi-sentinel"},
			check: func(t *testing.T, p providerOps) {
				g := p.(*gandi.Provider)
				if g.BearerToken != "gandi-sentinel" {
					t.Errorf("gandi BearerToken = %q; want gandi-sentinel", g.BearerToken)
				}
			},
		},
		{
			providerName: "hetzner",
			env:          map[string]string{"HETZNER_API_TOKEN": "hz-sentinel"},
			check: func(t *testing.T, p providerOps) {
				h := p.(*hetzner.Provider)
				if h.APIToken != "hz-sentinel" {
					t.Errorf("hetzner APIToken = %q; want hz-sentinel", h.APIToken)
				}
			},
		},
		{
			providerName: "digitalocean",
			env:          map[string]string{"DO_AUTH_TOKEN": "do-sentinel"},
			check: func(t *testing.T, p providerOps) {
				d := p.(*digitalocean.Provider)
				if d.APIToken != "do-sentinel" {
					t.Errorf("digitalocean APIToken = %q; want do-sentinel", d.APIToken)
				}
			},
		},
		{
			providerName: "linode",
			env:          map[string]string{"LINODE_TOKEN": "linode-sentinel"},
			check: func(t *testing.T, p providerOps) {
				l := p.(*linode.Provider)
				if l.APIToken != "linode-sentinel" {
					t.Errorf("linode APIToken = %q; want linode-sentinel", l.APIToken)
				}
			},
		},
		{
			providerName: "route53",
			env: map[string]string{
				"AWS_REGION":            "us-east-1",
				"AWS_ACCESS_KEY_ID":     "akid-sentinel",
				"AWS_SECRET_ACCESS_KEY": "secret-sentinel",
			},
			check: func(t *testing.T, p providerOps) {
				r := p.(*route53.Provider)
				if r.Region != "us-east-1" {
					t.Errorf("route53 Region = %q; want us-east-1", r.Region)
				}
				if r.AccessKeyId != "akid-sentinel" {
					t.Errorf("route53 AccessKeyId = %q; want akid-sentinel", r.AccessKeyId)
				}
				if r.SecretAccessKey != "secret-sentinel" {
					t.Errorf("route53 SecretAccessKey = %q; want secret-sentinel", r.SecretAccessKey)
				}
			},
		},
		{
			providerName: "ovh",
			env: map[string]string{
				"OVH_ENDPOINT":           "ovh-eu",
				"OVH_APPLICATION_KEY":    "ak-sentinel",
				"OVH_APPLICATION_SECRET": "as-sentinel",
				"OVH_CONSUMER_KEY":       "ck-sentinel",
			},
			check: func(t *testing.T, p providerOps) {
				o := p.(*ovh.Provider)
				if o.Endpoint != "ovh-eu" || o.ApplicationKey != "ak-sentinel" || o.ApplicationSecret != "as-sentinel" || o.ConsumerKey != "ck-sentinel" {
					t.Errorf("ovh fields not wired: %+v", o)
				}
			},
		},
		{
			providerName: "namecheap",
			env: map[string]string{
				"NAMECHEAP_API_KEY":   "nc-key",
				"NAMECHEAP_API_USER":  "nc-user",
				"NAMECHEAP_CLIENT_IP": "203.0.113.1",
			},
			check: func(t *testing.T, p providerOps) {
				n := p.(*namecheap.Provider)
				if n.APIKey != "nc-key" || n.User != "nc-user" || n.ClientIP != "203.0.113.1" {
					t.Errorf("namecheap fields not wired: %+v", n)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.providerName, func(t *testing.T) {
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			p, err := newProvider(c.providerName)
			if err != nil {
				t.Fatalf("newProvider(%q): %v", c.providerName, err)
			}
			c.check(t, p)
		})
	}
}

// fakeProvider captures the records passed to AppendRecords/DeleteRecords
// so we can assert what the wrapper emits on the wire-side libdns boundary,
// and returns canned records from GetRecords so we can exercise the
// txt-delete pre-fetch path.
//
// strictDataEqualDelete simulates the route53/ovh/linode/digitalocean
// behaviour: DeleteRecords identifies records by exact rr.Data equality
// against the stored value. If our wrapper accidentally outer-quotes
// records before passing them in (the workaround that's necessary for
// Cloudflare and *toxic* for these providers), the simulated provider
// returns 0 deletes and stored remains unchanged -- which our tests
// then catch.
type fakeProvider struct {
	stored                []libdns.Record
	appended              []libdns.Record
	deleted               []libdns.Record
	appendErr             error // if non-nil, AppendRecords returns this without storing.
	getRecordsErr         error // if non-nil, GetRecords returns this without listing.
	strictDataEqualDelete bool
}

func (f *fakeProvider) GetRecords(_ context.Context, _ string) ([]libdns.Record, error) {
	if f.getRecordsErr != nil {
		return nil, f.getRecordsErr
	}
	out := make([]libdns.Record, len(f.stored))
	copy(out, f.stored)
	return out, nil
}

func (f *fakeProvider) AppendRecords(_ context.Context, _ string, recs []libdns.Record) ([]libdns.Record, error) {
	if f.appendErr != nil {
		return nil, f.appendErr
	}
	f.appended = append(f.appended, recs...)
	f.stored = append(f.stored, recs...)
	return recs, nil
}

func (f *fakeProvider) DeleteRecords(_ context.Context, _ string, recs []libdns.Record) ([]libdns.Record, error) {
	f.deleted = append(f.deleted, recs...)
	var actuallyDeleted []libdns.Record
	for _, r := range recs {
		rrIn := r.RR()
		for i := 0; i < len(f.stored); i++ {
			rrSt := f.stored[i].RR()
			if rrSt.Type != rrIn.Type || rrSt.Name != rrIn.Name {
				continue
			}
			if f.strictDataEqualDelete {
				if rrSt.Data != rrIn.Data {
					continue
				}
			} else {
				// Lenient: also accept a wrap difference (cloudflare-
				// shape provider).
				if rrSt.Data != rrIn.Data && `"`+rrSt.Data+`"` != rrIn.Data {
					continue
				}
			}
			actuallyDeleted = append(actuallyDeleted, f.stored[i])
			f.stored = append(f.stored[:i], f.stored[i+1:]...)
			break
		}
	}
	return actuallyDeleted, nil
}

// TestRecordConstruction_DKIMShape exercises the v1.x record construction
// with a realistic, long DKIM TXT (~880-byte payload). It guards against the
// migration silently changing what gets sent to the upstream registrar --
// DKIM is signature-bytes-sensitive. libdns v1.x deliberately treats
// libdns.TXT.Text as a single arbitrary-length string (not chunked into
// 255-byte segments at this layer; subdrivers handle wire-format
// representation), so the assertions check byte-identity, not chunking.
func TestRecordConstruction_DKIMShape(t *testing.T) {
	// 800 bytes of arbitrary content ("p=" payload simulation) so the test
	// doesn't shrink to a too-short happy path.
	payload := strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA", 20)
	value := "v=DKIM1; k=rsa; p=" + payload
	name := "postern-2026-04._domainkey"

	rec := libdns.TXT{
		Name: name,
		Text: value,
		TTL:  5 * time.Minute,
	}

	rr := rec.RR()
	if rr.Type != "TXT" {
		t.Errorf("RR().Type = %q; want TXT", rr.Type)
	}
	if rr.Name != name {
		t.Errorf("RR().Name = %q; want %q", rr.Name, name)
	}
	if rr.Data != value {
		t.Errorf("RR().Data is not byte-identical to input Text\n got: %q\nwant: %q", rr.Data, value)
	}
	if rr.TTL != 5*time.Minute {
		t.Errorf("RR().TTL = %v; want 5m", rr.TTL)
	}

	// Simulate the actual wrapper code path: pass via []libdns.Record and
	// confirm the captured record's RR() round-trips byte-identically.
	fp := &fakeProvider{}
	if _, err := fp.AppendRecords(context.Background(), "example.com.", []libdns.Record{rec}); err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}
	if len(fp.appended) != 1 {
		t.Fatalf("appended count = %d; want 1", len(fp.appended))
	}
	got := fp.appended[0].RR()
	if got.Data != value {
		t.Errorf("captured RR().Data not byte-identical:\n got: %q\nwant: %q", got.Data, value)
	}
}

func TestNormalizeTXTData(t *testing.T) {
	// Single-segment TXT (≤255 bytes): no embedded separators, passthrough.
	if got := normalizeTXTData("v=DKIM1; k=rsa; p=ABC"); got != "v=DKIM1; k=rsa; p=ABC" {
		t.Errorf("short TXT mutated: %q", got)
	}
	// libdns/cloudflare leaks the zone-file segment delimiter `" "` between
	// chunks for TXT >255 bytes (its unwrapContent only strips outer quotes).
	// Reconstruct the original by removing every occurrence.
	chunked := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 200) + `" "` + strings.Repeat("B", 100)
	want := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 200) + strings.Repeat("B", 100)
	if got := normalizeTXTData(chunked); got != want {
		t.Errorf("chunked TXT not joined:\n got: %q\nwant: %q", got, want)
	}
	// Multiple chunk boundaries (very long TXT, e.g. 4096-bit DKIM).
	multi := strings.Repeat("X", 255) + `" "` + strings.Repeat("Y", 255) + `" "` + strings.Repeat("Z", 100)
	wantMulti := strings.Repeat("X", 255) + strings.Repeat("Y", 255) + strings.Repeat("Z", 100)
	if got := normalizeTXTData(multi); got != wantMulti {
		t.Errorf("multi-chunk TXT not joined: got len %d, want %d", len(got), len(wantMulti))
	}
}

func TestMatchTXT(t *testing.T) {
	other := libdns.TXT{Name: "_other", Text: "ignore me", TTL: time.Minute}
	wanted1 := libdns.TXT{Name: "postern-1._domainkey", Text: "v=DKIM1; p=A...", TTL: time.Minute}
	wanted2 := libdns.TXT{Name: "postern-1._domainkey", Text: "v=DKIM1; p=A...", TTL: time.Hour} // duplicate body, different TTL
	sameNameDifferentBody := libdns.TXT{Name: "postern-1._domainkey", Text: "v=DKIM1; p=B...", TTL: time.Minute}
	differentName := libdns.TXT{Name: "postern-2._domainkey", Text: "v=DKIM1; p=A...", TTL: time.Minute}
	all := []libdns.Record{other, wanted1, sameNameDifferentBody, differentName, wanted2}

	got := matchTXT(all, "postern-1._domainkey", "v=DKIM1; p=A...")
	if len(got) != 2 {
		t.Fatalf("matchTXT returned %d records; want 2 (wanted1 + wanted2)", len(got))
	}
	for _, rec := range got {
		rr := rec.RR()
		if rr.Name != "postern-1._domainkey" || rr.Data != "v=DKIM1; p=A..." {
			t.Errorf("matchTXT returned non-matching record: %+v", rr)
		}
	}

	// Empty zone -> no matches, no panic.
	if got := matchTXT(nil, "x", "y"); got != nil {
		t.Errorf("matchTXT(nil,...) = %+v; want nil", got)
	}

	// Wrong type filter (non-TXT records with same name should not match).
	addr := libdns.Address{Name: "postern-1._domainkey", IP: netip.MustParseAddr("203.0.113.1"), TTL: time.Minute}
	if got := matchTXT([]libdns.Record{addr}, "postern-1._domainkey", "203.0.113.1"); got != nil {
		t.Errorf("matchTXT must ignore non-TXT records, got: %+v", got)
	}
}

func TestIsDuplicateRecordError(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		// Recognized: Cloudflare's error string.
		{errStr("got error status: HTTP 400: [{Code:81058 Message:An identical record already exists. ErrorChain:[]}]"), true},
		{errStr("identical record already exists in zone foo"), true},
		// Adversarial: numeric code alone is too generic; we no longer key
		// on it. A different 5-digit code like 181058, or request IDs that
		// happen to contain 81058, must NOT trigger duplicate-recovery.
		{errStr("got error status: HTTP 500: error code 181058 (other)"), false},
		{errStr("request id 81058 timed out"), false},
		{errStr("provider error code 81058 (rate limit)"), false},
		// Generic errors propagate untouched.
		{errStr("authentication failed"), false},
		{errStr("rate limit exceeded"), false},
		{errStr("dial tcp: connection refused"), false},
		{errStr("zone not found"), false},
	}
	for _, c := range cases {
		var msg string
		if c.err == nil {
			msg = "<nil>"
		} else {
			msg = c.err.Error()
		}
		t.Run(msg, func(t *testing.T) {
			if got := isDuplicateRecordError(c.err); got != c.want {
				t.Errorf("isDuplicateRecordError(%q) = %t; want %t", msg, got, c.want)
			}
		})
	}
}

func errStr(s string) error { return errors.New(s) }

func TestRunCmd_TxtSet_Success(t *testing.T) {
	fp := &fakeProvider{}
	if err := runCmd(context.Background(), "cloudflare", fp, "txt-set", "host.example.com", "v=ok"); err != nil {
		t.Fatalf("runCmd: %v", err)
	}
	if len(fp.appended) != 1 {
		t.Errorf("AppendRecords called %d times; want 1", len(fp.appended))
	}
	// On the success path we should NOT issue a redundant GetRecords.
	if len(fp.stored) != 1 {
		t.Errorf("stored count = %d; want 1", len(fp.stored))
	}
}

func TestRunCmd_TxtSet_DuplicateRecoveredFromGetRecords(t *testing.T) {
	// AppendRecords returns the duplicate-detection error AND the desired
	// record is already in the zone -> idempotent success.
	preExisting := libdns.TXT{Name: "host", Text: "v=ok", TTL: time.Minute}
	fp := &fakeProvider{
		stored:    []libdns.Record{preExisting},
		appendErr: errStr("got error status: HTTP 400: [{Code:81058 Message:An identical record already exists}]"),
	}
	if err := runCmd(context.Background(), "cloudflare", fp, "txt-set", "host.example.com", "v=ok"); err != nil {
		t.Fatalf("runCmd: %v", err)
	}
}

func TestRunCmd_TxtSet_DuplicateButNoMatchInZone(t *testing.T) {
	// Provider says "duplicate" but our exact (name, value) is NOT in the
	// zone -> NOT silently treated as success.
	fp := &fakeProvider{
		stored:    []libdns.Record{libdns.TXT{Name: "host", Text: "v=other", TTL: time.Minute}},
		appendErr: errStr("got error status: HTTP 400: [{Code:81058 Message:An identical record already exists}]"),
	}
	err := runCmd(context.Background(), "cloudflare", fp, "txt-set", "host.example.com", "v=ok")
	if err == nil {
		t.Fatalf("runCmd: want error, got nil")
	}
	if !strings.Contains(err.Error(), "no matching record visible") {
		t.Errorf("error %q does not name the diagnostic anchor", err.Error())
	}
}

func TestRunCmd_UnknownCommand(t *testing.T) {
	fp := &fakeProvider{}
	err := runCmd(context.Background(), "cloudflare", fp, "txt-typo", "host.example.com", "v=ok")
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("runCmd unknown-command: got err=%v; want 'unknown command' anchor", err)
	}
}

func TestRunCmd_TxtSet_DuplicateButGetRecordsAlsoFails(t *testing.T) {
	// AppendRecords reports duplicate AND GetRecords (the recovery probe)
	// errors out. The wrapper must surface both errors so operators
	// don't see only one half of the failure.
	fp := &fakeProvider{
		stored:        []libdns.Record{libdns.TXT{Name: "host", Text: "v=ok", TTL: time.Minute}},
		appendErr:     errStr("got error status: HTTP 400: [{Code:81058 Message:An identical record already exists}]"),
		getRecordsErr: errStr("rate limit exceeded on GetRecords"),
	}
	err := runCmd(context.Background(), "cloudflare", fp, "txt-set", "host.example.com", "v=ok")
	if err == nil {
		t.Fatalf("runCmd: want error, got nil")
	}
	if !strings.Contains(err.Error(), "GetRecords failed") {
		t.Errorf("error %q does not name the GetRecords failure", err.Error())
	}
	if !strings.Contains(err.Error(), "rate limit exceeded on GetRecords") {
		t.Errorf("error %q does not include the original GetRecords error", err.Error())
	}
}

func TestRunCmd_TxtSet_GenericErrorIsNotMaskedByPriorRecord(t *testing.T) {
	// Critical regression guard: AppendRecords fails with a generic
	// (non-duplicate) error. A pre-existing matching record in the zone
	// (left over from a previous run, manual edit, etc.) MUST NOT cause
	// txt-set to silently exit 0. Auth failures, rate limits, network
	// glitches are real failures and operators / state machines need to
	// see them.
	preExisting := libdns.TXT{Name: "host", Text: "v=ok", TTL: time.Minute}
	fp := &fakeProvider{
		stored:    []libdns.Record{preExisting},
		appendErr: errStr("authentication failed: invalid API token"),
	}
	err := runCmd(context.Background(), "cloudflare", fp, "txt-set", "host.example.com", "v=ok")
	if err == nil {
		t.Fatalf("runCmd: want error (auth failure must propagate), got nil")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("error %q does not propagate the original auth failure", err.Error())
	}
}

func TestRunCmd_TxtDelete_NoMatch_IsIdempotent(t *testing.T) {
	fp := &fakeProvider{
		stored: []libdns.Record{libdns.TXT{Name: "_other", Text: "ignore me", TTL: time.Minute}},
	}
	if err := runCmd(context.Background(), "cloudflare", fp, "txt-delete", "host.example.com", "v=gone"); err != nil {
		t.Fatalf("runCmd: %v", err)
	}
	if len(fp.deleted) != 0 {
		t.Errorf("DeleteRecords was called with %d records; want 0 (no match locally)", len(fp.deleted))
	}
}

func TestRunCmd_TxtDelete_NonCloudflare_PassesRecordsThrough(t *testing.T) {
	// For every provider other than cloudflare, the workaround MUST be
	// off: passing outer-quoted Data into route53/ovh/digitalocean/etc.
	// breaks their byte-equal delete contracts. We assert the records
	// handed to DeleteRecords are byte-identical to the GetRecords output.
	target := libdns.TXT{Name: "host", Text: "v=ok", TTL: time.Minute}
	fp := &fakeProvider{
		stored:                []libdns.Record{target},
		strictDataEqualDelete: true, // simulate non-cloudflare strict semantics
	}
	if err := runCmd(context.Background(), "route53", fp, "txt-delete", "host.example.com", "v=ok"); err != nil {
		t.Fatalf("runCmd: %v (workaround must be off for non-cloudflare)", err)
	}
	if len(fp.deleted) != 1 {
		t.Fatalf("DeleteRecords got %d records; want 1", len(fp.deleted))
	}
	if got := fp.deleted[0].RR(); got.Data != "v=ok" {
		t.Errorf("DeleteRecords received wrapped data %q for non-cloudflare provider; must pass through unchanged", got.Data)
	}
	if len(fp.stored) != 0 {
		t.Errorf("stored should be empty after delete; got %d records (workaround likely interfered)", len(fp.stored))
	}
}

// concreteTypeFakeProvider models providers like libdns/digitalocean
// whose DeleteRecords type-asserts the input record to a provider-
// specific concrete type (`record.(DNS)` etc.). Stripping the type to
// libdns.RR (as the cloudflare workaround does) makes those providers
// silently fail the cast and report 0 deletes. This guards against a
// regression that would re-introduce the broken behaviour.
type concreteTypeFakeProvider struct {
	stored  []taggedRecord
	deleted []libdns.Record
}

// taggedRecord wraps libdns.RR with a provider-specific marker so a
// type assertion succeeds (or fails) the same way digitalocean's
// idFromRecord does in production. We can't embed libdns.RR (the
// embedded field name `RR` would shadow the `RR()` method needed by
// libdns.Record), so we hold it as a named field and forward.
type taggedRecord struct {
	rr         libdns.RR
	providerID string
}

func (t taggedRecord) RR() libdns.RR { return t.rr }

func (c *concreteTypeFakeProvider) GetRecords(_ context.Context, _ string) ([]libdns.Record, error) {
	out := make([]libdns.Record, len(c.stored))
	for i, r := range c.stored {
		out[i] = r
	}
	return out, nil
}

func (c *concreteTypeFakeProvider) AppendRecords(_ context.Context, _ string, recs []libdns.Record) ([]libdns.Record, error) {
	return recs, nil
}

func (c *concreteTypeFakeProvider) DeleteRecords(_ context.Context, _ string, recs []libdns.Record) ([]libdns.Record, error) {
	var actuallyDeleted []libdns.Record
	for _, r := range recs {
		// The "real" digitalocean shape: only delete if we can recover
		// the provider ID via type assertion.
		tr, ok := r.(taggedRecord)
		if !ok {
			continue
		}
		actuallyDeleted = append(actuallyDeleted, tr)
	}
	c.deleted = append(c.deleted, actuallyDeleted...)
	return actuallyDeleted, nil
}

func TestRunCmd_TxtDelete_NonCloudflare_RetainsConcreteType(t *testing.T) {
	// Regression guard for the digitalocean-style "DeleteRecords type-
	// asserts the input record" contract. The records returned by
	// GetRecords carry a concrete provider type (taggedRecord here);
	// the wrapper MUST hand them to DeleteRecords with that concrete
	// type intact -- otherwise the cast fails and the provider reports
	// zero deletes.
	stored := taggedRecord{
		rr:         libdns.RR{Name: "host", Type: "TXT", Data: "v=ok", TTL: time.Minute},
		providerID: "do-12345",
	}
	cp := &concreteTypeFakeProvider{stored: []taggedRecord{stored}}
	if err := runCmd(context.Background(), "digitalocean", cp, "txt-delete", "host.example.com", "v=ok"); err != nil {
		t.Fatalf("runCmd: %v (concrete-type retention must hold for non-cloudflare)", err)
	}
	if len(cp.deleted) != 1 {
		t.Fatalf("concreteTypeFakeProvider deleted %d records; want 1 -- the wrapper is stripping concrete types", len(cp.deleted))
	}
	tr, ok := cp.deleted[0].(taggedRecord)
	if !ok {
		t.Fatalf("DeleteRecords received %T; want taggedRecord (concrete-type stripped by wrapper)", cp.deleted[0])
	}
	if tr.providerID != "do-12345" {
		t.Errorf("ProviderData lost in transit: got providerID=%q; want do-12345", tr.providerID)
	}
}

func TestRunCmd_TxtDelete_Cloudflare_WrapsForChunkedTXT(t *testing.T) {
	// On cloudflare, the workaround MUST be on: each match is repackaged
	// with outer quotes so cloudflareRecord -> wrapContent becomes a no-op
	// and cfRec.Content matches CF's chunked stored representation.
	chunked := strings.Repeat("A", 200) + `" "` + strings.Repeat("B", 100) // CF-style stored shape
	stored := libdns.RR{Name: "host", Type: "TXT", Data: chunked, TTL: time.Minute}
	value := strings.Repeat("A", 200) + strings.Repeat("B", 100) // joined form
	fp := &fakeProvider{
		stored: []libdns.Record{stored},
	}
	if err := runCmd(context.Background(), "cloudflare", fp, "txt-delete", "host.example.com", value); err != nil {
		t.Fatalf("runCmd: %v", err)
	}
	if len(fp.deleted) != 1 {
		t.Fatalf("DeleteRecords got %d records; want 1", len(fp.deleted))
	}
	got := fp.deleted[0].RR().Data
	want := `"` + chunked + `"`
	if got != want {
		t.Errorf("cloudflare DeleteRecords got Data=%q; want outer-quoted %q", got, want)
	}
}

func TestRunCmd_TxtDelete_SubdriverNoOpFails(t *testing.T) {
	// Local match found but subdriver returns 0 deletes -- this is the
	// shape of the libdns/cloudflare#32 silent-no-op bug. We must surface
	// it as a hard failure so it can't drift into prod undetected.
	target := libdns.TXT{Name: "host", Text: "v=ok", TTL: time.Minute}
	fp := &fakeProvider{
		stored:                []libdns.Record{target},
		strictDataEqualDelete: true,
	}
	// On cloudflare the workaround wraps with `"v=ok"`. fp's strict
	// compare against stored `v=ok` then refuses, so 0 deleted.
	err := runCmd(context.Background(), "cloudflare", fp, "txt-delete", "host.example.com", "v=ok")
	if err == nil {
		t.Fatalf("runCmd: want error (silent no-op delete must propagate), got nil")
	}
	if !strings.Contains(err.Error(), "0 deleted records") {
		t.Errorf("error %q does not name the diagnostic anchor", err.Error())
	}
}

func TestMatchTXT_NormalizesChunkedData(t *testing.T) {
	// Regression guard for the libdns/cloudflare v0.2.2 round-trip bug:
	// GetRecords returns long TXT content with embedded `" "` segment
	// separators (zone-file format). matchTXT must compare against the
	// joined form, not the raw chunked one.
	value := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 200) + strings.Repeat("B", 100)
	chunked := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 200) + `" "` + strings.Repeat("B", 100)

	stored := libdns.RR{
		Name: "postern-target._domainkey",
		Type: "TXT",
		TTL:  5 * time.Minute,
		Data: chunked,
	}
	all := []libdns.Record{stored}
	got := matchTXT(all, "postern-target._domainkey", value)
	if len(got) != 1 {
		t.Fatalf("matchTXT failed to find chunked record (got %d, want 1)", len(got))
	}
}
