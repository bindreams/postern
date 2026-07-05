//go:build cfcontract

// Maintainer-only real-zone contract test for the Cloudflare `--proxied` REST
// bypass (cloudflare_proxied.go). Guarded by the `cfcontract` build tag so
// `go test ./...` never compiles it; run it explicitly with:
//
//	CLOUDFLARE_API_TOKEN=... CF_CONTRACT_TEST_ZONE=example.com \
//	  go test -tags cfcontract -run Contract -v ./...
//
// The whole point is to verify -- against LIVE Cloudflare, not a self-authored
// fake -- the assumption cloudflare_proxied.go rests on:
//
//	Cloudflare error 81058 ("identical record already exists") keys on
//	(zone, type, name, content) and EXCLUDES `proxied`.
//
// If that key ever includes `proxied`, the POST-then-PATCH flip path silently
// creates a second record instead of 81058-ing, and the fake in
// cloudflare_proxied_test.go (coded to the same assumption) would never catch
// it. This test is the ground truth.
//
// Fail-loud, no skip: per repo policy (CLAUDE.md) a missing token/zone is a hard
// failure, not a silent skip. Every record it creates is torn down via
// t.Cleanup even on partial failure.

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// contractEnv reads and validates the maintainer-supplied live-zone env. It
// fails loudly (never skips) when either variable is missing -- these tests hit
// a real Cloudflare zone and there is no hermetic fallback.
func contractEnv(t *testing.T) (token, zone string) {
	t.Helper()
	token = os.Getenv("CLOUDFLARE_API_TOKEN")
	zone = os.Getenv("CF_CONTRACT_TEST_ZONE")
	if token == "" || zone == "" {
		t.Fatalf("cfcontract: CLOUDFLARE_API_TOKEN and CF_CONTRACT_TEST_ZONE must both be set "+
			"(this maintainer-only test hits live Cloudflare; there is no skip path). "+
			"token_set=%t zone=%q", token != "", zone)
	}
	return token, zone
}

// uniqueName returns a per-run record name under the test zone so concurrent or
// repeated runs never collide and never touch a real record. Combines a coarse
// timestamp with crypto-random bytes.
func uniqueName(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("cfcontract: crypto/rand: %v", err)
	}
	return fmt.Sprintf("%s-cfcontract-%d-%s", prefix, time.Now().Unix(), hex.EncodeToString(b))
}

// deleteAddrByID removes one record by Cloudflare ID. Used only by cleanup.
func deleteAddrByID(ctx context.Context, c *cfClient, zoneID, id string) error {
	env, status, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, id), nil)
	if err != nil {
		return err
	}
	if !env.Success {
		return fmt.Errorf("delete %s (HTTP %d): %s", id, status, formatCFErrors(env.Errors))
	}
	return nil
}

// registerCleanup schedules deletion of every record of recType at fqdn when the
// test finishes -- listing at teardown (rather than tracking IDs) also sweeps up
// records that a production helper created internally and never handed us an ID
// for. Runs even on t.Fatalf/panic via t.Cleanup.
func registerCleanup(t *testing.T, ctx context.Context, c *cfClient, zoneID, recType, fqdn string) {
	t.Helper()
	t.Cleanup(func() {
		recs, err := c.listAddr(ctx, zoneID, recType, fqdn)
		if err != nil {
			t.Logf("cfcontract cleanup: list %s %s: %v (leaked records may remain)", recType, fqdn, err)
			return
		}
		for _, r := range recs {
			if err := deleteAddrByID(ctx, c, zoneID, r.ID); err != nil {
				t.Logf("cfcontract cleanup: delete %s (%s %s): %v (leaked)", r.ID, recType, fqdn, err)
			}
		}
	})
}

// findAddr returns the record at ip (parsed compare, mirroring firstAddrMatch).
func findAddr(recs []cfAddrRecord, ip netip.Addr) (cfAddrRecord, bool) {
	for _, r := range recs {
		if got, err := netip.ParseAddr(r.Content); err == nil && got == ip {
			return r, true
		}
	}
	return cfAddrRecord{}, false
}

// TestCloudflareProxiedContract exercises cloudflare_proxied.go against a live
// zone. Uses context.Background() (no overall deadline) so per-request bounds
// come from cfClient.HTTP's 30s timeout and t.Cleanup deletions still run after
// the test body returns.
func TestCloudflareProxiedContract(t *testing.T) {
	token, zone := contractEnv(t)
	ctx := context.Background()
	client := newCFClient(token)

	zoneID, err := client.zoneID(ctx, zone)
	if err != nil {
		t.Fatalf("cfcontract: resolve zone %q: %v (check CF_CONTRACT_TEST_ZONE and token zone scope)", zone, err)
	}
	t.Logf("cfcontract: using zone %q (id=%s)", zone, zoneID)

	// (a) The core assumption: 81058 excludes `proxied` ================================================================
	t.Run("DuplicateKeyExcludesProxied", func(t *testing.T) {
		name := uniqueName(t, "dup")
		fqdn := name + "." + zone
		ip := netip.MustParseAddr("192.0.2.10") // TEST-NET-1
		registerCleanup(t, ctx, client, zoneID, "A", fqdn)

		// Seed a gray (unproxied) record.
		if _, err := client.createAddr(ctx, zoneID, cfAddrRecord{
			Type: "A", Name: fqdn, Content: ip.String(), TTL: cfUnproxiedTTL, Proxied: false,
		}); err != nil {
			t.Fatalf("seed POST (proxied=false) failed: %v", err)
		}

		// POST identical (type,name,content) but with the OPPOSITE proxied value.
		// If 81058's key excludes proxied, this must be rejected as a duplicate.
		_, err := client.createAddr(ctx, zoneID, cfAddrRecord{
			Type: "A", Name: fqdn, Content: ip.String(), TTL: cfProxiedTTL, Proxied: true,
		})
		if err == nil {
			t.Fatalf("CONTRACT VIOLATED: POST of the same (type,name,content) with the opposite "+
				"proxied value was accepted (created a second record) -- Cloudflare's 81058 key "+
				"INCLUDES proxied. cloudflare_proxied.go's POST-then-PATCH flip path is unsafe: "+
				"fqdn=%s", fqdn)
		}
		if !errors.Is(err, errCFDuplicate) {
			t.Fatalf("expected 81058 errCFDuplicate on opposite-proxied POST, got: %v", err)
		}

		// Definitive: still exactly one record at the name.
		recs, err := client.listAddr(ctx, zoneID, "A", fqdn)
		if err != nil {
			t.Fatalf("list after dup probe: %v", err)
		}
		if len(recs) != 1 {
			t.Fatalf("expected exactly 1 record after opposite-proxied POST 81058'd, got %d: %+v", len(recs), recs)
		}
		t.Logf("cfcontract OK: 81058 excludes proxied (opposite-proxied POST rejected as duplicate)")
	})

	// (b) Production flip paths land the right final state, live =======================================================
	t.Run("SetProxiedTrueThenFalse", func(t *testing.T) {
		name := uniqueName(t, "flip")
		fqdn := name + "." + zone
		ip := netip.MustParseAddr("192.0.2.20") // TEST-NET-1
		rec := libdns.Address{Name: name, IP: ip, TTL: recordTTL}
		registerCleanup(t, ctx, client, zoneID, "A", fqdn)

		// Pre-seed gray so setAddrProxiedTrue takes the POST(81058)->list->PATCH
		// direction (the interesting "POST-then-PATCH" path, not a fresh create).
		if _, err := client.createAddr(ctx, zoneID, cfAddrRecord{
			Type: "A", Name: fqdn, Content: ip.String(), TTL: cfUnproxiedTTL, Proxied: false,
		}); err != nil {
			t.Fatalf("seed gray record: %v", err)
		}

		// --proxied=true : POST-then-PATCH must leave the record orange, ttl=1.
		if err := cloudflareAddrSetProxied(ctx, client, zone, rec, true); err != nil {
			t.Fatalf("cloudflareAddrSetProxied(true): %v", err)
		}
		recs, err := client.listAddr(ctx, zoneID, "A", fqdn)
		if err != nil {
			t.Fatalf("list after set-proxied-true: %v", err)
		}
		got, ok := findAddr(recs, ip)
		if !ok {
			t.Fatalf("record for %s vanished after set-proxied-true; got %+v", ip, recs)
		}
		if len(recs) != 1 {
			t.Errorf("expected 1 record after set-proxied-true, got %d (POST-then-PATCH duplicated): %+v", len(recs), recs)
		}
		if !got.Proxied {
			t.Errorf("set-proxied-true left the record gray: %+v", got)
		}
		if got.TTL != cfProxiedTTL {
			t.Errorf("set-proxied-true ttl=%d, want %d (Cloudflare forces ttl=1 for proxied)", got.TTL, cfProxiedTTL)
		}

		// --proxied=false : GET-then-PATCH must leave the record gray, ttl restored.
		if err := cloudflareAddrSetProxied(ctx, client, zone, rec, false); err != nil {
			t.Fatalf("cloudflareAddrSetProxied(false): %v", err)
		}
		recs, err = client.listAddr(ctx, zoneID, "A", fqdn)
		if err != nil {
			t.Fatalf("list after set-proxied-false: %v", err)
		}
		got, ok = findAddr(recs, ip)
		if !ok {
			t.Fatalf("record for %s vanished after set-proxied-false; got %+v", ip, recs)
		}
		if got.Proxied {
			t.Errorf("set-proxied-false left the record orange: %+v", got)
		}
		if got.TTL != cfUnproxiedTTL {
			t.Errorf("set-proxied-false ttl=%d, want %d", got.TTL, cfUnproxiedTTL)
		}
		t.Logf("cfcontract OK: POST-then-PATCH proxied=true and GET-then-PATCH proxied=false both land live")
	})

	// (c) OPEN QUESTION probe: does live CF normalize equivalent IPv6 forms? ===========================================
	// cloudflare_proxied.go (firstAddrMatch) and the fake (addrContentEqual in
	// cloudflare_proxied_test.go) both compare A/AAAA content by PARSED IP, i.e.
	// they model Cloudflare as normalizing "2001:db8:85a3::8a2e:370:7334" and
	// "2001:0db8:85a3:0:0:8a2e:0370:7334" to the same content-key. This probe
	// records whether live CF actually does so. We assert only self-consistency
	// (dup <=> one stored record) -- always true for a sane server regardless of
	// the answer -- and LOG the observed behavior, because this is a genuinely
	// open question, not a settled contract. Read the "CONTRACT PROBE RESULT"
	// line in the test output for the answer; if it says CF does NOT normalize,
	// the fake's parsed-IP-equality model is a superset of CF's real string key
	// and diverges (harmless for Postern today -- it always sends the canonical
	// netip.Addr.String() form -- but a documented follow-up).
	t.Run("IPv6NormalizationProbe", func(t *testing.T) {
		name := uniqueName(t, "v6")
		fqdn := name + "." + zone
		registerCleanup(t, ctx, client, zoneID, "AAAA", fqdn)

		const compact = "2001:db8:85a3::8a2e:370:7334"
		const expanded = "2001:0db8:85a3:0:0:8a2e:0370:7334"

		if _, err := client.createAddr(ctx, zoneID, cfAddrRecord{
			Type: "AAAA", Name: fqdn, Content: compact, TTL: cfUnproxiedTTL, Proxied: false,
		}); err != nil {
			t.Fatalf("POST AAAA %q: %v", compact, err)
		}

		// Same address, different textual form.
		_, secondErr := client.createAddr(ctx, zoneID, cfAddrRecord{
			Type: "AAAA", Name: fqdn, Content: expanded, TTL: cfUnproxiedTTL, Proxied: false,
		})
		normalized := errors.Is(secondErr, errCFDuplicate)
		if secondErr != nil && !normalized {
			t.Fatalf("second AAAA POST %q returned an unexpected error (neither success nor 81058): %v", expanded, secondErr)
		}

		recs, err := client.listAddr(ctx, zoneID, "AAAA", fqdn)
		if err != nil {
			t.Fatalf("list AAAA after probe: %v", err)
		}

		// Self-consistency: normalized => one record; not normalized => two.
		if normalized && len(recs) != 1 {
			t.Errorf("CF 81058'd the second form but stored %d records (want 1): %+v", len(recs), recs)
		}
		if !normalized && len(recs) != 2 {
			t.Errorf("CF accepted the second form but stored %d records (want 2): %+v", len(recs), recs)
		}

		verb := "does NOT normalize"
		if normalized {
			verb = "normalizes"
		}
		t.Logf("CONTRACT PROBE RESULT: live Cloudflare %s equivalent IPv6 forms "+
			"(%q vs %q => 81058=%t, stored records=%d). The fake in cloudflare_proxied_test.go "+
			"models normalization via parsed-IP equality; if the answer is \"does NOT normalize\", "+
			"that model diverges from reality -- track as a follow-up (do not edit the fake here).",
			verb, compact, expanded, normalized, len(recs))
	})
}
