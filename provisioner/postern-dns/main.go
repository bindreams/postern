// postern-dns -- thin Lego/libdns-style wrapper for publishing arbitrary TXT records.
//
// Used by the provisioner's Python entrypoint to publish/retire DKIM TXT
// records via the deployer's configured DNS provider.
//
// Subcommands:
//
//	postern-dns txt-set    <fqdn> <value>
//	postern-dns txt-delete <fqdn> <value>
//
// Provider selection: env var DNS_PROVIDER (matches a known provider name).
// Provider config: each provider's native env vars (e.g. CLOUDFLARE_API_TOKEN,
// AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY, GANDI_API_TOKEN, DO_AUTH_TOKEN).
// Postern documents the env-var contract per provider in docs/mta.md.
//
// Forward-compat: this binary is intentionally generic. A planned ACME
// DNS-01 cert-renewal feature will add `acme-issue` and `acme-renew`
// subcommands using the same providers; `txt-set`/`txt-delete` stay stable.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
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

// providerOps is the libdns interface intersection we need.
//
// RecordGetter is required so txt-delete can resolve a freshly-constructed
// libdns.TXT (with no provider-side ID/ProviderData populated) to the actual
// stored record(s) before calling DeleteRecords -- some subdrivers'
// content-matching delete path is brittle for long TXT values, so fetching
// first and passing the provider-returned record back is more robust.
type providerOps interface {
	libdns.RecordGetter
	libdns.RecordAppender
	libdns.RecordDeleter
}

func newProvider(name string) (providerOps, error) {
	switch strings.ToLower(name) {
	case "cloudflare":
		return &cloudflare.Provider{APIToken: os.Getenv("CLOUDFLARE_API_TOKEN")}, nil
	case "route53":
		// route53 v1.6 exposes a SessionToken field (the prior deprecated
		// Token field was removed). We don't currently wire a session
		// token through; add SessionToken: os.Getenv("AWS_SESSION_TOKEN")
		// if/when we need IAM role/STS credentials.
		return &route53.Provider{
			Region:          os.Getenv("AWS_REGION"),
			AccessKeyId:     os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		}, nil
	case "gandi":
		return &gandi.Provider{BearerToken: os.Getenv("GANDI_API_TOKEN")}, nil
	case "digitalocean":
		return &digitalocean.Provider{APIToken: os.Getenv("DO_AUTH_TOKEN")}, nil
	case "ovh":
		return &ovh.Provider{
			Endpoint:          os.Getenv("OVH_ENDPOINT"),
			ApplicationKey:    os.Getenv("OVH_APPLICATION_KEY"),
			ApplicationSecret: os.Getenv("OVH_APPLICATION_SECRET"),
			ConsumerKey:       os.Getenv("OVH_CONSUMER_KEY"),
		}, nil
	case "hetzner":
		return &hetzner.Provider{APIToken: os.Getenv("HETZNER_API_TOKEN")}, nil
	case "linode":
		return &linode.Provider{APIToken: os.Getenv("LINODE_TOKEN")}, nil
	case "namecheap":
		return &namecheap.Provider{
			APIKey:   os.Getenv("NAMECHEAP_API_KEY"),
			User:     os.Getenv("NAMECHEAP_API_USER"),
			ClientIP: os.Getenv("NAMECHEAP_CLIENT_IP"),
		}, nil
	default:
		return nil, fmt.Errorf("unknown provider %q (supported: cloudflare, route53, gandi, digitalocean, ovh, hetzner, linode, namecheap)", name)
	}
}

// splitFQDN takes "postern-2026-04._domainkey.example.com" and returns
// (zone="example.com.", name="postern-2026-04._domainkey").
//
// Caveat: the heuristic of "last two labels = zone" is wrong for FQDNs
// under multi-label public suffixes such as `co.uk`, `github.io`, etc.
// (it would produce zone="co.uk." for `host.example.co.uk`). Postern's
// public surface today is `<your-domain>` operated as a single zone at
// the SLD; users with a sub-domain delegation (`mail.example.co.uk`)
// hit the bug at provider-API-call time as a "zone not found" error.
//
// Tracked: https://github.com/bindreams/postern/issues/87 -- the fix
// is `golang.org/x/net/publicsuffix.EffectiveTLDPlusOne`.
func splitFQDN(fqdn string) (zone, name string) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return fqdn + ".", "@"
	}
	zone = strings.Join(parts[len(parts)-2:], ".") + "."
	name = strings.Join(parts[:len(parts)-2], ".")
	if name == "" {
		name = "@"
	}
	return zone, name
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  postern-dns txt-set    <fqdn> <value>
  postern-dns txt-delete <fqdn> <value>

env vars:
  DNS_PROVIDER -- provider name (cloudflare, route53, gandi, digitalocean,
                      ovh, hetzner, linode, namecheap)
  Plus the provider's native credential env vars; see docs/mta.md.`)
	os.Exit(2)
}

func main() {
	if len(os.Args) != 4 {
		usage()
	}
	cmd, fqdn, value := os.Args[1], os.Args[2], os.Args[3]
	providerName := os.Getenv("DNS_PROVIDER")
	if providerName == "" || providerName == "none" {
		fmt.Fprintln(os.Stderr, "postern-dns: DNS_PROVIDER not set or set to 'none'")
		os.Exit(1)
	}
	provider, err := newProvider(providerName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "postern-dns:", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := runCmd(ctx, providerName, provider, cmd, fqdn, value); err != nil {
		fmt.Fprintln(os.Stderr, "postern-dns:", err)
		os.Exit(1)
	}
}

// runCmd is the testable core of main(): given a configured provider and
// a command (txt-set/txt-delete), it does the libdns calls and returns
// either nil (success) or an error suitable for stderr + exit-1. Pulled
// out of main() so unit tests can drive it with a fakeProvider.
func runCmd(ctx context.Context, providerName string, provider providerOps, cmd, fqdn, value string) error {
	zone, name := splitFQDN(fqdn)
	switch cmd {
	case "txt-set":
		return doTxtSet(ctx, provider, zone, name, value)
	case "txt-delete":
		return doTxtDelete(ctx, providerName, provider, zone, name, value)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// displayFQDN renders a (name, zone) pair as a single readable FQDN for
// log/error messages, special-casing the apex name "@" so we emit
// "example.com." instead of "@.example.com.".
func displayFQDN(name, zone string) string {
	if name == "@" {
		return zone
	}
	return name + "." + zone
}

// doTxtSet publishes the record. If the provider rejects it because an
// identical record already exists (Cloudflare API code 81058), we treat
// txt-set as idempotent: re-fetch, confirm a matching record is present,
// and return success. We *only* take the idempotent path when the error
// is recognized as duplicate-detection (see isDuplicateRecordError) --
// generic errors (auth, rate-limit, network, validation) propagate so
// operators don't get silent success on top of an unrelated failure.
func doTxtSet(ctx context.Context, provider providerOps, zone, name, value string) error {
	rec := libdns.TXT{Name: name, Text: value, TTL: 5 * time.Minute}
	fqdn := displayFQDN(name, zone)
	_, appendErr := provider.AppendRecords(ctx, zone, []libdns.Record{rec})
	if appendErr == nil {
		return nil
	}
	if !isDuplicateRecordError(appendErr) {
		return fmt.Errorf("txt-set %s: %w", fqdn, appendErr)
	}
	all, getErr := provider.GetRecords(ctx, zone)
	if getErr != nil {
		return fmt.Errorf("txt-set %s: AppendRecords reported duplicate but GetRecords failed: %w (original AppendRecords error: %v)", fqdn, getErr, appendErr)
	}
	if len(matchTXT(all, name, value)) == 0 {
		return fmt.Errorf("txt-set %s: provider reported duplicate but no matching record visible to GetRecords: %w", fqdn, appendErr)
	}
	// Record present after a refresh -- the AppendRecords error was a
	// duplicate-detection no-op; the desired state is already in place.
	// Surface this on stderr so operators can see when the idempotency
	// path triggered (it normally indicates leftover state in the
	// provider's database that isn't yet visible via DNS).
	fmt.Fprintf(os.Stderr, "postern-dns(warn): txt-set %s: AppendRecords returned %q; record already present, treating as idempotent success\n", fqdn, appendErr)
	return nil
}

// doTxtDelete removes any TXT record(s) at name with text == value.
//
// Workflow:
//  1. Fetch the zone via GetRecords and locally pick records whose
//     (Type, Name, Data) matches our target. matchTXT also tolerates the
//     embedded zone-file segment separators that libdns/cloudflare leaks
//     for TXT >255 bytes (see normalizeTXTData / libdns/cloudflare#32).
//  2. Pass those records into DeleteRecords. Most providers do an ID-or-
//     value-based delete and accept the records returned by GetRecords
//     verbatim. For Cloudflare we additionally re-wrap the rr.Data in
//     outer quotes so cloudflareRecord -> wrapContent becomes a no-op
//     and the chunked stored representation matches byte-for-byte.
//  3. Treat "no matches found" as success (idempotent semantics, matching
//     libdns.RecordDeleter docs); treat "matches found but provider
//     reported zero deletions" as failure (silent no-op = fix it).
func doTxtDelete(ctx context.Context, providerName string, provider providerOps, zone, name, value string) error {
	fqdn := displayFQDN(name, zone)
	all, getErr := provider.GetRecords(ctx, zone)
	if getErr != nil {
		return fmt.Errorf("txt-delete %s: GetRecords: %w", fqdn, getErr)
	}
	matches := matchTXT(all, name, value)
	if len(matches) == 0 {
		// Idempotent: nothing matches, nothing to remove.
		return nil
	}
	toDelete := deleteRecordsForProvider(providerName, matches)
	deleted, delErr := provider.DeleteRecords(ctx, zone, toDelete)
	if delErr != nil {
		return fmt.Errorf("txt-delete %s: %w", fqdn, delErr)
	}
	if len(deleted) == 0 {
		// Local match was found, subdriver still no-op'd. This is the
		// libdns/cloudflare v0.2.2 silent-delete shape (see
		// libdns/cloudflare#32). Surface it instead of papering over so
		// future regressions on any provider are immediately visible.
		return fmt.Errorf("txt-delete %s: subdriver returned 0 deleted records despite %d local matches", fqdn, len(matches))
	}
	return nil
}

// deleteRecordsForProvider prepares the libdns.Record values to pass into a
// provider's DeleteRecords. For most providers we pass the records that
// GetRecords returned through unchanged: any concrete type (libdns.TXT or
// a provider-specific shape carrying ProviderData/IDs) is the most
// faithful match for the subdriver's delete path.
//
// Cloudflare needs special handling. libdns/cloudflare v0.2.2's
// DeleteRecords always re-derives match keys via cloudflareRecord ->
// wrapContent (it ignores ProviderData), and wrapContent only adds outer
// quotes to TXT content -- it never chunks. Cloudflare itself stores TXT
// content >255 bytes in zone-file chunked form (`"<chunk1>" "<chunk2>"`),
// so the cfRec.Content computed from a libdns.TXT (`"<410>"`) never
// equals the stored form, and DeleteRecords becomes a silent no-op. The
// fix is to hand DeleteRecords a libdns.RR whose Data is *already* the
// chunked + outer-quoted form -- wrapContent then sees a string that
// already starts and ends with `"` and skips its quoting step, so
// cfRec.Content == stored content and the match succeeds.
//
// Tracking upstream: https://github.com/libdns/cloudflare/issues/32 .
// When that's fixed and released, drop the cloudflare branch here and
// the normalization in matchTXT.
func deleteRecordsForProvider(providerName string, matches []libdns.Record) []libdns.Record {
	if strings.ToLower(providerName) != "cloudflare" {
		return matches
	}
	out := make([]libdns.Record, 0, len(matches))
	for _, m := range matches {
		rr := m.RR()
		out = append(out, libdns.RR{
			Name: rr.Name,
			TTL:  rr.TTL,
			Type: rr.Type,
			Data: `"` + rr.Data + `"`,
		})
	}
	return out
}

// isDuplicateRecordError matches an AppendRecords error string against
// known "this exact record already exists" signals. Currently only the
// Cloudflare error phrase is recognized; other providers we ship may
// need their own anchors here once we observe the duplicate-detection
// shape on the wire.
//
// We deliberately match the human-readable phrase rather than a numeric
// code: the phrase "identical record already exists" appears verbatim
// in Cloudflare's API response (model: "An identical record already
// exists"), and a substring check on that phrase is unlikely to false-
// positive on unrelated errors. The numeric code "81058" by itself is
// too short to anchor reliably (could substring-match other 5-digit
// codes, request IDs, or log fragments) and Cloudflare always emits
// the phrase alongside the code, so we don't need it.
//
// Tracked: https://github.com/bindreams/postern/issues/88 -- per-
// provider duplicate-detection coverage is open work; see that issue
// before broadening the heuristic to other providers.
func isDuplicateRecordError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "identical record already exists")
}

// normalizeTXTData reverses the zone-file segmentation that some providers
// (notably libdns/cloudflare v0.2.2) bake into rr.Data for long TXT
// records. Cloudflare stores TXT content as `"<chunk1>" "<chunk2>"` once
// it exceeds 255 bytes, and libdns/cloudflare's unwrapContent only strips
// the outer quotes -- leaving the embedded `" "` between chunks. Removing
// those embedded separators reconstructs the original, single-string TXT.
//
// Short TXT values (no embedded separators) pass through unchanged.
//
// Tracking upstream: https://github.com/libdns/cloudflare/issues/32 .
func normalizeTXTData(s string) string {
	return strings.ReplaceAll(s, `" "`, "")
}

// matchTXT returns the records from `all` whose RR is a TXT at the given
// name and whose Data equals `text`. To stay safe against TXT values that
// legitimately contain the byte sequence `" "` mid-string, we accept
// EITHER the raw rr.Data or its chunk-stripped form; that way:
//
//   - Cloudflare's chunked form `<chunk1>" "<chunk2>` matches `text`
//     after normalization (the bug we have to work around).
//   - A non-chunked rr.Data containing `" "` legitimately
//     (e.g. `"key1"="v" "k"="v2"`) still matches against `text` of
//     identical bytes via the raw comparison.
func matchTXT(all []libdns.Record, name, text string) []libdns.Record {
	var out []libdns.Record
	for _, rec := range all {
		rr := rec.RR()
		if rr.Type != "TXT" || rr.Name != name {
			continue
		}
		if rr.Data == text || normalizeTXTData(rr.Data) == text {
			out = append(out, rec)
		}
	}
	return out
}
