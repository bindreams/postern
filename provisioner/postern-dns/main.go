// postern-dns -- thin libdns wrapper for publishing/retiring DNS records.
//
// Used by the provisioner's Python entrypoint to publish/retire records via
// the deployer's configured DNS provider. TXT records have always been
// supported (DKIM rotation, lego's DNS-01 challenges); A/AAAA/MX/TLSA/CAA
// were added (#113) so the same binary serves the planned cert-manager and
// MTA-records auto-publishers.
//
// Subcommands:
//
//	postern-dns txt-set     <fqdn> <value>
//	postern-dns txt-delete  <fqdn> <value>
//	postern-dns a-set       <fqdn> <ipv4>
//	postern-dns a-delete    <fqdn> <ipv4>
//	postern-dns aaaa-set    <fqdn> <ipv6>
//	postern-dns aaaa-delete <fqdn> <ipv6>
//	postern-dns mx-set      <fqdn> <preference> <target>
//	postern-dns mx-delete   <fqdn> <preference> <target>
//	postern-dns caa-set     <fqdn> <flags> <tag> <value>
//	postern-dns caa-delete  <fqdn> <flags> <tag> <value>
//	postern-dns tlsa-set    <fqdn> <usage> <selector> <matching-type> <cert-hex>
//	postern-dns tlsa-delete <fqdn> <usage> <selector> <matching-type> <cert-hex>
//
// Provider selection: env var DNS_PROVIDER (matches a known provider name).
// Provider config: each provider's native env vars (e.g. CLOUDFLARE_API_TOKEN,
// AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY, GANDI_API_TOKEN, DO_AUTH_TOKEN).
// Postern documents the env-var contract per provider in docs/mta.md.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strconv"
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

// recordTTL is the TTL applied to records this binary publishes. Short enough
// that a mistake doesn't linger; long enough that periodic renewals don't
// hammer the provider API.
const recordTTL = 5 * time.Minute

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
  postern-dns txt-set     <fqdn> <value>
  postern-dns txt-delete  <fqdn> <value>
  postern-dns a-set       <fqdn> <ipv4>
  postern-dns a-delete    <fqdn> <ipv4>
  postern-dns aaaa-set    <fqdn> <ipv6>
  postern-dns aaaa-delete <fqdn> <ipv6>
  postern-dns mx-set      <fqdn> <preference> <target>
  postern-dns mx-delete   <fqdn> <preference> <target>
  postern-dns caa-set     <fqdn> <flags> <tag> <value>
  postern-dns caa-delete  <fqdn> <flags> <tag> <value>
  postern-dns tlsa-set    <fqdn> <usage> <selector> <matching-type> <cert-hex>
  postern-dns tlsa-delete <fqdn> <usage> <selector> <matching-type> <cert-hex>

env vars:
  DNS_PROVIDER -- provider name (cloudflare, route53, gandi, digitalocean,
                  ovh, hetzner, linode, namecheap)
  Plus the provider's native credential env vars; see docs/mta.md.`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 4 {
		usage()
	}
	cmd := os.Args[1]
	fqdn := os.Args[2]
	args := os.Args[3:]
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

	if err := runCmd(ctx, providerName, provider, cmd, fqdn, args); err != nil {
		fmt.Fprintln(os.Stderr, "postern-dns:", err)
		os.Exit(1)
	}
}

// runCmd is the testable core of main(): given a configured provider, a
// subcommand, the FQDN, and the remaining positional args, it parses the
// type-specific args into a libdns record and dispatches to the right
// publish/retire helper. Pulled out of main() so unit tests can drive it
// with a fakeProvider.
func runCmd(ctx context.Context, providerName string, provider providerOps, cmd, fqdn string, args []string) error {
	zone, name := splitFQDN(fqdn)

	switch cmd {
	case "txt-set":
		if len(args) != 1 {
			return fmt.Errorf("txt-set: expected <value>, got %d arg(s)", len(args))
		}
		return doTxtSet(ctx, provider, zone, name, args[0])
	case "txt-delete":
		if len(args) != 1 {
			return fmt.Errorf("txt-delete: expected <value>, got %d arg(s)", len(args))
		}
		return doTxtDelete(ctx, providerName, provider, zone, name, args[0])

	case "a-set", "aaaa-set":
		rec, err := parseAddressArgs(cmd, name, args)
		if err != nil {
			return err
		}
		return doRecordSet(ctx, provider, zone, rec)
	case "a-delete", "aaaa-delete":
		rec, err := parseAddressArgs(strings.TrimSuffix(cmd, "-delete")+"-set", name, args)
		if err != nil {
			return err
		}
		return doRecordDelete(ctx, provider, zone, rec)

	case "mx-set":
		rec, err := parseMXArgs(name, args)
		if err != nil {
			return err
		}
		return doRecordSet(ctx, provider, zone, rec)
	case "mx-delete":
		rec, err := parseMXArgs(name, args)
		if err != nil {
			return err
		}
		return doRecordDelete(ctx, provider, zone, rec)

	case "caa-set":
		rec, err := parseCAAArgs(name, args)
		if err != nil {
			return err
		}
		return doRecordSet(ctx, provider, zone, rec)
	case "caa-delete":
		rec, err := parseCAAArgs(name, args)
		if err != nil {
			return err
		}
		return doRecordDelete(ctx, provider, zone, rec)

	case "tlsa-set":
		rec, err := parseTLSAArgs(name, args)
		if err != nil {
			return err
		}
		// libdns/cloudflare v0.2.2 doesn't marshal TLSA structured fields,
		// so Cloudflare's API rejects the request (#127). Until upstream
		// adds a TLSA case to cloudflareRecord, talk to the API directly.
		if providerName == "cloudflare" {
			return cloudflareTLSASet(ctx, newCFClient(os.Getenv("CLOUDFLARE_API_TOKEN")), zone, rec)
		}
		return doRecordSet(ctx, provider, zone, rec)
	case "tlsa-delete":
		rec, err := parseTLSAArgs(name, args)
		if err != nil {
			return err
		}
		if providerName == "cloudflare" {
			return cloudflareTLSADelete(ctx, newCFClient(os.Getenv("CLOUDFLARE_API_TOKEN")), zone, rec)
		}
		return doRecordDelete(ctx, provider, zone, rec)

	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// Per-type arg parsing ==================================================================================================

// parseAddressArgs handles `a-set`/`aaaa-set` (and the `-delete` variants, which
// pass the same args after trimming). The caller passes "a-set" or "aaaa-set"
// so this function can verify the IP family matches the subcommand.
func parseAddressArgs(cmd, name string, args []string) (libdns.Address, error) {
	wantType := "A"
	if cmd == "aaaa-set" {
		wantType = "AAAA"
	}
	if len(args) != 1 {
		return libdns.Address{}, fmt.Errorf("%s: expected <ip>, got %d arg(s)", cmd, len(args))
	}
	ip, err := netip.ParseAddr(args[0])
	if err != nil {
		return libdns.Address{}, fmt.Errorf("%s: invalid IP %q: %w", cmd, args[0], err)
	}
	if wantType == "A" && !ip.Is4() {
		return libdns.Address{}, fmt.Errorf("%s: %q is not an IPv4 address (use aaaa-set for IPv6)", cmd, args[0])
	}
	if wantType == "AAAA" && !ip.Is6() {
		return libdns.Address{}, fmt.Errorf("%s: %q is not an IPv6 address (use a-set for IPv4)", cmd, args[0])
	}
	return libdns.Address{Name: name, IP: ip, TTL: recordTTL}, nil
}

func parseMXArgs(name string, args []string) (libdns.MX, error) {
	if len(args) != 2 {
		return libdns.MX{}, fmt.Errorf("mx: expected <preference> <target>, got %d arg(s)", len(args))
	}
	pref, err := strconv.ParseUint(args[0], 10, 16)
	if err != nil {
		return libdns.MX{}, fmt.Errorf("mx: preference must be a uint16: %w", err)
	}
	target := args[1]
	if target == "" {
		return libdns.MX{}, fmt.Errorf("mx: target must be non-empty")
	}
	// libdns/cloudflare's libdnsRecord() returns MX targets with a trailing dot
	// (it calls ensureTrailingDot on the provider's content field), and the
	// resulting RR.Data is "<pref> <target>." -- with the dot. matchRR does
	// strict Data == Data equality. If we accept a no-dot target here, the
	// matcher silently fails to find the round-tripped record, breaking the
	// "duplicate -> confirm via GetRecords -> idempotent success" fallback in
	// doRecordSet. Normalize to canonical trailing-dot form at parse time so
	// the matcher stays a dumb byte-comparator.
	if !strings.HasSuffix(target, ".") {
		target += "."
	}
	return libdns.MX{
		Name:       name,
		Preference: uint16(pref),
		Target:     target,
		TTL:        recordTTL,
	}, nil
}

func parseCAAArgs(name string, args []string) (libdns.CAA, error) {
	if len(args) != 3 {
		return libdns.CAA{}, fmt.Errorf("caa: expected <flags> <tag> <value>, got %d arg(s)", len(args))
	}
	flags, err := strconv.ParseUint(args[0], 10, 8)
	if err != nil {
		return libdns.CAA{}, fmt.Errorf("caa: flags must be a uint8: %w", err)
	}
	// Per RFC 8659, valid flag values are 0 and 128 (the critical bit). Anything
	// else is meaningless on the wire and almost always a typo.
	if flags != 0 && flags != 128 {
		return libdns.CAA{}, fmt.Errorf("caa: flags must be 0 or 128 (got %d)", flags)
	}
	// The canonical tag set is issue/issuewild/iodef/contactemail/contactphone.
	// Validating that here would lock out future IANA-assigned tags, so we just
	// check non-empty.
	tag := args[1]
	if tag == "" {
		return libdns.CAA{}, fmt.Errorf("caa: tag must be non-empty")
	}
	return libdns.CAA{
		Name:  name,
		Flags: uint8(flags),
		Tag:   tag,
		Value: args[2],
		TTL:   recordTTL,
	}, nil
}

// parseTLSAArgs builds a generic libdns.RR for TLSA (libdns v1.1.1 has no typed
// TLSA struct). The wire format is `<usage> <selector> <matching-type> <hex>`;
// libdns/cloudflare's default-case parser accepts this shape via RR.Parse().
func parseTLSAArgs(name string, args []string) (libdns.RR, error) {
	if len(args) != 4 {
		return libdns.RR{}, fmt.Errorf("tlsa: expected <usage> <selector> <matching-type> <cert-hex>, got %d arg(s)", len(args))
	}
	usage, err := strconv.ParseUint(args[0], 10, 8)
	if err != nil || usage > 3 {
		return libdns.RR{}, fmt.Errorf("tlsa: usage must be 0..3 (RFC 6698 §2.1.1), got %q", args[0])
	}
	selector, err := strconv.ParseUint(args[1], 10, 8)
	if err != nil || selector > 1 {
		return libdns.RR{}, fmt.Errorf("tlsa: selector must be 0 or 1 (RFC 6698 §2.1.2), got %q", args[1])
	}
	matchType, err := strconv.ParseUint(args[2], 10, 8)
	if err != nil || matchType > 2 {
		return libdns.RR{}, fmt.Errorf("tlsa: matching-type must be 0..2 (RFC 6698 §2.1.3), got %q", args[2])
	}
	certHex := strings.ToLower(args[3])
	if _, err := hex.DecodeString(certHex); err != nil {
		return libdns.RR{}, fmt.Errorf("tlsa: cert-hex must be valid hex: %w", err)
	}
	return libdns.RR{
		Name: name,
		Type: "TLSA",
		Data: fmt.Sprintf("%d %d %d %s", usage, selector, matchType, certHex),
		TTL:  recordTTL,
	}, nil
}

// Generic set / delete helpers (for non-TXT types) =====================================================================
//
// TXT keeps its own pair (doTxtSet / doTxtDelete) because of the chunked-content
// workarounds for libdns/cloudflare#32. The other record types here use the
// straightforward libdns flow: AppendRecords on set, GetRecords + DeleteRecords
// on delete, with content-equality matching via the RR shape.

// doRecordSet publishes `rec` via AppendRecords. Duplicate-record errors from
// the provider are treated as idempotent success (matching the doTxtSet
// contract): the desired state is already present.
func doRecordSet(ctx context.Context, provider providerOps, zone string, rec libdns.Record) error {
	rr := rec.RR()
	fqdn := displayFQDN(rr.Name, zone)
	_, err := provider.AppendRecords(ctx, zone, []libdns.Record{rec})
	if err == nil {
		return nil
	}
	if !isDuplicateRecordError(err) {
		return fmt.Errorf("%s-set %s: %w", strings.ToLower(rr.Type), fqdn, err)
	}
	// Confirm the record is present after duplicate-detection.
	all, getErr := provider.GetRecords(ctx, zone)
	if getErr != nil {
		return fmt.Errorf("%s-set %s: AppendRecords reported duplicate but GetRecords failed: %w (original AppendRecords error: %v)", strings.ToLower(rr.Type), fqdn, getErr, err)
	}
	if len(matchRR(all, rr)) == 0 {
		return fmt.Errorf("%s-set %s: provider reported duplicate but no matching record visible to GetRecords: %w", strings.ToLower(rr.Type), fqdn, err)
	}
	fmt.Fprintf(os.Stderr, "postern-dns(warn): %s-set %s: AppendRecords returned %q; record already present, treating as idempotent success\n", strings.ToLower(rr.Type), fqdn, err)
	return nil
}

// doRecordDelete removes any record matching `rec`'s (Type, Name, Data) shape.
// Matches the doTxtDelete contract: no-match -> idempotent success;
// local-matches-but-provider-reports-0-deleted -> error (silent no-op is a bug).
func doRecordDelete(ctx context.Context, provider providerOps, zone string, rec libdns.Record) error {
	rr := rec.RR()
	fqdn := displayFQDN(rr.Name, zone)
	all, getErr := provider.GetRecords(ctx, zone)
	if getErr != nil {
		return fmt.Errorf("%s-delete %s: GetRecords: %w", strings.ToLower(rr.Type), fqdn, getErr)
	}
	matches := matchRR(all, rr)
	if len(matches) == 0 {
		return nil
	}
	deleted, delErr := provider.DeleteRecords(ctx, zone, matches)
	if delErr != nil {
		return fmt.Errorf("%s-delete %s: %w", strings.ToLower(rr.Type), fqdn, delErr)
	}
	if len(deleted) == 0 {
		return fmt.Errorf("%s-delete %s: subdriver returned 0 deleted records despite %d local matches", strings.ToLower(rr.Type), fqdn, len(matches))
	}
	return nil
}

// matchRR filters `all` to records whose (Type, Name, Data) match `want`.
// Generic counterpart to matchTXT (which has TXT-specific chunk normalization).
func matchRR(all []libdns.Record, want libdns.RR) []libdns.Record {
	var out []libdns.Record
	for _, rec := range all {
		got := rec.RR()
		if got.Type != want.Type {
			continue
		}
		if got.Name != want.Name {
			continue
		}
		if got.Data == want.Data {
			out = append(out, rec)
		}
	}
	return out
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
