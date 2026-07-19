// Cloudflare zone-level SSL/TLS encryption-mode support for the edge profile's
// batteries-included fronting.
//
// Orange-clouding the apex makes Cloudflare fetch the origin per the zone's SSL/TLS
// mode. On off/flexible, CF talks to the origin over HTTP :80, which Postern's nginx
// always 308-redirects to HTTPS -> the browser hits an infinite redirect
// (ERR_TOO_MANY_REDIRECTS). Raising the mode to full/strict makes CF use :443 (valid
// LE cert, the app). The mode is a zone SETTING, not a DNS record, with no libdns
// model -- so, like ech (cloudflare_ech.go), it bypasses libdns and PATCHes
// /zones/{id}/settings/ssl directly. Raise-only and zone-WIDE; see cloudflareZoneSSLSet.
//
// GET-then-PATCH is not atomic (no CF CAS/ETag): every PATCH raises relative to the
// just-read value, so target=strict never lowers a mode; target=full carries an accepted,
// irreducible GET/PATCH race with a concurrent human/process raise. See the Convergence
// invariant in CLAUDE.md for the full argument.
package main

import (
	"context"
	"fmt"
)

// sslModeRank orders the four Cloudflare SSL/TLS modes so "raise-only" can compare
// them. ok=false for an unrecognized value (fail loud rather than guess).
func sslModeRank(mode string) (int, bool) {
	switch mode {
	case "off":
		return 0, true
	case "flexible":
		return 1, true
	case "full":
		return 2, true
	case "strict":
		return 3, true
	default:
		return 0, false
	}
}

// cloudflareZoneSSLSet raises the zone's SSL/TLS mode to `target` when the current
// mode is below `full` (off/flexible); it is a no-op when the zone is already at
// full/strict. target must be "full" or "strict". Idempotent GET-then-PATCH. Returns the
// mode the zone is LEFT in (`current` on a no-op, `target` after a raise) so the caller
// can surface target-vs-actual drift -- e.g. a zone already at `full` when the operator
// targets `strict` is left at `full` (raise-only), and the returned "full" makes that
// visible instead of the state file implying `strict` landed.
func cloudflareZoneSSLSet(ctx context.Context, client *cfClient, zone, target string) (string, error) {
	fullRank, _ := sslModeRank("full")
	targetRank, ok := sslModeRank(target)
	if !ok || targetRank < fullRank {
		return "", fmt.Errorf("ssl-set: target must be 'full' or 'strict' (got %q)", target)
	}
	zoneID, err := client.zoneID(ctx, zone)
	if err != nil {
		return "", err
	}
	current, err := client.getZoneSetting(ctx, zoneID, "ssl")
	if err != nil {
		return "", err
	}
	currentRank, ok := sslModeRank(current)
	if !ok {
		return "", fmt.Errorf("ssl-set: Cloudflare returned an unknown ssl mode %q for zone %q", current, zone)
	}
	if currentRank >= fullRank {
		return current, nil // already sufficient; left as-is (may be below the configured target)
	}
	if err := client.patchZoneSetting(ctx, zoneID, "ssl", target); err != nil {
		return "", err
	}
	return target, nil
}
