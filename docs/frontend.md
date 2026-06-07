# Frontend customization

This page covers two operator-facing knobs on the portal UI introduced with the
redesigned login / OTP / dashboard pages: a custom brand icon and the optional
visitor-IP enrichment shown on the login page.

Everything below is optional; the portal renders cleanly with neither.

## Brand icon override

Templates pull the header logo from the `/brand-icon` route, which falls back to
a built-in gradient-square SVG when no override is configured. To ship a custom
mark:

1. Place an SVG (preferred) or 96x96 PNG anywhere readable by the portal
   container; the conventional location is `/var/lib/postern/brand.svg` on the
   host.
1. Add a read-only bind mount under the `portal` service in `compose.yaml`
   (commented snippet already there):
   ```yaml
   - type: bind
     source: /var/lib/postern/brand.svg
     target: /brand/icon.svg
     read_only: true
   ```
1. Set in `.env`:
   ```ini
   PRODUCT_ICON_PATH=/brand/icon.svg
   ```
1. `docker compose up -d portal`.

The route enforces a strict allowlist: suffix must be `.svg` or `.png`, file
size \<= 256 KB. Anything else (missing file, oversized, wrong extension, path
traversal) silently falls back to the built-in default so a misconfiguration
never takes the portal down.

The icon is also wired as the browser favicon and the `<img>` alt is empty (the
brand name is rendered as accompanying text already).

## IP enrichment (MaxMind GeoLite2)

The login and OTP pages render an "You appear as" card with the visitor's
public IP and -- when enabled -- the country flag + city, ISP, and ASN. The
dashboard never shows the card. Enrichment is off by default.

To enable:

1. Create a free MaxMind account at <https://www.maxmind.com/en/geolite2/signup>
   and generate a license key.
1. Download the latest **GeoLite2-City.mmdb** and **GeoLite2-ASN.mmdb** files
   (see <https://dev.maxmind.com/geoip/geolite2-free-geolocation-data> for the
   download URLs and the recommended `geoipupdate` tool).
1. Place both files in a host directory, e.g. `/var/lib/postern/geoip/`:
   ```
   /var/lib/postern/geoip/GeoLite2-City.mmdb
   /var/lib/postern/geoip/GeoLite2-ASN.mmdb
   ```
1. Uncomment the GeoIP bind mount in `compose.yaml` and the `GEOIP_DB_DIR`
   line in `.env`:
   ```yaml
   - type: bind
     source: /var/lib/postern/geoip
     target: /geoip
     read_only: true
   ```
   ```ini
   GEOIP_DB_DIR=/geoip
   ```
1. `docker compose up -d portal`.

The portal opens the DBs on first request, not at startup, so missing files
degrade silently to "IP only". File names must be exactly `GeoLite2-City.mmdb`
and `GeoLite2-ASN.mmdb`.

### Rotation

The portal stat()s each MMDB on every request and reopens automatically when
the mtime advances. Operators can drop in MaxMind's monthly updates with
`mv new.mmdb GeoLite2-City.mmdb` (atomic rename on the same filesystem); no
portal restart is needed.

### Attribution

When GeoIP enrichment is active AND has produced a result on the current
request, the login card footer renders a small "Geo data: GeoLite2 by MaxMind"
link, satisfying the MaxMind EULA's attribution requirement. The link is
omitted on pages where the data was not used.

## Reduced motion

The login and dashboard pages render a Conway's Game of Life canvas as a
moving background. The animation is suppressed for visitors with
`prefers-reduced-motion: reduce` in their OS / browser settings -- a single
static seed renders and the rAF loop is never armed. The footer controls
(reseed, pause, slower, faster) still respond.

## Asset stack

The frontend ships fully inside the portal wheel; no CDN dependency.

- `postern.css` -- single dark theme, design tokens declared as CSS variables
  on `:root`. Section-ordered: tokens, reset, brand, chrome, background,
  cards, footer.
- `postern.js` -- IIFE-wrapped, self-bootstraps on `DOMContentLoaded`. Drives
  the GoL canvas, fade transitions, and footer controls. Honors
  `prefers-reduced-motion`.
- `static/fonts/InterVariable.woff2` (rsms/Inter v4.1, OFL) -- variable axis,
  ~350 KB, browser-cached after first hit.
- `static/fonts/FiraCode-Regular.woff2` (tonsky/FiraCode v6.2, OFL) --
  monospace, ~100 KB.
- `static/flags/<cc>.svg` (lipis/flag-icons v7.5.0, MIT) -- one file per
  ISO 3166-1 alpha-2 country, rendered into the identity card via the
  `flag-<cc>` class declared in `static/flags/flags.css`.

The flags directory is reproducible from upstream via
[portal/scripts/sync-flags.sh](../portal/scripts/sync-flags.sh) -- bump the
`FLAG_ICONS_TAG` constant at the top to update.

## CSP

The frontend is constrained by `default-src 'self'` (see
`nginx/etc/nginx.conf.tmpl`). This forbids inline `<style>` blocks, inline
`<script>` blocks, and HTML event-handler attributes (`onclick=`, `onerror=`,
etc.). All CSS lives in `postern.css`; all JS lives in `postern.js`; event
handlers attach via `addEventListener`. Operators do not need to do anything to
enforce this; the test suite asserts it.
