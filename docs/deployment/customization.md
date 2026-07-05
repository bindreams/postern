# Portal customization

Two optional knobs change how the portal looks to your users: a custom brand icon and GeoIP enrichment of the login page. The portal renders cleanly with neither. The displayed product name (`PRODUCT_NAME`) is a plain setting — see [configuration](configuration.md).

## Brand icon

Templates pull the header logo (and browser favicon) from the `/brand-icon` route, which serves a built-in gradient-square SVG by default. To ship a custom mark:

1. Place an SVG (preferred) or 96x96 PNG anywhere readable by the portal container; the conventional location is `/var/lib/postern/brand.svg` on the host.

1. Add a read-only bind mount under the `portal` service in [compose.yaml](https://github.com/bindreams/postern/blob/main/compose.yaml) (a commented snippet is already there):

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

1. Apply:

   ```bash
   docker compose up -d portal
   ```

```{note}
The route enforces a strict allowlist: suffix must be `.svg` or `.png`, file size \<= 256 KB. Anything else (missing file, oversized, wrong extension, path traversal) silently falls back to the built-in default, so a misconfigured icon never takes the portal down.
```

## IP enrichment (MaxMind GeoLite2)

The login and OTP pages render a "You appear as" card with the visitor's public IP and — when enabled — the country flag + city, ISP, and ASN. The dashboard never shows the card. Enrichment is off by default. To enable:

1. Create a free MaxMind account at <https://www.maxmind.com/en/geolite2/signup> and generate a license key.

1. Download the latest **GeoLite2-City.mmdb** and **GeoLite2-ASN.mmdb** (see <https://dev.maxmind.com/geoip/geolite2-free-geolocation-data> for download URLs and the recommended `geoipupdate` tool).

1. Place both files in a host directory, e.g. `/var/lib/postern/geoip/`:

   ```text
   /var/lib/postern/geoip/GeoLite2-City.mmdb
   /var/lib/postern/geoip/GeoLite2-ASN.mmdb
   ```

1. Uncomment the GeoIP bind mount in `compose.yaml` and the `GEOIP_DB_DIR` line in `.env`:

   ```yaml
   - type: bind
     source: /var/lib/postern/geoip
     target: /geoip
     read_only: true
   ```

   ```ini
   GEOIP_DB_DIR=/geoip
   ```

1. Apply:

   ```bash
   docker compose up -d portal
   ```

```{note}
File names must be exactly `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`. The portal opens the databases on first request, not at startup, so missing files degrade silently to "IP only".
```

### Rotation

The portal stat()s each MMDB on every request and reopens it automatically when the mtime advances. Drop in MaxMind's monthly updates with `mv new.mmdb GeoLite2-City.mmdb` (atomic rename on the same filesystem); no portal restart is needed.

### Attribution

When GeoIP enrichment is active and has produced a result on the current request, the login card footer renders a "Geo data: GeoLite2 by MaxMind" link, satisfying the MaxMind EULA's attribution requirement. The link is omitted on pages where the data was not used.

## Reduced motion

The login and dashboard pages render a Conway's Game of Life canvas as a moving background. For visitors with `prefers-reduced-motion: reduce` in their OS or browser settings, the animation is suppressed — a single static seed renders and the animation loop is never armed. The footer controls (reseed, pause, slower, faster) still respond.
