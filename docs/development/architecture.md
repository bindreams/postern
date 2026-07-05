---
orphan: true
---

# Frontend internals

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
[portal/scripts/sync-flags.sh](https://github.com/bindreams/postern/blob/main/portal/scripts/sync-flags.sh) -- bump the
`FLAG_ICONS_TAG` constant at the top to update.

## CSP

The frontend is constrained by `default-src 'self'` (see
`nginx/etc/nginx.conf.tmpl`). This forbids inline `<style>` blocks, inline
`<script>` blocks, and HTML event-handler attributes (`onclick=`, `onerror=`,
etc.). All CSS lives in `postern.css`; all JS lives in `postern.js`; event
handlers attach via `addEventListener`. Operators do not need to do anything to
enforce this; the test suite asserts it.
