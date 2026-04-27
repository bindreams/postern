"""Provisioner-side state-machine drivers, COPYed into the provisioner image.

Tests live under `portal/tests/` so the existing `cd portal && uv run pytest`
discovers them. The package itself is provisioner-specific code; the portal
container does not import it (the portal uses `postern.cert` for state reads
and trigger writes only).
"""
