"""Cert renewal state, persistence, and inspection helpers.

Mirrors the structure of `postern.mta` -- this package is shared between
the portal CLI (which reads state and writes trigger files) and the
provisioner image (which advances the state machine). The provisioner
imports it as `postern_cert` from a `COPY` step in `provisioner/Dockerfile`.
"""
