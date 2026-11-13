# syntax=docker/dockerfile:1
# The Docker API allow-list: a pinned HAProxy socket proxy running our policy as a Lua action.
# The tag and the digest are bumped together; the digest is what is pinned (Renovate does not automerge this base:
# a HAProxy or Lua change is checked by the policy suites first, see .github/renovate.json).
FROM ghcr.io/linuxserver/socket-proxy:3.4.7-r0-ls105@sha256:823dda971e9a3951257eb251586a804199819fe1587c35faa43adc7b52a2ff16

COPY haproxy.cfg policy.lua action.lua /etc/postern-proxy/

# Replaces the base entrypoint, which renders the stock section-per-variable config. Exec form: no shell.
ENTRYPOINT ["/usr/sbin/haproxy", "-f", "/etc/postern-proxy/haproxy.cfg", "-db"]

# Build provenance. Last in the stage: a new revision invalidates only this layer.
ARG GIT_REVISION=""
LABEL org.opencontainers.image.revision="${GIT_REVISION}"
