# syntax=docker/dockerfile:1

FROM dhi.io/python:3.13-alpine3.23-dev AS build
COPY --from=ghcr.io/astral-sh/uv:0.11.2 /uv /bin/uv
WORKDIR /app
COPY portal/pyproject.toml portal/uv.lock ./
COPY portal/src/ src/
# --link-mode=copy: hardlinks don't survive `COPY --from`; a copy-mode venv is
# self-contained and survives the cross-stage transfer in stage 2.
RUN uv sync --frozen --no-dev --link-mode=copy
RUN mkdir /data

FROM dhi.io/python:3.13-alpine3.23

LABEL org.opencontainers.image.source="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.url="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.title="postern-portal"
LABEL org.opencontainers.image.description="Postern VPN management portal"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"

WORKDIR /app
ENV PATH="/app/.venv/bin:$PATH"
# /app is intentionally root-owned: nonroot only needs read+execute, and venv files
# are mode 644/755. /data is the only nonroot-writable path, hence the explicit chown.
# BuildKit's `COPY --from` does NOT preserve source ownership without --chown.
COPY --from=build /app /app
COPY --from=build --chown=65532:65532 /data /data
COPY LICENSE.md /usr/share/licenses/postern/LICENSE.md

USER nonroot
EXPOSE 8000
CMD ["uvicorn", "postern.app:app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--timeout-graceful-shutdown", "30"]
