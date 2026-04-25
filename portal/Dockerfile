# syntax=docker/dockerfile:1
FROM dhi.io/python:3.13-alpine3.21-dev

LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"

COPY --from=ghcr.io/astral-sh/uv:0.11.2 /uv /bin/uv
WORKDIR /app
ENV PATH="/app/.venv/bin:$PATH"

RUN addgroup -S user && adduser -S -G user -u 1000 user \
	&& mkdir -p /data && chown user:user /data

COPY portal/pyproject.toml portal/uv.lock ./
COPY portal/src/ src/
RUN uv sync --frozen --no-dev
COPY portal/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
COPY LICENSE.md /usr/share/licenses/voyager/LICENSE.md

USER user
EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "voyager.app:app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--timeout-graceful-shutdown", "30"]
