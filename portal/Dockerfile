# syntax=docker/dockerfile:1
FROM dhi.io/python:3.13-alpine3.21-dev

COPY --from=ghcr.io/astral-sh/uv:0.11.2 /uv /bin/uv
WORKDIR /app

RUN addgroup -S user && adduser -S -G user -u 1000 user \
    && mkdir -p /data && chown user:user /data

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY src/ src/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER user
EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["uv", "run", "uvicorn", "voyager.app:app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--timeout-graceful-shutdown", "30"]
