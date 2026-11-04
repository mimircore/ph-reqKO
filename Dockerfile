# Multi-stage build for ph-reqKO (amd64 and arm64 friendly: pure Python).
FROM python:3.11.9-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
# Build the wheel once; the runtime stage installs only the wheel
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /dist .

# ── runtime stage ──────────────────────────────────────────────────────────────
FROM python:3.11.9-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/mimircore/ph-reqKO" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.title="ph-reqKO" \
      org.opencontainers.image.description="DNS sinkhole resolver with filtering, statistics and a REST API"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Non-root runtime user (fixed UID/GID) and the data volume it owns.
# The resolver listens on unprivileged ports (5353) inside the container,
# so no CAP_NET_BIND_SERVICE and no root are needed.
RUN groupadd --gid 10001 reqko \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin reqko \
 && mkdir -p /data \
 && chown -R 10001:10001 /data

COPY --from=builder /dist/ /tmp/dist/
RUN pip install --no-cache-dir /tmp/dist/*.whl \
 && rm -rf /tmp/dist

VOLUME ["/data"]

USER 10001:10001

# DNS on unprivileged 5353 (mapped to host 53 in compose), API on 8080
EXPOSE 5353/tcp 5353/udp 8080/tcp

# /health is public and needs no token; no curl in the image, so use python
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request, sys; r = urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4); sys.exit(0 if r.status == 200 else 1)"]

ENTRYPOINT ["python", "-m", "reqko"]
