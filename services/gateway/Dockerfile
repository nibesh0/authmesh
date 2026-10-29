# Build context is the repository root.
#
#   docker build -f services/gateway/Dockerfile -t authmesh/gateway:dev .

FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

COPY libs/common/requirements.txt libs/common/requirements.txt
COPY services/gateway/requirements.txt services/gateway/requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
 && /opt/venv/bin/pip install -r services/gateway/requirements.txt

COPY libs/common libs/common
COPY services/gateway services/gateway
RUN /opt/venv/bin/pip install --no-deps ./libs/common ./services/gateway


FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="authmesh-gateway" \
      org.opencontainers.image.description="HTTP/REST gateway for the authmesh platform" \
      org.opencontainers.image.source="https://github.com/example/authmesh"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    HTTP_PORT=8080 \
    METRICS_PORT=9100

RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv

USER 10001:10001
WORKDIR /app

EXPOSE 8080

# The gateway serves /metrics from its own HTTP app, so there is no second port.
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/readyz', timeout=4).status == 200 else 1)"]

STOPSIGNAL SIGTERM

CMD ["gateway"]
