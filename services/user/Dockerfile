# Build context is the repository root.
#
#   docker build -f services/user/Dockerfile -t authmesh/user-service:dev .

FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

COPY libs/common/requirements.txt libs/common/requirements.txt
COPY services/user/requirements.txt services/user/requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
 && /opt/venv/bin/pip install -r services/user/requirements.txt

COPY libs/common libs/common
COPY services/user services/user
RUN /opt/venv/bin/pip install --no-deps ./libs/common ./services/user


FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="authmesh-user-service" \
      org.opencontainers.image.description="MongoDB-backed user and audit service (gRPC)" \
      org.opencontainers.image.source="https://github.com/example/authmesh"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    GRPC_PORT=50052 \
    METRICS_PORT=9102

RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv

USER 10001:10001
WORKDIR /app

EXPOSE 50052 9102

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-m", "authmesh_common.healthcheck", "--port", "50052", "--service", "ready"]

STOPSIGNAL SIGTERM

CMD ["user-service"]
