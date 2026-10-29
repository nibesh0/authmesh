# Build context is the repository root: the image needs both the service and the
# shared library, and the two must be pinned to the same commit.
#
#   docker build -f services/auth/Dockerfile -t authmesh/auth-service:dev .

FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Requirements are copied on their own so the (slow) dependency layer is reused
# whenever only application code changes.
COPY libs/common/requirements.txt libs/common/requirements.txt
COPY services/auth/requirements.txt services/auth/requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
 && /opt/venv/bin/pip install -r services/auth/requirements.txt

COPY libs/common libs/common
COPY services/auth services/auth
# --no-deps: every dependency is already pinned and installed above, and this
# stops pip from trying to resolve the local `authmesh-common` from PyPI.
RUN /opt/venv/bin/pip install --no-deps ./libs/common ./services/auth


FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="authmesh-auth-service" \
      org.opencontainers.image.description="JWT/TOTP authentication service (gRPC)" \
      org.opencontainers.image.source="https://github.com/example/authmesh"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    GRPC_PORT=50051 \
    METRICS_PORT=9101

# Non-root with no shell and no home: nothing to escalate into if the process is
# compromised. The numeric id is what the Kubernetes securityContext pins.
RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv

USER 10001:10001
WORKDIR /app

EXPOSE 50051 9101

# Compose-friendly probe; in Kubernetes the native gRPC probes are used instead.
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-m", "authmesh_common.healthcheck", "--port", "50051", "--service", "ready"]

STOPSIGNAL SIGTERM

CMD ["auth-service"]
