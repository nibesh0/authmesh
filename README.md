# authmesh

A secure, production-oriented authentication platform built as a small distributed system: a REST gateway fronts gRPC services for authentication, user data management, and session security. The stack is designed for local development with Docker Compose and for Kubernetes deployment with Helm.

## What this project includes

- HTTP API gateway for browser and client integrations
- gRPC authentication service with login, registration, refresh, logout, TOTP, and session revocation
- gRPC user service for persistent user records and audit event storage
- Redis-backed session and rate-limit state
- MongoDB-backed user and audit persistence
- Prometheus and Grafana observability support
- Helm deployment manifests for Kubernetes
- Unit, integration, and smoke test coverage

## Architecture

```text
                ┌─────────────────────────────────────┐
                │            HTTP clients              │
                └───────────────┬─────────────────────┘
                                │ HTTPS
                                ▼
                    ┌──────────────────────┐
                    │   gateway (FastAPI)  │
                    │   /auth, /me routes   │
                    └──────────┬───────────┘
                               │ gRPC
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ auth-service     │  │ user-service     │  │ Redis            │
│ - login/register │  │ - users          │  │ - sessions      │
│ - refresh/logout │  │ - audit log      │  │ - rate limits   │
│ - TOTP           │  │ - password state │  │ - deny list     │
└────────┬─────────┘  └────────┬─────────┘  └──────────────────┘
         │                      │
         └──────────────┬───────┘
                        ▼
               ┌──────────────────┐
               │ MongoDB          │
               │ user records     │
               │ audit events     │
               └──────────────────┘
```

## Core security features

- Password validation with configurable strength requirements
- BCrypt password hashing with tunable rounds
- Access tokens and refresh tokens with explicit TTLs
- Refresh token rotation and replay detection
- Session revocation for single-session and global logout
- TOTP enrollment and verification for MFA
- Recovery-code support for emergency access
- Rate limiting for login and registration attempts
- Account lockout after repeated failed authentication attempts
- Audit logging of security-relevant actions
- Standardized error responses with request IDs

## Repository layout

```text
.
├── .env.example              # local development secrets and config
├── docker-compose.yml        # local stack definition
├── Makefile                  # common dev/test/deploy commands
├── pyproject.toml            # repo-wide Python tooling config
├── services/
│   ├── auth/                # authentication gRPC service
│   ├── gateway/             # REST gateway
│   └── user/                # user data gRPC service
├── libs/
│   └── common/              # shared config, logging, metrics, gRPC helpers
├── deploy/
│   ├── helm/authmesh/       # Kubernetes Helm chart
│   └── observability/       # Prometheus/Grafana setup
├── proto/                   # protocol definitions
├── scripts/                 # Dev, smoke, and deployment utilities
├── tests/
│   ├── unit/                # unit tests
│   └── integration/         # service-level integration tests
└── .gitignore
```

## Prerequisites

Before running the stack locally, install:

- Docker
- Docker Compose
- Python 3.12+
- make

Optional for Kubernetes deployment:

- kind
- Helm
- kubectl

## Quick start

1. Create a local environment file:

```bash
cp .env.example .env
```

2. Start the stack:

```bash
make dev-up
```

This starts:

- MongoDB
- Redis
- auth-service
- user-service
- gateway

The gateway is exposed at:

- http://localhost:8080
- http://localhost:8080/docs

3. Stop the stack:

```bash
make dev-down
```

## Common commands

```bash
make help            # list available commands
make build           # build all service images
make lint            # run Ruff lint and format checks
make test            # run unit tests
make test-integration # run integration tests against the compose stack
make smoke           # run the end-to-end smoke test
make dev-logs        # follow logs for gateway/auth-service/user-service
make dev-ps          # show running containers
```

## API overview

The gateway exposes a REST API under `/api/v1` and the service is documented with OpenAPI at `/docs`.

### Authentication routes

- `POST /api/v1/auth/register` — create a user account
- `POST /api/v1/auth/login` — log in with email/password and optional TOTP
- `POST /api/v1/auth/mfa/verify` — complete MFA challenge
- `POST /api/v1/auth/refresh` — rotate a refresh token
- `POST /api/v1/auth/logout` — revoke the current session
- `POST /api/v1/auth/introspect` — validate an access token

### Account routes

- `GET /api/v1/me` — fetch the current user profile
- `POST /api/v1/me/password` — change password
- `POST /api/v1/me/2fa/enroll` — begin TOTP enrollment
- `POST /api/v1/me/2fa/activate` — complete TOTP activation
- `POST /api/v1/me/2fa/disable` — disable TOTP
- `GET /api/v1/me/sessions` — list active sessions
- `DELETE /api/v1/me/sessions/{session_id}` — revoke a single session
- `POST /api/v1/me/sessions/revoke-all` — sign out everywhere

## Observability

The stack can be started with telemetry enabled:

```bash
make dev-up-observability
```

This adds:

- Prometheus on http://localhost:9090
- Grafana on http://localhost:3000

## Kubernetes deployment

The project includes a Helm chart in `deploy/helm/authmesh`.

Useful commands:

```bash
make kind-up
make kind-load
make helm-template
make deploy
make k8s-smoke
```

## Development notes

- Generated gRPC stubs are under `libs/common/src/authmesh/...` and are refreshed via `make proto`.
- The gateway does not hold signing keys; it validates bearer tokens by calling the auth service.
- The auth service owns the security logic and the user service acts as the persistent data layer.
- The system intentionally keeps security decisions centralized to reduce drift and simplify auditing.

## License

This project does not currently declare a repository license in the source tree. Check with the owning team before reusing it in production or publishing derivative work.
