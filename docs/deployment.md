# Deployment

## Service-owned packaging and Coolify migration

ADR [0003](decisions/0003-service-owned-packaging.md) defines the replacement
for the earlier `deploy/authorization` pilot. Source packaging is colocated:

```text
services/authorization/
  Dockerfile                   # service-owned image, rooted build context
  docker-compose.yaml         # portable runtime with required inputs
  docker-compose.coolify.yaml # optional Coolify adapter via extends
  runtime.py
  access/
```

The legacy all-in-one Compose remains untouched. Split deployments still run as
independent Coolify Applications; their existing Dockerfile strategy is not
changed by merging source packaging. The root Dockerfile remains available
for other units until they have separately passed runtime acceptance.

For the **unaccepted** Authorization Compose pilot, the Git repository root is
the build context (`../..` relative to `services/authorization`), and the
Dockerfile is `services/authorization/Dockerfile`. The image copies only the
common Python runtime library and the Auth package, and does not import the
privileged PostgreSQL provisioner or the root entrypoint.

Candidate Coolify Git-backed resource settings (not instructions to modify
production until parser acceptance):

- Base Directory: `/services/authorization`
- Docker Compose Location: `/docker-compose.coolify.yaml` (relative to Base)
- Raw Compose: **off**. The installed Coolify parser inspects the selected
  adapter for managed variable discovery **before** Docker Compose expands
  `extends.file`. The adapter therefore mirrors the portable environment keys
  (not their secret values). The regression test enforces an exact match. A
  Docker Compose CLI config/build check verifies the separate inheritance step.
- Watch Paths: `services/authorization/**`, `services/common/**`,
  `pyproject.toml`, `uv.lock`. Other common dependencies may be added only
  when a concrete consumer actually needs them; unrelated provider changes
  must not trigger an Auth deploy.
- The current Coolify adapter attaches the service to the **already existing**
  external `mcp` Docker network used by PostgreSQL/Valkey. It requires **no**
  `AUTHORIZATION_SHARED_NETWORK` variable and creates no new network.
- Auth uses the canonical `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`,
  `POSTGRES_USER` and `POSTGRES_PASSWORD` names, like Admin API. Give the Auth
  resource `POSTGRES_DB=authorization` (not the Admin API `mcp-bridge` DB):
  both apps have incompatible `oauth_sessions` table schemas. The host/port
  defaults are `postgres`/`5432`.
- Bind the **existing** Production Environment Shared Variables explicitly:
  `POSTGRES_USER={{environment.POSTGRES_USER}}` and
  `POSTGRES_PASSWORD={{environment.POSTGRES_PASSWORD}}`. Do not create fresh
  credentials or reuse stale generated `POSTGRES_USER is required` values.
  Both keys are runtime-only protected secrets (never build arguments).
- Coolify owns the public Auth route with `SERVICE_URL_AUTHORIZATION_8000: /`.
  The application issuer `AUTHORIZATION_PUBLIC_BASE_URL` defaults to the
  generated **unqualified** `SERVICE_URL_AUTHORIZATION`, following the validated
  Coolify/Zoomies URL pattern, and still accepts an explicit override. Portable
  Compose accepts an explicit `AUTHORIZATION_PUBLIC_BASE_URL`; if neither it
  nor the Coolify-generated URL is available, the app rejects startup instead
  of inventing an issuer. A generated route and the app's resolved issuer
  **must be validated separately**; Coolify parser timing can differ by version.
- `MCP_PUBLIC_BASE_URL` remains required: it identifies the public OAuth
  resource audiences (`/mcp`, `/github/mcp`, etc.), **not** the internal Gateway
  container. It belongs to the Gateway/project route owner and must be shared
  with the Auth and Gateway consumers consistently. It cannot be derived from
  the Auth domain and must not be hardcoded into portable Compose.
- Bind existing bootstrap/JWT/service tokens at their actual confirmed
  Production Shared Variable scope. Do not infer a signing key from Admin API's
  Fernet encryption key or reuse unrelated API/session tokens.
- Ensure secrets are runtime-only, Protected; PEM signing key is multiline.
  Confirm no stale/duplicated parser-managed variables are being reused.
- No automatic deploy/domain reassignment until non-production parser, build,
  Auth DB role/provisioner, startup, OAuth/JWKS and rollback checks pass.

Resource-specific domain, credentials, fixed network name and server metadata
belong to the private infrastructure inventory, not in reusable manifests.

## Runtime Docker targets

Application Docker targets:

- `admin-api`
- `authorization`
- `gateway`
- `github`
- `gitlab`
- `files`
- `web`
- `terminal`
- `analysis`
- `ghidra`
- `observability`

`admin-ui` is built from `admin-web-app/Dockerfile`.

## Current deployment-specific notes (not part of the portable templates)

These details describe one active infrastructure and are not defaults for other
users of the Compose files above. Durable live infrastructure authority belongs
in its own infrastructure inventory.

All MCP production resources use the Coolify destination/network `mcp-bridge-network` (`mcp`).
Internal service addressing should use the stable service/container names configured in Coolify.

The root `docker-compose.yaml` contains only long-lived external infrastructure that does not build project source:

- PostgreSQL — durable primary relational database;
- Valkey — disposable Redis-compatible cache.

Application source changes must not rebuild the infrastructure resource.

Admin API accepts `POSTGRES_HOST`, `POSTGRES_PORT` and `POSTGRES_DB` with defaults `postgres`, `5432` and `mcp-bridge`, plus shared `POSTGRES_USER` and `POSTGRES_PASSWORD`; it selects the SQLAlchemy `postgresql+asyncpg` driver internally. The legacy SQLite database is a one-time migration source only; use `infrastructure.sqlite_to_postgres` during cutover and retain the original file until acceptance is complete.

Authorization owns both OAuth identity and agent-access state in one PostgreSQL database/role. Provision it idempotently against the existing cluster with:

```text
python scripts/provision_authorization_database.py
```

The one-shot provisioner uses the existing `POSTGRES_*` connection. In shared-credential mode, it creates the separate `authorization` database when missing, without altering an existing PostgreSQL role or database owner. `AUTHORIZATION_POSTGRES_USER` and `AUTHORIZATION_POSTGRES_PASSWORD` are **optional provisioner-only** settings for a future explicitly selected dedicated role; they are not required by the Auth runtime. Reusing the shared PostgreSQL account grants Auth the privileges of that account, a security trade-off until a dedicated role is accepted.

Authorization additionally requires `AUTHORIZATION_PUBLIC_BASE_URL`, `MCP_PUBLIC_BASE_URL`, local bootstrap credentials, an ES256 private signing key, one gateway service token and one admin service token. Production authorization is public at `https://authorization.mcp.koba-nexus.ru`; MCP resources stay at `https://mcp.koba-nexus.ru`. Gateway receives `AUTHORIZATION_PUBLIC_BASE_URL`, `MCP_PUBLIC_BASE_URL`, `AUTHORIZATION_JWT_PUBLIC_KEY_PEM` and the gateway token for agent-session checks. Gateway does not proxy OAuth endpoints. Agent-session state uses Valkey as a read-through cache; cache loss falls back to durable state in the same authorization database. Admin API reaches authorization privately through `AUTHORIZATION_INTERNAL_URL` (default `http://authorization:8000`).

The legacy monolith remains pinned to `e41085d9c86124a0f711411314265b36f4c23dea` until split-runtime acceptance is complete.

The static infrastructure Compose stack attaches `postgres` and `valkey` directly to the pre-existing external Docker network `mcp`; it does not rely on a Compose-generated default network or manual `docker network connect`.

Coolify resource environment variables are the Compose inputs. Production references shared variables rather than generated `SERVICE_*` placeholders:

```text
POSTGRES_DB={{project.OTEL_SERVICE_NAMESPACE}}
POSTGRES_USER={{environment.POSTGRES_USER}}
POSTGRES_PASSWORD={{environment.POSTGRES_PASSWORD}}
```

`POSTGRES_DB` remains optional at the Compose level and defaults to `mcp-bridge`. `POSTGRES_USER` and `POSTGRES_PASSWORD` are required. The PostgreSQL healthcheck reads the resolved container environment instead of re-interpolating Compose inputs.

The completed legacy SQLite -> PostgreSQL migration was performed as a one-shot process outside the Admin API runtime. Any future recovery/import operation must mount its legacy SQLite source read-only and keep the PostgreSQL target/row-count validation rules from the importer.
