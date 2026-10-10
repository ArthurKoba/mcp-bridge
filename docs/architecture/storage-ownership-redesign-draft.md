# Briareus — storage ownership and migration boundaries (DRAFT)

**Status:** PROPOSAL, NOT IMPLEMENTATION/RELEASE ACCEPTANCE. Owner explicitly
stopped creating/deploying Authorization on 2026-10-10 and challenged the
accepted **Authorization = sole migrator of all Briareus tables** design.
Until the revised storage topology is accepted, do NOT create/start
Authorization, apply its current global Alembic 0001/0002 to live data,
create/drop logical databases, or change the live Data deployment.

This proposal supersedes the *deployment authorization* of the previously
published `docs/architecture/target-project-platform.md` §5.3 and
`coordination/CONTRACTS.md` MIGRATION-AUTO; their historical source decisions
are retained for audit but are not a green light to operate. The new database
boundary and per-domain migration design require separate owner acceptance.

## Verified source baseline, not guessed runtime facts

- Published `main` currently defines one PostgreSQL DB `briareus_dev` and
  **31 tables in 10 schemas**, with **42 cross-schema FKs** in SQLAlchemy
  `platform_metadata()`. These cross-boundary SQL FKs cannot be preserved
  when the owners move to separate PostgreSQL databases.
- `authorization.platform_composition.platform_metadata()` imports ORM from
  Identity, Teams, Projects, Agents, Sessions, Resources, Files, Reverse,
  Runtime and Authorization. Authorization `schema_migrations.py` is currently
  the global Alembic owner. It is source-published, NOT accepted for a live
  migration under the new owner requirement.
- `External Services` provides a real PostgreSQL/Valkey deployment and must
  keep running. Its healthy status does not certify DB emptiness or schema.
- Admin UI/API have been deployed; do not break them while refactoring
  database ownership. Existing C1-B2/C2 security gates remain unchanged.

## Required invariants (proposal for owner review)

1. Each **persistent bounded context** owns its records, logical database,
   schema history, least-privilege runtime role and migration authority.
   Ownership follows BUSINESS capabilities, never just a container count.
   Each database has its own Alembic head and migration lock: no global
   version table, no central migrator importing unrelated ORM metadata.
2. Application data is accessible only through its owner. No other service
   directly reads/writes the owner's SQL tables or migrations. No cross-DB
   foreign keys, joins or shared SQL transactions. Use opaque IDs, versioned
   authenticated APIs and published domain events, with idempotent consumers
   and owner-local transactional outbox. Cross-owner workflow rollback is
   compensation/reconciliation, not an imaginary distributed SQL commit.
3. `Authorization` owns ONLY authentication/authorization decisions, grants,
   sessions, service identity/revocations and their local persistence. It
   must not create Teams/Projects/Files/Integrations/Runtime/MCP telemetry
   tables. A failure in Authorization cannot silently grant access; other
   domain housekeeping may continue but privileged operations fail closed.
4. `Admin API` is a typed BFF/facade, not a second god-database or schema
   owner. The thin Gateway routes/validates, not DDL or business persistence.
5. Each deployable domain release may own its Dockerfile, Compose and worker;
   this does NOT require embedding a Postgres daemon in every Compose.
   Existing external `briareus-net` is a **Docker network, not a VPC/security
   entitlement**. Identity/permissions still require authenticated service
   transports and strict SQL role grants. Additional private DB networks
   may be added only when Coolify routing and DNS effects are proven.
6. Schema provisioning (database+role, infrastructure-owned) is separate from
   **schema migration (domain-owned)**. Neither is an ad hoc manual SQL/script
   step. Keep migrations source-tracked, deterministic, automatically applied
   or verified as a normal owner startup/release step with a per-database
   advisory lock, safe upgrade plan and fail-closed readiness. Dangerous DDL
   needs expand/contract deployment and explicit review. No separate
   global `Schema Init` service or migration-everything `Core` service.
7. One physical PostgreSQL cluster can host many logical databases with
   distinct roles/backups. That yields logical ownership separation, NOT
   physical availability/performance isolation. Large workloads can later
   move to separate PostgreSQL instances or other stores behind the same
   domain-owned repository ports, with no cross-database SQL coupling.
8. Project/Team ownership and rights checks remain mandatory even in a
   separate DB. Never create one database or one namespace per user or
   Project as an MVP default. Valkey stays ephemeral cache/broker with
   service-scoped ACL/key prefixes; it is never source-of-truth for grants.

## Suggested logical store owners (not a demand for seven Postgres containers)

| Owner | Suggested DB in one shared PostgreSQL instance | Data authority | Delivery |
| --- | --- | --- | --- |
| Identity | `briareus_identity` | user records, invitations, login/bootstrap/account credential lifecycle | bounded Identity owner; independent migration set |
| Authorization | `briareus_access` | sessions/grants/revocations, access decisions, service identity and short security audit | Authorization private runtime; own Alembic ONLY |
| Platform Control | `briareus_platform` | Teams, memberships, Projects and Agent definitions/ownership | new or extracted coherent Control API/workers; no global migration responsibility |
| Resource Catalog | `briareus_resources` | provider/MCP accounts, Team/Project integrations, protected credentials and variables, resource lifecycle | own owner API/worker; no other module decrypts raw stored secrets |
| Execution and Files (on activation) | `briareus_runtime`, `briareus_files`, `briareus_reverse` separately **where persistent state is actually needed** | runtime sessions/jobs, file quotas/metadata, native import metadata | respective owners; no database for stateless Web/Gateway by default |
| High-volume MCP events | telemetry/event storage separate from OLTP | request metadata, duration, trace/correlation IDs, aggregates | OTLP → existing observability stack first; ClickHouse or equivalent ONLY after measured volume/query/retention requirements |

These are **candidate logical ownership names**, not authorized deploy/ENV
identifiers. Initial DB provisioning may be incremental. Group bounded
contexts in one runtime where sensible; independent data owner is not
synonymous with one Python microservice per table.

`scope_events`, `commands`, `outbox`, `audit`, `external_operations`,
`browser_telemetry_budgets` currently live under the Authorization schema,
but **their business owner must be classified individually**. In particular,
transactional outbox belongs with the originating owner database; raw/high-
volume MCP calls are NOT auth tables. Only security-critical audit summaries
belong with security data; bulk telemetry belongs in the event pipeline.

## Critical migration and consistency redesign

- Classify all 31 tables and 42 cross-schema FKs by owner. Replace each
  cross-owner FK with an opaque identifier and an explicit authority check
  via typed API or versioned, authenticated event projection. Keep SQL FKs
  and transactions **inside** the owner database.
- Rework the current monolithic `PlatformBase.metadata` and
  `authorization.platform_composition.platform_metadata()` to owner-local
  metadata/DSNs/unit-of-work, repositories, separate Alembic folders/heads
  and DB readiness per owner. Stop Authorization importing unrelated ORM.
- Teams, Projects, Sessions and Resources presently share atomic SQL
  assumptions. Rework onboarding, invitations, grants, session creation,
  revoked membership and resource leases into explicit cross-owner
  state transitions with idempotency, fencing and compensation. Security
  checks must not trust stale Team/Project memberships; define maximum
  propagation delay and fail-closed policy before C2 release.
- The `0001_briareus_baseline` and `0002_browser_telemetry` revisions are
  **historical global source artifacts**, not suitable as new per-domain
  baselines. Do not rename them in place or run them on fresh separated DBs.
  Create new independently reviewed initial revisions for each new logical
  DB and freeze/change only after exact ownership and target DB are approved.
- Never assume `briareus_dev` is empty or safe to drop. Inspect actual live
  DB schemas/rows/role/volume and back up before any migration; if still
  untouched, bootstrap new logical DBs side-by-side without touching existing
  volumes. Existing physical storage is not a disposable sandbox by fiat.
- Startup ordering: physical DB available -> database+role provisioned by
  infrastructure -> owner-local Alembic head verified -> owner service ready
  -> dependent service checks typed signed readiness. No central runtime
  globally migrates all schemas or unconditionally restarts every owner.

## Architecture rollout decision boundaries

0. **Immediate freeze (now):** do not create or start Authorization, do not
   run global Alembic/DDL, do not enable protected Gateway/C2. Healthy Data,
   Admin UI and Admin API may continue with existing untrusted/fail-closed
   boundaries. Avoid unnecessary hotfixes to live secrets/volumes.
1. **Specification:** publish a reviewed table→owner inventory, cross-DB FK
   conversion/consistency contract, runtime→DB map, per-owner migrations and
   signed API dependencies. Confirm which candidates must be separate from
   day one and which can wait for feature activation.
2. **Source redesign:** backend recompose metadata, business services and
   migration owners; Runtime/Frontend update typed ports/readiness; D4
   modifies Compose/registry/env to add logical DB/role provisioning without
   breaking running Data. Hold all new startup until source and rollout
   impact are independently accepted.
3. **Controlled data cutover:** independently inspect state/permissions,
   install empty owner databases with scoped roles, validate owner startup
   one-at-a-time with actual schema head and safe rollback. Do not claim
   runtime readiness merely from container health.
4. **Scale telemetry on evidence:** identify event volume, retention,
   sampling, PII redaction, query patterns and cost before introducing
   ClickHouse or other new mandatory infra.

## Explicit unresolved decisions

- Initial physical topology: one Postgres instance / several logical DBs is
  recommended; per-domain physical instances are deferred until a measured
  isolation/capacity requirement is demonstrated.
- Exact table ownership and grouping of Identity/Platform/Resource Catalog
  are pending review; no cross-DB SQL FK or owner ambiguity is accepted.
- Migration credentials and least-privilege DB/role bootstrap contract must
  be resolved without reintroducing unsafe manual schema-init workflows.
- Synchronization correctness for membership/revocation and first superuser
  registration across independently owned databases is an acceptance blocker.
- Telemetry: OTLP to existing stack is the first collection path; whether to
  persist high-volume MCP call data in ClickHouse, object storage or another
  store depends on observed workload and privacy/retention requirements.
