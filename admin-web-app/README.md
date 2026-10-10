# Briareus Admin UI

Standalone Vue 3 + TypeScript + Vite application for Briareus Users, Teams,
Projects, AgentIdentity, AgentSessions and source-authorized resources.
The old MCP Bridge operator UI, cookie REST client, telemetry and global
realtime components have been **removed from this product source**.

## Source layout

- `src/app/` — Briareus application entry, navigation and styles.
- `src/features/platform/` — typed platform API boundary, scoped state,
  revocation-safe commands and reusable components.
- `src/pages/platform/` — User/Team/Project/Agent/Session and resource screens.
- `src/shared/` — small standalone UI primitives, locale and non-secret UI
  preferences (stored under `briareus:ui:v1`).

The **historical** accepted Backend A9 source OpenAPI defines **60 routes,
68 operations and 68 schemas**, unchanged from A8; it is NOT compatible with
the selected B15 per-owner database/migration architecture. The obsolete
A9 global-database `api/draft/**` client was deleted after proving it had
**no importers** outside its own directory; the accepted A11 typed private
`a11-owner-bff-source.ts` and `bff-boundary.ts` are the only owner contract
sources. No public REST adapter, HTTP proxy, OAuth principal, WebSocket or
generated service keys are activated on page load.

## Build

- `bun install --frozen-lockfile`
- `bun run typecheck`
- `bun run build`

The build embeds **only** the source `package.json` version through a Vite
compile-time constant. This is not a deployed service version, source commit
hash or current deployment environment/Authorization readiness.

## Browser diagnostic privacy and time

Briareus contains a first-party browser diagnostics recorder under
`src/features/platform/model/browser-telemetry.ts`. It is **opt-in and off
by default**; pre-B14 UI preferences do not silently authorize collection.
Consent is a standalone in-memory boolean for the current tab and authenticated
User. Older persisted B14 consent is revoked on load; logout and User switch
reset opt-in to OFF. At most
64 fixed-schema records / 16 KiB / 24 events per minute are kept **only in
memory** for up to five minutes; no URLs, query strings, raw exception text,
credentials, token values or User/Team/Project IDs are read or recorded.
Events are purged on scope/principal changes, logout, disconnect, pagehide,
consent revocation and expiration. Server delivery is **disabled** pending
an A10 authenticated same-origin telemetry relay; this code contains no
collector endpoint or Team `OTLP_BEARER_TOKEN` and sends NOTHING to SigNoz.

All accepted server instants are UTC-aware ISO-8601; display can use UTC or
viewer device time in Settings, not a fabricated Team/deployment `TZ`.
Native `datetime-local` inputs are device-local and convert to explicit UTC
before a write, rejecting missing/duplicated DST wall-clock values.
Browser `clientObservedAtUtc` diagnostic times and deadline displays are NOT
backend audit timestamps or Authorization schema readiness evidence.

Production images are defined in the **separately owned**
`deploy/admin-ui/Dockerfile` and its portable/Coolify Compose files.
Only the Briareus source and existing static Nginx assets are copied.
Vite development and preview bind `127.0.0.1`; there is no old API proxy
or hostname-based service inference. No runtime-config JS or operator ENV
flags are consumed.

## B15 independently owned BFF source boundary (not deployed)

The selected owner architecture retains one existing physical PostgreSQL 18
cluster but separates four initial logical owner databases and roles:
`briareus_identity` (User, invitations, bootstrap), `briareus_access`
(authorization, AgentSessions, approvals), `briareus_platform` (Team,
Project, AgentIdentity and scope projections) and `briareus_resources`
(provider/variable credentials and leases). Files, Runtime and Reverse are
separate deferred owner-store contracts, NOT implicit extra startup DBs.

`src/features/platform/api/bff-boundary.ts` defines a **source-only**, strictly
typed composition of `identity`, `access`, `control` and `catalog` behind
**one** future authenticated same-origin Admin BFF. It deliberately exposes
no individual database DSN, owner service URL or credentials to the browser.
`src/features/platform/model/refresh-owner-boundary.ts` re-reads current
server-issued actor/scope/owner revisions with AbortSignal and bounded TTL;
`project-context.ts` fails closed on unavailable Identity/Access/Control and
also Catalog for resource actions. An operator may view only verified owner
status, revision and age; a Project name cached in a UI projection is never a
fresh permission or schema-ready receipt. The actual BFF wire/HTTPS installer
has not been accepted. Neither `.bff` nor a source port can be installed by
an arbitrary browser setting or existing historical A10 source constructor.

Privileged writes use a **single original Idempotency-Key**, held in browser
memory, and a typed command state `pending`, `unknown`, `reconciling`,
`confirmed` or `denied`. After a possible distributed commit, the frontend
never turns owner-local 2xx into full success: a bounded authenticated status
GET for the original actor/scope/key must confirm **every required owner at
current revisions** and an authorized original effect-domain read must
succeed. Unknown/pending/permission loss never causes a fresh-key replay.
Temporary offline state preserves a same-tab unresolved key for re-login of
the same actor; explicit logout/revocation erases it. Durable cross-tab and
post-reload exactly-once guarantees are **Backend A11 responsibilities**, not
something that can be simulated through localStorage.

The old A10 single `briareus_dev` metadata/Alembic `0001/0002` and global
Authorization command-status port are **superseded**; they are NOT a migration
input or a valid B15 authorization proof. Each actual owner runs its own
migration/transaction/outbox and verifies Identity+Access+Control at the
sensitive effect boundary. No part of Briareus UI runs SQL, initializes a DB,
provisions roles, starts a service or exposes a manual schema wizard. The
current owner hold forbids all live provisioning and C1-B2/C2 activation.

## B17 A11 private BFF DTO compatibility (source only)

Independently accepted Backend A11 includes an **UNMOUNTED** `owner_bff_contract`
with source-only `GET /v1/platform/projects`, `/teams` and project/Team
original-command local status. `src/features/platform/api/a11-owner-bff-source.ts`
provides exact bounded `after_id` UUIDv4/limit 1..100 page DTO readers,
Project `active|deleting|deleted`, Team membership revision and owner-local
status vocabulary. None of those returned data are signed current all-owner
authorizations. An A11 local `COMMITTED` status is NEVER a BFF-composite
success. There is no public installer, direct owner API call or browser DB
client.

Accepted A11 original command status requires **two independent immutable
identifiers**: `Operation-UUID` (UUIDv4) and a printable ASCII
`Idempotency-Key` (the current frontend generates a UUIDv4 key). Briareus holds both
inside its current-tab command fence and checks both with the original actor,
scope, operation/target and authenticated signed multi-owner evidence before
any confirmation; it never remints either for a retry. Team ownership transfer
uses accepted A11 `team.owner.transfer`, NOT historical A9
`team.transfer_owner`. Backend A12 must still supply the signed recipient-
bound result and authenticated current owner revisions; an A11 owner-local
HTTP status has no source to do that.

**Accepted A12 compatibility blocker (tracked for Backend A13):** private
`owner_bff_evidence.BffEffectEvidence` does **not** return the original
`Operation-UUID`, while the B17/B18 UI's BFF result requires the server to
return it and match it to the original in-memory command. A12's recipient-
signed `OwnerEffectCommand` / `OwnerEffectReceipt` also require
`operation_uuid === idempotency_uuid`, whereas the current UI keeps the
original operation UUID and printable Idempotency-Key as independently
minted UUIDv4 values. These are distinct source wire contracts. Do NOT
silently copy the sent operation UUID into a response, coerce the two keys
equal, or treat a local `COMMITTED` as signed all-owner confirmation. Until
A13 provides a reviewed binding/translation and trusted C1-B2/C2 transport,
all mutation effects remain UNKNOWN/fenced and public Port activation remains
blocked.

Source-approved Project lifecycle is required to open/reassign a Project;
missing `lifecycleStatus` is **unknown**, not permission to assume `active`.
A pre-C2 one-use invitation/reset/first-admin form is disabled even if an
unapproved adapter offers old methods, and any opened raw token is scrubbed
from the URL and discarded rather than held in an inactive input. An unknown
one-use redemption does not become `acknowledged` merely because its HTTP
response was 2xx/400/422.

B17 shared scoped search is **UI-only** over already received User, Team,
Project, Agent, Session, Approval, Provider Connection and Variable rows.
Unloaded keyset pages are not searched and missing matches never prove
revocation or deletion; original source rows and grants control every action,
not a filtered alias or list position. Catalog credentials and variable values
are write-only with the accepted A11 owner length bound of 1..131072 UTF-8
bytes. Reconciliation controls only inspect the ORIGINAL scope/key using a
current signed BFF status; `pending/unknown` cannot be dismissed or replayed.

## B19 scoped operator UX and accessibility (source-only)

B19 shares strict frontend-only `current-record.ts` owner/decision revision
checks and `scoped-keyset.ts` UUIDv4 ordered-page merge across live User,
Invitation, TeamMember, Session and Approval continuation UI. A server 2xx
page is rejected if it overlaps/duplicates previous or same-page identities,
uses a backwards/missing continuation cursor, changes an authenticated source
revision or contains a foreign Project Session. A locally filtered or
incomplete list **never** proves the absence/deletion of an entity. This
client consistency check is not a substitute for server-side signed ACLs,
owner-local commands or complete snapshot identity.

Dangerous User/Team/Project/Agent/Session actions additionally require a
fresh immutable source record revision; Team/Project mutations require an
exact current source owner decision epoch. UI selection of an inactive
Project reverts immediately rather than leaving a visually selected but
unauthorized option. During owner outage, the previous explicit selected
Team/Project is displayed only as a short **unverified non-interactive**
label; it does not regain any source capability. AgentSession approvals,
revocation and grant requests require valid source revision, active original
UUIDv4 Session, timezone-aware unexpired source deadline and per-request
source allowed action. Invalid/missing hard-expiration blocks source UI
buttons rather than trusting browser wall-clock state as authorization.

`ConfirmAction.vue` now resets typed destructive permission on **any target
or source detail change**, requires the current open dialog and guards rapid
Enter/double-submit. `AppDialog.vue` prioritizes its intended autofocus field,
labels the confirmation detail for screen readers, traps keyboard Tab and
restores focus on close. The responsive mobile navigation uses `inert` and
`aria-hidden` ONLY while visually offscreen on mobile, never while visible on
desktop; closing/revoking context routes focus back to safe reachable content.
A suspended/disabled Identity explicitly purges browser bearer and original
in-memory command keys and revokes per-User telemetry consent. Anonymous,
unmounted first-user/invitation/reset and global destructive writes remain
inaccessible without a reviewed BFF signed original-key API. No UI feature
flag, direct per-owner socket, fake preview User or browser OTLP relay exists.

## Authentication and deployment boundary

`PlatformPort` remains **non-installable** until C1-B2-PUBLIC/C2 approve
actual mounted TLS-origin/authentication, current User and Team/Project
permissions, Bearer/cookie policy, revocation, command reconciliation and
scoped realtime transport. Until that contract exists the UI explicitly
shows that the Admin API is unavailable; it never simulates login or
falls back to the old product. The first-superuser setup route is also
blocked until Backend and Deployment approve an authenticated operator-only
channel. During an Authorization migration or outage, a backend 503 is shown
as service-unavailable-or-possibly-upgrading; Briareus does not run migrations
or infer readiness from Data container health. No DB/JWT/encryption/service private keys belong in browser source,
Vue build args or stored browser preferences.

Live Coolify deployments, image publication and restricted DEV acceptance
belong to the infrastructure owner; a successful static build is not
real authentication or runtime acceptance.
