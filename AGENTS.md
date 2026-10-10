# MCP Bridge — local engineering map

This repository checkout belongs to the persistent Koba Terminal workspace
`mcp-bridge-platform` (`/workspace/projects/mcp-bridge-platform/repo`).

## Authority and navigation

**LATEST IMPLEMENTATION AUTHORITY (2026-10-10):** Owner directed the Orchestrator to make all work executable through «Продолжай». The selected SOURCE implementation architecture is `docs/architecture/storage-ownership-orchestrator-review.md`; Backend A11, Frontend B15, Runtime R13 and Deployment D4 have FULL SOURCE/STAGING tasks in `agents/*.task.md`. Previous ARCH READ-ONLY-only restrictions are superseded **for code/staging**, but NOT for live infrastructure: do NOT start Authorization/global Alembic `0001/0002`, provision DBs/roles, modify Coolify applications/volumes/secrets or enable C1-B2/C2 without a separate explicitly authorized rollout and independent review. Four initial logical databases in existing physical PostgreSQL: Identity, Access, Platform Control, Resource Catalog; later Files/Runtime/Reverse. No god-Core/migrator/cross-DB FKs. Follow the final SOURCE-IMPLEMENTATION section of `coordination/CONTRACTS.md` and latest owner tasks, not older historical holds.

**LATEST OWNER HOLD (2026-10-10): do NOT create/start Authorization or run published global Alembic `0001/0002`, create/delete/split live databases, or activate protected C1-B2/C2. The owner demands independent domain-owned storage/migrations. Read `docs/architecture/storage-ownership-orchestrator-review.md` (selected SOURCE implementation authority; live approval pending), `docs/architecture/storage-ownership-redesign-draft.md` (D4 DRAFT), `coordination/requests/orchestrator.md` (owner intent intake) and final `coordination/CONTRACTS.md` storage source-implementation contract before acting. Existing healthy Coolify resources/volumes are untouched; A/B/R may implement independently safe SOURCE, D4 may stage deployment files offline, and real DB/Authorization/Coolify changes remain held.**

- Current target: `docs/architecture/target-project-platform.md` (still DRAFT for unresolved matters).
- ONLY active implementation tracker: ArthurKoba/mcp-bridge issue #390 (all slices and future implementation). Issue #391 is a separate POST-REFACTOR INDEPENDENT AUDIT, not a worker task, activated only after stable implementation. Do not create slice issues.
- Current application code is historical implementation evidence, not accepted target state.
- Read the root `README.md` for the old runtime map and load relevant workflow-library skills before changing a domain.
- Admin UI/API refactor is a cross-cutting part of #390; use architecture §14 and the project-scoped API contracts. Post-refactor acceptance belongs to #391 only.
- Identity/Team/Project/Agent/Authorization are separate logical domains; one domain does not imply one container.

## Work contract

**Current Python release contract (2026-10-10):** `coordination/CONTRACTS.md` §PACKAGING-V1 selects ONE immutable versioned + SHA-pinned installed `briareus` wheel for all first-party Python Applications; service lifecycles remain independent through scoped DB roles/entrypoints and per-App artifact selection. D4 Dockerfiles cannot stop at `uv sync --no-install-project` or use source-overlay only; shared Python artifact builder has its own input graph and Coolify App watches only genuine module release-pin inputs. Backend owns `pyproject.toml`/metadata, Runtime root Dockerfile, D4 deploy staging. No live infrastructure activation.

- Edit ONLY this local checkout for active tasks. Scratch, temporary Alembic revisions,
  local runtime state and logs belong in `../local/`, outside this Git repository.
- Never import legacy users/sessions/files/provider data into the new greenfield platform.
- Follow async FastAPI/Pydantic/Pydantic Settings/SQLAlchemy, explicit transaction and idempotency contracts.
- Keep REST/OpenAPI as default inter-runtime API, FastMCP for agents, and leave gRPC/GraphQL optional.
- Do not create Git commits, push, open PRs, or merge during individual task slices.
  Maintain a recoverable working tree; one intentional publication/review cycle after slice integration.
- **SUPERSEDED for live deployment (2026-10-10):** published A10 Authorization-global Alembic revisions are historical artifacts, not authorized live migrations. New owner-local source-tracked Alembic baselines/startup lifecycles can be implemented ONLY after approval of the specific logical store owner/role/API architecture. No manual one-shot schema init, `create_all` workaround, new universal Core/migrator or legacy data migration.
- Do not add/run unit/integration/e2e/CI suites or write test-policy files.
  Local app configuration, builds, runtime investigation, and isolated schema migration application are allowed.
- Do not modify production containers/databases or wipe existing infrastructure from this checkout.
- Stop at architectural/security contradictions and record them before coding across that boundary.

## Единый формат отчётов агентам и оркестратору

**CHAT-REPORT-V1** из `coordination/CONTRACTS.md` обязателен для сообщений пользователю: статус с эмодзи, до 4 результатов, только проверенные проверки, 1–2 следующих действия. Сдача агентом `READY_FOR_REVIEW` оформляется fenced `text` кодовым блоком с копируемой строкой «НА ПРИЁМКУ»; статус `ACCEPTED` может выдавать только оркестратор после независимой проверки. Большие техотчёты и доказательства остаются в `agents/<lane>.progress.md`, не в чате.

## Orchestrator repeatable handoff

When the human requests acceptance of A/B/C, reread current progress files,
exact owned source deltas using coordination hash snapshots, current contracts
and tasks; independently review source/security/static/build levels, then
integrate only accepted changes into central `repo/`, refresh all worktrees,
write next large tasks in `agents/<lane>.task.md`, reset their first progress
`State:` to READY, and update the same #390 issue. The human can then say
`Продолжай работу` in each agent's existing chat; each lane's own AGENTS.md
routes this short command to its current task, ownership and contracts.

Never claim that a source/static/build check is a live auth or product
acceptance. Keep #391 as separate later post-refactor audit; do not run
forbidden unit/integration/e2e/smoke tests or create intermediate Git
commits/pushes/PRs/issues.

## Compact #390 tracker rule after EACH independent acceptance

The owner wants issue #390 SHORT. Keep at its top: general progress, the
conceptual MVP checklist, six implementation slices, actual blockers and one
compact accepted-waves table. **Do not add acceptance checklists**, large
per-wave sections or repeat the agent progress report in issue comments.

After an independent acceptance: (1) verify the lane's source and evidence,
(2) mark only genuinely completed conceptual/slice checklist items and leave
PUBLIC/LIVE/OS/DB/security gates open, (3) edit the relevant row in the
three-lane accepted-wave summary and current A/B/C states, (4) mention only
NEW material blockers, and (5) update the existing #390 BODY and verify it.
The complete detailed evidence belongs in `agents/<lane>.progress.md` and
coordination request/contract files, not duplicated as GitHub checklists.

Accepted means the specified SOURCE/STATIC/BUILD work was implemented and
integrated locally, **never** automatically deployed into production. F1–F7
remain deferred outside MVP. Do not treat checked-box totals as a product
completion percentage. Preserve the original historical issue snapshot in
Koba Files `mcp-bridge-platform/review-archives/issue-390-original-2026-10-09.md`.
Do not edit active agent worktrees, create new issues/commits/push/PRs, or
run forbidden test suites as part of tracker maintenance.
