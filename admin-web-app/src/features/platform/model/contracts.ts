import type { AuthenticatedBffBoundary } from "@/features/platform/api/bff-boundary"

/**
 * Normalized FRONTEND VIEW MODELS and dependency-injected ports, NOT REST DTOs.
 * A5 has accepted SOURCE development DTO/permission projections. The actual
 * mounted public wire contracts, URLs and caller security remain C1-B2/C2 gated.
 */
export type UserId = string
export type TeamId = string
export type PlatformProjectId = string
export type AgentIdentityId = string
export type AgentSessionUuid = string

/** UI actions are mapped from *server-issued* effective permissions by an approved adapter. */
export type UiCapability =
  | "profile.read" | "profile.password" | "invitations.issue" | "invitations.revoke"
  | "users.read" | "users.manage" | "users.resetPassword" | "users.roles"
  | "teams.read" | "teams.create" | "teams.members" | "teams.ownership"
  | "projects.read" | "projects.create" | "projects.transfer"
  | "agents.read" | "agents.manage"
  | "sessions.read" | "sessions.open" | "sessions.request" | "sessions.resolve" | "sessions.revoke"
  | "accounts.read" | "accounts.manage" | "accounts.teamManage"
  | "variables.read" | "variables.manage" | "variables.teamManage"
  | "operations.metadata.read"
  | "dashboard.read" | "calls.read" | "oauth.read" | "files.read" | "terminal.read"
  | "browser.managed.read" | "browser.external.read" | "analysis.read" | "settings.read"

export interface AuthenticatedUser {
  userId: UserId
  username: string
  displayName: string
  active: boolean
  isSuperuser: boolean
}
export interface AvailableProject {
  projectId: PlatformProjectId
  /** Backend A11 explicitly includes active/deleting/deleted. Unknown is NOT
   * active and cannot be inferred from a cached Team membership list. */
  lifecycleStatus?: "active"|"deleting"|"deleted"
  name: string
  owner: { kind: "user"; userId: UserId } | { kind: "team"; teamId: TeamId; teamName: string }
}
export interface AvailableTeamScope { teamId: TeamId; name: string }
export interface AccessProjection {
  user: AuthenticatedUser
  projects: AvailableProject[]
  /** Visible Team scopes, including a Team with zero Projects. */
  teams?: AvailableTeamScope[]
  /** Server-issued capabilities for identity-level actions (no Project selected). */
  permissions: Partial<Record<UiCapability, boolean>>
  /** Server-issued capabilities evaluated separately for each authorized Project. */
  projectPermissions?: Record<PlatformProjectId, Partial<Record<UiCapability, boolean>>>
  /** Signed-in caller decisions bound to membership, owner and resource revisions. */
  projectDecisionVersions?: Record<PlatformProjectId, string>
  teamDecisionVersions?: Record<TeamId, string>
  /** Authoritative Team-level actions, separate from Team Project membership. */
  teamPermissions?: Record<TeamId, Partial<Record<UiCapability, boolean>>>
  /** Server-issued capabilities for verified global operator context only. */
  operatorPermissions?: Partial<Record<UiCapability, boolean>>
}
export type ScopeSelection =
  | { kind: "account" }
  | { kind: "team"; teamId: TeamId }
  | { kind: "project"; projectId: PlatformProjectId }
  | { kind: "operator" }
export interface QueryContext {
  scope: ScopeSelection
  signal: AbortSignal
  revision: number
  /** A4 access decision revision from the current verified User snapshot. */
  decisionVersion?: string | null
}
/** Backend A11 requires TWO original immutable UUIDv4 identities: the
 * operation_uuid and the printable Idempotency-Key. Neither may be regenerated
 * by a response retry, route change, owner transfer or reconciliation. */
export interface CommandContext extends QueryContext { idempotencyKey: string; operationUuid: string }
/** A6 SOURCE idempotency status selectors; each is independently authorized. */
export type SourceCommandTarget =
  | {kind:"project";id:PlatformProjectId}
  | {kind:"team";id:TeamId}
  | {kind:"project_resource";id:PlatformProjectId}
  | {kind:"resource";id:string;owner:ResourceOwner}
export interface SourceCommandBinding {operation:string;target:SourceCommandTarget}
export interface ListResult<T> {
  items: T[]
  /** A6 keyset continuation exists ONLY when source returned has_more. */
  nextAfterId?: string | null
  hasMore?: boolean
  pageSize?: number
  revision?: string | null
  /** Source-specific pagination/truncation metadata; no omitted rows inferred. */
  serverLimit?: number
  possiblyTruncated?: boolean
  observedAt?: string
}
export interface MutationResult { revision?: string | null }

export interface UserView {
  id: UserId
  username: string
  displayName: string
  active: boolean
  isSuperuser: boolean
  revision?: string
  ownsTeams?: number
  ownsPersonalProjects?: number
  /** Exact A5 per-row action codes (never granted from superuser role alone). */
  sourceActions?: string[]
  /** Effective per-record actions issued by the server. Missing means deny. */
  allowedActions?: Partial<Record<UiCapability, boolean>>
}
export interface InvitationView {
  id: string
  kind?: "registration" | "password_reset"
  createdAt?: string
  issuerLabel: string
  expiresAt: string | null
  consumedAt?: string | null
  revokedAt?: string | null
}
export interface InvitationIssued { invitationUrl: string; expiresAt: string | null }
export interface TeamView {
  id: TeamId; name: string; ownerId: UserId; ownerLabel: string
  members: TeamMemberView[] | null; revision?: string; decisionVersion?: string
  memberNextAfterId?:string|null; memberHasMore?:boolean
  allowedActions?: Partial<Record<UiCapability, boolean>>
}
export interface TeamMemberView { userId: UserId; label: string; active: boolean; owner: boolean }
export interface ProjectView extends AvailableProject { revision?: string; decisionVersion?: string; allowedActions?: Partial<Record<UiCapability, boolean>> }
export interface AgentView { id: AgentIdentityId; projectId: PlatformProjectId; label: string; parentAgentId: AgentIdentityId | null; status: string; revision?: string }
export interface GrantOption { id: string; label: string; description?: string }
export interface AgentSessionView {
  sessionUuid: AgentSessionUuid
  projectId: PlatformProjectId
  label: string
  status: "active" | "expired" | "revoked" | "pending"
  elevation: "normal" | "elevated"
  elevationPolicy: "fixed" | "requestable" | null
  expiresAt: string
  grants: string[]
  revision?: string
  createdAt?: string
  allowedActions?: Partial<Record<UiCapability, boolean>>
}
export interface AgentSessionRequestView {
  id: string
  projectId: PlatformProjectId
  sessionUuid: AgentSessionUuid
  requestedBy: string
  status: "pending" | "approved" | "rejected"
  requestedGrants: string[]
  requestedUntil: string | null
  revision?: string
  /** A local data-comparison key, NOT an unprovided server approval version. */
  snapshotKey?: string
  /** Source-based reason approval cannot be executed; no guessed server action. */
  blockReason?: "missing-base-session" | "inactive-base-session" | "expired-request" | "invalid-deadline" | "missing-approval-rights"
  allowedActions?: Partial<Record<UiCapability, boolean>>
}
export interface SessionSnapshot {
  sessions: AgentSessionView[]
  requests: AgentSessionRequestView[]
  sessionsNextAfterId?:string|null
  approvalsNextAfterId?:string|null
  sessionsHasMore?:boolean
  approvalsHasMore?:boolean
  sourcePageSize?:number
  availableGrants: GrantOption[]
  normalHardTtlSeconds?: number
  elevatedMaxSeconds?: number
}
/** Exactly one persisted resource owner: Team OR Project; never both. */
export type ResourceOwner = { kind: "team"; teamId: TeamId } | { kind: "project"; projectId: PlatformProjectId }
/**
 * UI-only effective/project visibility projection. The server determines scope,
 * inheritance and permissions. The OWNER-APPROVED `all` returns both entries
 * for duplicate Team/Project names; never shadow/merge in the frontend.
 */
export type ResourceVisibility = { kind: "project"; projectId: PlatformProjectId } | { kind: "team"; teamId: TeamId }
/** OWNER-APPROVED read selector, independent of the unapproved route/DTO shape. */
export type ResourceScope = "all" | "team" | "project"
export interface ProjectAccountView {
  id: string
  visibleIn: ResourceVisibility
  owner: ResourceOwner
  /** Explicit provenance: Team-owned items inherited only through the owning Team. */
  inherited: boolean
  provider: "github" | "gitlab" | "signoz" | "coolify" | "grafana" | "zoomies"
  alias: string
  /** Absent in current draft ResourceView: MUST NOT synthesize configuration. */
  baseUrl: string | null
  enabled: boolean | null
  updatedAt: string | null
  revision: string
  /** A5 decision fencing; not a credential or shareable entitlement. */
  projectAccessRevision?: string | null
  teamAccessRevision?: string | null
  credentialConfigured: boolean | null
  authType?: string | null
  connectionStatus?: string | null
  providerSettings?: Record<string, unknown> | null
  displayName?: string
  allowedActions?: Partial<Record<UiCapability, boolean>>
}
export interface ProjectAccountInput {
  owner: ResourceOwner
  provider: ProjectAccountView["provider"]
  alias: string
  baseUrl: string
  /** Not represented by Backend ResourceView: never silently toggle this. */
  enabled?: boolean
  /** Source-backed provider auth_type and validated provider_settings JSON. */
  authType?: string
  providerSettings?: Record<string, unknown>
  credential?: string
  /** A blank credential preserves the current secret when editing. */
  expectedRevision?: string
}
export interface ProjectVariableView {
  id: string
  visibleIn: ResourceVisibility
  owner: ResourceOwner
  /** Explicit provenance: Team-owned items inherited only through the owning Team. */
  inherited: boolean
  key: string
  kind: "plain" | "secret"
  /** No plaintext secret in responses. Plain values are redacted by default. */
  revision: string
  projectAccessRevision?: string | null
  teamAccessRevision?: string | null
  valueConfigured: boolean
  updatedAt?: string | null
  allowedActions?: Partial<Record<UiCapability, boolean>>
}
export interface ProjectVariableInput {
  owner: ResourceOwner
  key: string
  kind: "plain" | "secret"
  value?: string
  expectedRevision?: string
  /** Current draft separates rename (PATCH) from rotate (POST). */
  action?: "rename" | "rotate"
}

/** UI-only safe read projections. No REST route or full runtime control is implied. */
export type OperationalArea = "dashboard" | "calls" | "oauth" | "files" | "terminal" | "browserManaged" | "browserExternal" | "analysis" | "settings"
export interface OperationalItemView {
  id: string
  projectId: PlatformProjectId
  label: string
  status: string
  updatedAt?: string | null
  /** A5 read-only DB record origin. Never infer process health from status. */
  ledgerKind?: "runtime-session" | "job" | "file-quota" | "native-project" | "native-import"
  observedAt?: string | null
  version?: number
  hardExpiresAt?: string | null
  cleanupState?: string | null
  /** Source database status, NEVER a process/service health confirmation. */
  reportedStatus?: string
  fileCount?: number
  byteLimit?: number
  usedBytes?: number
  reservedBytes?: number
  // Deliberately excludes file contents, terminal arguments, secrets and browser URLs.
}
export interface ScopedEvent {
  /** Normalized after SERVER verification; not an invented WS topic. */
  kind: "invalidate" | "access-revoked" | "principal-revoked" | "permissions-changed" | "session-request"
  projectId: PlatformProjectId | null
  /** Present only for server-authorized Team-scoped events. */
  teamId?: TeamId | null
  resource: "users" | "teams" | "projects" | "agents" | "sessions" | "accounts" | "variables" | "operations" | "all"
}
export interface ScopedRealtimePort {
  /** Server must authorize handshake, subscribe, snapshot AND delivery. */
  connect(context: QueryContext, receive: (event: ScopedEvent) => void): Promise<() => void>
}

export interface PlatformPort {
  /** Single trusted BFF source interface; absent on accepted A10 private port. */
  bff?: AuthenticatedBffBoundary
  /** The following normalized public fields are a PRESENTATION FACADE over
   * the reviewed BFF's explicit identity/access/control/catalog capabilities.
   * No method is permission, a raw per-owner service URL or database client.
   * `groupVerifiedBffCapabilities` enforces this typed composition boundary. */
  /** Explicit capability flags of the adapter transport, not of a User's permissions. */
  capabilities?: {
    candidateVerification: boolean
    scopedRealtime: boolean
    operationalSummary: boolean
    sessionLabels: boolean
    normalSessionOpen: boolean
    elevatedSessionOpen: boolean
    sessionApprovalTtlEdit: boolean
  }
  auth: {
    restore(signal: AbortSignal): Promise<AccessProjection | null>
    login(input: { username: string; password: string }, signal: AbortSignal): Promise<AccessProjection>
    logout(signal: AbortSignal): Promise<void>
    /** Re-read the authenticated principal and current permissions; never rotates Bearer. */
    refresh(signal: AbortSignal): Promise<AccessProjection | null>
    /** Rotate the current bearer explicitly if the accepted backend supports it. */
    renew?(signal: AbortSignal): Promise<AccessProjection | null>
    /** Clear a memory-only credential AFTER confirmed local sensitive action. */
    invalidate?(): void
    /** Optional local-only signal from the reviewed auth transport. */
    onCredentialInvalidated?(listener: () => void): () => void
    /** Optional until invitation/bootstrap and reset HTTP contracts are approved. */
    register?(input: { invitationToken: string; username: string; password: string }, signal: AbortSignal, idempotencyKey:string): Promise<void>
    redeemPasswordReset?(input: { resetToken: string; password: string }, signal: AbortSignal, idempotencyKey:string): Promise<void>
  }
  users: {
    list(context: QueryContext, after?: string | null): Promise<ListResult<UserView>>
    invitations(context: QueryContext, after?: string | null): Promise<ListResult<InvitationView>>
    issueInvitation(context: CommandContext): Promise<InvitationIssued>
    revokeInvitation(context: CommandContext, invitationId: string): Promise<MutationResult>
    changePassword(context: CommandContext, oldPassword: string, newPassword: string): Promise<MutationResult>
    issueReset(context: CommandContext, userId: UserId): Promise<InvitationIssued>
    setActive(context: CommandContext, user: UserView, active: boolean): Promise<MutationResult>
    setSuperuser(context: CommandContext, user: UserView, enabled: boolean): Promise<MutationResult>
    remove(context: CommandContext, user: UserView): Promise<MutationResult>
  }
  teams: {
    list(context: QueryContext): Promise<ListResult<TeamView>>
    memberPage?(context:QueryContext,team:TeamView,after:string):Promise<ListResult<TeamMemberView>>
    create(context: CommandContext, name: string): Promise<TeamView>
    addMember(context: CommandContext, team: TeamView, userId: UserId): Promise<MutationResult>
    removeMember(context: CommandContext, team: TeamView, userId: UserId): Promise<MutationResult>
    transferOwner(context: CommandContext, team: TeamView, newOwnerId: UserId): Promise<MutationResult>
  }
  projects: {
    list(context: QueryContext): Promise<ListResult<ProjectView>>
    create(context: CommandContext, input: { name: string; owner: ProjectView["owner"] }): Promise<ProjectView>
    transfer(context: CommandContext, project: ProjectView, newOwner: ProjectView["owner"]): Promise<MutationResult>
    /** Current A3 has a separate explicitly confirmed superuser-only route. */
    adminReassign(context: CommandContext, project: ProjectView, newOwner: ProjectView["owner"]): Promise<MutationResult>
  }
  agents: {
    list(context: QueryContext): Promise<ListResult<AgentView>>
    create(context: CommandContext, input: { label: string; parentAgentId: AgentIdentityId | null }): Promise<AgentView>
    rename(context: CommandContext, agent: AgentView, label: string): Promise<MutationResult>
    setEnabled(context: CommandContext, agent: AgentView, enabled: boolean): Promise<MutationResult>
  }
  sessions: {
    list(context: QueryContext): Promise<SessionSnapshot>
    pageSessions?(context:QueryContext,after:string):Promise<ListResult<AgentSessionView>>
    pageApprovals?(context:QueryContext,after:string):Promise<ListResult<AgentSessionRequestView>>
    open(context: CommandContext, input: { label: string; kind: "normal" | "elevated"; elevationPolicy: "fixed" | "requestable" }): Promise<AgentSessionView>
    request(context: CommandContext, input: { sessionUuid: AgentSessionUuid; grants: string[]; requestedUntil: string | null }): Promise<MutationResult>
    resolve(context: CommandContext, request: AgentSessionRequestView, approve: boolean, grants: string[], until: string | null, confirmation: { explicitExpansion: boolean }): Promise<MutationResult>
    revoke(context: CommandContext, session: AgentSessionView): Promise<MutationResult>
  }
  accounts: {
    list(context: QueryContext, selector: { scope: ResourceScope }): Promise<ListResult<ProjectAccountView>>
    save(context: CommandContext, input: ProjectAccountInput, accountId?: string): Promise<ProjectAccountView>
    verify(context: CommandContext, input: ProjectAccountInput): Promise<{ ok: boolean; detail?: string }>
    rotate(context: CommandContext, account: ProjectAccountView, credential: string): Promise<ProjectAccountView>
    remove(context: CommandContext, account: ProjectAccountView): Promise<MutationResult>
  }
  variables: {
    list(context: QueryContext, selector: { scope: ResourceScope }): Promise<ListResult<ProjectVariableView>>
    save(context: CommandContext, input: ProjectVariableInput, variableId?: string): Promise<ProjectVariableView>
    remove(context: CommandContext, variable: ProjectVariableView): Promise<MutationResult>
  }
  /** A5 source defines a separate superuser-only global summary, not Project operations. */
  operator?: {
    summary(context: QueryContext): Promise<{ users: number; teams: number; projects: number; agentSessions: number }>
  }
  providers?: {
    catalog(context:QueryContext):Promise<{providers:{provider:string;authTypes:string[];connectivityStatus:string}[];networkVerificationAvailable:boolean}>
  }
  /** Read-only operation summary adapter after accepted C1-B/C2; optional until then. */
  operations?: {
    list(context: QueryContext, area: OperationalArea): Promise<ListResult<OperationalItemView>>
  }
  realtime: ScopedRealtimePort
}

/** C1-A domain IDs are opaque canonical UUIDs; only AgentSession requires version 4. */
export const canonicalUuid = (value: string): boolean =>
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)

/** Server-confirmed identity is always necessary; client capabilities are presentation hints only. */
export const canonicalUuid4 = (value: string): boolean =>
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
