import { reactive, readonly } from "vue"
import { commandCoordinator } from "@/features/platform/model/command-coordinator"
import type { AccessProjection, UiCapability, ScopeSelection } from "@/features/platform/model/contracts"
import { BFF_OWNERS, requiredOwners, verifiedBffEvidence, type BffOwnerEvidence } from "@/features/platform/api/bff-boundary"

/** These are UI projections, not wire DTOs or permission decisions. */
export interface AuthenticatedUserContext {
  key: string
  label: string
  active: boolean
  isSuperuser: boolean
}
export type ProjectOwnership = "personal" | "team"
export interface AvailableProjectContext {
  key: string
  lifecycleStatus?: "active"|"deleting"|"deleted"
  label: string
  ownership: ProjectOwnership
  ownerLabel?: string
  ownerTeamId?: string
}
export interface AvailableTeamContext { key: string; label: string }
export interface ResolvedUserProjects {
  user: AuthenticatedUserContext
  projects: AvailableProjectContext[]
  teams?: AvailableTeamContext[]
  permissions?: Partial<Record<UiCapability, boolean>>
  projectPermissions?: Record<string, Partial<Record<UiCapability, boolean>>>
  teamPermissions?: Record<string, Partial<Record<UiCapability, boolean>>>
  operatorPermissions?: Partial<Record<UiCapability, boolean>>
  projectDecisionVersions?: Record<string, string>
  teamDecisionVersions?: Record<string, string>
}
export type ShellScope = "signed-out" | "choose-project" | "project" | "team" | "operator" | "suspended" | "offline"

const state = reactive({
  scope: "signed-out" as ShellScope,
  user: null as AuthenticatedUserContext | null,
  projects: [] as AvailableProjectContext[],
  teams: [] as AvailableTeamContext[],
  permissions: {} as Partial<Record<UiCapability, boolean>>,
  projectPermissions: {} as Record<string, Partial<Record<UiCapability, boolean>>>,
  teamPermissions: {} as Record<string, Partial<Record<UiCapability, boolean>>>,
  operatorPermissions: {} as Partial<Record<UiCapability, boolean>>,
  projectDecisionVersions: {} as Record<string,string>,
  teamDecisionVersions: {} as Record<string,string>,
  activeProjectKey: null as string | null,
  activeTeamKey: null as string | null,
  revision: 0,
  ownerEvidence: null as BffOwnerEvidence | null,
  /** A BFF owner epoch change invalidates even a previously verified
   * permission projection until a NEW server-authenticated auth.refresh. */
  grantsFresh:false,
  ownerStatus: "unknown" as "unknown" | "loading" | "ready" | "upgrading" | "unavailable",
})
const transitionListeners = new Set<() => void>()
let lastVerifiedSnapshot: string | null = null
/** Source owner version memory survives transient offline and Team/Project
 * selection (not explicit logout or a change of signed-in User). */
let lastOwnerStamp:{actor:string;rows:readonly string[]}|null=null
let ownerExpiryTimer:ReturnType<typeof setTimeout>|null=null
function resetOwnerEvidence(status:typeof state.ownerStatus="unknown"):void {
  if(ownerExpiryTimer!==null){clearTimeout(ownerExpiryTimer);ownerExpiryTimer=null}
  state.ownerEvidence=null
  state.ownerStatus=status
}


/** Stable comparison without exposing credentials or interpreting unknown grants. */
function verifiedSnapshot(context: ResolvedUserProjects): string {
  const sortedMap = (input?: Record<string, unknown>) =>
    Object.entries(input ?? {}).sort(([a],[b])=>a.localeCompare(b)).map(([key,value])=>{
      if (value && typeof value==="object" && !Array.isArray(value)) {
        return [key, Object.entries(value).sort(([a],[b])=>a.localeCompare(b))]
      }
      return [key,value]
    })
  return JSON.stringify({
    user:context.user,
    teams:[...(context.teams??[])].sort((a,b)=>a.key.localeCompare(b.key)),
    projects:[...context.projects].sort((a,b)=>a.key.localeCompare(b.key)),
    permissions:sortedMap(context.permissions),
    projectPermissions:sortedMap(context.projectPermissions),
    teamPermissions:sortedMap(context.teamPermissions),
    operatorPermissions:sortedMap(context.operatorPermissions),
    projectDecisionVersions:sortedMap(context.projectDecisionVersions),
    teamDecisionVersions:sortedMap(context.teamDecisionVersions),
  })
}

function transition(scope: ShellScope, project: string | null = null, team: string | null = null): void {
  // A selected Project/Team cannot reuse a readiness receipt from a former
  // User, scope, revision or lifetime. A queued WS projection is NOT a grant.
  resetOwnerEvidence()
  state.scope = scope
  state.activeProjectKey = project
  state.activeTeamKey = team
  ++state.revision
  // All requests, caches, subscriptions and old views must be invalidated here.
  for (const listener of transitionListeners) listener()
}
function resetIdentity(forgetCommands=true): void {
  resetOwnerEvidence()
  lastVerifiedSnapshot = null
  state.grantsFresh=false
  if(forgetCommands)lastOwnerStamp=null
  // Transient owner outage must NOT discard a possibly committed command's
  // original Idempotency-Key, or the same actor could double-write on return.
  // Explicit logout/credential revocation still clears identity-bound memory.
  if(forgetCommands)commandCoordinator.clearAll()
  state.user = null
  state.projects = []
  state.teams = []
  state.permissions = {}
  state.projectPermissions = {}
  state.teamPermissions = {}
  state.operatorPermissions = {}
  state.projectDecisionVersions = {}
  state.teamDecisionVersions = {}
}
function clear(): void {
  resetIdentity()
  transition("signed-out")
}
function offline(): void {
  resetIdentity(false)
  transition("offline")
}
function suspend(): void {
  // Explicit Identity suspension is credential revocation, NOT the temporary
  // offline state: no old User's private outstanding IDs/owner revisions may
  // survive as if they belonged to a newly authenticated principal.
  commandCoordinator.clearAll()
  lastOwnerStamp=null
  lastVerifiedSnapshot = null
  state.grantsFresh=false
  state.projects = []
  state.teams = []
  state.permissions = {}
  state.projectPermissions = {}
  state.teamPermissions = {}
  state.operatorPermissions = {}
  state.projectDecisionVersions = {}
  state.teamDecisionVersions = {}
  transition("suspended")
}

function installResolvedContext(context: ResolvedUserProjects): void {
  if (!context.user.active) {
    state.user = { ...context.user }
    suspend()
    return
  }
  const signature = verifiedSnapshot(context)
  if (lastVerifiedSnapshot === signature && state.user?.key === context.user.key &&
      ["choose-project","project","team","operator"].includes(state.scope)){
    // This call is made only with a FRESH verified auth.refresh, so the
    // identical effective grants may be rebound to the new owner evidence.
    state.grantsFresh=true
    return
  }
  const previousUser=state.user?.key
  if(previousUser&&previousUser!==context.user.key)lastOwnerStamp=null
  state.grantsFresh=true
  const previousScope=state.scope
  const previousProject=state.activeProjectKey
  const previousTeam=state.activeTeamKey
  state.user = { ...context.user }
  state.projects = context.projects.map(project => ({ ...project }))
  state.teams = (context.teams ?? []).map(team => ({ ...team }))
  state.permissions = { ...context.permissions }
  state.projectPermissions = Object.fromEntries(
    context.projects.map(project => [project.key, { ...context.projectPermissions?.[project.key] }]),
  )
  state.teamPermissions = Object.fromEntries(
    state.teams.map(team => [team.key, { ...context.teamPermissions?.[team.key] }]),
  )
  state.operatorPermissions = context.user.isSuperuser ? { ...context.operatorPermissions } : {}
  state.projectDecisionVersions = {...context.projectDecisionVersions}
  state.teamDecisionVersions = {...context.teamDecisionVersions}
  lastVerifiedSnapshot=signature

  // Exactly ONE invalidation for a changed server grant/owner/principal.
  // Keep the explicit selection if the SAME authenticated User still sees
  // that entity; a Team-owner transfer changes scope rights, not its ID.
  if (previousUser === context.user.key) {
    if (previousScope === "project" && previousProject && context.projects.some(project => project.key === previousProject)) {
      transition("project", previousProject)
      return
    }
    if (previousScope === "team" && previousTeam && context.teams?.some(team => team.key === previousTeam)) {
      transition("team", null, previousTeam)
      return
    }
    if (previousScope === "operator" && context.user.isSuperuser) {
      transition("operator")
      return
    }
  }
  transition("choose-project")
}

/** Adapter may only call this with a server-authenticated projection (no fake fallback). */
function installServerProjection(projection: AccessProjection): void {
  // The previous User may be null after an offline/reconnect fence. Drop
  // other principals' opaque pending command keys before installing the new
  // verified actor; retain only this actor's unknown original operations.
  commandCoordinator.retainOnlyActor(projection.user.userId)
  const next: ResolvedUserProjects = {
    user: {
      key: projection.user.userId,
      label: projection.user.displayName || projection.user.username,
      active: projection.user.active,
      isSuperuser: projection.user.isSuperuser,
    },
    teams: projection.teams?.map(team => ({key:team.teamId,label:team.name})),
    projects: projection.projects.map(project => ({
      key: project.projectId,
      lifecycleStatus:project.lifecycleStatus,
      label: project.name,
      ownership: project.owner.kind === "user" ? "personal" : "team",
      ownerLabel: project.owner.kind === "team" ? project.owner.teamName : undefined,
      ownerTeamId: project.owner.kind === "team" ? project.owner.teamId : undefined,
    })),
    permissions: projection.permissions,
    projectPermissions: projection.projectPermissions,
    teamPermissions: projection.teamPermissions,
    operatorPermissions: projection.operatorPermissions,
    projectDecisionVersions: projection.projectDecisionVersions,
    teamDecisionVersions: projection.teamDecisionVersions,
  }
  installResolvedContext(next)
}

function selectProject(key: string): boolean {
  if (!state.user?.active||!coreOwnerReady()||!state.projects.some(project =>
    project.key===key&&project.lifecycleStatus==="active")) return false
  if (state.scope !== "project" || state.activeProjectKey !== key) transition("project", key)
  return true
}
function selectTeam(key: string): boolean {
  if (!state.user?.active||!coreOwnerReady()||!state.teams.some(team => team.key === key)) return false
  if (state.scope !== "team" || state.activeTeamKey !== key) transition("team", null, key)
  return true
}
function selectOperator(): boolean {
  if (!state.user?.active||!coreOwnerReady()||!state.user.isSuperuser) return false
  if (state.scope !== "operator") transition("operator")
  return true
}
function selectNone(): void {
  if (state.user?.active) transition("choose-project")
}
function selection(): ScopeSelection | null {
  if (state.scope === "choose-project" && state.user?.active) return { kind: "account" }
  if (state.scope === "project" && state.activeProjectKey) return { kind: "project", projectId: state.activeProjectKey }
  if (state.scope === "team" && state.activeTeamKey) return { kind: "team", teamId: state.activeTeamKey }
  if (state.scope === "operator" && state.user?.isSuperuser) return { kind: "operator" }
  return null
}
function coreOwnerReady():boolean {
  const actor=state.user?.key
  const scope=selection()
  const proof=state.ownerEvidence
  if(!actor||!scope||!proof||!state.grantsFresh||!verifiedBffEvidence(proof,actor,scope))return false
  return (["identity","access","control"] as const).every(owner=>proof.owners[owner].availability==="ready")
}
function can(action: UiCapability): boolean {
  if (!state.user?.active || !coreOwnerReady()) return false
  // Catalog-dependent reads and writes additionally require its own current
  // server revision; even a scope-filtered list must not leak stale secrets.
  const proof=state.ownerEvidence
  if(!proof||!requiredOwners(action).every(owner=>proof.owners[owner].availability==="ready"))return false
  // A selected deleting/deleted/unknown Project may remain visible so the
  // User can explicitly switch away, but it MUST NOT carry Project-local
  // read/write/Session/Catalog privileges from a previous active epoch.
  if(state.scope==="project"&&state.activeProjectKey){
    const project=state.projects.find(item=>item.key===state.activeProjectKey)
    if(project?.lifecycleStatus!=="active"&&
       !["profile.read","teams.read","projects.read","settings.read"].includes(action))return false
  }
  // These are PERSON-scoped actions, not Project/Team grants. They remain
  // accessible while a verified User has selected a Team or Project.
  if (["profile.read", "profile.password", "invitations.issue", "invitations.revoke",
       "teams.read", "teams.create", "projects.read", "projects.create"].includes(action)) {
    return state.permissions[action] === true
  }
  if (state.scope === "choose-project") return state.permissions[action] === true
  if (state.scope === "project" && state.activeProjectKey) return state.projectPermissions[state.activeProjectKey]?.[action] === true
  if (state.scope === "team" && state.activeTeamKey) return state.teamPermissions[state.activeTeamKey]?.[action] === true
  if (state.scope === "operator" && state.user.isSuperuser) return state.operatorPermissions[action] === true
  return false
}
/** A BFF-only owner readiness is a second authority boundary. No source
 * DTO, page settings, Team TZ, local proof or database health can mint it. */
function installOwnerEvidence(evidence:BffOwnerEvidence):boolean {
  const scope=selection()
  const actor=state.user?.key
  if(!scope||!actor||!verifiedBffEvidence(evidence,actor,scope)){
    ownerUnavailable()
    return false
  }
  const stamp={actor,rows:BFF_OWNERS.map(owner=>
    `${owner}:${evidence.owners[owner].availability}:${evidence.owners[owner].revision??"unknown"}`)}
  const changed=lastOwnerStamp?.actor===actor&&
    stamp.rows.some((row,index)=>row!==lastOwnerStamp?.rows[index])
  if(changed){
    // An old permission map can no longer be bound to a new owner epoch.
    // Explicitly require another independently authenticated projection.
    state.grantsFresh=false
    // An owner's epoch changed under the SAME selected Project. Abort
    // in-flight reads/writes and discard old decision versions before its
    // new attestation can authorize any later operation.
    transition(state.scope,state.activeProjectKey,state.activeTeamKey)
  }
  resetOwnerEvidence()
  lastOwnerStamp=stamp
  state.ownerEvidence={
    actorUserId:evidence.actorUserId,
    scope:evidence.scope,
    observedAtUtc:evidence.observedAtUtc,
    expiresAtUtc:evidence.expiresAtUtc,
    owners:Object.fromEntries(Object.entries(evidence.owners).map(([key,item])=>
      [key,{availability:item.availability,revision:item.revision}])) as BffOwnerEvidence["owners"],
  }
  const rows=Object.values(state.ownerEvidence.owners)
  state.ownerStatus=rows.every(item=>item.availability==="ready")?"ready":
    rows.some(item=>item.availability==="upgrading")?"upgrading":"unavailable"
  const expiry=Date.parse(evidence.expiresAtUtc)-Date.now()
  ownerExpiryTimer=setTimeout(()=>{
    ownerExpiryTimer=null
    // Preserve the explicit selection, but cancel pending work before a
    // stale owner attestation could authorize the next write.
    transition(state.scope,state.activeProjectKey,state.activeTeamKey)
  },Math.max(1,expiry))
  return true
}
function ownerLoading():void {
  if(state.user?.active&&state.ownerEvidence===null)state.ownerStatus="loading"
}
function ownerUnavailable():void {
  if(state.ownerEvidence){
    // Owner loss is a security epoch boundary, not a cosmetic badge change.
    transition(state.scope,state.activeProjectKey,state.activeTeamKey)
  }
  resetOwnerEvidence("unavailable")
}
/** Consent, authentication and owner DB readiness have independent proofs. */
function ownerAvailability():typeof state.ownerStatus {
  const proof=state.ownerEvidence
  const scope=selection()
  if(proof&&(!scope||!state.user||!verifiedBffEvidence(proof,state.user.key,scope)))return "unavailable"
  return state.ownerStatus
}
function onTransition(listener: () => void): () => void {
  transitionListeners.add(listener)
  return () => { transitionListeners.delete(listener) }
}

/** The server must independently authorize EVERY protected call and event. */
export const projectContext = {
  state: readonly(state),
  clear, offline, suspend,
  installServerProjection,
  selectProject, selectTeam, selectOperator, selectNone,
  selection, can, onTransition,
  installOwnerEvidence,ownerLoading,ownerUnavailable,ownerAvailability,coreOwnerReady,
}
