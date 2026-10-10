import { reactive } from "vue"
import { A11_TEAM_STATUS_OPERATIONS } from "@/features/platform/api/a11-owner-bff-source"
import { canonicalUuid4, type ScopeSelection, type UiCapability, type SourceCommandBinding, type SourceCommandTarget } from "@/features/platform/model/contracts"

/**
 * In-memory command outcome fence shared across Project pages in ONE tab.
 * An AbortSignal stops the frontend wait, NOT an already accepted server write.
 * These entries deliberately never reach localStorage, a URL, telemetry or logs.
 * A durable cross-reload proof requires a server idempotency/status endpoint.
 */
export type CommandResource = "profile" | "invitations" | "users" | "teams" | "projects" | "agents" | "sessions" | "accounts" | "variables"
/**
 * Authoritative reads are *typed by the original effect domain*. A successful
 * unrelated GET must never release an uncertain mutation (e.g., refreshing
 * Projects cannot reconcile credential rotation or a pending invitation).
 * A matching GET only provides current state, NOT a transaction-status proof.
 */
export function resourceForAction(action: UiCapability): CommandResource | null {
  if (action === "profile.password") return "profile"
  if (action === "invitations.issue" || action === "invitations.revoke") return "invitations"
  if (action.startsWith("users.")) return "users"
  if (action.startsWith("teams.")) return "teams"
  if (action.startsWith("projects.")) return "projects"
  if (action.startsWith("agents.")) return "agents"
  if (action.startsWith("sessions.")) return "sessions"
  if (action.startsWith("accounts.")) return "accounts"
  if (action.startsWith("variables.")) return "variables"
  return null
}

/** Narrow historical source-selector vocabulary, NOT proof that A11 accepts a
 * public mutation. Backend A12 must independently approve the actual wire. */
const PROJECT_COMMANDS=new Set(["agent.create","session.open","project.transfer_owner","project.admin_reassign"])
const RESOURCE_CREATES=new Set(["integration.create","variable.create"])
/** Accepted PRIVATE A11 Team vocabulary, never an owner grant on its own. */
const TEAM_MEMBER_ACTIONS=new Set<string>(A11_TEAM_STATUS_OPERATIONS)
const RESOURCE_EDITS=new Set(["integration.update","integration.rotate","integration.revoke",
 "variable.update","variable.rotate","variable.revoke"])
const scopedCommand=/^(?:agent\.(?:rename|state)|session\.(?:elevation|resolve|revoke)):(?:[0-9a-f]{8}-){1}[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
function acceptedProjectOperation(value:string):boolean {
  return PROJECT_COMMANDS.has(value)||scopedCommand.test(value)
}
function checkedSourceBinding(scope:ScopeSelection,requested:string|SourceCommandBinding|null):SourceCommandBinding|null|false {
  if(requested===null)return null
  const selected:SourceCommandBinding=typeof requested==="string"?
    scope.kind==="project"?{operation:requested,target:{kind:"project",id:scope.projectId}}:
    {operation:requested,target:{kind:"project",id:""}}:requested
  const {operation,target}=selected
  if(!canonicalUuid4(target.id))return false
  if(target.kind==="project")return (
    (scope.kind==="project"&&scope.projectId===target.id&&acceptedProjectOperation(operation))||
    (scope.kind==="operator"&&["project.admin_reassign","project.transfer_owner"].includes(operation))
  )?selected:false
  if(target.kind==="project_resource")return scope.kind==="project"&&scope.projectId===target.id&&RESOURCE_CREATES.has(operation)?selected:false
  if(target.kind==="team")return (
    (scope.kind==="team"?scope.teamId===target.id:
      ["project","account","operator"].includes(scope.kind))&&
    (RESOURCE_CREATES.has(operation)||TEAM_MEMBER_ACTIONS.has(operation))
  )?selected:false
  if(target.kind==="resource"){
    if(!RESOURCE_EDITS.has(operation)||!(scope.kind==="team"||scope.kind==="project"))return false
    const owner=target.owner
    if(owner.kind==="team")return canonicalUuid4(owner.teamId)&&
      (scope.kind!=="team"||scope.teamId===owner.teamId)?selected:false
    return scope.kind==="project"&&owner.projectId===scope.projectId?selected:false
  }
  return false
}
export type CommandState = "pending" | "unknown" | "reconciling"
export type PublicCommandPhase = "idle" | "pending" | "unknown" | "reconciling" | "confirmed" | "denied"
export interface PendingCommand {
  /** User-selected original scope, retained memory-only to allow an explicit
   * return to the correct effect-domain page after navigation. */
  readonly originalScope:ScopeSelection
  readonly scopeKey: string
  readonly action: UiCapability
  readonly commandId: string
  /** Source A11 Operation-UUID header and immutable owner-local command ID. */
  readonly operationUuid:string
  readonly decisionVersion: string | null
  /** Exact immutable A5 idempotency operation, never derived from UI label. */
  readonly sourceOperation: string | null
  readonly sourceTarget: SourceCommandTarget | null
  readonly state: CommandState
}
const pending = reactive(new Map<string, PendingCommand>())
/** Only a controlled action CATEGORY is exposed. Never the original
 * idempotency key, User/Team/Project ID, secret or raw backend response. */
const activity=reactive({phase:"idle" as PublicCommandPhase, action:null as UiCapability|null})
function recordPhase(phase:PublicCommandPhase,action:UiCapability):void {
  activity.phase=phase
  activity.action=action
}
function denied(action:UiCapability):void {
  if(!pending.size)recordPhase("denied",action)
}
function scopeKey(principal: string, scope: ScopeSelection): string {
  switch (scope.kind) {
    case "team": return `${principal}:team:${scope.teamId}`
    case "project": return `${principal}:project:${scope.projectId}`
    case "operator": return `${principal}:operator`
    case "account": return `${principal}:account`
  }
}
function lookup(principal: string, scope: ScopeSelection | null): PendingCommand | null {
  if (!principal || !scope) return null
  const own=pending.get(scopeKey(principal, scope))
  if(own)return own
  // A Team-owned connection can be accessed from multiple Projects in the
  // same Team. Until the server exposes command-result lookup, a mutation
  // whose outcome is UNKNOWN must fence every scope for that principal.
  for(const entry of pending.values()){
    if(entry.scopeKey.startsWith(`${principal}:`))return entry
  }
  return null
}
/** Pure original-command status identity check. Presence of a selector NEVER
 * creates an API or grants User privileges. No global unsupported status
 * operation is allowed to be optimistically written. */
function supportedSourceBinding(scope:ScopeSelection,selector:string|SourceCommandBinding|null):boolean {
  const binding=checkedSourceBinding(scope,selector)
  return binding!==null&&binding!==false
}
function begin(principal: string, scope: ScopeSelection, action: UiCapability, decisionVersion: string | null, selector: string | SourceCommandBinding | null = null): PendingCommand | null {
  if (!principal) return null
  const binding=checkedSourceBinding(scope,selector)
  if(binding===false)return null
  const key = scopeKey(principal, scope)
  // Only one unfinished mutation is permitted in a scope. A confirmation
  // dialog or route remount must never mint a fresh idempotency key for it.
  if (lookup(principal, scope)) return null
  const entry: PendingCommand = {
    scopeKey: key,originalScope:{...scope}, action, commandId: crypto.randomUUID(),
    operationUuid:crypto.randomUUID(),
    decisionVersion,sourceOperation:binding?.operation??null,
    sourceTarget:binding?.target??null,state: "pending",
  }
  pending.set(key, entry)
  recordPhase("pending",action)
  return entry
}
function confirm(entry: PendingCommand): void {
  if (pending.get(entry.scopeKey)?.commandId === entry.commandId){
    pending.delete(entry.scopeKey)
    recordPhase("confirmed",entry.action)
  }
}
function uncertain(entry: PendingCommand): void {
  if (pending.get(entry.scopeKey)?.commandId === entry.commandId) {
    pending.set(entry.scopeKey, { ...entry, state: "unknown" })
    recordPhase("unknown",entry.action)
  }
}
function reconciling(entry:PendingCommand):boolean {
  const current=pending.get(entry.scopeKey)
  if(!current||current.commandId!==entry.commandId||current.state!=="unknown")return false
  pending.set(entry.scopeKey,{...current,state:"reconciling"})
  recordPhase("reconciling",entry.action)
  return true
}
function unresolved(entry:PendingCommand):void {
  const current=pending.get(entry.scopeKey)
  if(current?.commandId===entry.commandId&&current.state==="reconciling"){
    pending.set(entry.scopeKey,{...current,state:"unknown"})
    recordPhase("unknown",entry.action)
  }
}
function reconcile(principal: string, scope: ScopeSelection, entry: PendingCommand, readResource: CommandResource): boolean {
  const key = scopeKey(principal, scope)
  if (key !== entry.scopeKey || pending.get(key)?.commandId !== entry.commandId ||
      resourceForAction(entry.action) !== readResource) return false
  if (!["unknown","reconciling"].includes(pending.get(key)?.state??"")) return false
  pending.delete(key)
  recordPhase("confirmed",entry.action)
  return true
}
/** Never inspect A5 command status using an entry from another actor/scope. */
/** Never disclose the key/UUID in the navigation UI; the original scope
 * is only read for the SAME authenticated actor and only for navigation.
 * This does NOT bypass Project/Team owner readiness or server grants. */
function originalScope(principal:string,selected:ScopeSelection|null):ScopeSelection|null {
  const entry=lookup(principal,selected)
  if(!entry||!entry.scopeKey.startsWith(`${principal}:`))return null
  return {...entry.originalScope}
}
function originalResource(principal:string,selected:ScopeSelection|null):CommandResource|null {
  const entry=lookup(principal,selected)
  return entry?resourceForAction(entry.action):null
}
function matches(entry:PendingCommand,principal:string,scope:ScopeSelection):boolean {
  return Boolean(principal&&entry.scopeKey===scopeKey(principal,scope))
}
/** Forget opaque identity references only when account authentication ends. */
function retainOnlyActor(actor:string):void {
  for(const [key] of pending){if(!actor||!key.startsWith(`${actor}:`))pending.delete(key)}
  const original=pending.values().next().value
  if(original){
    activity.phase=original.state
    activity.action=original.action
  }else{
    activity.phase="idle"
    activity.action=null
  }
}
/** Completed or pre-flight denied notice is locally dismissible, but an
 * unresolved original command is NEVER discarded by dismissing a banner. */
function dismissNotice():void {
  if(pending.size)return
  activity.phase="idle"
  activity.action=null
}
function clearAll(): void {
  pending.clear()
  activity.phase="idle"
  activity.action=null
}

export const commandCoordinator = { begin, lookup, confirm, uncertain, reconciling, unresolved,
  reconcile, matches, clearAll, retainOnlyActor, denied, activity, supportedSourceBinding,
  originalScope, originalResource, dismissNotice }
