import { computed, onBeforeUnmount, reactive, shallowReactive, watch, watchEffect } from "vue"
import { projectContext } from "@/features/platform/model/project-context"
import { browserTelemetry, type DiagnosticOutcome } from "@/features/platform/model/browser-telemetry"
import { platformPort } from "@/features/platform/api/port"
import { normalizeUiError, type UiError } from "@/features/platform/model/errors"
import { scopedEvents } from "@/features/platform/model/project-events"
import { refreshAuthenticatedProjection } from "@/features/platform/model/refresh-identity"
import { refreshBffOwnerBoundary } from "@/features/platform/model/refresh-owner-boundary"
import { appendVerifiedKeyset } from "@/features/platform/model/scoped-keyset"
import { commandCoordinator, resourceForAction, type CommandResource, type PendingCommand } from "@/features/platform/model/command-coordinator"
import { confirmedBffEffect, crossOwnerMutation, groupVerifiedBffCapabilities,
  verifiedBffEvidence } from "@/features/platform/api/bff-boundary"
import type { CommandContext, PlatformPort, QueryContext, ScopeSelection, UiCapability, SourceCommandBinding } from "@/features/platform/model/contracts"

function verifiedDecisionVersion(scope: ScopeSelection): string | null {
  if(scope.kind==="project")return projectContext.state.projectDecisionVersions[scope.projectId]??null
  if(scope.kind==="team")return projectContext.state.teamDecisionVersions[scope.teamId]??null
  return null
}

/** Only an accepted typed backend read of the mutated resource counts as reconciliation. */
async function readActionDomain(port:PlatformPort, context:QueryContext, resource:CommandResource, principal:string):Promise<void>{
  switch(resource){
    case "profile": {
      const projection=await port.auth.refresh(context.signal)
      if(!projection || !projection.user.active || projection.user.userId!==principal)throw new Error("Authoritative principal read unavailable")
      return
    }
    case "invitations": {
      const snapshot=await port.users.invitations(context)
      if(!Array.isArray(snapshot.items))throw new Error("Authoritative invitations snapshot unavailable")
      return
    }
    case "users": {
      if(context.scope.kind!=="operator")throw new Error("Operator scope required for User reconciliation")
      const snapshot=await port.users.list(context)
      if(!Array.isArray(snapshot.items))throw new Error("Authoritative Users snapshot unavailable")
      return
    }
    case "teams": {
      const snapshot=await port.teams.list(context)
      if(!Array.isArray(snapshot.items))throw new Error("Authoritative Teams snapshot unavailable")
      return
    }
    case "projects": {
      const snapshot=await port.projects.list(context)
      if(!Array.isArray(snapshot.items))throw new Error("Authoritative Projects snapshot unavailable")
      return
    }
    case "agents": {
      if(context.scope.kind!=="project")throw new Error("Project required for Agent reconciliation")
      const snapshot=await port.agents.list(context)
      if(!Array.isArray(snapshot.items))throw new Error("Authoritative Agents snapshot unavailable")
      return
    }
    case "sessions": {
      if(context.scope.kind!=="project")throw new Error("Project required for Session reconciliation")
      const snapshot=await port.sessions.list(context)
      if(!Array.isArray(snapshot.sessions)||!Array.isArray(snapshot.requests))throw new Error("Authoritative Session snapshot unavailable")
      return
    }
    case "accounts": {
      if(context.scope.kind!=="project"&&context.scope.kind!=="team")throw new Error("Resource owner scope required")
      const snapshot=await port.accounts.list(context,{scope:"all"})
      if(!Array.isArray(snapshot.items))throw new Error("Authoritative connection snapshot unavailable")
      return
    }
    case "variables": {
      if(context.scope.kind!=="project"&&context.scope.kind!=="team")throw new Error("Resource owner scope required")
      const snapshot=await port.variables.list(context,{scope:"all"})
      if(!Array.isArray(snapshot.items))throw new Error("Authoritative Variable snapshot unavailable")
      return
    }
  }
}

/** Cross-owner completion requires original effect + every owner's acknowledged
 * status. An A10 Project/Team HTTP 2xx alone is not a distributed commit. */
async function completeCrossOwnerEffect(port:PlatformPort,context:QueryContext,entry:PendingCommand):Promise<boolean>{
  if(!crossOwnerMutation(entry.action))return true
  if(!port.bff?.inspectOriginalCommand||!entry.sourceOperation||!entry.sourceTarget)return false
  const binding={operation:entry.sourceOperation,target:entry.sourceTarget}
  // A write may advance owner revision. Recheck the current actor/scope/owner
  // heads AFTER the write, then compare the effect receipts with those heads.
  // This is an authenticated source GET, NOT a fresh mutation request.
  if(!await refreshBffOwnerBoundary()||context.signal.aborted||
     !sameScope(context.scope,context.revision))return false
  const evidence=projectContext.state.ownerEvidence
  if(!evidence)return false
  // Only one bounded status inspection, never a poll loop or POST retry.
  const timeout=AbortSignal.timeout(5_000)
  const signal=AbortSignal.any([context.signal,timeout])
  const result=await port.bff.inspectOriginalCommand({...context,signal},{binding,idempotencyKey:entry.commandId,operationUuid:entry.operationUuid})
  if(signal.aborted)return false
  return confirmedBffEffect(result,{
    actor:projectContext.state.user?.key??"",scope:context.scope,binding,
    idempotencyKey:entry.commandId,operationUuid:entry.operationUuid,
    action:entry.action,ownerEvidence:evidence,
  })
}

export interface DomainLoad<T> {
  items:T[]; revision?:string|null; serverLimit?:number; possiblyTruncated?:boolean; observedAt?:string
  nextAfterId?:string|null; hasMore?:boolean; pageSize?:number
}
export type ReadDomain<T> = (port: PlatformPort, context: QueryContext, after?:string|null) => Promise<DomainLoad<T>>
export type WriteDomain = (port: PlatformPort, context: CommandContext) => Promise<unknown>
/** One central source-only UI availability predicate for every button/form.
 * It checks an inspectable original operation, current ACL/owner attestation,
 * no unresolved in-memory command, and a *present* reviewed BFF inspector.
 * This cannot install or authorize a REST endpoint by itself. */
export function sourceMutationReady(ability:UiCapability,selector:string|SourceCommandBinding|null):boolean {
  const port=platformPort.value
  const scope=projectContext.selection()
  const principal=projectContext.state.user?.key??""
  if(!port?.bff?.inspectOriginalCommand||!scope||!principal||!selector||
     !projectContext.can(ability)||!commandCoordinator.supportedSourceBinding(scope,selector)||
     commandCoordinator.lookup(principal,scope))return false
  // Explicit owner-bound source fence. An adapter's projected allowedAction
  // is not permission to choose an unrelated Team-owned resource or run a
  // Team command against another Team while inside a Project.
  if(typeof selector!=="string"){
    const owner=selector.target.kind==="resource"?selector.target.owner:
      selector.target.kind==="team"?{kind:"team" as const,teamId:selector.target.id}:null
    if(owner?.kind==="team"){
      if(scope.kind==="team"&&owner.teamId!==scope.teamId)return false
      if(scope.kind==="project"){
        const project=projectContext.state.projects.find(item=>item.key===scope.projectId)
        if(project?.ownership!=="team"||project.ownerTeamId!==owner.teamId||
           project.lifecycleStatus!=="active")return false
      }
      if(scope.kind==="account"&&!projectContext.state.teams.some(item=>item.key===owner.teamId))return false
    }
  }
  return true
}
export type LoadStatus = "blocked" | "idle" | "loading" | "ready" | "empty" | "error"

function sameScope(expected: ScopeSelection, revision: number): boolean {
  const selected = projectContext.selection()
  if (revision !== projectContext.state.revision || !selected || selected.kind !== expected.kind) return false
  if (selected.kind === "project") return expected.kind === "project" && selected.projectId === expected.projectId
  if (selected.kind === "team") return expected.kind === "team" && selected.teamId === expected.teamId
  return true
}
/** Only trusted fixed error KIND enters telemetry. Never raw server code/URL. */
function diagnosticOutcome(error:UiError):DiagnosticOutcome {
  if(error.kind==="uncertain"||error.kind==="unknown"||error.kind==="conflict")return "uncertain"
  if(error.kind==="forbidden"||error.kind==="unauthorized")return "blocked"
  if(error.kind==="invalid")return "rejected"
  return "unavailable"
}
function handlePermissionError(error: UiError, scope: ScopeSelection): boolean {
  if (error.kind === "unauthorized") { projectContext.clear(); return true }
  if (error.kind === "forbidden") {
    // Never retain stale Team/Project/operator actions after 403 or a
    // decision-version drift. A fresh AUTHENTICATED projection is necessary.
    projectContext.selectNone()
    void refreshAuthenticatedProjection()
    return true
  }
  return false
}

/** Reads and mutations have INDEPENDENT generations: a WS read must not erase an acknowledged write. */
export function useDomain<T>(
  resource: string,
  ability: UiCapability,
  read: ReadDomain<T>,
  scopes: ScopeSelection["kind"][] = ["account", "team", "project", "operator"],
  available: (port: PlatformPort) => boolean = () => true,
  keyOf?: (item:T)=>string,
) {
  const state = shallowReactive({
    items: [] as T[],
    status: "blocked" as LoadStatus,
    revision: null as string | null,
    serverLimit: null as number | null,
    possiblyTruncated: false,
    observedAt: null as string | null,
    nextAfterId: null as string | null,
    hasMore: false,
    pageSize: null as number | null,
    loadingMore: false,
    loadMoreError: null as UiError | null,
    error: null as UiError | null,
    busy: false,
    actionError: null as UiError | null,
    reconciliationRequired: false,
    reconciliationNotice: false,
  })
  let readRun = 0
  let writeRun = 0
  let controller: AbortController | null = null
  let pagination: AbortController | null = null
  let mutation: AbortController | null = null
  let activeWrite: PendingCommand | null = null
  let disposed = false

  function usable(): boolean {
    const scope = projectContext.selection()
    const port = platformPort.value
    // Every protected UI read is served only by a real same-origin BFF
    // composition. The retired global A10 source port is not eligible even
    // if its opaque User/project read projection happens to parse.
    const domains=port?groupVerifiedBffCapabilities(port):null
    const ownerProof=projectContext.state.ownerEvidence
    return Boolean(port&&domains&&available(port)&&scope&&scopes.includes(scope.kind)&&
      projectContext.state.user?.active&&ownerProof&&
      verifiedBffEvidence(ownerProof,projectContext.state.user.key,scope)&&
      projectContext.can(ability))
  }
  function invalidate(): void {
    ++readRun
    ++writeRun
    controller?.abort()
    pagination?.abort()
    pagination=null
    // A discarded in-flight response is an UNKNOWN server write outcome.
    if (activeWrite) commandCoordinator.uncertain(activeWrite)
    activeWrite = null
    mutation?.abort()
    controller = null
    mutation = null
    state.items = []
    state.revision = null
    state.serverLimit = null
    state.possiblyTruncated = false
    state.observedAt = null
    state.nextAfterId=null
    state.hasMore=false
    state.pageSize=null
    state.loadingMore=false
    state.loadMoreError=null
    state.error = null
    state.actionError = null
    state.reconciliationRequired = false
    state.reconciliationNotice = false
    state.busy = false
    state.status = "blocked"
  }
  function snapshot(signal: AbortSignal): QueryContext | null {
    const scope = projectContext.selection()
    return scope ? {
      scope,signal,revision:projectContext.state.revision,
      decisionVersion:verifiedDecisionVersion(scope),
    } : null
  }
  async function reload(): Promise<boolean> {
    ++readRun
    controller?.abort()
    pagination?.abort()
    pagination=null
    state.loadingMore=false
    state.loadMoreError=null
    state.nextAfterId=null
    state.hasMore=false
    state.pageSize=null
    controller = null
    state.error = null
    state.items = []
    state.revision = null
    state.serverLimit = null
    state.possiblyTruncated = false
    state.observedAt = null
    if (!usable() || disposed) { state.status = "blocked"; return false }
    const port = platformPort.value
    if (!port) { state.status = "blocked"; return false }
    const generation = readRun
    const telemetryStart=performance.now()
    const abort = new AbortController()
    controller = abort
    const context = snapshot(abort.signal)
    if (!context) { state.status = "blocked"; return false }
    state.status = "loading"
    try {
      const result = await read(port, context)
      if (disposed || generation !== readRun || abort.signal.aborted || !sameScope(context.scope, context.revision) || port !== platformPort.value) return false
      // A previously authorized GET can return AFTER the 60-second owner
      // evidence TTL or a same-revision Identity/Access revoke. Do not paint
      // stale protected rows while the expiry/epoch invalidation is pending.
      if(!usable()){invalidate();return false}
      state.items = result.items
      state.revision = result.revision ?? null
      state.serverLimit = result.serverLimit ?? null
      state.possiblyTruncated = result.possiblyTruncated === true
      state.observedAt = result.observedAt ?? null
      state.nextAfterId=result.nextAfterId??null
      state.hasMore=result.hasMore===true
      state.pageSize=result.pageSize??null
      state.status = result.items.length ? "ready" : "empty"
      browserTelemetry.read(resource,"ok",performance.now()-telemetryStart)
      return true
    } catch (cause) {
      if (disposed || generation !== readRun || abort.signal.aborted || !sameScope(context.scope, context.revision)) return false
      const normalized = normalizeUiError(cause)
      if (handlePermissionError(normalized, context.scope)) return false
      state.error = normalized
      state.status = "error"
      browserTelemetry.read(resource,diagnosticOutcome(normalized),performance.now()-telemetryStart)
      return false
    } finally {
      if (controller === abort) controller = null
    }
  }
  /** One bounded A6 keyset GET, never a background auto-fetch or fake snapshot. */
  async function loadMore():Promise<boolean> {
    if(disposed||!usable()||!state.hasMore||!state.nextAfterId||state.loadingMore||
       state.status==="loading"||state.busy)return false
    const port=platformPort.value
    if(!port)return false
    const cursor=state.nextAfterId
    const version=readRun
    const telemetryStart=performance.now()
    const abort=new AbortController()
    pagination=abort
    const context=snapshot(abort.signal)
    if(!context)return false
    state.loadingMore=true
    state.loadMoreError=null
    try {
      const result=await read(port,context,cursor)
      if(disposed||abort.signal.aborted||version!==readRun||
         !sameScope(context.scope,context.revision)||port!==platformPort.value)return false
      if(!usable()){invalidate();return false}
      // A keyset continuation must have an explicit stable UUIDv4 row key.
      // Never append arbitrary generic objects, duplicate/foreign rows or an
      // out-of-order page merely because its HTTP call returned successfully.
      if(!keyOf)throw new Error("Missing server row identity for keyset paging")
      if(state.revision&&result.revision&&state.revision!==result.revision)
        throw new Error("Source page revision changed")
      const verified=appendVerifiedKeyset(state.items,result,cursor,keyOf)
      // Page N is authenticated independently and may have changed since N-1.
      // Retain partial-read warnings; do not infer deletion or entitlement.
      state.items=verified.rows
      state.nextAfterId=verified.next
      state.hasMore=verified.hasMore
      state.possiblyTruncated=state.possiblyTruncated||result.possiblyTruncated===true
      state.pageSize=result.pageSize??state.pageSize
      state.status=state.items.length?"ready":"empty"
      browserTelemetry.read(resource,"ok",performance.now()-telemetryStart)
      return true
    }catch(error){
      if(!disposed&&!abort.signal.aborted&&version===readRun&&sameScope(context.scope,context.revision)){
        const issue=normalizeUiError(error)
        if(!handlePermissionError(issue,context.scope)){
          state.loadMoreError=issue
          browserTelemetry.read(resource,diagnosticOutcome(issue),performance.now()-telemetryStart)
        }
      }
      return false
    }finally{
      if(pagination===abort){pagination=null;state.loadingMore=false}
    }
  }
  async function execute(action: UiCapability, write: WriteDomain, sourceOperation: string | SourceCommandBinding | null = null): Promise<boolean> {
    const port = platformPort.value
    if(!sourceMutationReady(action,sourceOperation)){
      const pending=commandCoordinator.lookup(projectContext.state.user?.key??"",projectContext.selection())
      state.actionError=pending?
        {kind:"uncertain",code:"original_command_still_pending",message:"outcomeUncertain"}:
        !sourceOperation||!port?.bff?.inspectOriginalCommand?
        {kind:"unavailable",code:"original_command_status_missing",message:"serverCommandStatusRequired"}:
        {kind:"forbidden",code:"owner_or_scope_authority_missing",message:"ownerAuthorityRequired"}
      return false
    }
    if(!projectContext.can(action)&&!commandCoordinator.lookup(projectContext.state.user?.key??"",projectContext.selection())){
      commandCoordinator.denied(action)
      state.actionError={kind:"forbidden",code:"bff_owner_authority_required",message:"ownerAuthorityRequired"}
      return false
    }
    if (!usable() || !projectContext.can(action) || state.busy || state.reconciliationRequired || !port || disposed ||
        commandCoordinator.lookup(projectContext.state.user?.key ?? "", projectContext.selection())) return false
    const generation = ++writeRun
    const telemetryStart=performance.now()
    const abort = new AbortController()
    mutation = abort
    const base = snapshot(abort.signal)
    if (!base) return false
    const principal = projectContext.state.user?.key ?? ""
    const pending = commandCoordinator.begin(principal, base.scope, action, base.decisionVersion ?? null, sourceOperation)
    if (!pending) return false
    activeWrite = pending
    const context: CommandContext = { ...base, idempotencyKey: pending.commandId,operationUuid:pending.operationUuid }
    state.busy = true
    state.actionError = null
    state.reconciliationNotice = false
    try {
      await write(port, context)
      if (disposed || generation !== writeRun || abort.signal.aborted || !sameScope(base.scope, base.revision) || port !== platformPort.value) {
        commandCoordinator.uncertain(pending)
        if(activeWrite===pending)activeWrite=null
        return false
      }
      const bffConfirmed=await completeCrossOwnerEffect(port,context,pending)
      if(!bffConfirmed){
        commandCoordinator.uncertain(pending)
        if(activeWrite===pending)activeWrite=null
        state.actionError={kind:"uncertain",code:"bff_distributed_effect_unconfirmed",message:"crossOwnerOutcomeUnknown"}
        state.reconciliationRequired=true
        browserTelemetry.write(resource,"uncertain",performance.now()-telemetryStart)
        return false
      }
      if(disposed||abort.signal.aborted||generation!==writeRun||!sameScope(base.scope,base.revision)||port!==platformPort.value){
        commandCoordinator.uncertain(pending)
        if(activeWrite===pending)activeWrite=null
        return false
      }
      // The exact owner command receipt is not sufficient for UI success:
      // the original affected domain must still be currently authorized.
      const affected=resourceForAction(action)
      if(!affected)throw new Error("Missing original effect domain")
      await readActionDomain(port,context,affected,principal)
      if(disposed||abort.signal.aborted||generation!==writeRun||!sameScope(base.scope,base.revision)||port!==platformPort.value){
        commandCoordinator.uncertain(pending)
        if(activeWrite===pending)activeWrite=null
        return false
      }
      const fresh=await reload()
      if(!fresh||disposed||abort.signal.aborted||generation!==writeRun||!sameScope(base.scope,base.revision)||port!==platformPort.value){
        commandCoordinator.uncertain(pending)
        if(activeWrite===pending)activeWrite=null
        return false
      }
      commandCoordinator.confirm(pending)
      if(activeWrite===pending)activeWrite=null
      browserTelemetry.write(resource,"ok",performance.now()-telemetryStart)
      return true
    } catch (cause) {
      // The request may have reached the server even when its component was
      // unmounted, aborted or its response failed validation.
      // A response/permission error AFTER invocation may follow an actual
      // owner-local commit. Unknown remains locked with the ORIGINAL key.
      commandCoordinator.uncertain(pending)
      if (activeWrite === pending) activeWrite = null
      if (!disposed && !abort.signal.aborted && generation === writeRun && sameScope(base.scope, base.revision)) {
        const normalized = normalizeUiError(cause, "mutation")
        if (!handlePermissionError(normalized, base.scope)) {
          browserTelemetry.write(resource,diagnosticOutcome(normalized),performance.now()-telemetryStart)
          state.actionError = normalized
          state.reconciliationRequired = true
        }
      }
      return false
    } finally {
      if (mutation === abort) { state.busy = false; mutation = null }
    }
  }
  /** Verify A5 outcome (when Project-owned), THEN read authoritative effect domain. */
  async function reconcile():Promise<boolean> {
    if(state.busy||disposed)return false
    const scope=projectContext.selection()
    const principal=projectContext.state.user?.key??""
    const port=platformPort.value
    const entry=commandCoordinator.lookup(principal,scope)
    if(entry&&!scope)return false
    if(entry&&scope&&!commandCoordinator.matches(entry,principal,scope)){
      state.actionError={kind:"uncertain",code:"reconcile_scope_mismatch",message:"reconcileOriginalScope"}
      return false
    }
    if(entry&&resourceForAction(entry.action)!==resource){
      state.actionError={kind:"uncertain",code:"reconcile_domain_mismatch",message:"reconcileOriginalDomain"}
      return false
    }
    if(!scope||!port)return false
    const revision=projectContext.state.revision
    const abort=new AbortController()
    const stop=projectContext.onTransition(()=>abort.abort())
    const off=watch(platformPort,()=>abort.abort())
    if(entry)commandCoordinator.reconciling(entry)
    try {
      const context:QueryContext={scope,signal:abort.signal,revision,decisionVersion:verifiedDecisionVersion(scope)}
      if(entry){
        if(!await completeCrossOwnerEffect(port,context,entry)){
          state.actionError={kind:"uncertain",code:"bff_distributed_effect_unconfirmed",message:"crossOwnerOutcomeUnknown"}
          return false
        }
        await readActionDomain(port,context,resource as CommandResource,principal)
      }
      if(abort.signal.aborted||!sameScope(scope,revision)||port!==platformPort.value||principal!==projectContext.state.user?.key)return false
      const fresh=await reload()
      if(!fresh||disposed||abort.signal.aborted||!sameScope(scope,revision)||port!==platformPort.value)return false
      if(entry&&!commandCoordinator.reconcile(principal,scope,entry,resource as CommandResource)){
        state.actionError={kind:"uncertain",code:"reconcile_scope_mismatch",message:"reconcileOriginalScope"}
        return false
      }
      state.reconciliationRequired=false
      state.actionError=null
      state.reconciliationNotice=Boolean(entry)
      return true
    }catch(cause){
      if(!disposed&&!abort.signal.aborted&&sameScope(scope,revision)){
        const issue=normalizeUiError(cause)
        if(!handlePermissionError(issue,scope)){
          state.actionError=issue.kind==="unknown"?{kind:"unavailable",code:"source_reconciliation_failed",message:"reconcileReadFailed"}:issue
        }
      }
      return false
    }finally{
      if(entry)commandCoordinator.unresolved(entry)
      stop();off();abort.abort()
    }
  }

  const stop = watch(() => [projectContext.state.revision, platformPort.value] as const, () => {
    invalidate()
    if (usable()) void reload()
  }, { immediate: true })
  const unsubscribe = scopedEvents.subscribe(event => {
    if (event.resource === resource || event.resource === "all") void reload()
  })
  onBeforeUnmount(() => { disposed = true; stop(); unsubscribe(); invalidate() })
  return { state, reload, loadMore, execute, reconcile, usable }
}

/** Standalone mutation needs a verified list-read to unlock uncertain results. */
export function useCommand(scopes: ScopeSelection["kind"][] = ["account", "team", "project", "operator"]) {
  const state = reactive({ busy: false, error: null as UiError | null, reconciliationRequired: false, reconciliationNotice: false })
  let active: AbortController | null = null
  let nonce = 0
  let disposed = false
  const currentEntry = computed(() => commandCoordinator.lookup(
    projectContext.state.user?.key ?? "", projectContext.selection(),
  ))
  const stopBarrier = watchEffect(() => {
    const blocked = currentEntry.value !== null
    const unconfirmed = ["unknown","reconciling"].includes(currentEntry.value?.state??"")
    state.reconciliationRequired = blocked
    if (unconfirmed && !state.error) {
      state.error = { kind: "uncertain", code: "command_outcome_pending", message: "outcomeUncertain" }
    }
    if (!blocked && state.error?.code === "command_outcome_pending") state.error = null
  })
  let commandInFlight: PendingCommand | null = null
  function invalidate(): void {
    ++nonce
    if (commandInFlight) commandCoordinator.uncertain(commandInFlight)
    commandInFlight = null
    active?.abort()
    active = null
    state.busy = false
    state.error = null
    state.reconciliationRequired = false
    state.reconciliationNotice = false
  }
  const stop = projectContext.onTransition(invalidate)
  const stopAdapter = watch(platformPort, invalidate)
  async function submit(ability: UiCapability, action: WriteDomain, sourceOperation: string | SourceCommandBinding | null = null): Promise<boolean> {
    const port = platformPort.value
    // Never send a WRITE when the original actor/operation/owner status
    // cannot be queried. A positive local owner HTTP is not an ACK across
    // the selected B15 four-owner databases.
    if(!sourceMutationReady(ability,sourceOperation)){
      const pending=commandCoordinator.lookup(projectContext.state.user?.key??"",projectContext.selection())
      state.error=pending?
        {kind:"uncertain",code:"original_command_still_pending",message:"outcomeUncertain"}:
        !sourceOperation||!port?.bff?.inspectOriginalCommand?
        {kind:"unavailable",code:"original_command_status_missing",message:"serverCommandStatusRequired"}:
        {kind:"forbidden",code:"owner_or_scope_authority_missing",message:"ownerAuthorityRequired"}
      return false
    }
    const scope = projectContext.selection()
    if(!projectContext.can(ability)&&!commandCoordinator.lookup(projectContext.state.user?.key??"",scope)){
      commandCoordinator.denied(ability)
      state.error={kind:"forbidden",code:"bff_owner_authority_required",message:"ownerAuthorityRequired"}
      return false
    }
    if (disposed || state.busy || state.reconciliationRequired || !port ||
        !groupVerifiedBffCapabilities(port)||!scope||!scopes.includes(scope.kind)||
        !projectContext.can(ability)) return false
    const actor = projectContext.state.user?.key ?? ""
    const generation = ++nonce
    const telemetryStart=performance.now()
    const diagnosticResource=resourceForAction(ability)??"other"
    const abort = new AbortController()
    const revision = projectContext.state.revision
    const pending = commandCoordinator.begin(actor, scope, ability, verifiedDecisionVersion(scope), sourceOperation)
    if (!pending) return false
    active = abort
    commandInFlight = pending
    state.busy = true
    state.error = null
    state.reconciliationNotice = false
    try {
      await action(port, {
        scope,revision,signal:abort.signal,idempotencyKey:pending.commandId,operationUuid:pending.operationUuid,
        decisionVersion:pending.decisionVersion,
      })
      if(disposed || abort.signal.aborted || nonce !== generation || !sameScope(scope,revision) || platformPort.value!==port){
        commandCoordinator.uncertain(pending)
        if(commandInFlight===pending)commandInFlight=null
        return false
      }
      const context:QueryContext={scope,revision,signal:abort.signal,decisionVersion:pending.decisionVersion}
      if(!await completeCrossOwnerEffect(port,context,pending)){
        commandCoordinator.uncertain(pending)
        if(commandInFlight===pending)commandInFlight=null
        state.error={kind:"uncertain",code:"bff_distributed_effect_unconfirmed",message:"crossOwnerOutcomeUnknown"}
        state.reconciliationRequired=true
        browserTelemetry.write(diagnosticResource,"uncertain",performance.now()-telemetryStart)
        return false
      }
      if(disposed||abort.signal.aborted||nonce!==generation||!sameScope(scope,revision)||platformPort.value!==port){
        commandCoordinator.uncertain(pending)
        if(commandInFlight===pending)commandInFlight=null
        return false
      }
      const affected=resourceForAction(ability)
      if(!affected)throw new Error("Missing original effect domain")
      await readActionDomain(port,{
        scope,revision,signal:abort.signal,decisionVersion:pending.decisionVersion,
      },affected,actor)
      if(disposed||abort.signal.aborted||nonce!==generation||!sameScope(scope,revision)||platformPort.value!==port){
        commandCoordinator.uncertain(pending)
        if(commandInFlight===pending)commandInFlight=null
        return false
      }
      // The UI may only report confirmed after BOTH all owner ACKs and
      // an authenticated read of the very domain the operation changed.
      commandCoordinator.confirm(pending)
      commandInFlight = null
      browserTelemetry.write(diagnosticResource,"ok",performance.now()-telemetryStart)
      return true
    } catch (cause) {
      const normalized = normalizeUiError(cause, "mutation")
      // Treat every post-invocation failure as uncertain. A server 403/422
      // might be a post-commit permission/owner acknowledgement failure.
      commandCoordinator.uncertain(pending)
      if (commandInFlight === pending) commandInFlight = null
      if (!disposed && !abort.signal.aborted && nonce === generation && sameScope(scope, revision) && platformPort.value === port) {
        const normalized = normalizeUiError(cause, "mutation")
        if (!handlePermissionError(normalized, scope)) {
          browserTelemetry.write(diagnosticResource,diagnosticOutcome(normalized),performance.now()-telemetryStart)
          state.error = normalized
          state.reconciliationRequired = true
        }
      }
      return false
    } finally {
      if (active === abort) { state.busy = false; active = null }
    }
  }
  async function reconcile(): Promise<boolean> {
    if(disposed||state.busy)return false
    const context=projectContext.selection()
    const revision=projectContext.state.revision
    const port=platformPort.value
    const principal=projectContext.state.user?.key??""
    const entry=commandCoordinator.lookup(principal,context)
    if(!context||!port||!entry)return false
    const resource=resourceForAction(entry.action)
    if(!commandCoordinator.matches(entry,principal,context)){
      state.error={kind:"uncertain",code:"reconcile_scope_mismatch",message:"reconcileOriginalScope"}
      return false
    }
    if(!resource){
      state.error={kind:"unavailable",code:"command_status_required",message:"serverCommandStatusRequired"}
      return false
    }
    const abort=new AbortController()
    const off=projectContext.onTransition(()=>abort.abort())
    const unwatch=watch(platformPort,()=>abort.abort())
    commandCoordinator.reconciling(entry)
    try {
      const currentContext:QueryContext={scope:context,signal:abort.signal,revision,
        decisionVersion:verifiedDecisionVersion(context)}
      if(!await completeCrossOwnerEffect(port,currentContext,entry)){
        state.error={kind:"uncertain",code:"bff_distributed_effect_unconfirmed",message:"crossOwnerOutcomeUnknown"}
        return false
      }
      await readActionDomain(port,{
        scope:context,signal:abort.signal,revision,
        decisionVersion:verifiedDecisionVersion(context),
      },resource,principal)
      if(disposed||abort.signal.aborted||!sameScope(context,revision)||port!==platformPort.value ||
         principal!==projectContext.state.user?.key)return false
      if(!commandCoordinator.reconcile(principal,context,entry,resource)){
        state.error={kind:"uncertain",code:"reconcile_scope_mismatch",message:"reconcileOriginalScope"}
        return false
      }
      state.error=null
      state.reconciliationRequired=false
      state.reconciliationNotice=true
      return true
    } catch(cause) {
      if(!disposed&&!abort.signal.aborted&&sameScope(context,revision)){
        const normalized=normalizeUiError(cause)
        state.error=normalized.kind==="unknown" ?
          {kind:"unavailable",code:"source_reconciliation_failed",message:"reconcileReadFailed"}:normalized
        if(normalized.kind==="unauthorized"||normalized.kind==="forbidden")handlePermissionError(normalized,context)
      }
      return false
    } finally {
      off()
      commandCoordinator.unresolved(entry)
      unwatch()
      abort.abort()
    }
  }
  onBeforeUnmount(() => { disposed = true; stop(); stopAdapter(); invalidate() })
  return { state, submit, reconcile }
}
