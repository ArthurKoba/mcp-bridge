/**
 * Exact READ-ONLY SOURCE shape from independently accepted Backend A11
 * `services/admin-api/src/presentation/owner_bff_contract.py`.
 * The accepted A11 router is PRIVATE/UNMOUNTED; this module cannot fetch,
 * authenticate, mint grants or turn owner-local COMMITTED into BFF success.
 * Backend A12 is changing signatures; defer public wire installation.
 */
import { canonicalUuid4 } from "@/features/platform/model/contracts"

export const A11_TEAM_STATUS_OPERATIONS = [
  "team.member.add","team.member.remove","team.owner.transfer",
] as const
export type A11TeamStatusOperation = typeof A11_TEAM_STATUS_OPERATIONS[number]
export type A11OwnerName = "identity"|"access"|"platform"|"resources"|
  "files"|"runtime"|"reverse"|"ingest"
/** A11 database owner literals are NOT the four normalized Frontend BFF
 * capability names. This map is SOURCE vocabulary only, never a source of
 * current grants or a substitute for recipient-signed result verification. */
export const A11_INITIAL_OWNER_ROLES = Object.freeze({
  identity:"identity",access:"access",platform:"control",resources:"catalog",
} as const)
export type A11OwnerLocalState = "NOT_FOUND"|"UNKNOWN"|"COMMITTED"|"DENIED"
export const A11_OWNER_NAMES = ["identity","access","platform","resources","files","runtime","reverse","ingest"] as const
export type A11ProjectLifecycle = "active"|"deleting"|"deleted"
export interface A11ProjectSource {
  project_id:string;name:string;owner_user_id:string|null;owner_team_id:string|null
  version:number;lifecycle_status:A11ProjectLifecycle;resource_revision:number
  current_identity_revision:number;current_access_revision:number
  effective_permissions:readonly string[]
}
export interface A11TeamSource {
  team_id:string;name:string;owner_user_id:string;version:number
  current_membership_revision:number
}
export interface A11SourcePage<T> {
  readonly items:readonly T[];readonly next_after_id:string|null;readonly has_more:boolean
}
/** Source A11 `OwnerRealtimeProjection`: a read-side hint, NEVER a grant,
 * completion ACK, signed lease or refresh of BFF owner evidence. */
export interface A11OwnerRealtimeSource {
  scope_kind:"user"|"team"|"project"
  scope_id:string
  sequence:number
  epoch:string
  event_type:string
  created_at:string
}
export interface A11OwnerCommandSource {
  owner:A11OwnerName;operation_uuid:string;project_id:string;operation:string
  state:A11OwnerLocalState;reconciliation_required:boolean;operation_replay_safe:false
}
export interface A11TeamCommandSource {
  team_id:string;operation_uuid:string;operation:A11TeamStatusOperation
  state:A11OwnerLocalState;reconciliation_required:boolean;operation_replay_safe:false
}
export const A11_ACCEPTED_SOURCE_ONLY = Object.freeze({
  routes:Object.freeze(["/v1/platform/projects","/v1/platform/teams",
    "/v1/platform/projects/{project_id}/commands/{operation}/status",
    "/v1/platform/teams/{team_id}/commands/{operation}/status"] as const),
  statusHeaders:Object.freeze(["Idempotency-Key","Operation-UUID"] as const),
  publicMounted:false,ownerSignedCompositeEffect:false,
  /** No accepted A11 public registration/password-reset/first-admin command
   * result protocol; an `auth.register` method alone is NOT proof of safety. */
  publicOneUseStatusApproved:false,
  callerSource:"verified-admin-bearer" as const,
})

function record(value:unknown):Record<string,unknown> {
  if(!value||typeof value!=="object"||Array.isArray(value))throw new Error("A11 source DTO not an object")
  return value as Record<string,unknown>
}
function exactFields(v:Record<string,unknown>,keys:readonly string[]):void {
  if(Object.keys(v).some(key=>!keys.includes(key)) || keys.some(key=>!(key in v)))
    throw new Error("A11 source DTO field mismatch")
}
function uuid4(value:unknown):string {
  if(typeof value!=="string"||!canonicalUuid4(value))throw new Error("A11 invalid UUIDv4")
  return value
}
const awareUtc=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/i
function time(value:unknown):string {
  if(typeof value!=="string"||value.length>64||!awareUtc.test(value)||!Number.isFinite(Date.parse(value)))
    throw new Error("A11 source timestamp not timezone aware")
  return new Date(value).toISOString()
}
function revision(value:unknown,min=1):number {
  if(typeof value!=="number"||!Number.isSafeInteger(value)||value<min)
    throw new Error("A11 invalid owner revision")
  return value
}
function name(value:unknown):string {
  if(typeof value!=="string"||value.length===0||value.length>255||
     /[\x00-\x1f\x7f]/.test(value))throw new Error("A11 invalid name")
  return value
}
function sourcePage<T>(raw:unknown,decode:(row:unknown)=>T,id:(row:T)=>string,
  after:string|null,limit:number):A11SourcePage<T> {
  if(!Number.isSafeInteger(limit)||limit<1||limit>100)throw new Error("A11 page limit invalid")
  if(after!==null)uuid4(after)
  const page=record(raw)
  exactFields(page,["items","next_after_id","has_more"])
  if(!Array.isArray(page.items)||page.items.length>limit||typeof page.has_more!=="boolean")
    throw new Error("A11 invalid bounded page")
  const items=page.items.map(decode)
  let previous=after
  for(const row of items){
    const cursor=uuid4(id(row))
    if(previous!==null&&cursor<=previous)throw new Error("A11 cursor out of order")
    previous=cursor
  }
  const next=page.next_after_id===null?null:uuid4(page.next_after_id)
  if(page.has_more && (!items.length||next!==previous))throw new Error("A11 page cannot advance")
  if(!page.has_more&&next!==null)throw new Error("A11 invalid terminal cursor")
  return {items,next_after_id:next,has_more:page.has_more}
}
export function parseA11ProjectPage(raw:unknown,after:string|null=null,limit=50):A11SourcePage<A11ProjectSource> {
  return sourcePage(raw,item=>{
    const v=record(item)
    exactFields(v,["project_id","name","owner_user_id","owner_team_id","version","lifecycle_status",
      "resource_revision","current_identity_revision","current_access_revision","effective_permissions"])
    const ownerUser=v.owner_user_id===null?null:uuid4(v.owner_user_id)
    const ownerTeam=v.owner_team_id===null?null:uuid4(v.owner_team_id)
    if((ownerUser===null)===(ownerTeam===null))throw new Error("A11 project must have exactly one owner")
    if(!["active","deleting","deleted"].includes(String(v.lifecycle_status)))throw new Error("A11 project lifecycle invalid")
    if(!Array.isArray(v.effective_permissions)||v.effective_permissions.length>128||
       v.effective_permissions.some(x=>typeof x!=="string"||x.length<1||x.length>128||
         /[\x00-\x1f\x7f]/.test(x)))
      throw new Error("A11 invalid source permission list")
    return {project_id:uuid4(v.project_id),name:name(v.name),owner_user_id:ownerUser,owner_team_id:ownerTeam,
      version:revision(v.version),lifecycle_status:v.lifecycle_status as A11ProjectLifecycle,
      resource_revision:revision(v.resource_revision,0),current_identity_revision:revision(v.current_identity_revision),
      current_access_revision:revision(v.current_access_revision),effective_permissions:[...v.effective_permissions] as string[]}
  },row=>row.project_id,after,limit)
}
export function parseA11TeamPage(raw:unknown,after:string|null=null,limit=50):A11SourcePage<A11TeamSource> {
  return sourcePage(raw,item=>{
    const v=record(item)
    exactFields(v,["team_id","name","owner_user_id","version","current_membership_revision"])
    return {team_id:uuid4(v.team_id),name:name(v.name),owner_user_id:uuid4(v.owner_user_id),
      version:revision(v.version),current_membership_revision:revision(v.current_membership_revision)}
  },row=>row.team_id,after,limit)
}
/** Accepted A11 owner command is a LOCAL ledger result, not the later
 * A12 independently signed composite recipient-effect receipt. */
export function parseA11OwnerCommand(raw:unknown, expected:{
  owner:A11OwnerName; projectId:string; operationUuid:string; operation:string
}):A11OwnerCommandSource {
  const v=record(raw)
  exactFields(v,["owner","operation_uuid","project_id","operation","state","reconciliation_required","operation_replay_safe"])
  if(!A11_OWNER_NAMES.includes(v.owner as A11OwnerName)||v.owner!==expected.owner||
     uuid4(v.operation_uuid)!==uuid4(expected.operationUuid)||
     uuid4(v.project_id)!==uuid4(expected.projectId)||
     typeof v.operation!=="string"||v.operation!==expected.operation||
     v.operation.length<1||v.operation.length>128||
     !["NOT_FOUND","UNKNOWN","COMMITTED","DENIED"].includes(String(v.state))||
     typeof v.reconciliation_required!=="boolean"||v.operation_replay_safe!==false)
    throw new Error("A11 owner-local result provenance invalid")
  return {
    owner:v.owner as A11OwnerName,operation_uuid:v.operation_uuid as string,
    project_id:v.project_id as string,operation:v.operation,
    state:v.state as A11OwnerLocalState,
    reconciliation_required:v.reconciliation_required,
    operation_replay_safe:false,
  }
}
/** No stream/receipt is installed. Even a valid source payload must be
 * re-authorized against the current signed BFF scope before affecting UI. */
export function parseA11RealtimeProjection(raw:unknown,scope:{kind:"user"|"team"|"project";id:string}):A11OwnerRealtimeSource {
  const v=record(raw)
  exactFields(v,["scope_kind","scope_id","sequence","epoch","event_type","created_at"])
  if(v.scope_kind!==scope.kind||uuid4(v.scope_id)!==uuid4(scope.id)||
     !Number.isSafeInteger(v.sequence)||Number(v.sequence)<0||
     typeof v.event_type!=="string"||v.event_type.length<1||v.event_type.length>128||
     /[\x00-\x1f\x7f]/.test(v.event_type))throw new Error("A11 scope feed not source-authorized")
  return {
    scope_kind:v.scope_kind as A11OwnerRealtimeSource["scope_kind"],
    scope_id:v.scope_id as string,sequence:v.sequence as number,
    epoch:uuid4(v.epoch),event_type:v.event_type,
    created_at:time(v.created_at),
  }
}
export function parseA11TeamCommand(raw:unknown,expected:{teamId:string;operationUuid:string;operation:A11TeamStatusOperation}):A11TeamCommandSource {
  const v=record(raw)
  exactFields(v,["team_id","operation_uuid","operation","state","reconciliation_required","operation_replay_safe"])
  if(uuid4(v.team_id)!==uuid4(expected.teamId)||uuid4(v.operation_uuid)!==uuid4(expected.operationUuid)||
     v.operation!==expected.operation||!A11_TEAM_STATUS_OPERATIONS.includes(v.operation as A11TeamStatusOperation)||
     !["NOT_FOUND","UNKNOWN","COMMITTED","DENIED"].includes(String(v.state))||
     typeof v.reconciliation_required!=="boolean"||v.operation_replay_safe!==false)
    throw new Error("A11 Team command status provenance invalid")
  return {
    team_id:v.team_id as string,operation_uuid:v.operation_uuid as string,
    operation:v.operation as A11TeamStatusOperation,
    state:v.state as A11OwnerLocalState,
    reconciliation_required:v.reconciliation_required,
    operation_replay_safe:false,
  }
}
/** A11 owner-local COMMITTED is insufficient to release a distributed
 * Idempotency-Key fence; A12 signed composite receipt is separate authority. */
export const A11_LOCAL_STATUS_IS_NOT_DISTRIBUTED_PROOF = true as const
/** Strict, privacy-reduced boundary for transport/error results to the UI.
 * This never includes response body, secrets, raw error, URL or operation IDs.
 * After any sent mutation, even 401/403/422/503 could occur post-commit. */
export type A11FailurePhase="read"|"after-write"|"status-inspect"
export type A11BffErrorCategory="authentication"|"permission"|"upgrading"|"unknown"|"rejected"
export function classifyA11BffError(status:unknown,phase:A11FailurePhase):A11BffErrorCategory {
  if(phase!=="read")return "unknown"
  if(status===401)return "authentication"
  if(status===403)return "permission"
  if(status===503||status===502||status===504||status===429)return "upgrading"
  if(status===400||status===422)return "rejected"
  return "unknown"
}
/** Accepted A11 keyset restrictions, without constructing a URL or network client. */
export function a11PageCursor(limit:number,after:string|null):{limit:number;after_id:string|null} {
  if(!Number.isSafeInteger(limit)||limit<1||limit>100)throw new Error("A11 page limit invalid")
  return {limit,after_id:after===null?null:uuid4(after)}
}
