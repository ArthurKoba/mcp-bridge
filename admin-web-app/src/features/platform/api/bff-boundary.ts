import type { PlatformPort, QueryContext, ScopeSelection, SourceCommandBinding, UiCapability } from "@/features/platform/model/contracts"

/** Selected B15 ownership model. These are DOMAIN OWNERS behind one BFF,
 * not browser-addressable database/service origins or HTTP wire DTOs. */
export type BffOwner = "identity" | "access" | "control" | "catalog"
export type OwnerAvailability = "ready" | "upgrading" | "unavailable" | "unknown"
export type OwnerEffectPhase = "pending" | "unknown" | "reconciling" | "confirmed" | "denied"
export const BFF_OWNERS = ["identity", "access", "control", "catalog"] as const
export const OWNER_PROOF_MAX_AGE_MS = 60_000
const UTC_AWARE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:\d{2})$/i

export interface BffOwnerState {
  readonly availability: OwnerAvailability
  /** Opaque authoritative per-owner revision, never a SQL migration head. */
  readonly revision: string | null
}
/** This may ONLY be produced by a source-reviewed authenticated BFF port.
 * Constructing this shape in the browser is NOT a trust grant. */
export interface BffOwnerEvidence {
  readonly actorUserId: string
  readonly scope: ScopeSelection
  readonly observedAtUtc: string
  readonly expiresAtUtc: string
  readonly owners: Readonly<Record<BffOwner, BffOwnerState>>
}
export interface BffOwnerEffect {
  readonly phase: OwnerEffectPhase
  /** Signed source owner revision from the SAME authenticated BFF view. */
  readonly revision: string
}
export interface BffEffectEvidence {
  readonly actorUserId: string
  readonly scope: ScopeSelection
  readonly binding: SourceCommandBinding
  readonly idempotencyKey: string
  /** A11 Operation-UUID, independently bound to signed owner-local effect. */
  readonly operationUuid:string
  readonly phase: OwnerEffectPhase
  readonly owners: Readonly<Partial<Record<BffOwner, BffOwnerEffect>>>
  readonly observedAtUtc: string
}
/** Accepted A12 private owner-signed source is NOT this reviewed public
 * interface: its normalized `BffEffectEvidence` omits the ORIGINAL
 * Operation-UUID. A12 recipient effect receipts also require
 * `operation_uuid === idempotency_uuid`, whereas B17/B18 UI preserves two
 * independently minted UUIDv4 values. Backend A13 must reconcile both
 * contracts before a source-authenticated public same-origin BFF can supply
 * a value of this type. Never synthesize or echo the request Operation-UUID
 * as a result. The installer remains closed under C1-B2/C2. */
export interface AuthenticatedBffBoundary {
  current(context: QueryContext): Promise<BffOwnerEvidence>
  inspectOriginalCommand?(context: QueryContext, input: {
    binding: SourceCommandBinding; idempotencyKey: string; operationUuid:string
  }): Promise<BffEffectEvidence>
}
/** Composition boundary, no direct browser access to owner DBs or services. */
export interface BffDomainCapabilities {
  readonly identity: Pick<PlatformPort, "auth" | "users">
  readonly access: Pick<PlatformPort, "sessions" | "realtime">
  readonly control: Pick<PlatformPort, "teams" | "projects" | "agents" | "operator">
  readonly catalog: Pick<PlatformPort, "accounts" | "variables" | "providers">
  readonly boundary: AuthenticatedBffBoundary
}
export function groupVerifiedBffCapabilities(port: PlatformPort): BffDomainCapabilities | null {
  if(!port.bff)return null
  return {
    identity:{auth:port.auth,users:port.users},
    access:{sessions:port.sessions,realtime:port.realtime},
    control:{teams:port.teams,projects:port.projects,agents:port.agents,operator:port.operator},
    catalog:{accounts:port.accounts,variables:port.variables,providers:port.providers},
    boundary:port.bff,
  }
}
export function sameBffScope(a: ScopeSelection, b: ScopeSelection): boolean {
  if(a.kind!==b.kind)return false
  if(a.kind==="project")return b.kind==="project"&&a.projectId===b.projectId
  if(a.kind==="team")return b.kind==="team"&&a.teamId===b.teamId
  return true
}
const validRevision=(value:unknown):value is string=>typeof value==="string"&&
  value.length>0&&value.length<=160&&/^[A-Za-z0-9_.:-]+$/.test(value)
const validUtc=(value:unknown):value is string=>typeof value==="string"&&value.length<=64&&
  UTC_AWARE.test(value)&&Number.isFinite(Date.parse(value))
/** Pure format/date/scope defense in depth; ONLY an approved BFF installer
 * can supply the authoritative source. No local proof minting or bypass. */
export function verifiedBffEvidence(value:BffOwnerEvidence,actor:string,scope:ScopeSelection,now=Date.now()):boolean {
  if(!actor||value.actorUserId!==actor||!sameBffScope(value.scope,scope))return false
  if(!validUtc(value.observedAtUtc)||!validUtc(value.expiresAtUtc))return false
  const observed=Date.parse(value.observedAtUtc),expires=Date.parse(value.expiresAtUtc)
  if(observed>now+5_000||expires<=now||expires<=observed||expires-observed>OWNER_PROOF_MAX_AGE_MS)return false
  if(!value.owners||Object.keys(value.owners).sort().join(",")!==[...BFF_OWNERS].sort().join(","))return false
  for(const owner of BFF_OWNERS){
    const row=value.owners[owner]
    if(!row||!["ready","upgrading","unavailable","unknown"].includes(row.availability))return false
    if(row.availability==="ready"?!validRevision(row.revision):row.revision!==null)return false
  }
  return true
}
/** Identity + Access + Control are ALWAYS current for a privileged effect.
 * Catalog adds its own owner proof for credentials/variables and providers. */
export function requiredOwners(action:UiCapability):readonly BffOwner[] {
  const common:readonly BffOwner[]=["identity","access","control"]
  return action.startsWith("accounts.")||action.startsWith("variables.")?
    [...common,"catalog"]:common
}
export function isPrivilegedAction(action:UiCapability):boolean {
  return !["profile.read","users.read","teams.read","projects.read","agents.read","sessions.read",
    "accounts.read","variables.read","operations.metadata.read","dashboard.read","calls.read",
    "oauth.read","files.read","terminal.read","browser.managed.read","browser.external.read",
    "analysis.read","settings.read"].includes(action)
}
/** Local owner-local ACK is NOT a distributed commit. A multi-owner effect is
 * confirmed only after BFF source reports every required owner confirmed. */
export function confirmedBffEffect(value:BffEffectEvidence,input:{actor:string;scope:ScopeSelection;binding:SourceCommandBinding;idempotencyKey:string;operationUuid:string;action:UiCapability;ownerEvidence:BffOwnerEvidence},now=Date.now()):boolean {
  // A12's PRIVATE `BffEffectEvidence` has no response Operation-UUID, so
  // even an apparently `confirmed` A12 result MUST fail here. This is a
  // source-identity equality check, not browser-side signature verification.
  if(typeof value?.operationUuid!=="string"||
     value.phase!=="confirmed"||value.actorUserId!==input.actor||!sameBffScope(value.scope,input.scope)||
     value.idempotencyKey!==input.idempotencyKey||value.operationUuid!==input.operationUuid||
     value.binding.operation!==input.binding.operation||
     JSON.stringify(value.binding.target)!==JSON.stringify(input.binding.target)||
     !validUtc(value.observedAtUtc)||Math.abs(now-Date.parse(value.observedAtUtc))>OWNER_PROOF_MAX_AGE_MS)return false
  if(!verifiedBffEvidence(input.ownerEvidence,input.actor,input.scope,now)||!value.owners||
     typeof value.owners!=="object"||Array.isArray(value.owners))return false
  return requiredOwners(input.action).every(owner=>{
    const actual=value.owners[owner]
    const expected=input.ownerEvidence.owners[owner]
    return actual?.phase==="confirmed"&&validRevision(actual.revision)&&
      expected.availability==="ready"&&actual.revision===expected.revision
  })
}
/** A source-owned saga may involve several databases; never infer completion
 * from one Project/Team mutation 2xx or an eventually delivered WS event. */
/** Every privileged action may span authoritative owner stores or revoke
 * downstream grants; never infer distributed success from local HTTP 2xx.
 * Only non-mutating read projections may be shown without owner effect ACK. */
export function crossOwnerMutation(action:UiCapability):boolean {return isPrivilegedAction(action)}
