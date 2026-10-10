import { reactive, readonly, watch } from "vue"
import { projectContext } from "@/features/platform/model/project-context"
import { uiPreferences } from "@/shared/lib/preferences"

/**
 * Briareus first-party browser diagnostics. SOURCE-ONLY LOCAL OBSERVATION.
 * No fetch, OTLP, localStorage, cookies, token/URL, DOM content, exception
 * stack/message, source error code, Resource ID or Team/User/Project UUID.
 * A10's authenticated same-origin relay is UNACCEPTED; NEVER send straight
 * to the Team collector (or embed OTLP_BEARER_TOKEN / OTLP_ENDPOINT).
 */
export type DiagnosticEventName = "navigation" | "read" | "write" | "error" | "performance" | "lifecycle"
export type DiagnosticArea = "home" | "users" | "teams" | "projects" | "agents" | "sessions" |
  "integrations" | "variables" | "dashboard" | "calls" | "oauth" | "files" |
  "terminal" | "browser-managed" | "browser-external" | "analysis" | "settings" | "app" | "other"
export type DiagnosticOutcome = "ok" | "unavailable" | "blocked" | "rejected" | "uncertain" | "cancelled"
export type DiagnosticScope = "anonymous" | "account" | "team" | "project" | "operator" | "unavailable"

/** Browser timestamps are client observed UTC instants, NOT audit evidence. */
export interface BrowserDiagnostic {
  name:DiagnosticEventName
  area:DiagnosticArea
  outcome:DiagnosticOutcome
  scope:DiagnosticScope
  clientObservedAtUtc:string
  durationMs?:number
}

/** Future A10 typed design seam; not installed or callable in B14. A relay
 * must authenticate the actual server principal and independently authorize
 * the scope, consent and rate limit; source browser data is untrusted. */
export interface ReviewedBrowserTelemetryRelay {
  submit(batch:readonly BrowserDiagnostic[],signal:AbortSignal):Promise<void>
}

const AREAS = new Set<DiagnosticArea>([
  "home","users","teams","projects","agents","sessions","integrations","variables",
  "dashboard","calls","oauth","files","terminal","browser-managed","browser-external",
  "analysis","settings","app","other",
])
const OUTCOMES = new Set<DiagnosticOutcome>(["ok","unavailable","blocked","rejected","uncertain","cancelled"])
const MAX_EVENTS=64
const MAX_EVENTS_PER_MINUTE=24
const RETENTION_MS=5*60*1_000
const BUFFER_MAX_BYTES=16*1_024
const memory:BrowserDiagnostic[]=[]
let starts:number[]=[]
let revision=projectContext.state.revision
const state=reactive({
  consent:uiPreferences.diagnosticsConsent.value,
  buffered:0,
  dropped:0,
  /** No relay is accepted for any active Briareus release yet. */
  delivery:"unavailable" as const,
})

function clear():void {
  memory.length=0
  starts=[]
  state.buffered=0
  state.dropped=0
  revision=projectContext.state.revision
}
/** Enforce actual 5-minute TTL even while tab is idle; status is not a
 * promise that a disk/server exporter exists. */
function pruneExpired():void {
  const threshold=Date.now()-RETENTION_MS
  let removed=0
  while(memory[0]&&Date.parse(memory[0].clientObservedAtUtc)<threshold){
    memory.shift()
    removed++
  }
  if(removed){state.dropped+=removed;state.buffered=memory.length}
  starts=starts.filter(t=>t>=Date.now()-60_000)
}
function activeScope():DiagnosticScope {
  if(!projectContext.state.user?.active)return "anonymous"
  switch(projectContext.state.scope){
    case "choose-project":return "account"
    case "team":return "team"
    case "project":return "project"
    case "operator":return "operator"
    default:return "unavailable"
  }
}
function normalizeArea(area:string):DiagnosticArea {
  return AREAS.has(area as DiagnosticArea)?area as DiagnosticArea:"other"
}
function record(name:DiagnosticEventName,area:string,outcome:DiagnosticOutcome,durationMs?:number):void {
  if(!uiPreferences.diagnosticsConsent.value)return
  if(revision!==projectContext.state.revision)clear()
  const now=Date.now()
  pruneExpired()
  // This is a privacy/CPU cap, not a source for billing or authoritative
  // per-actor traffic counts. No unbounded client-side retry queue.
  if(starts.length>=MAX_EVENTS_PER_MINUTE){state.dropped++;return}
  starts.push(now)
  const data:BrowserDiagnostic={
    name,
    area:normalizeArea(area),
    outcome:OUTCOMES.has(outcome)?outcome:"unavailable",
    scope:activeScope(),
    clientObservedAtUtc:new Date(now).toISOString(),
  }
  if(durationMs!==undefined&&Number.isFinite(durationMs)){
    // Deliberately quantize timing to reduce fingerprint/side-channel surface.
    data.durationMs=Math.max(0,Math.min(60_000,Math.round(durationMs/25)*25))
  }
  // Sanity bound on FIXED-schema record, not a serializer for arbitrary attrs.
  if(JSON.stringify(data).length>256){state.dropped++;return}
  memory.push(data)
  while(memory.length>MAX_EVENTS||
    JSON.stringify(memory).length>BUFFER_MAX_BYTES||
    (memory[0]&&now-Date.parse(memory[0].clientObservedAtUtc)>RETENTION_MS)){
    memory.shift()
    state.dropped++
  }
  state.buffered=memory.length
}

/** Call only with fixed category labels; NEVER raw request/error data. */
function error(area:string,category:"window"|"promise"|"authentication"|"read"|"write"|"realtime"):void {
  const nameArea=category==="window"||category==="promise"?"app":area
  record("error",nameArea,"unavailable")
}
function read(area:string,outcome:DiagnosticOutcome,durationMs?:number):void {
  record("read",area,outcome,durationMs)
}
function write(area:string,outcome:DiagnosticOutcome,durationMs?:number):void {
  record("write",area,outcome,durationMs)
}
function navigation(area:string):void {record("navigation",area,"ok")}
function performance(durationMs:number):void {record("performance","app","ok",durationMs)}
function lifecycle(outcome:DiagnosticOutcome):void {record("lifecycle","app",outcome)}

// A new authenticated principal or logout REVOKES opt-in, not just buffered
// telemetry. Same-User Team/Project scope switches clear events while leaving
// that User's current-tab choice intact; no User inherits prior User consent.
let consentActor=projectContext.state.user?.active?projectContext.state.user.key:null
const stopPrincipalTransitions=projectContext.onTransition(()=>{
  const nextActor=projectContext.state.user?.active?projectContext.state.user.key:null
  if(nextActor!==consentActor){
    consentActor=nextActor
    uiPreferences.diagnosticsConsent.value=false
  }
  clear()
})
const retentionTimer=window.setInterval(pruneExpired,60_000)
window.addEventListener("pagehide",clear)
const stopConsentWatch=watch(uiPreferences.diagnosticsConsent,enabled=>{
  state.consent=enabled
  if(!enabled)clear()
},{flush:"sync"})
if(import.meta.hot)import.meta.hot.dispose(()=>{
  stopPrincipalTransitions()
  stopConsentWatch()
  window.clearInterval(retentionTimer)
  window.removeEventListener("pagehide",clear)
  clear()
})

export const browserTelemetry={
  state:readonly(state),clear,error,read,write,navigation,performance,lifecycle,
}
