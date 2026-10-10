/** Presentation-level error categories, independent of still-unapproved C1-B routes. */
export type UiErrorKind = "conflict" | "unauthorized" | "forbidden" | "unavailable" | "invalid" | "uncertain" | "unknown"
export interface UiError { kind: UiErrorKind; message: string; code: string }

/** B18: No global A9 `DraftContractError` remains after the dead client
 * was deleted. Only the real local pre-send BFF capability guard can deny a
 * command without risking a previously committed remote side effect. */
/** Only known error codes may enter reactive UI state; never raw exception
 * text, arbitrary server-selected values, payloads, secrets or full URLs. */
const errorCodes = new Set([
  "contract_not_available","invalid_invitation","last_superuser","resource_ambiguous",
  "operation_in_progress","idempotency_key_conflict",
])
export function normalizeUiError(error: unknown, phase: "read" | "mutation" = "read"): UiError {
  const data = error && typeof error === "object" ? error as Record<string, unknown> : {}
  const envelope = data.error && typeof data.error === "object" ? data.error as Record<string, unknown> : {}
  const status = typeof data.status === "number" ? data.status : typeof envelope.status === "number" ? envelope.status : null
  const candidate = typeof data.code === "string" ? data.code : typeof envelope.code === "string" ? envelope.code : ""
  // Allow only a short identifier; never retain a raw URL, stack, token,
  // response body, user/project ID or attacker-supplied free-form error.
  const code = errorCodes.has(candidate)?candidate:""
  // After an outbound write, 400/401/403/404/409/422/503 and network loss
  // are all POSSIBLY post-commit. Only the ORIGINAL signed BFF owner status
  // plus a current affected-domain read may resolve the retry fence.
  if(phase==="mutation")return {kind:"uncertain",code,message:"outcomeUncertain"}
  if (code === "contract_not_available") {
    return { kind: "unavailable", code, message: "contractPending" }
  }
  if (status === 401) return { kind: "unauthorized", code, message: "authenticationExpired" }
  // A future Authorization-owned schema migration may temporarily keep
  // verified Admin callers unavailable. 503 is NOT evidence migrations ran;
  // never trigger a client-side migration, fake readiness or replay a write.
  if (status === 503 && phase === "read")return {kind:"unavailable",code:"service_unavailable",message:"serviceUnavailableOrUpgrading"}
  if (status === 429) return { kind: "unavailable", code, message: "rateLimited" }
  if (status === 403) return { kind: "forbidden", code, message: "permissionDenied" }
  if (code === "invalid_invitation" && (status === 400 || status === 422)) {
    return { kind: "invalid", code, message: "invitationInvalid" }
  }
  if (code === "last_superuser" && status === 409) {
    return { kind: "conflict", code, message: "lastSuperuser" }
  }
  if (status === 404) return { kind: "invalid", code, message: "recordMissing" }
  if (status === 409) {
    if (code === "resource_ambiguous") return { kind: "conflict", code, message: "resourceAmbiguous" }
    if (code === "operation_in_progress") return { kind: "conflict", code, message: "operationInProgress" }
    if (code === "idempotency_key_conflict") return { kind: "conflict", code, message: "idempotencyConflict" }
    return { kind: "conflict", code, message: "conflict" }
  }
  if (status === 400 || status === 422) return { kind: "invalid", code, message: "invalidInput" }
  if (status === 408 || status === 502 || status === 503 || status === 504 || (status !== null && status >= 500)) {
    return { kind: "unavailable", code, message: "unavailable" }
  }
  if (data.kind === "network" || error instanceof TypeError) {
    return { kind: "unavailable", code, message: "unavailable" }
  }
  if (data.kind === "aborted" || (error instanceof DOMException && error.name === "AbortError")) {
    // A transport-side cancellation of a mutation can arrive after the server
    // accepted the write. A caller scope-switch is ignored upstream instead.
    return { kind: "unavailable", code, message: "requestCancelled" }
  }
  return { kind: "unknown", code, message: "unknownError" }
}
