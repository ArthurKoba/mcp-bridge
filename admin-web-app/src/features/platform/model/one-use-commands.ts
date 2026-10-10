/**
 * Same-tab, in-memory guard for a PUBLIC one-use invitation/reset token.
 * Never store the token plaintext, hash, command ID or request body in URL,
 * persistent web storage, diagnostics or reactive app state. Only a SHA-256
 * token fingerprint and opaque idempotency key are held in this private map.
 * Cross-tab/reload consistency belongs to Backend's one-use transaction.
 */
type OneUseMode = "invitation" | "reset"
export interface OneUseAttempt {
  readonly fingerprint: string
  readonly mode: OneUseMode
  readonly idempotencyKey: string
}
const attempts = new Map<string, {attempt:OneUseAttempt; state:"pending"|"uncertain"}>()
const MAX_ATTEMPTS = 128

async function begin(mode:OneUseMode, token:string):Promise<OneUseAttempt | null> {
  if (!token || attempts.size>=MAX_ATTEMPTS || !crypto.subtle) return null
  const source=new TextEncoder().encode(`${mode}:${token}`)
  const fingerprint=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",source)))
    .map(byte=>byte.toString(16).padStart(2,"0")).join("")
  if (attempts.has(fingerprint)) return null
  const attempt:OneUseAttempt={fingerprint,mode,idempotencyKey:crypto.randomUUID()}
  attempts.set(fingerprint,{attempt,state:"pending"})
  return attempt
}
function uncertain(attempt:OneUseAttempt):void {
  const entry=attempts.get(attempt.fingerprint)
  if(entry?.attempt.idempotencyKey===attempt.idempotencyKey && entry.state==="pending") {
    attempts.set(attempt.fingerprint,{attempt,state:"uncertain"})
  }
}
/** No accepted A11 signed redemption/first-user result; never expose an
 * optimistic acknowledged/rejected state from an HTTP response. The only
 * safe post-invocation state remains UNKNOWN until Backend A12 is approved. */
export const oneUseCommands={begin,uncertain}
