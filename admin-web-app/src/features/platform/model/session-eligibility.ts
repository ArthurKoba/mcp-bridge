import { canonicalUuid4, type AgentSessionView } from "@/features/platform/model/contracts"
import { asUtcInstant } from "@/shared/lib/event-time"

/** UI-only fail-closed hint. Hard-expiry and grants remain solely controlled
 * by Access under current signed Identity/Control/AgentSession owner proof.
 * A server `active` flag or a browser clock is NOT authorization by itself.
 */
export function sessionIsCurrentlyActive(session:AgentSessionView,now:number):boolean {
  const utc=asUtcInstant(session.expiresAt)
  return canonicalUuid4(session.sessionUuid)&&session.status==="active"&&
    utc!==null&&Date.parse(utc)>now
}
/** Invalid/naive source expiry must never be normalized to "active". */
export function sessionExpiryUnverified(session:AgentSessionView):boolean {
  return session.status==="active"&&asUtcInstant(session.expiresAt)===null
}
