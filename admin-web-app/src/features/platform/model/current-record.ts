/** Source field is an opaque revision string, NOT a client-side ACL token.
 * Every destructive action also requires current signed Identity/Access/
 * Control, the exact selected scope, and fresh row-specific allowedActions.
 */
export function hasCurrentRecordRevision(record:{revision?:string|null}):boolean {
  const version=record.revision
  return typeof version==="string"&&version.length>0&&version.length<=160&&
    /^[A-Za-z0-9_.:-]+$/.test(version)
}
/** Signed Project/Team decision-epoch must match both the displayed row and
 * the currently authenticated owner projection. An absent epoch is UNKNOWN.
 */
export function hasCurrentDecisionEpoch(
  record:{revision?:string|null;decisionVersion?:string|null},
  accepted:string|null|undefined,
):boolean {
  return hasCurrentRecordRevision(record)&&
    typeof accepted==="string"&&accepted.length>0&&accepted.length<=160&&
    /^[A-Za-z0-9_.:-]+$/.test(accepted)&&record.decisionVersion===accepted
}
