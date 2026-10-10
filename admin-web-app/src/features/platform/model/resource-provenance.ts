import {
  canonicalUuid4,
  type ProjectAccountView, type ProjectVariableView,
  type ResourceOwner, type ResourceVisibility, type UiCapability,
} from "@/features/platform/model/contracts"

/** Catalog resources use UUID+owner+visibility+revision, NEVER an alias/key.
 * A Team inherited row and a Project direct row may have the same name.
 * This pure predicate is a UI fence, not an authoritative source permission. */
export function sameResourceOwner(left:ResourceOwner,right:ResourceOwner):boolean {
  return left.kind===right.kind && (left.kind==="team"?
    right.kind==="team"&&left.teamId===right.teamId:
    right.kind==="project"&&left.projectId===right.projectId)
}
export function sameResourceVisibility(left:ResourceVisibility,right:ResourceVisibility):boolean {
  return left.kind===right.kind && (left.kind==="team"?
    right.kind==="team"&&left.teamId===right.teamId:
    right.kind==="project"&&left.projectId===right.projectId)
}
export type CurrentCatalogView = Pick<ProjectAccountView|ProjectVariableView,
  "id"|"owner"|"visibleIn"|"inherited"|"revision"|"allowedActions"|"projectAccessRevision"|"teamAccessRevision">

/** Fail closed for an unversioned/ambiguous/stale row or absent per-row grant.
 * `rows` MUST come from a successful, current BFF-authorized, scoped read.
 * Expiry/actor/scope are checked independently by `sourceMutationReady`. */
export function currentCatalogRowAllows<T extends CurrentCatalogView>(
  rows:readonly T[],candidate:T,action:UiCapability,
):boolean {
  if(!canonicalUuid4(candidate.id)||typeof candidate.revision!=="string"||
     candidate.revision.length<1||candidate.revision.length>160)return false
  const matching=rows.filter(row=>row.id===candidate.id&&
    sameResourceOwner(row.owner,candidate.owner)&&
    sameResourceVisibility(row.visibleIn,candidate.visibleIn))
  if(matching.length!==1)return false
  const row=matching[0]
  if(!row||row.inherited!==candidate.inherited||
     row.revision!==candidate.revision||
     row.projectAccessRevision!==candidate.projectAccessRevision||
     row.teamAccessRevision!==candidate.teamAccessRevision)return false
  return row.allowedActions?.[action]===true
}
