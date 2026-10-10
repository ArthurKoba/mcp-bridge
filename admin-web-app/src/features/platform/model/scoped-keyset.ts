import { canonicalUuid4 } from "@/features/platform/model/contracts"

/** Frontend presentation merge ONLY for already authenticated bounded
 * source keyset pages. A cursor, list item or locally filtered index does
 * not grant any permission, nor prove completeness outside `hasMore=false`.
 */
export interface PageContinuation<T> {
  items:readonly T[]
  nextAfterId?:string|null
  hasMore?:boolean
}
export interface VerifiedAppend<T> {
  rows:T[]
  next:string|null
  hasMore:boolean
}
export function appendVerifiedKeyset<T>(
  existing:readonly T[],page:PageContinuation<T>,after:string,
  keyOf:(item:T)=>string,
):VerifiedAppend<T> {
  if(!canonicalUuid4(after)||!Array.isArray(page.items)||page.items.length>100||
     typeof page.hasMore!=="boolean")throw new Error("Invalid authorized page")
  const keys=new Set<string>()
  for(const row of existing){
    const key=keyOf(row)
    if(!canonicalUuid4(key)||keys.has(key))throw new Error("Ambiguous current row")
    keys.add(key)
  }
  let previous=after
  for(const row of page.items){
    const key=keyOf(row)
    if(!canonicalUuid4(key)||keys.has(key)||key<=previous)
      throw new Error("Inconsistent authorized page cursor")
    keys.add(key)
    previous=key
  }
  if(page.hasMore){
    if(!page.items.length||!page.nextAfterId||!canonicalUuid4(page.nextAfterId)||
       page.nextAfterId!==previous||page.nextAfterId<=after)
      throw new Error("Missing continuation for authorized page")
  }
  // A terminal source read is never permission to fabricate an extra page.
  return {
    rows:[...existing,...page.items],
    next:page.hasMore?page.nextAfterId??null:null,
    hasMore:page.hasMore,
  }
}
