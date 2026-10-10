/** B17 UI-only search of ALREADY server-authorized rows.
 * This is not a global directory lookup or proof an absent entity is deleted.
 * No full-text query is sent, stored or included in diagnostics/URLs. */
export function matchesLoaded(query:string,...text:(string|null|undefined)[]):boolean {
  const needle=query.trim().slice(0,120).normalize("NFKC").toLocaleLowerCase()
  if(!needle)return true
  return text.some(value=>typeof value==="string"&&
    value.slice(0,512).normalize("NFKC").toLocaleLowerCase().includes(needle))
}
