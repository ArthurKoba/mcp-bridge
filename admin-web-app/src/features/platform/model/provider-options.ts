/** Mirrors current projects/_provider_registry.py, not legacy Admin AccountPayload. */
export const providerCatalog = {
  github: ["personal_token", "github_app"],
  gitlab: ["personal_token", "oauth"],
  coolify: ["api_token"],
  signoz: ["api_token"],
  grafana: ["api_token"],
  zoomies: ["api_token"],
} as const
export type SourceProviderName = keyof typeof providerCatalog
export interface SourceProviderDraft {
  provider: SourceProviderName
  authType: string
  baseUrl: string
  displayName: string
  installationId: string
  organization: string
  namespace: string
  tenant: string
}
// This mirrors accepted Backend A5 Pydantic string field constraints for
// presentation only. Backend DNS/SSRF/credential validation is authoritative.
const githubOrganization = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/
const gitlabNamespace = /^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/
const infrastructureTenant = /^[A-Za-z0-9][A-Za-z0-9_-]*$/
const aliasPattern = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/
const variableNamePattern = /^[A-Z_][A-Z0-9_]{0,127}$/
export const validResourceAlias = (value: string) => aliasPattern.test(value.trim())
export const validVariableName = (value: string) => variableNamePattern.test(value.trim().toUpperCase())
/** Accepted A11 Catalog owner `_secret_digest` accepts 1..131072 UTF-8
 * bytes. This is validation only; a signed current Catalog BFF grant and
 * owner-local encryption/SSRF controls remain server responsibilities. */
export function validCatalogValue(value:string):boolean {
  if(!value)return false
  const length=new TextEncoder().encode(value).byteLength
  return length>=1&&length<=131_072
}
export function providerAuthTypes(provider: SourceProviderName): readonly string[] { return providerCatalog[provider] }
export function sourceProviderOptions(value: SourceProviderDraft): Record<string, unknown> | null {
  if (!providerAuthTypes(value.provider).includes(value.authType)) return null
  const baseUrl = value.baseUrl.trim()
  if (value.displayName.length > 128 || [value.organization,value.namespace,value.tenant].some(item => item.length > 128)) return null
  if ([baseUrl,value.displayName,value.organization,value.namespace,value.tenant].some(item=>/[\x00-\x1f\x7f]/.test(item))) return null
  if (baseUrl) {
    try {
      const parsed = new URL(baseUrl)
      const host=parsed.hostname.toLowerCase()
      if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password ||
          parsed.search || parsed.hash || baseUrl.length > 2048 ||
          /[\s%]/.test(parsed.host) ||
          !["", "443", "8443"].includes(parsed.port) ||
          [".local", ".localhost", ".internal", ".lan", ".home", ".onion"].some(tld=>host.endsWith(tld))) return null
      // Server performs final public-DNS/IP-range checks and guards redirects
      // and DNS rebinding; client-side URL parsing cannot establish those facts.
    } catch { return null }
  }
  const options: Record<string,unknown> = {base_url:baseUrl.replace(/\/+$/, ""),display_name:value.displayName.trim()}
  if (value.provider === "github") {
    if (value.authType === "github_app") {
      if (!/^[1-9][0-9]*$/.test(value.installationId) || !Number.isSafeInteger(Number(value.installationId))) return null
      options.installation_id = Number(value.installationId)
    }
    const org=value.organization.trim()
    if (org && !githubOrganization.test(org)) return null
    options.organization = org
  } else if (value.provider === "gitlab") {
    const namespace=value.namespace.trim()
    if(namespace && !gitlabNamespace.test(namespace)) return null
    options.namespace = namespace
  } else {
    const tenant=value.tenant.trim()
    if(tenant && !infrastructureTenant.test(tenant))return null
    options.tenant = tenant
  }
  return options
}
