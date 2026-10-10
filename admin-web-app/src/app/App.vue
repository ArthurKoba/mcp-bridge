<script setup lang="ts">
import { computed, defineAsyncComponent, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue"
import { Menu, Moon, PanelLeftClose, PanelLeftOpen, Sun, X } from "lucide-vue-next"
import { useI18n } from "vue-i18n"
import { platformPort } from "@/features/platform/api/port"
import { projectContext } from "@/features/platform/model/project-context"
import { refreshBffOwnerBoundary } from "@/features/platform/model/refresh-owner-boundary"
import { browserTelemetry } from "@/features/platform/model/browser-telemetry"
import { normalizeUiError } from "@/features/platform/model/errors"
import { validPlatformPage, type PlatformPageId } from "@/app/platform-navigation"
import PlatformNav from "@/app/PlatformNav.vue"
import ContextSwitcher from "@/features/platform/ui/ContextSwitcher.vue"
import ScopedRealtimeStatus from "@/features/platform/ui/ScopedRealtimeStatus.vue"
import OperationProgress from "@/features/platform/ui/OperationProgress.vue"
import PublicAccountPage from "@/pages/platform/PublicAccountPage.vue"
import Button from "@/shared/ui/Button.vue"
import ToastHost from "@/shared/notifications/ToastHost.vue"
import { useUiPreferences } from "@/shared/lib/preferences"

/** Briareus is a greenfield application, not a legacy MCP operator console. */
const pages:Record<PlatformPageId,ReturnType<typeof defineAsyncComponent>>={
  home:defineAsyncComponent(()=>import("@/pages/platform/PlatformHomePage.vue")),
  users:defineAsyncComponent(()=>import("@/pages/platform/UsersPage.vue")),
  teams:defineAsyncComponent(()=>import("@/pages/platform/TeamsPage.vue")),
  projects:defineAsyncComponent(()=>import("@/pages/platform/ProjectsPage.vue")),
  agents:defineAsyncComponent(()=>import("@/pages/platform/AgentsPage.vue")),
  sessions:defineAsyncComponent(()=>import("@/pages/platform/AgentSessionsPage.vue")),
  integrations:defineAsyncComponent(()=>import("@/pages/platform/ProjectAccountsPage.vue")),
  variables:defineAsyncComponent(()=>import("@/pages/platform/ProjectVariablesPage.vue")),
  dashboard:defineAsyncComponent(()=>import("@/pages/platform/ResourceBoundaryPage.vue")),
  calls:defineAsyncComponent(()=>import("@/pages/platform/ResourceBoundaryPage.vue")),
  oauth:defineAsyncComponent(()=>import("@/pages/platform/ResourceBoundaryPage.vue")),
  files:defineAsyncComponent(()=>import("@/pages/platform/ResourceBoundaryPage.vue")),
  terminal:defineAsyncComponent(()=>import("@/pages/platform/ResourceBoundaryPage.vue")),
  "browser-managed":defineAsyncComponent(()=>import("@/pages/platform/ResourceBoundaryPage.vue")),
  "browser-external":defineAsyncComponent(()=>import("@/pages/platform/ResourceBoundaryPage.vue")),
  analysis:defineAsyncComponent(()=>import("@/pages/platform/ResourceBoundaryPage.vue")),
  settings:defineAsyncComponent(()=>import("@/pages/platform/PlatformSettingsPage.vue")),
}
const resourcePage:Partial<Record<PlatformPageId,string>>={
  dashboard:"dashboard",calls:"calls",oauth:"oauth",files:"files",terminal:"terminal",analysis:"analysis",
  "browser-managed":"browserManaged","browser-external":"browserExternal",
}
const {t}=useI18n()
const {theme,sidebarCollapsed}=useUiPreferences()
const routePage=ref("home")
const activePage=computed<PlatformPageId>(()=>validPlatformPage(routePage.value)?routePage.value:"home")
const title=computed(()=>t(`platform.navigation.${resourcePage[activePage.value]??activePage.value}`))
const screen=computed(()=>pages[activePage.value])
const verified=computed(()=>projectContext.state.user?.active===true&&
  ["choose-project","project","team","operator"].includes(projectContext.state.scope))
const missingTransport=computed(()=>platformPort.value===null)
const loading=ref(true)
const unavailable=ref(false)
/** Never infer DB schema version/head from unauthenticated health/ENV. */
const serviceUpgradingPossible=ref(false)
const submitting=ref(false)
const error=ref("")
const username=ref("")
const password=ref("")
const mobileNavOpen=ref(false)
const isMobile=ref(false)
let mobileQuery:MediaQueryList|null=null
function syncMobile(event:MediaQueryListEvent|MediaQueryList):void {
  isMobile.value=event.matches
  if(!event.matches)mobileNavOpen.value=false
}
const mobileNavPanel=ref<HTMLElement|null>(null)
const publicFlow=ref<"invitation"|"reset"|null>(null)
const publicToken=ref("")
/** Separate one-use links of the SAME mode must never reuse a prior form. */
const publicLinkRevision=ref(0)
const publicLinkError=ref(false)
let authGeneration=0
let authAbort:AbortController|null=null
let unsubscribeCredential:(()=>void)|undefined

/** Expire the entire verified User/Team/Project identity, never a cached username. */
function expireAuth():void {
  browserTelemetry.clear()
  ++authGeneration
  authAbort?.abort()
  authAbort=null
  projectContext.clear()
  password.value=""
  username.value=""
  publicToken.value=""
  loading.value=false
  submitting.value=false
  unavailable.value=false
  serviceUpgradingPossible.value=false
}
/** Single-use credentials do not survive a URL/history navigation. */
function readOneUseLink():void {
  const url=new URL(location.href)
  const invite=url.searchParams.get("invite")
  const reset=url.searchParams.get("reset")
  if(invite===null&&reset===null)return
  url.searchParams.delete("invite")
  url.searchParams.delete("reset")
  history.replaceState(null,"",`${url.pathname}${url.search}${url.hash}`)
  // Do not use the token itself as a Vue :key, DOM attribute or telemetry.
  // A new token invalidates any previous sensitive form, even of same type.
  ++publicLinkRevision.value
  if(invite!==null&&reset!==null){
    publicFlow.value=null
    publicToken.value=""
    publicLinkError.value=true
    return
  }
  publicLinkError.value=false
  publicFlow.value=invite!==null?"invitation":"reset"
  publicToken.value=invite??reset??""
}
function closePublicFlow():void {
  publicFlow.value=null
  publicToken.value=""
  publicLinkError.value=false
}
function readHash():void {
  const [root,child]=location.hash.slice(1).split("/")
  if(root!=="platform"){
    // There is no legacy route and no legacy operator API fallback.
    history.replaceState(null,"",`${location.pathname}${location.search}#platform/home`)
    routePage.value="home"
  }else routePage.value=child||"home"
  mobileNavOpen.value=false
}
function onHistory():void {
  readOneUseLink()
  readHash()
  browserTelemetry.navigation(activePage.value)
}
function ensureRoute():void {
  if(!validPlatformPage(routePage.value)){
    history.replaceState(null,"",`${location.pathname}${location.search}#platform/home`)
    routePage.value="home"
  }
}
async function restore():Promise<void>{
  const generation=++authGeneration
  authAbort?.abort()
  const controller=new AbortController()
  authAbort=controller
  loading.value=true
  unavailable.value=false
  serviceUpgradingPossible.value=false
  error.value=""
  const port=platformPort.value
  try {
    if(!port){
      projectContext.clear()
      browserTelemetry.lifecycle("blocked")
      return
    }
    const projection=await port.auth.restore(controller.signal)
    if(generation!==authGeneration||controller.signal.aborted||port!==platformPort.value)return
    if(projection){
      projectContext.installServerProjection(projection)
      if(!projection.user.active){
        // Suspended/disabled Identity is explicit revocation. Purge the local
        // memory-only bearer and command state; never call BFF owners or
        // report a successful authenticated login under that principal.
        port.auth.invalidate?.()
        error.value=String(t("platform.suspendedNotice"))
        return
      }
      await refreshBffOwnerBoundary()
    }else{
      port.auth.invalidate?.()
      projectContext.clear()
    }
    if(generation!==authGeneration||controller.signal.aborted||port!==platformPort.value)return
    browserTelemetry.lifecycle("ok")
    ensureRoute()
  }catch(cause){
    if(generation!==authGeneration||controller.signal.aborted)return
    const issue=normalizeUiError(cause)
    browserTelemetry.error("app","authentication")
    if(issue.kind==="unauthorized"){
      // An authenticated 401 is not schema upgrading or a valid User.
      // Clear the browser memory credential and show normal sign-in only.
      port?.auth.invalidate?.()
      projectContext.clear()
      error.value=String(t("platform.authSessionExpired"))
      unavailable.value=false
      return
    }
    projectContext.offline()
    serviceUpgradingPossible.value=issue.message==="serviceUnavailableOrUpgrading"
    unavailable.value=true
  }finally{
    if(generation===authGeneration){loading.value=false;authAbort=null}
  }
}
async function login():Promise<void>{
  const port=platformPort.value
  if(!port||submitting.value)return
  const generation=++authGeneration
  authAbort?.abort()
  const controller=new AbortController()
  authAbort=controller
  submitting.value=true
  error.value=""
  try {
    const projection=await port.auth.login({username:username.value,password:password.value},controller.signal)
    if(generation!==authGeneration||controller.signal.aborted||port!==platformPort.value)return
    projectContext.installServerProjection(projection)
    if(!projection.user.active){
      port.auth.invalidate?.()
      error.value=String(t("platform.suspendedNotice"))
      return
    }
    await refreshBffOwnerBoundary()
    if(generation!==authGeneration||controller.signal.aborted||port!==platformPort.value)return
    browserTelemetry.lifecycle("ok")
    unavailable.value=false
    ensureRoute()
  }catch(cause){
    if(generation===authGeneration&&!controller.signal.aborted){
      const issue=normalizeUiError(cause)
      browserTelemetry.error("app","authentication")
      error.value=String(t(issue.message==="serviceUnavailableOrUpgrading"?
        "platform.serviceUnavailableOrUpgrading":"platform.signInFailed"))
    }
  }finally{
    password.value=""
    if(generation===authGeneration){submitting.value=false;authAbort=null}
  }
}
async function logout():Promise<void>{
  if(submitting.value)return
  // Fence any in-flight restore before server revocation. The selected
  // Project can no longer issue a command while logout is pending.
  ++authGeneration
  authAbort?.abort()
  authAbort=null
  const adapter=platformPort.value
  submitting.value=true
  projectContext.clear()
  password.value=""
  let remoteUncertain=false
  try {
    if(adapter)await adapter.auth.logout(new AbortController().signal)
  }catch{
    remoteUncertain=true
  }finally{
    // Even an unconfirmed remote logout MUST purge local bearer material.
    browserTelemetry.clear()
    adapter?.auth.invalidate?.()
    expireAuth()
    if(remoteUncertain)error.value=String(t("platform.logoutUncertain"))
  }
}
function observeCredential():void {
  unsubscribeCredential?.()
  unsubscribeCredential=platformPort.value?.auth.onCredentialInvalidated?.(expireAuth)
}
function closeMobileNav():void { mobileNavOpen.value=false }
watch(mobileNavOpen,async open=>{
  await nextTick()
  if(open){
    const first=mobileNavPanel.value?.querySelector<HTMLElement>("nav button:not(:disabled)")
    ;(first??mobileNavPanel.value)?.focus()
  }else if(window.matchMedia("(max-width: 767px)").matches&&mobileNavPanel.value?.contains(document.activeElement)){
    document.getElementById("mobile-nav-trigger")?.focus()
  }
})
function handleMobileNavKey(event:KeyboardEvent):void {
  if(!mobileNavOpen.value||window.matchMedia("(min-width: 768px)").matches)return
  if(event.key==="Escape"){event.preventDefault();closeMobileNav();return}
  if(event.key!=="Tab"||!mobileNavPanel.value)return
  const focusable=[...mobileNavPanel.value.querySelectorAll<HTMLElement>(
    "button:not(:disabled),a[href],select:not(:disabled),[tabindex]:not([tabindex='-1'])",
  )].filter(item=>item.getClientRects().length>0)
  const first=focusable[0],last=focusable[focusable.length-1]
  if(!first||!last){event.preventDefault();mobileNavPanel.value.focus();return}
  if(event.shiftKey&&(document.activeElement===first||!mobileNavPanel.value.contains(document.activeElement))){
    event.preventDefault();last.focus()
  }else if(!event.shiftKey&&(document.activeElement===last||!mobileNavPanel.value.contains(document.activeElement))){
    event.preventDefault();first.focus()
  }
}
function handleSidebarClick(event:MouseEvent):void {
  if(mobileNavOpen.value&&event.target instanceof Element&&event.target.closest("nav button"))closeMobileNav()
}
watch(platformPort,()=>{observeCredential();expireAuth();void restore()})
watch(routePage,async()=>{
  // SPA hash-route navigation must move keyboard/screen-reader focus from
  // the old menu into the new page heading after the lazy view changes.
  await nextTick()
  document.getElementById("briareus-page-title")?.focus()
})
// Every explicit Team/Project switch invalidates prior owner revisions. Only
// the authenticated BFF can restore owner readiness, never the UI cache.
watch(()=>projectContext.state.revision,()=>{if(projectContext.state.user?.active)void refreshBffOwnerBoundary()})
watch([verified,routePage,()=>projectContext.state.revision],()=>{if(verified.value)ensureRoute()})
onMounted(()=>{
  mobileQuery=window.matchMedia("(max-width: 767px)")
  syncMobile(mobileQuery)
  mobileQuery.addEventListener("change",syncMobile)
  observeCredential()
  onHistory()
  window.addEventListener("hashchange",onHistory)
  window.addEventListener("popstate",onHistory)
  window.addEventListener("keydown",handleMobileNavKey)
  void restore()
})
onBeforeUnmount(()=>{
  mobileQuery?.removeEventListener("change",syncMobile)
  mobileQuery=null
  ++authGeneration
  authAbort?.abort()
  // Unsub FIRST, then revoke all browser-memory bearer material when this
  // authenticated shell is disposed (including route-owner replacement/HMR).
  unsubscribeCredential?.()
  platformPort.value?.auth.invalidate?.()
  window.removeEventListener("hashchange",onHistory)
  window.removeEventListener("popstate",onHistory)
  window.removeEventListener("keydown",handleMobileNavKey)
  password.value=""
  publicToken.value=""
  projectContext.clear()
})
</script>
<template>
  <ToastHost />
  <div v-if="loading" role="status" class="grid min-h-screen place-items-center text-sm text-muted-foreground">{{t('app.loading')}}</div>
  <div v-else-if="publicFlow" class="grid min-h-screen place-items-center bg-muted/30 p-6">
    <PublicAccountPage :key="`${publicFlow}:${publicLinkRevision}`" :mode="publicFlow" :initial-token="publicToken" @token-copied="publicToken=''" @back="closePublicFlow" />
  </div>
  <div v-else-if="missingTransport" class="grid min-h-screen place-items-center p-6">
    <section class="w-full max-w-lg rounded-xl border border-border bg-card p-6 text-center shadow-sm" role="status">
      <h1 class="text-xl font-semibold">{{t('platform.brand')}}</h1>
      <p class="mt-3 text-sm text-muted-foreground">{{t('platform.adminApiNotConnected')}}</p>
      <p class="mt-2 text-xs text-muted-foreground">{{t('platform.noLegacyFallback')}}</p>
      <p v-if="publicLinkError" class="mt-3 text-sm text-destructive" role="alert">{{t('platform.ambiguousPublicLink')}}</p>
    </section>
  </div>
  <div v-else-if="unavailable" class="grid min-h-screen place-items-center p-6">
    <section class="w-full max-w-md rounded-xl border border-border bg-card p-6 text-center shadow-sm" role="alert">
      <h1 class="text-lg font-semibold">{{t('platform.brand')}}</h1>
      <p class="mt-2 text-sm text-muted-foreground">{{t(serviceUpgradingPossible?'platform.serviceUnavailableOrUpgrading':'platform.unverifiedOffline')}}</p>
      <Button class="mt-5" @click="restore">{{t('common.retry')}}</Button>
    </section>
  </div>
  <div v-else-if="!verified" class="grid min-h-screen place-items-center bg-muted/30 p-6">
    <section class="w-full max-w-sm rounded-xl border border-border bg-card p-6 shadow-sm">
      <h1 class="text-xl font-semibold">{{t('platform.brand')}}</h1>
      <p class="mt-1 text-sm text-muted-foreground">{{t('app.console')}}</p>
      <p v-if="projectContext.state.scope==='suspended'" class="mt-4 text-sm text-destructive" role="alert">{{t('platform.suspendedNotice')}}</p>
      <p v-if="publicLinkError" class="mt-4 text-sm text-destructive" role="alert">{{t('platform.ambiguousPublicLink')}}</p>
      <form class="mt-6 space-y-4" @submit.prevent="login">
        <label class="block space-y-1.5 text-sm"><span>{{t('app.username')}}</span><input v-model="username" autocomplete="username" class="field" required /></label>
        <label class="block space-y-1.5 text-sm"><span>{{t('app.password')}}</span><input v-model="password" type="password" autocomplete="current-password" class="field" required /></label>
        <p v-if="error" class="text-sm text-destructive" role="alert">{{error}}</p>
        <Button class="w-full" type="submit" :disabled="submitting">{{t('app.signIn')}}</Button>
      </form>
      <div class="mt-4 flex flex-wrap justify-center gap-2">
        <Button variant="ghost" size="sm" @click="publicFlow='invitation'">{{t('platform.haveInvitation')}}</Button>
        <Button variant="ghost" size="sm" @click="publicFlow='reset'">{{t('platform.haveResetLink')}}</Button>
      </div>
    </section>
  </div>
  <div v-else class="min-h-screen bg-background text-foreground md:grid" :class="sidebarCollapsed?'md:grid-cols-[68px_minmax(0,1fr)]':'md:grid-cols-[240px_minmax(0,1fr)]'">
    <button v-if="mobileNavOpen" class="fixed inset-0 z-30 bg-black/40 md:hidden" :aria-label="t('platform.closeMenu')" tabindex="-1" @click="closeMobileNav" />
    <aside ref="mobileNavPanel" tabindex="-1" :inert="isMobile&&!mobileNavOpen" :aria-hidden="isMobile&&!mobileNavOpen?'true':undefined" :role="mobileNavOpen?'dialog':undefined" :aria-modal="mobileNavOpen?'true':undefined" :aria-label="t('platform.navigation.title')" @click="handleSidebarClick"
      class="fixed inset-y-0 left-0 z-40 h-screen w-60 overflow-y-auto border-r border-border bg-sidebar p-3 transition-transform md:sticky md:top-0 md:w-auto md:translate-x-0"
      :class="mobileNavOpen?'translate-x-0':'-translate-x-full'">
      <div class="mb-5 flex h-10 items-center justify-between">
        <div v-if="!sidebarCollapsed||mobileNavOpen" class="truncate px-2 font-semibold tracking-tight">{{t('platform.brand')}}</div>
        <Button variant="ghost" size="icon" class="hidden md:inline-flex" :aria-label="t('platform.toggleSidebar')" @click="sidebarCollapsed=!sidebarCollapsed"><PanelLeftOpen v-if="sidebarCollapsed" class="size-4"/><PanelLeftClose v-else class="size-4"/></Button>
        <Button variant="ghost" size="icon" class="md:hidden" :aria-label="t('platform.closeMenu')" @click="closeMobileNav"><X class="size-4"/></Button>
      </div>
      <PlatformNav :collapsed="sidebarCollapsed&&!mobileNavOpen" :active-page="activePage" />
    </aside>
    <main class="min-w-0">
      <header class="sticky top-0 z-20 flex min-h-14 flex-wrap items-center gap-2 border-b border-border bg-background/95 px-3 py-2 backdrop-blur sm:px-6">
        <Button id="mobile-nav-trigger" variant="ghost" size="icon" class="md:hidden" :aria-label="t('platform.openMenu')" :aria-expanded="mobileNavOpen" @click="mobileNavOpen=true"><Menu class="size-4"/></Button>
        <h1 id="briareus-page-title" tabindex="-1" class="min-w-0 flex-1 truncate text-sm text-muted-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring">{{title}}</h1>
        <div class="ml-auto flex min-w-0 flex-wrap items-center justify-end gap-2">
          <ContextSwitcher />
          <ScopedRealtimeStatus />
          <span class="hidden max-w-32 truncate text-xs text-muted-foreground lg:inline">{{projectContext.coreOwnerReady()?projectContext.state.user?.label:t('platform.ownerBoundaryState.unknown')}}</span>
          <Button variant="ghost" size="icon" :aria-label="t('settings.theme')" @click="theme=theme==='dark'?'light':'dark'"><Sun v-if="theme==='dark'" class="size-4"/><Moon v-else class="size-4"/></Button>
          <Button variant="outline" size="sm" :disabled="submitting" @click="logout">{{t('app.signOut')}}</Button>
        </div>
      </header>
      <div class="mx-auto w-full max-w-[1600px] p-3 sm:p-6">
        <OperationProgress :active-page="activePage" />
        <component :is="screen" :key="`${projectContext.state.revision}:${activePage}`" v-bind="resourcePage[activePage]?{resource:resourcePage[activePage]}:{}" />
      </div>
    </main>
  </div>
</template>
