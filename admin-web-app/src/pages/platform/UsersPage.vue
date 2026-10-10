<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { projectContext } from "@/features/platform/model/project-context"
import { platformPort } from "@/features/platform/api/port"
import { useCommand, useDomain, sourceMutationReady } from "@/features/platform/model/use-domain"
import { refreshAuthenticatedProjection } from "@/features/platform/model/refresh-identity"
import type { InvitationView, UserView } from "@/features/platform/model/contracts"
import PlatformFeedback from "@/features/platform/ui/PlatformFeedback.vue"
import ConfirmAction from "@/features/platform/ui/ConfirmAction.vue"
import Button from "@/shared/ui/Button.vue"
import InstantTime from "@/shared/ui/InstantTime.vue"
import PageHeader from "@/shared/ui/PageHeader.vue"
import ScopedSearch from "@/features/platform/ui/ScopedSearch.vue"
import { matchesLoaded } from "@/features/platform/model/scoped-search"
import { hasCurrentRecordRevision } from "@/features/platform/model/current-record"

const { t } = useI18n()
const users = useDomain<UserView>("users", "users.read", (port, ctx, after) => port.users.list(ctx,after),
  ["operator"],()=>true,item=>item.id)
const userSearch=ref("")
const filteredUsers=computed(()=>users.state.items.filter(user=>
  matchesLoaded(userSearch.value,user.username,user.displayName,user.id)))
const invitations = useDomain<InvitationView>("users", "invitations.issue", (port, ctx, after) => port.users.invitations(ctx,after),
  ["account","team","project","operator"],()=>true,item=>item.id)
const command = useCommand()
/** No accepted A11 source owner command-status identity for global Identity
 * changes yet: buttons remain disabled, with explicit UX explanation. */
const globalWriteReady=computed(()=>sourceMutationReady("profile.password",null))
const passwords = reactive({ current: "", next: "", confirmation: "" })
const passwordError = ref("")
const clock = ref(Date.now())
let clockInterval: ReturnType<typeof setInterval> | null = null
onMounted(() => { clockInterval=setInterval(()=>{clock.value=Date.now()},30_000) })
const issuedLink = ref<{ kind: "invitation" | "reset"; url: string; expiresAt: string | null } | null>(null)
const revealIssuedLink=ref(false)
const confirmation = ref<{ type: "suspend" | "role" | "remove" | "reset" | "invitation"; user?: UserView; invitationId?: string; target: string } | null>(null)
const can = projectContext.can
function invitationActive(item:InvitationView):boolean {
  return !item.consumedAt && !item.revokedAt && (!item.expiresAt || Date.parse(item.expiresAt)>clock.value)
}
function invitationStatus(item:InvitationView):string {
  if(item.consumedAt)return t("platform.used")
  if(item.revokedAt)return t("platform.revoked")
  if(item.expiresAt&&(!Number.isFinite(Date.parse(item.expiresAt))||Date.parse(item.expiresAt)<=clock.value))
    return t("platform.expiredLink")
  return t("platform.active")
}
function askRevokeInvitation(item:InvitationView):void {
  if(!invitationActive(item)||!can("invitations.revoke")||command.state.busy||command.state.reconciliationRequired)return
  confirmation.value={type:"invitation",invitationId:item.id,target:item.id}
}
/** Exact A5 per-record action codes; role or User UUID is NOT permission. */
function rowAction(user:UserView,type:"suspend"|"role"|"remove"|"reset"):boolean {
  if(!hasCurrentRecordRevision(user))return false
  const codes=user.sourceActions??[]
  const required=type==="suspend"?(user.active?"identity.suspend":"identity.restore"):
    type==="role"?(user.isSuperuser?"identity.superuser.demote":"identity.superuser.promote"):
    type==="remove"?"identity.delete":"identity.password_reset.issue"
  return codes.includes(required)
}
function sameUserAuthority(left:UserView,right:UserView):boolean {
  return hasCurrentRecordRevision(left)&&hasCurrentRecordRevision(right)&&
    left.revision===right.revision&&
    JSON.stringify(left.allowedActions??{})===JSON.stringify(right.allowedActions??{})&&
    left.id===right.id&&left.active===right.active&&
    left.isSuperuser===right.isSuperuser&&
    left.ownsTeams===right.ownsTeams&&
    left.ownsPersonalProjects===right.ownsPersonalProjects&&
    JSON.stringify([...(left.sourceActions??[])].sort())===JSON.stringify([...(right.sourceActions??[])].sort())
}
function ownAssetsBlocked(user:UserView):boolean {
  // A6's per-User source `identity.delete` is calculated against all
  // ownership obligations and the last active superuser in the database.
  // Operator-visible Team/Project lists are NOT a complete User-owned count.
  return !user.sourceActions?.includes("identity.delete")
}

const passwordValid = computed(() => passwords.current.length > 0 && passwords.next.length >= 12 && passwords.next.length <= 4096 && passwords.next === passwords.confirmation)
const unsubscribe = projectContext.onTransition(() => {
  issuedLink.value = null
  revealIssuedLink.value=false
  passwords.current = ""
  passwords.next = ""
  passwords.confirmation = ""
  confirmation.value = null
})
onBeforeUnmount(()=>{
  unsubscribe()
  if(clockInterval!==null)clearInterval(clockInterval)
  issuedLink.value=null
  revealIssuedLink.value=false
  passwords.current="";passwords.next="";passwords.confirmation=""
})
watch([() => users.state.items, () => invitations.state.items, userSearch], () => {
  const pending=confirmation.value
  if(!pending)return
  if(pending.type==="invitation"){
    const invitation=invitations.state.items.find(item=>item.id===pending.invitationId)
    if(!invitation||invitation.revokedAt||invitation.consumedAt||
       (invitation.expiresAt&&Date.parse(invitation.expiresAt)<=Date.now()))confirmation.value=null
  }else if(pending.user){
    const current=users.state.items.find(item=>item.id===pending.user?.id)
    if(!current||!sameUserAuthority(current,pending.user)){
      confirmation.value=null
    }
  }
})

async function copyPrivateLink() {
  if (!issuedLink.value) return
  try { await navigator.clipboard.writeText(issuedLink.value.url) } catch { /* user can manually select the link */ }
}
async function changePassword() {
  passwordError.value = ""
  if (!globalWriteReady.value)return
  if (!passwordValid.value) { passwordError.value = String(t("platform.passwordMismatch")); return }
  const updated = await command.submit("profile.password", (port, ctx) => port.users.changePassword(ctx, passwords.current, passwords.next))
  passwords.current = ""; passwords.next = ""; passwords.confirmation = ""
  if (updated) {
    // A password change increments credential_version; the old login bearer
    // can no longer be treated as an authenticated principal in this UI.
    platformPort.value?.auth.invalidate?.()
    projectContext.clear()
  }
}
async function issue() {
  if(!globalWriteReady.value)return
  // Never expose a one-use URL just because the initial Identity owner
  // returned a response: other owner acknowledgements may remain UNKNOWN.
  let newLink:{url:string;expiresAt:string|null}|null=null
  try {
    const done=await command.submit("invitations.issue",async(port,ctx)=>{
      const issued=await port.users.issueInvitation(ctx)
      if(!ctx.signal.aborted)newLink={url:issued.invitationUrl,expiresAt:issued.expiresAt}
    })
    if(done && newLink && projectContext.state.user?.active){
      issuedLink.value={kind:"invitation",...newLink}
      revealIssuedLink.value=false
      await invitations.reload()
    }
  }finally{
    newLink=null
  }
}
async function confirmAction() {
  const pending = confirmation.value
  if (!pending||!globalWriteReady.value) return
  const ability = pending.type === "invitation" ? "invitations.revoke" : pending.type === "role" ? "users.roles" : pending.type === "reset" ? "users.resetPassword" : "users.manage"
  const globalAction = pending.type === "suspend" || pending.type === "role" || pending.type === "remove" || pending.type === "reset"
  if (globalAction && (projectContext.state.scope !== "operator" || !projectContext.state.user?.isSuperuser)) return
  if (!can(ability) || (pending.user && pending.user.allowedActions?.[ability] !== true)) return
  if(pending.user && !rowAction(pending.user,pending.type as "suspend"|"role"|"remove"|"reset"))return
  if (pending.type === "remove" && pending.user && ownAssetsBlocked(pending.user)) return
  if (pending.type === "invitation") {
    const current = invitations.state.items.find(item=>item.id===pending.invitationId)
    if(!current||current.consumedAt||current.revokedAt||
       (current.expiresAt && Date.parse(current.expiresAt)<=Date.now()))return
  }
  if (pending.user) {
    const current=users.state.items.find(item=>item.id===pending.user?.id)
    if(!current||!sameUserAuthority(current,pending.user)||
       !rowAction(current,pending.type as "suspend"|"role"|"remove"|"reset"))return
  }
  let pendingResetLink:{url:string;expiresAt:string|null}|null=null
  const done = await command.submit(
    pending.type === "invitation" ? "invitations.revoke" : pending.type === "role" ? "users.roles" : pending.type === "reset" ? "users.resetPassword" : "users.manage",
    async (port, ctx) => {
      if (pending.type === "invitation" && pending.invitationId) await port.users.revokeInvitation(ctx, pending.invitationId)
      else if (pending.user && pending.type === "suspend") await port.users.setActive(ctx, pending.user, !pending.user.active)
      else if (pending.user && pending.type === "role") await port.users.setSuperuser(ctx, pending.user, !pending.user.isSuperuser)
      else if (pending.user && pending.type === "remove") await port.users.remove(ctx, pending.user)
      else if (pending.user && pending.type === "reset") {
        const result = await port.users.issueReset(ctx, pending.user.id)
        if(!ctx.signal.aborted){
          pendingResetLink={url:result.invitationUrl,expiresAt:result.expiresAt}
        }
      }
    },
  )
  if(done&&pendingResetLink&&pending.type==="reset"&&projectContext.state.user?.active){
    issuedLink.value={kind:"reset",...pendingResetLink}
    revealIssuedLink.value=false
  }
  pendingResetLink=null
  if (done) {
    confirmation.value = null
    // Privilege and account changes refresh current principal FIRST; old
    // operator rights cannot be used to fire an unrelated User GET after a
    // successful downgrade, self-suspension or password reset.
    if (pending.type !== "invitation" && pending.type !== "reset") await refreshAuthenticatedProjection()
    void users.reload()
    void invitations.reload()
  }
}
</script>
<template>
  <div class="space-y-6">
    <PageHeader :title="t('platform.users')" :description="t('platform.usersHint')" />
    <p v-if="!globalWriteReady" role="status" class="rounded-md border border-border bg-muted/30 p-3 text-xs text-muted-foreground">{{t('platform.globalCommandStatusMissing')}}</p>
    <section class="settings-card space-y-3">
      <h2 class="font-semibold">{{t('platform.changePassword')}}</h2>
      <form class="grid gap-3 sm:grid-cols-3" @submit.prevent="changePassword">
        <label class="text-xs">{{t('platform.currentPassword')}}<input v-model="passwords.current" class="field mt-1" type="password" autocomplete="current-password" :disabled="!can('profile.password') || !globalWriteReady || (command.state.busy || command.state.reconciliationRequired)" /></label>
        <label class="text-xs">{{t('platform.newPassword')}}<input v-model="passwords.next" class="field mt-1" type="password" autocomplete="new-password" :disabled="!can('profile.password') || !globalWriteReady || (command.state.busy || command.state.reconciliationRequired)" /></label>
        <label class="text-xs">{{t('platform.confirmPassword')}}<input v-model="passwords.confirmation" class="field mt-1" type="password" autocomplete="new-password" :disabled="!can('profile.password') || !globalWriteReady || (command.state.busy || command.state.reconciliationRequired)" /></label>
        <div class="sm:col-span-3"><Button type="submit" size="sm" :disabled="!can('profile.password') || !globalWriteReady || (command.state.busy || command.state.reconciliationRequired) || !passwordValid">{{t('common.save')}}</Button></div>
      </form>
      <p v-if="passwordError" class="text-sm text-destructive" role="alert">{{passwordError}}</p>
    </section>
    <section class="settings-card space-y-3">
      <div class="flex flex-wrap items-center justify-between gap-3"><div><h2 class="font-semibold">{{t('platform.invitations')}}</h2><p class="mt-1 text-xs text-muted-foreground">{{t('platform.invitationsHint')}}</p></div><Button size="sm" :disabled="!can('invitations.issue') || !globalWriteReady || (command.state.busy || command.state.reconciliationRequired)" @click="issue">{{t('platform.issueInvitation')}}</Button></div>
      <div v-if="issuedLink?.kind==='invitation'" class="rounded-lg border border-border bg-muted/30 p-3 text-sm"><p class="font-medium">{{t('platform.secretLink')}}</p><input class="field mt-2" readonly :type="revealIssuedLink?'text':'password'" :value="issuedLink.url" :aria-label="t('platform.secretLink')" @focus="($event.target as HTMLInputElement).select()"/><p class="mt-2 text-xs text-muted-foreground"><InstantTime v-if="issuedLink.expiresAt" :value="issuedLink.expiresAt" /><span v-else>{{t('platform.untilRevoked')}}</span></p><Button variant="outline" size="sm" class="mt-2" @click="copyPrivateLink">{{t('platform.copyLink')}}</Button><Button variant="ghost" size="sm" class="mt-2" @click="revealIssuedLink=!revealIssuedLink">{{t(revealIssuedLink?'platform.maskPrivateLink':'platform.revealPrivateLink')}}</Button><Button variant="ghost" size="sm" class="mt-2" @click="issuedLink=null">{{t('platform.hidePrivateLink')}}</Button></div>
      <PlatformFeedback :status="invitations.state.status" :error="invitations.state.error" @retry="invitations.reload" /><p v-if="invitations.state.hasMore" role="status" class="rounded-md border border-border p-3 text-xs text-muted-foreground">{{t('platform.a6PartialPage')}}</p>
      <div v-if="invitations.state.status === 'ready'" class="overflow-x-auto"><table class="w-full min-w-[480px] text-left text-sm"><thead class="text-xs text-muted-foreground"><tr><th class="py-2">{{t('platform.issuer')}}</th><th>{{t('platform.linkType')}}</th><th>{{t('platform.expiration')}}</th><th>{{t('common.status')}}</th><th>{{t('common.actions')}}</th></tr></thead><tbody><tr v-for="invitation in invitations.state.items" :key="invitation.id" class="border-t border-border"><td class="py-2">{{invitation.issuerLabel}}</td><td>{{invitation.kind==='password_reset'?t('platform.resetTitle'):t('platform.registerTitle')}}</td><td><InstantTime v-if="invitation.expiresAt" :value="invitation.expiresAt" /><span v-else>{{t('platform.untilRevoked')}}</span></td><td>{{invitationStatus(invitation)}}</td><td><Button variant="outline" size="sm" :disabled="!can('invitations.revoke') || !globalWriteReady || !invitationActive(invitation) || (command.state.busy || command.state.reconciliationRequired)" @click="askRevokeInvitation(invitation)">{{t('platform.revoke')}}</Button></td></tr></tbody></table></div>
      <div v-if="invitations.state.hasMore" class="flex items-center gap-2">
        <Button variant="outline" size="sm" :disabled="invitations.state.loadingMore || !invitations.state.nextAfterId" @click="invitations.loadMore">{{t('platform.loadMoreA6')}}</Button>
        <span v-if="invitations.state.loadingMore" role="status" class="text-xs text-muted-foreground">{{t('app.loading')}}</span>
      </div>
      <p v-if="invitations.state.loadMoreError" role="alert" class="text-xs text-destructive">{{t(`platform.errors.${invitations.state.loadMoreError.message}`)}}</p>
    </section>
    <section class="settings-card space-y-3">
      <div class="flex flex-wrap items-center justify-between gap-3"><div><h2 class="font-semibold">{{t('platform.userDirectory')}}</h2><p class="mt-1 text-xs text-muted-foreground">{{t('platform.userDirectoryHint')}}</p></div><Button size="sm" variant="outline" :disabled="projectContext.state.scope!=='operator' || !can('users.read')" @click="users.reload">{{t('common.refresh')}}</Button></div>
      <div v-if="issuedLink?.kind==='reset'" class="rounded-lg border border-border bg-muted/30 p-3 text-sm" role="status"><p class="font-medium">{{t('platform.passwordResetLinkIssued')}}</p><p class="mt-1 text-xs text-muted-foreground">{{t('platform.passwordResetLinkHint')}}</p><input class="field mt-2" readonly :type="revealIssuedLink?'text':'password'" :value="issuedLink.url" :aria-label="t('platform.passwordResetLinkIssued')" @focus="($event.target as HTMLInputElement).select()"/><p class="mt-2 text-xs text-muted-foreground"><InstantTime v-if="issuedLink.expiresAt" :value="issuedLink.expiresAt" /><span v-else>{{t('platform.untilRevoked')}}</span></p><Button size="sm" variant="outline" class="mt-2" @click="copyPrivateLink">{{t('platform.copyLink')}}</Button><Button variant="ghost" size="sm" class="mt-2" @click="revealIssuedLink=!revealIssuedLink">{{t(revealIssuedLink?'platform.maskPrivateLink':'platform.revealPrivateLink')}}</Button><Button variant="ghost" size="sm" class="mt-2" @click="issuedLink=null">{{t('platform.hidePrivateLink')}}</Button></div>
      <PlatformFeedback :status="users.state.status" :error="users.state.error" @retry="users.reload" />
      <ScopedSearch v-if="users.state.status==='ready'" v-model="userSearch" :label="t('platform.searchUsers')" :total="users.state.items.length" :visible="filteredUsers.length" :partial="users.state.possiblyTruncated||users.state.hasMore" />
      <p v-if="users.state.status==='ready'&&userSearch&&!filteredUsers.length" role="status" class="text-xs text-muted-foreground">{{t('platform.noSearchResults')}}</p><p v-if="users.state.hasMore" role="status" class="rounded-md border border-border p-3 text-xs text-muted-foreground">{{t('platform.a6PartialPage')}}</p>
      <div v-if="users.state.status === 'ready'" class="overflow-x-auto"><table class="w-full min-w-[640px] text-left text-sm"><thead class="text-xs text-muted-foreground"><tr><th class="py-2">{{t('platform.user')}}</th><th>{{t('common.status')}}</th><th>{{t('platform.role')}}</th><th>{{t('common.actions')}}</th></tr></thead><tbody><tr v-for="user in filteredUsers" :key="user.id" class="border-t border-border"><td class="py-3"><div class="font-medium">{{user.displayName || user.username}}</div><div class="text-xs text-muted-foreground">{{user.username}}</div><div class="font-mono text-[10px] text-muted-foreground" :title="user.id">{{user.id}}</div></td><td>{{user.active ? t('platform.active') : t('platform.suspended')}}</td><td>{{user.isSuperuser ? 'superuser' : 'User'}}</td><td><div class="flex flex-wrap gap-1"><Button size="sm" variant="outline" :disabled="projectContext.state.scope!=='operator' || !can('users.manage') || !globalWriteReady || user.allowedActions?.['users.manage']!==true || !rowAction(user,'suspend') || (command.state.busy || command.state.reconciliationRequired)" @click="confirmation={type:'suspend',user,target:user.id}">{{user.active?t('platform.suspend'):t('platform.unsuspend')}}</Button><Button size="sm" variant="outline" :disabled="projectContext.state.scope!=='operator' || !can('users.roles') || !globalWriteReady || user.allowedActions?.['users.roles']!==true || !rowAction(user,'role') || (command.state.busy || command.state.reconciliationRequired)" @click="confirmation={type:'role',user,target:user.id}">{{t('platform.changeRole')}}</Button><Button size="sm" variant="outline" :disabled="projectContext.state.scope!=='operator' || !can('users.resetPassword') || !globalWriteReady || user.allowedActions?.['users.resetPassword']!==true || !rowAction(user,'reset') || (command.state.busy || command.state.reconciliationRequired)" @click="confirmation={type:'reset',user,target:user.id}">{{t('platform.resetPassword')}}</Button><Button size="sm" variant="destructive" :disabled="projectContext.state.scope!=='operator' || !can('users.manage') || !globalWriteReady || user.allowedActions?.['users.manage']!==true || ownAssetsBlocked(user) || !rowAction(user,'remove') || (command.state.busy || command.state.reconciliationRequired)" @click="confirmation={type:'remove',user,target:user.id}">{{t('common.delete')}}</Button></div></td></tr></tbody></table></div>
      <div v-if="users.state.hasMore" class="flex items-center gap-2"><Button variant="outline" size="sm" :disabled="users.state.loadingMore || !users.state.nextAfterId" @click="users.loadMore">{{t('platform.loadMoreA6')}}</Button><span v-if="users.state.loadingMore" role="status" class="text-xs text-muted-foreground">{{t('app.loading')}}</span></div>
      <p v-if="users.state.loadMoreError" role="alert" class="text-xs text-destructive">{{t(`platform.errors.${users.state.loadMoreError.message}`)}}</p>
      <p class="text-xs text-muted-foreground">{{t('platform.ownershipGuards')}} {{t('platform.dangerTargetIdNotice')}}</p>
    </section>
    <PlatformFeedback status="idle" :action-error="command.state.error" :reconciled="command.state.reconciliationNotice" :busy="command.state.busy" @reconcile="command.reconcile" />
    <ConfirmAction :open="!!confirmation" :busy="command.state.busy" :title="t('platform.confirmDanger')" :detail="t('platform.dangerHint')" :target="confirmation?.target ?? ''" @cancel="confirmation=null" @confirm="confirmAction" />
  </div>
</template>
