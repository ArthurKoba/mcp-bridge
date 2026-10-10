<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { canonicalUuid4, type TeamMemberView, type TeamView } from "@/features/platform/model/contracts"
import { useCommand, useDomain, sourceMutationReady } from "@/features/platform/model/use-domain"
import { refreshAuthenticatedProjection } from "@/features/platform/model/refresh-identity"
import { projectContext } from "@/features/platform/model/project-context"
import { platformPort } from "@/features/platform/api/port"
import PlatformFeedback from "@/features/platform/ui/PlatformFeedback.vue"
import ConfirmAction from "@/features/platform/ui/ConfirmAction.vue"
import Button from "@/shared/ui/Button.vue"
import PageHeader from "@/shared/ui/PageHeader.vue"
import ScopedSearch from "@/features/platform/ui/ScopedSearch.vue"
import { matchesLoaded } from "@/features/platform/model/scoped-search"
import { appendVerifiedKeyset } from "@/features/platform/model/scoped-keyset"
import { hasCurrentDecisionEpoch } from "@/features/platform/model/current-record"

const { t } = useI18n()
const teams = useDomain<TeamView>("teams", "teams.read", (port, ctx) => port.teams.list(ctx))
const command = useCommand()
const teamSearch=ref("")
const filteredTeams=computed(()=>teams.state.items.filter(team=>
  matchesLoaded(teamSearch.value,team.name,team.ownerLabel,team.id)))
const teamName = ref("")
const chosenId = ref(projectContext.state.activeTeamKey??"")
const newMemberId = ref("")
const newOwnerId = ref("")
const pending = ref<{ kind: "remove" | "transfer"; team: TeamView; userId: string; label: string } | null>(null)
const can = projectContext.can
function currentTeamEpoch(team:TeamView):boolean {
  return hasCurrentDecisionEpoch(team,projectContext.state.teamDecisionVersions[team.id]??null)
}
const createReady=computed(()=>sourceMutationReady("teams.create",null))
const memberReady=computed(()=>Boolean(active.value&&currentTeamEpoch(active.value)&&
  active.value.allowedActions?.["teams.members"]===true&&sourceMutationReady("teams.members",{
  operation:"team.member.add",target:{kind:"team",id:active.value.id},
})))
const ownershipReady=computed(()=>Boolean(active.value&&currentTeamEpoch(active.value)&&
  active.value.allowedActions?.["teams.ownership"]===true&&sourceMutationReady("teams.ownership",{
  operation:"team.owner.transfer",target:{kind:"team",id:active.value.id},
})))
const active = computed(() => teams.state.items.find(team => team.id === chosenId.value) ?? null)
const moreMembers=ref<TeamMemberView[]>([])
const memberCursor=ref<string|null>(null)
const memberHasMore=ref<boolean|null>(null)
const memberLoading=ref(false)
const memberError=ref(false)
let memberRequest:AbortController|null=null
function resetMemberPages():void {
  memberRequest?.abort()
  memberRequest=null
  moreMembers.value=[]
  memberCursor.value=null
  memberHasMore.value=null
  memberLoading.value=false
  memberError.value=false
}
const activeMembers=computed(() => [...(active.value?.members??[]),...moreMembers.value])
const canLoadMembers=computed(()=>Boolean(
  active.value && !memberLoading.value && projectContext.can("teams.read") &&
  (memberHasMore.value ?? active.value.memberHasMore) &&
  (memberCursor.value ?? active.value.memberNextAfterId) &&
  platformPort.value?.teams.memberPage,
))
async function loadMoreMembers():Promise<void>{
  const team=active.value
  const port=platformPort.value
  const after=memberCursor.value??team?.memberNextAfterId
  const scope=projectContext.selection()
  const revision=projectContext.state.revision
  if(!team||!port?.teams.memberPage||!after||!scope||!canLoadMembers.value)return
  const ctrl=new AbortController()
  memberRequest=ctrl
  memberLoading.value=true
  memberError.value=false
  try {
    const result=await port.teams.memberPage({scope,signal:ctrl.signal,revision,
      decisionVersion:scope.kind==="team"?projectContext.state.teamDecisionVersions[scope.teamId]??null:
        scope.kind==="project"?projectContext.state.projectDecisionVersions[scope.projectId]??null:null},team,after)
    if(ctrl.signal.aborted||revision!==projectContext.state.revision||port!==platformPort.value||
       active.value?.id!==team.id||active.value.decisionVersion!==team.decisionVersion||
       active.value.revision!==team.revision||!projectContext.can("teams.read"))return
    // Reject duplicates across pages and within a single page, backward
    // cursors and missing forward continuation before updating the UI.
    const next=appendVerifiedKeyset(activeMembers.value,result,after,item=>item.userId)
    moreMembers.value=next.rows.slice(active.value?.members?.length??0)
    memberCursor.value=next.next
    memberHasMore.value=next.hasMore
  }catch {
    if(!ctrl.signal.aborted&&revision===projectContext.state.revision)memberError.value=true
  }finally{
    if(memberRequest===ctrl){memberRequest=null;memberLoading.value=false}
  }
}
watch(chosenId,resetMemberPages)
watch(()=>teams.state.items,resetMemberPages)
onBeforeUnmount(resetMemberPages)
watch(() => projectContext.state.revision, () => {
  // A new owner BFF proof may rotate revision on an otherwise valid Team.
  // Keep explicit Team ID selected, discard only stale form/confirmation.
  newMemberId.value = ""; newOwnerId.value = ""; pending.value = null
})
watch(()=>projectContext.state.activeTeamKey,key=>{
  if(key&&key!==chosenId.value)chosenId.value=key
})
// Never silently switch to a DIFFERENT Team after membership removal or a
// list refresh. Selection is always an explicit User choice.
watch(() => [teams.state.status,teams.state.items.map(team => team.id).join("|")] as const, () => {
  // A loading/blocked/denied projection is not proof of Team deletion.
  if(!["ready","empty"].includes(teams.state.status))return
  if(teams.state.hasMore||teams.state.possiblyTruncated)return
  if(chosenId.value&&!teams.state.items.some(item=>item.id===chosenId.value)){
    chosenId.value=""
    newMemberId.value=""
    newOwnerId.value=""
    pending.value=null
  }
})
watch(chosenId,()=>{
  newMemberId.value=""
  newOwnerId.value=""
  pending.value=null
})
// Team member/owner changes invalidate old confirmation snapshots even when
// the selected Team ID stays the same across a list refresh.
watch(() => teams.state.items, () => {
  const attempt=pending.value
  if (!attempt) return
  const now=teams.state.items.find(team=>team.id===attempt.team.id)
  if (!now || now.revision!==attempt.team.revision ||
      now.decisionVersion!==attempt.team.decisionVersion ||
      now.ownerId!==attempt.team.ownerId ||
      (attempt.kind==="remove" && !now.members?.some(member=>member.userId===attempt.userId && member.active && !member.owner))) {
    pending.value=null
  }
})

async function createTeam() {
  const name = teamName.value.trim()
  if (!name||!createReady.value) return
  const success = await command.submit("teams.create", (port, ctx) => port.teams.create(ctx, name))
  if (success) { teamName.value = ""; await refreshAuthenticatedProjection(); await teams.reload() }
}
async function addMember() {
  const team = active.value
  if (!team || !currentTeamEpoch(team)||!memberReady.value || team.allowedActions?.["teams.members"] !== true || !can("teams.members") || !canonicalUuid4(newMemberId.value.trim())) return
  const success = await command.submit("teams.members", (port, ctx) => port.teams.addMember(ctx, team, newMemberId.value.trim()),
    {operation:"team.member.add",target:{kind:"team",id:team.id}})
  if (success) { newMemberId.value = ""; await refreshAuthenticatedProjection(); await teams.reload() }
}
async function confirmAction() {
  const action = pending.value
  const current=active.value
  if (!action || !current || !currentTeamEpoch(current)||current.id!==action.team.id ||
      current.revision!==action.team.revision || current.decisionVersion!==action.team.decisionVersion ||
      current.ownerId!==action.team.ownerId ||
      !can(action.kind === "transfer" ? "teams.ownership" : "teams.members") ||
      !sourceMutationReady(action.kind === "transfer" ? "teams.ownership" : "teams.members",{
        operation:action.kind==="transfer"?"team.owner.transfer":"team.member.remove",target:{kind:"team",id:current.id},
      })) return
  if (current.allowedActions?.[action.kind === "transfer" ? "teams.ownership" : "teams.members"] !== true) return
  const success = await command.submit(action.kind === "transfer" ? "teams.ownership" : "teams.members", (port, ctx) => action.kind === "transfer"
    ? port.teams.transferOwner(ctx, current, action.userId)
    : port.teams.removeMember(ctx, current, action.userId),
    {operation:action.kind==="transfer"?"team.owner.transfer":"team.member.remove",target:{kind:"team",id:current.id}})
  if (success) { pending.value = null; newOwnerId.value = ""; await refreshAuthenticatedProjection(); await teams.reload() }
}
function askTransfer() {
  const team = active.value
  if (!team || !currentTeamEpoch(team)||!ownershipReady.value || !can("teams.ownership") || team.allowedActions?.["teams.ownership"] !== true || !canonicalUuid(newOwnerId.value) || newOwnerId.value === team.ownerId) return
  pending.value = { kind: "transfer", team, userId: newOwnerId.value, label: team.id }
}
</script>
<template>
  <div class="space-y-6">
    <p v-if="!createReady" role="status" class="rounded-md border border-border bg-muted/30 p-3 text-xs text-muted-foreground">{{t('platform.globalCommandStatusMissing')}}</p>
    <PageHeader :title="t('platform.teams')" :description="t('platform.teamHint')"><Button variant="outline" size="sm" :disabled="!can('teams.read')" @click="teams.reload">{{t('common.refresh')}}</Button></PageHeader>
    <section class="settings-card space-y-3">
      <h2 class="font-semibold">{{t('platform.createTeam')}}</h2>
      <form class="flex flex-wrap items-end gap-3" @submit.prevent="createTeam"><label class="min-w-52 flex-1 text-xs">{{t('platform.teamName')}}<input v-model="teamName" class="field mt-1" maxlength="255" :disabled="!createReady || (command.state.busy || command.state.reconciliationRequired)" required /></label><Button size="sm" type="submit" :disabled="!createReady || (command.state.busy || command.state.reconciliationRequired) || !teamName.trim()">{{t('common.add')}}</Button></form>
    </section>
    <section class="settings-card space-y-4">
      <h2 class="font-semibold">{{t('platform.myTeams')}}</h2>
      <PlatformFeedback :status="teams.state.status" :error="teams.state.error" @retry="teams.reload" />
      <ScopedSearch v-if="teams.state.status==='ready'" v-model="teamSearch" :label="t('platform.searchTeams')" :total="teams.state.items.length" :visible="filteredTeams.length" :partial="teams.state.possiblyTruncated||teams.state.hasMore" />
      <p v-if="teams.state.status==='ready'&&teamSearch&&!filteredTeams.length" role="status" class="text-xs text-muted-foreground">{{t('platform.noSearchResults')}}</p>
      <div v-if="teams.state.items.length" class="grid gap-5 lg:grid-cols-[250px_minmax(0,1fr)]">
        <nav class="space-y-1" :aria-label="t('platform.teams')"><button v-for="team in filteredTeams" :key="team.id" type="button" class="block w-full rounded-md px-3 py-2 text-left text-sm" :aria-pressed="team.id===chosenId" :class="team.id === chosenId ? 'bg-accent font-medium' : 'hover:bg-muted'" @click="chosenId=team.id">{{team.name}}<span class="block text-xs font-normal text-muted-foreground">{{team.ownerLabel}} · {{team.id.slice(0,8)}}</span></button></nav>
        <p v-if="!active" role="status" class="rounded-md border border-border p-3 text-xs text-muted-foreground">{{t('platform.chooseExplicitTeam')}}</p>
        <div v-if="active" class="min-w-0 space-y-4">
          <div><h3 class="text-base font-semibold">{{active.name}}</h3><p class="text-xs text-muted-foreground">{{t('platform.teamOwner')}}: {{active.ownerLabel}}</p></div>
          <p v-if="active.members===null" role="status" class="text-xs text-muted-foreground">{{t('platform.membersNotHydrated')}}</p>
          <p v-if="memberHasMore ?? active.memberHasMore" role="status" class="text-xs text-muted-foreground">{{t('platform.a6PartialPage')}}</p>
          <div class="overflow-x-auto"><table class="w-full min-w-[460px] text-left text-sm"><thead class="text-xs text-muted-foreground"><tr><th class="py-2">{{t('platform.user')}}</th><th>{{t('common.status')}}</th><th>{{t('common.actions')}}</th></tr></thead><tbody><tr v-for="member in activeMembers" :key="member.userId" class="border-t border-border"><td class="py-3">{{member.label}} · {{member.userId.slice(0,8)}} <span v-if="member.owner" class="text-xs text-muted-foreground">({{t('platform.teamOwner')}})</span></td><td>{{member.active?t('platform.active'):t('platform.suspended')}}</td><td><Button variant="outline" size="sm" :disabled="!sourceMutationReady('teams.members',{operation:'team.member.remove',target:{kind:'team',id:active.id}}) || active.allowedActions?.['teams.members']!==true || member.owner || (command.state.busy || command.state.reconciliationRequired)" @click="pending={kind:'remove',team:active,userId:member.userId,label:member.userId}">{{t('platform.removeMember')}}</Button></td></tr></tbody></table></div>
          <div v-if="canLoadMembers || memberLoading" class="flex items-center gap-2">
            <Button size="sm" variant="outline" :disabled="!canLoadMembers" @click="loadMoreMembers">{{t('platform.loadMoreA6')}}</Button>
            <span v-if="memberLoading" role="status" class="text-xs text-muted-foreground">{{t('app.loading')}}</span>
          </div>
          <p v-if="memberError" role="alert" class="text-xs text-destructive">{{t('platform.a6PageReadFailed')}}</p>
          <form class="flex flex-wrap items-end gap-2" @submit.prevent="addMember"><label class="min-w-52 flex-1 text-xs">{{t('platform.memberUserId')}}<input v-model="newMemberId" class="field mt-1" autocomplete="off" :disabled="!memberReady || (command.state.busy || command.state.reconciliationRequired)" required /></label><Button type="submit" size="sm" :disabled="!memberReady || active.allowedActions?.['teams.members']!==true || (command.state.busy || command.state.reconciliationRequired) || !canonicalUuid(newMemberId.trim())">{{t('platform.addMember')}}</Button><p v-if="newMemberId && !canonicalUuid(newMemberId.trim())" class="w-full text-xs text-destructive" role="status">{{t('platform.invalidUserUuid')}}</p></form>
          <form class="flex flex-wrap items-end gap-2 border-t border-border pt-4" @submit.prevent="askTransfer"><label class="min-w-52 flex-1 text-xs">{{t('platform.transferTeamOwner')}}<select v-model="newOwnerId" class="field mt-1" :disabled="!ownershipReady || (command.state.busy || command.state.reconciliationRequired)"><option value="">{{t('platform.chooseMember')}}</option><option v-for="member in activeMembers.filter(item => item.active && !item.owner)" :key="member.userId" :value="member.userId">{{member.label}}</option></select></label><Button type="submit" size="sm" variant="outline" :disabled="!ownershipReady || active.allowedActions?.['teams.ownership']!==true || (command.state.busy || command.state.reconciliationRequired) || !newOwnerId">{{t('platform.transfer')}}</Button></form>
          <p class="text-xs text-muted-foreground">{{t('platform.teamDeletionDeferred')}} {{t('platform.dangerTargetIdNotice')}}</p>
        </div>
      </div>
    </section>
    <PlatformFeedback status="idle" :action-error="command.state.error" :reconciled="command.state.reconciliationNotice" :busy="command.state.busy" @reconcile="command.reconcile" />
    <ConfirmAction :open="!!pending" :busy="command.state.busy" :title="t('platform.confirmDanger')" :detail="t('platform.dangerHint')" :target="pending?.label??''" @cancel="pending=null" @confirm="confirmAction" />
  </div>
</template>
