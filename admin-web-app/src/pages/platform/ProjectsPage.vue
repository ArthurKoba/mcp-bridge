<script setup lang="ts">
import { computed, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { refreshAuthenticatedProjection } from "@/features/platform/model/refresh-identity"
import { canonicalUuid4, type ProjectView, type TeamView, type SourceCommandBinding } from "@/features/platform/model/contracts"
import { useCommand, useDomain, sourceMutationReady } from "@/features/platform/model/use-domain"
import { projectContext } from "@/features/platform/model/project-context"
import PlatformFeedback from "@/features/platform/ui/PlatformFeedback.vue"
import ConfirmAction from "@/features/platform/ui/ConfirmAction.vue"
import Button from "@/shared/ui/Button.vue"
import PageHeader from "@/shared/ui/PageHeader.vue"
import ScopedSearch from "@/features/platform/ui/ScopedSearch.vue"
import { matchesLoaded } from "@/features/platform/model/scoped-search"
import { hasCurrentDecisionEpoch } from "@/features/platform/model/current-record"

const {t}=useI18n()
const projects = useDomain<ProjectView>("projects", "projects.read", (port, ctx) => port.projects.list(ctx))
const teams = useDomain<TeamView>("teams", "teams.read", (port, ctx) => port.teams.list(ctx))
const command = useCommand()
const projectSearch=ref("")
const filteredProjects=computed(()=>projects.state.items.filter(item=>
  matchesLoaded(projectSearch.value,item.name,item.projectId,item.owner.kind==='team'?item.owner.teamName:item.owner.userId)))
const name = ref("")
const ownerKind = ref<"user" | "team">("user")
const teamId = ref("")
const targetTeamId = ref("")
const selectedId = ref(projectContext.state.activeProjectKey??"")
const confirmation = ref<ProjectView | null>(null)
const adminConfirmation = ref<ProjectView | null>(null)
const adminOwnerKind = ref<"user" | "team">("user")
const adminOwnerUserId = ref("")
const adminOwnerTeamId = ref("")
const can=projectContext.can
const selected = computed(() => projects.state.items.find(project=>project.projectId===selectedId.value)??null)
const projectEpochReady=computed(()=>Boolean(selected.value&&
  hasCurrentDecisionEpoch(selected.value,projectContext.state.projectDecisionVersions[selected.value.projectId]??null)))
const currentUser = computed(() => projectContext.state.user?.key ?? "")
const createReady=computed(()=>sourceMutationReady("projects.create",null))
function transferBinding(project:ProjectView|null):SourceCommandBinding|null {
  if(!project)return null
  const scope=projectContext.selection()
  if(scope?.kind==="project"&&scope.projectId!==project.projectId)return null
  if(scope?.kind!=="project"&&scope?.kind!=="operator")return null
  return {operation:"project.transfer_owner",target:{kind:"project",id:project.projectId}}
}
const canTransfer = computed(() => Boolean(projectEpochReady.value&&selected.value?.lifecycleStatus==="active"&&
  selected.value.allowedActions?.["projects.transfer"]===true&&
  sourceMutationReady("projects.transfer",transferBinding(selected.value))))
const canReassign = computed(() => projectContext.state.scope === "operator" && Boolean(projectContext.state.user?.isSuperuser) &&
  Boolean(projectEpochReady.value&&selected.value?.lifecycleStatus==="active"&&selected.value.allowedActions?.["projects.transfer"]&&
    sourceMutationReady("projects.transfer",{operation:"project.admin_reassign",target:{kind:"project",id:selected.value.projectId}})))
const adminTarget = computed<ProjectView["owner"] | null>(() => {
  if (adminOwnerKind.value === "user") {
    return canonicalUuid4(adminOwnerUserId.value.trim()) ? {kind:"user",userId:adminOwnerUserId.value.trim()} : null
  }
  const team = teams.state.items.find(item => item.id === adminOwnerTeamId.value)
  return team ? {kind:"team",teamId:team.id,teamName:team.name} : null
})
const ownerTeam = computed(() => selected.value?.owner.kind === "team" ? teams.state.items.find(team => team.id === (selected.value?.owner.kind === "team" ? selected.value.owner.teamId : "")) : null)
const canWithdrawTeamProject=computed(()=>selected.value?.owner.kind!=="team" || Boolean(ownerTeam.value && ownerTeam.value.ownerId===currentUser.value))
watch(() => projectContext.state.revision, () => {
  confirmation.value = null; adminConfirmation.value = null
  // Keep the explicit Project choice across normal authenticated route
  // changes; never preserve a previously confirmed mutation/target choice.
  targetTeamId.value = ""; name.value = ""
  adminOwnerUserId.value = ""; adminOwnerTeamId.value = ""
})
watch(() => [projects.state.status,projects.state.items.map(project => project.projectId).join("|")] as const, () => {
  // Only a CURRENT successfully authorized list (ready or empty) proves
  // an old selected Project has vanished; loading/403 is UNKNOWN, not delete.
  if(!["ready","empty"].includes(projects.state.status))return
  if(projects.state.hasMore||projects.state.possiblyTruncated)return
  if(selectedId.value&&!projects.state.items.some(item=>item.projectId===selectedId.value)){
    selectedId.value="";confirmation.value=null;adminConfirmation.value=null
    targetTeamId.value=""
  }
})
watch(selectedId,()=>{
  confirmation.value=null;adminConfirmation.value=null;targetTeamId.value=""
})
watch(()=>projectContext.state.activeProjectKey,id=>{
  if(id && id!==selectedId.value)selectedId.value=id
})
watch(() => teams.state.items.map(team=>team.id).join("|"),()=>{
  // Never turn a stale selected Team UUID into another Team by name/order.
  if(teamId.value&&!teams.state.items.some(team=>team.id===teamId.value))teamId.value=""
  if(targetTeamId.value&&!teams.state.items.some(team=>team.id===targetTeamId.value))targetTeamId.value=""
  if(adminOwnerTeamId.value&&!teams.state.items.some(team=>team.id===adminOwnerTeamId.value))adminOwnerTeamId.value=""
})
watch(() => projects.state.items, () => {
  for(const candidate of [confirmation.value,adminConfirmation.value]) {
    if (!candidate) continue
    const now=projects.state.items.find(item=>item.projectId===candidate.projectId)
    if (!now || now.revision!==candidate.revision || now.decisionVersion!==candidate.decisionVersion ||
        JSON.stringify(now.owner)!==JSON.stringify(candidate.owner)) {
      confirmation.value=null
      adminConfirmation.value=null
      return
    }
  }
})

async function createProject() {
  const trimmed=name.value.trim()
  if (!trimmed || !createReady.value || !currentUser.value ||
      (ownerKind.value === "team" && !teams.state.items.some(team=>team.id===teamId.value)))return
  const owner: ProjectView["owner"] = ownerKind.value === "team" ? {kind:"team",teamId:teamId.value,teamName:teams.state.items.find(team=>team.id===teamId.value)?.name??""} : {kind:"user",userId:currentUser.value}
  const success=await command.submit("projects.create",(port,ctx)=>port.projects.create(ctx,{name:trimmed,owner}))
  if (success) { name.value="";await refreshAuthenticatedProjection();await projects.reload() }
}
function chooseProject(project:ProjectView) {
  if(project.lifecycleStatus!=="active"||!hasCurrentDecisionEpoch(project,
      projectContext.state.projectDecisionVersions[project.projectId]??null)||
      !projectContext.selectProject(project.projectId))return
  location.hash="#platform/projects"
}
function askTransfer() { if (selected.value) confirmation.value=selected.value }
function askAdminReassign(): void {
  if (!selected.value || !canReassign.value || !adminTarget.value || command.state.busy || command.state.reconciliationRequired) return
  adminConfirmation.value = selected.value
}
async function adminReassignProject(): Promise<void> {
  const project = adminConfirmation.value
  const owner = adminTarget.value
  if (!project || !owner || !canReassign.value || project.projectId !== selectedId.value) return
  if(owner.kind==="team"&&!teams.state.items.some(item=>item.id===owner.teamId))return
  const success = await command.submit("projects.transfer", (port,ctx) => port.projects.adminReassign(ctx, project, owner),
    {operation:"project.admin_reassign",target:{kind:"project",id:project.projectId}})
  if (success) {
    adminConfirmation.value = null
    adminOwnerUserId.value = ""
    adminOwnerTeamId.value = ""
    await refreshAuthenticatedProjection()
    await projects.reload()
  }
}
async function transferProject() {
  const project=confirmation.value
  if (!project || !canTransfer.value || !canWithdrawTeamProject.value || project.projectId !== selectedId.value) return
  let owner: ProjectView["owner"]
  if (project.owner.kind === "user") {
    const team=teams.state.items.find(item=>item.id===targetTeamId.value)
    if (!team) return
    owner={kind:"team",teamId:team.id,teamName:team.name}
  } else {
    const team=ownerTeam.value
    if (!team) return
    owner={kind:"user",userId:team.ownerId}
  }
  const binding=transferBinding(project)
  if(!binding||!sourceMutationReady("projects.transfer",binding))return
  const success=await command.submit("projects.transfer",(port,ctx)=>port.projects.transfer(ctx,project,owner),binding)
  if (success) { confirmation.value=null;targetTeamId.value="";await refreshAuthenticatedProjection();await projects.reload() }
}
</script>
<template>
  <div class="space-y-6">
    <p v-if="!createReady" role="status" class="rounded-md border border-border bg-muted/30 p-3 text-xs text-muted-foreground">{{t('platform.globalCommandStatusMissing')}}</p>
    <PageHeader :title="t('platform.projects')" :description="t('platform.projectsHint')"><Button variant="outline" size="sm" :disabled="!can('projects.read')" @click="projects.reload">{{t('common.refresh')}}</Button></PageHeader>
    <section class="settings-card space-y-3">
      <h2 class="font-semibold">{{t('platform.createProject')}}</h2>
      <form class="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)_auto] sm:items-end" @submit.prevent="createProject">
        <label class="text-xs">{{t('platform.projectName')}}<input v-model="name" maxlength="255" class="field mt-1" required :disabled="!createReady || (command.state.busy || command.state.reconciliationRequired)" /></label>
        <label class="text-xs">{{t('platform.ownerType')}}<select v-model="ownerKind" class="field mt-1" :disabled="!createReady || (command.state.busy || command.state.reconciliationRequired)"><option value="user">{{t('platform.personal')}}</option><option value="team">{{t('platform.team')}}</option></select></label>
        <label v-if="ownerKind==='team'" class="text-xs">{{t('platform.team')}}<select v-model="teamId" class="field mt-1" :disabled="!createReady || (command.state.busy || command.state.reconciliationRequired)"><option value="">{{t('platform.selectTeam')}}</option><option v-for="team in teams.state.items" :key="team.id" :value="team.id">{{team.name}} · {{team.id.slice(0,8)}}</option></select></label>
        <Button type="submit" size="sm" :disabled="!createReady || (command.state.busy || command.state.reconciliationRequired) || !name.trim() || (ownerKind==='team' && !teamId)">{{t('common.add')}}</Button>
      </form>
      <p class="text-xs text-muted-foreground">{{t('platform.projectMembershipRule')}}</p>
    </section>
    <section class="settings-card space-y-3">
      <h2 class="font-semibold">{{t('platform.availableProjects')}}</h2>
      <PlatformFeedback :status="projects.state.status" :error="projects.state.error" @retry="projects.reload" />
      <ScopedSearch v-if="projects.state.status==='ready'" v-model="projectSearch" :label="t('platform.searchProjects')" :total="projects.state.items.length" :visible="filteredProjects.length" :partial="projects.state.possiblyTruncated||projects.state.hasMore" />
      <p v-if="projects.state.status==='ready'&&projectSearch&&!filteredProjects.length" role="status" class="text-xs text-muted-foreground">{{t('platform.noSearchResults')}}</p>
      <div v-if="projects.state.items.length" class="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <div class="space-y-2"><button v-for="project in filteredProjects" :key="project.projectId" type="button" class="w-full rounded-lg border border-border p-3 text-left hover:bg-muted" :aria-pressed="project.projectId===selectedId" :class="project.projectId === selectedId ? 'bg-accent' : ''" @click="selectedId=project.projectId"><span class="block text-sm font-medium">{{project.name}}</span><span class="block text-xs text-muted-foreground">{{project.owner.kind === 'user' ? t('platform.personal') : project.owner.teamName}} · {{project.projectId.slice(0,8)}}</span><span v-if="project.lifecycleStatus!=='active'" class="mt-1 block text-xs text-destructive">{{t('platform.projectNotActive')}}</span></button></div>
        <p v-if="!selected" role="status" class="rounded-md border border-border p-3 text-xs text-muted-foreground">{{t('platform.chooseExplicitProject')}}</p>
        <div v-if="selected" class="space-y-4 rounded-lg border border-border p-4">
          <div><h3 class="font-semibold">{{selected.name}}</h3><p class="mt-1 text-xs text-muted-foreground">{{t('platform.projectIsolated')}}</p></div>
          <p v-if="selected.lifecycleStatus!=='active'" role="alert" class="text-xs text-destructive">{{t('platform.projectNotActive')}}</p>
          <Button size="sm" :disabled="!selected || selected.lifecycleStatus!=='active'||!projectContext.coreOwnerReady()" @click="chooseProject(selected)">{{t('platform.openProject')}}</Button>
          <div class="space-y-2 border-t border-border pt-3"><h4 class="text-sm font-medium">{{t('platform.transferOwnership')}}</h4>
            <template v-if="selected.owner.kind==='user'"><p class="text-xs text-muted-foreground">{{t('platform.transferToTeam')}}</p><select v-model="targetTeamId" class="field" :disabled="!canTransfer || (command.state.busy || command.state.reconciliationRequired)"><option value="">{{t('platform.selectTeam')}}</option><option v-for="team in teams.state.items" :key="team.id" :value="team.id">{{team.name}} · {{team.id.slice(0,8)}}</option></select></template>
            <p v-else class="text-xs text-muted-foreground">{{t('platform.withdrawToOwner')}}</p>
            <Button size="sm" variant="outline" :disabled="!canTransfer || (command.state.busy || command.state.reconciliationRequired) || (selected.owner.kind==='user' && !targetTeamId) || (selected.owner.kind==='team' && (!ownerTeam || !canWithdrawTeamProject))" @click="askTransfer">{{t('platform.transfer')}}</Button>
            <p class="text-xs text-muted-foreground">{{t('platform.transferWarning')}} {{t('platform.dangerTargetIdNotice')}}</p><p v-if="selected.owner.kind==='team' && !canWithdrawTeamProject" role="status" class="text-xs text-muted-foreground">{{t('platform.teamWithdrawRequiresOwner')}}</p>
          </div>
          <div v-if="projectContext.state.scope==='operator' && projectContext.state.user?.isSuperuser" class="space-y-3 border-t border-border pt-4">
            <h4 class="text-sm font-semibold">{{t('platform.adminReassignProject')}}</h4>
            <p class="text-xs text-muted-foreground">{{t('platform.adminReassignWarning')}}</p>
            <label class="block max-w-xs text-xs">{{t('platform.ownerType')}}
              <select v-model="adminOwnerKind" class="field mt-1" :disabled="!canReassign || (command.state.busy || command.state.reconciliationRequired)"><option value="user">{{t('platform.user')}}</option><option value="team">{{t('platform.team')}}</option></select>
            </label>
            <label v-if="adminOwnerKind==='user'" class="block max-w-sm text-xs">{{t('platform.memberUserId')}}
              <input v-model="adminOwnerUserId" class="field mt-1" autocomplete="off" :disabled="!canReassign || (command.state.busy || command.state.reconciliationRequired)" />
            </label>
            <label v-else class="block max-w-sm text-xs">{{t('platform.team')}}
              <select v-model="adminOwnerTeamId" class="field mt-1" :disabled="!canReassign || (command.state.busy || command.state.reconciliationRequired)"><option value="">{{t('platform.selectTeam')}}</option><option v-for="team in teams.state.items" :key="team.id" :value="team.id">{{team.name}} · {{team.id.slice(0,8)}}</option></select>
            </label>
            <Button variant="destructive" size="sm" :disabled="!canReassign || !adminTarget || (command.state.busy || command.state.reconciliationRequired)" @click="askAdminReassign">{{t('platform.transferOwnership')}}</Button>
          </div>
        </div>
      </div>
    </section>
    <PlatformFeedback status="idle" :action-error="command.state.error" :reconciled="command.state.reconciliationNotice" :busy="command.state.busy" @reconcile="command.reconcile" />
    <ConfirmAction :open="!!confirmation" :busy="command.state.busy" :title="t('platform.confirmDanger')" :detail="t('platform.transferWarning')" :target="confirmation?.projectId??''" @cancel="confirmation=null" @confirm="transferProject" />
    <ConfirmAction :open="!!adminConfirmation" :busy="command.state.busy" :title="t('platform.adminReassignProject')" :detail="t('platform.adminReassignWarning')" :target="adminConfirmation?.projectId??''" @cancel="adminConfirmation=null" @confirm="adminReassignProject" />
  </div>
</template>
