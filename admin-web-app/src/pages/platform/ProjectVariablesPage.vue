<script setup lang="ts">
import { computed, onBeforeUnmount, reactive, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { projectContext } from "@/features/platform/model/project-context"
import { refreshAuthenticatedProjection } from "@/features/platform/model/refresh-identity"
import { useCommand, useDomain, sourceMutationReady } from "@/features/platform/model/use-domain"
import { currentCatalogRowAllows } from "@/features/platform/model/resource-provenance"
import { validVariableName, validCatalogValue } from "@/features/platform/model/provider-options"
import type { ProjectVariableInput, ProjectVariableView, ResourceOwner, ResourceScope, UiCapability, SourceCommandBinding } from "@/features/platform/model/contracts"
import PlatformFeedback from "@/features/platform/ui/PlatformFeedback.vue"
import ScopedResourcePicker from "@/features/platform/ui/ScopedResourcePicker.vue"
import ConfirmAction from "@/features/platform/ui/ConfirmAction.vue"
import AppDialog from "@/shared/ui/AppDialog.vue"
import Button from "@/shared/ui/Button.vue"
import InstantTime from "@/shared/ui/InstantTime.vue"
import PageHeader from "@/shared/ui/PageHeader.vue"
import ScopedSearch from "@/features/platform/ui/ScopedSearch.vue"
import { matchesLoaded } from "@/features/platform/model/scoped-search"

const {t}=useI18n()
const selectedProject=computed(()=>projectContext.state.projects.find(project=>project.key===projectContext.state.activeProjectKey))
const teamId=computed(()=>projectContext.state.scope==="team"?projectContext.state.activeTeamKey:selectedProject.value?.ownerTeamId??null)
const scopeFilter=ref<ResourceScope>("all")
const readScope=computed<ResourceScope>(()=>projectContext.state.scope==="team"?"team":scopeFilter.value)
const variables=useDomain<ProjectVariableView>("variables","variables.read",async(port,ctx)=>{
  const ctxScope=ctx.scope
  if(ctxScope.kind!=="project"&&ctxScope.kind!=="team")throw new Error("Resource scope required")
  const scope=readScope.value
  const result=await port.variables.list(ctx,{scope})
  const mismatch=result.items.some(item=>{
    if(scope==="team"&&item.owner.kind!=="team")return true
    if(scope==="project"&&item.owner.kind!=="project")return true
    if(ctxScope.kind==="team")return item.visibleIn.kind!=="team"||item.visibleIn.teamId!==ctxScope.teamId||item.owner.kind!=="team"||item.owner.teamId!==ctxScope.teamId||item.inherited
    if(item.visibleIn.kind!=="project"||item.visibleIn.projectId!==ctxScope.projectId)return true
    if(item.owner.kind==="project")return item.owner.projectId!==ctxScope.projectId||item.inherited
    return item.owner.teamId!==teamId.value||!item.inherited
  })
  if(mismatch)throw new Error("Scoped variable ownership mismatch")
  return result // Preserve both equal Team/Project variable keys.
},["project","team"])
watch(scopeFilter,()=>{void variables.reload()})
const variableSearch=ref("")
const filteredVariables=computed(()=>variables.state.items.filter(item=>
  matchesLoaded(variableSearch.value,item.key,item.id,item.owner.kind==="team"?item.owner.teamId:item.owner.projectId)))
const choices=computed(()=>filteredVariables.value.map(item=>({id:item.id,name:item.key,owner:item.owner})))
const command=useCommand(["project","team"])
const can=projectContext.can
const ownerKind=ref<"team"|"project">("project")
const editing=ref<ProjectVariableView|null>(null)
const mode=ref<null|"create"|"rename"|"rotate">(null)
const form=reactive({key:"",kind:"plain" as "plain"|"secret",value:""})
const toRemove=ref<ProjectVariableView|null>(null)
const confirmRotation=ref(false)
const canManageTeam=computed(()=>Boolean(teamId.value&&can("variables.teamManage")))
const canCreate=computed(()=>Boolean(requestedOwner.value&&
  sourceMutationReady(actionFor(requestedOwner.value),statusFor(requestedOwner.value,"create"))))
const actionFor=(owner:ResourceOwner):UiCapability=>owner.kind==="team"?"variables.teamManage":"variables.manage"
function statusFor(owner:ResourceOwner,kind:"create"|"update"|"rotate"|"revoke",id?:string):SourceCommandBinding {
  const operation=`variable.${kind}`
  if(kind!=="create"){
    if(!id)throw new Error("Existing source variable UUID required")
    return {operation,target:{kind:"resource",id,owner}}
  }
  return {operation,target:owner.kind==="team"?{kind:"team",id:owner.teamId}:
    {kind:"project_resource",id:owner.projectId}}
}
const requestedOwner=computed<ResourceOwner|null>(()=>{
  if(editing.value)return editing.value.owner
  if(projectContext.state.scope==="team"||ownerKind.value==="team")return teamId.value?{kind:"team",teamId:teamId.value}:null
  return projectContext.state.activeProjectKey?{kind:"project",projectId:projectContext.state.activeProjectKey}:null
})
function canManage(item:ProjectVariableView,kind:"update"|"rotate"|"revoke"="update"):boolean {
  if(variables.state.status!=="ready")return false
  const action=actionFor(item.owner)
  return currentCatalogRowAllows(variables.state.items,item,action)&&
    sourceMutationReady(action,statusFor(item.owner,kind,item.id))
}
const mayWrite=computed(()=>Boolean(requestedOwner.value&&
  (mode.value==="create"?canCreate.value:editing.value&&
    canManage(editing.value,mode.value==="rotate"?"rotate":"update"))))
const valid=computed(()=>{
  if(!mayWrite.value||!validVariableName(form.key))return false
  if(mode.value==="rename")return Boolean(editing.value&&form.key.trim().toUpperCase()!==editing.value.key)
  if(mode.value==="rotate"||mode.value==="create")return validCatalogValue(form.value)
  return false
})
function clearForm():void {
  // Closing a form only discards local inputs. The cross-page command fence
  // survives, so uncertainty must never trap secrets in a modal dialog.
  if(command.state.busy)return
  form.value=""
  form.key=""
  form.kind="plain"
  mode.value=null
  editing.value=null
}
function begin(newMode:"create"|"rename"|"rotate",item?:ProjectVariableView):void {
  if(newMode==="create"&&!canCreate.value)return
  if(newMode!=="create"&&(!item||!canManage(item,newMode==="rotate"?"rotate":"update")))return
  editing.value=item??null
  ownerKind.value=item?.owner.kind??(projectContext.state.scope==="team"||(!can("variables.manage")&&canManageTeam.value)?"team":"project")
  form.key=item?.key??""
  form.kind=item?.kind??"plain"
  form.value="" // No saved values returned to the UI; secret replacement is write-only.
  mode.value=newMode
}
const stop=projectContext.onTransition(()=>{
  form.value="";form.key="";mode.value=null;editing.value=null;toRemove.value=null;confirmRotation.value=false
  ownerKind.value="project";scopeFilter.value="all"
})
onBeforeUnmount(()=>{stop();form.value=""})
function payload():ProjectVariableInput|null {
  const owner=requestedOwner.value
  if(!owner||!mode.value)return null
  return {owner,key:form.key.trim().toUpperCase(),kind:form.kind,
    ...(mode.value!=="rename"?{value:form.value}:{}),
    ...(editing.value?{expectedRevision:editing.value.revision,action:mode.value==="rotate"?"rotate" as const:"rename" as const}:{})}
}
async function save():Promise<void> {
  if(!valid.value||mode.value==="rotate")return
  const input=payload()
  if(!input)return
  const done=await command.submit(actionFor(input.owner),(port,ctx)=>port.variables.save(ctx,input,editing.value?.id),
    statusFor(input.owner,editing.value?"update":"create",editing.value?.id))
  form.value=""
  if(done){clearForm();await refreshAuthenticatedProjection();await variables.reload()}
}
function askRotate():void { if(mode.value==="rotate"&&valid.value)confirmRotation.value=true }
async function rotate():Promise<void> {
  const input=payload()
  if(!valid.value||mode.value!=="rotate"||!input||!editing.value)return
  const done=await command.submit(actionFor(input.owner),(port,ctx)=>port.variables.save(ctx,input,editing.value?.id),
    statusFor(input.owner,"rotate",editing.value.id))
  form.value=""
  confirmRotation.value=false
  if(done){clearForm();await refreshAuthenticatedProjection();await variables.reload()}
}
async function remove():Promise<void> {
  const item=toRemove.value
  if(!item||!canManage(item,"revoke"))return
  const done=await command.submit(actionFor(item.owner),(port,ctx)=>port.variables.remove(ctx,item),
    statusFor(item.owner,"revoke",item.id))
  if(done){toRemove.value=null;await refreshAuthenticatedProjection();await variables.reload()}
}
</script>
<template>
  <div class="space-y-6">
    <PageHeader :title="t('platform.navigation.variables')" :description="t('platform.variablesHint')"><Button size="sm" variant="outline" :disabled="!can('variables.read')" @click="variables.reload">{{t('common.refresh')}}</Button><Button size="sm" :disabled="!canCreate" @click="begin('create')">{{t('common.add')}}</Button></PageHeader>
    <p class="rounded-lg border border-border bg-muted/30 p-3 text-xs text-muted-foreground">{{t('platform.variablesSafetyHint')}} {{t('platform.scopeCollisionRule')}}</p>
    <p v-if="!platformPort.value?.bff?.inspectOriginalCommand" role="status" class="rounded-md border border-border bg-muted/30 p-3 text-xs text-muted-foreground">{{t('platform.sourceCommandUnavailable')}}</p>
    <section class="settings-card space-y-3">
      <label v-if="projectContext.state.scope==='project'" class="block max-w-xs text-xs">{{t('platform.resourceReadScope')}}
        <select v-model="scopeFilter" class="field mt-1"><option value="all">{{t('platform.scopeAll')}}</option><option v-if="teamId" value="team">{{t('platform.scopeTeam')}}</option><option value="project">{{t('platform.scopeProject')}}</option></select>
      </label>
      <p v-else class="text-xs text-muted-foreground">{{t('platform.scopeTeam')}}</p>
      <ScopedSearch v-if="variables.state.status==='ready'" v-model="variableSearch" :label="t('platform.searchVariables')" :total="variables.state.items.length" :visible="filteredVariables.length" :partial="variables.state.possiblyTruncated||variables.state.hasMore" />
            <p v-if="variables.state.status==='ready'&&filteredVariables.some(item=>!canManage(item))" role="status" class="text-xs text-muted-foreground">{{t('platform.catalogCurrentGrantRequired')}}</p>
<p v-if="variables.state.status==='ready'&&variableSearch&&!filteredVariables.length" role="status" class="text-xs text-muted-foreground">{{t('platform.noSearchResults')}}</p>
      <ScopedResourcePicker v-if="variables.state.status==='ready'" :items="choices" :label="t('platform.chooseVariable')" />
      <PlatformFeedback :status="variables.state.status" :error="variables.state.error" @retry="variables.reload" />
      <div v-if="variables.state.items.length" class="overflow-x-auto"><table class="w-full min-w-[650px] text-left text-sm"><thead class="text-xs text-muted-foreground"><tr><th class="py-2">{{t('platform.variableKey')}}</th><th>{{t('platform.variableType')}}</th><th>{{t('platform.sourceOwner')}}</th><th>{{t('common.actions')}}</th></tr></thead><tbody>
        <tr v-for="item in filteredVariables" :key="`${item.visibleIn.kind}:${item.owner.kind}:${item.id}`" class="border-t border-border"><td class="py-3 font-mono text-xs">{{item.key}}<span v-if="item.updatedAt" class="block text-[10px] text-muted-foreground"><InstantTime :value="item.updatedAt" /></span><span class="block text-[10px] text-muted-foreground" :title="item.id">{{t('platform.resourceId')}}: {{item.id.slice(0,12)}}…</span></td><td class="text-xs">{{item.kind==='secret'?t('platform.encryptedSecret'):t('platform.plainVariable')}} · {{item.valueConfigured?t('platform.secretConfigured'):t('platform.secretMissing')}}</td><td class="text-xs">{{item.owner.kind==='team'?t('platform.teamOwned'):t('platform.projectOwned')}}<span class="block text-muted-foreground">{{item.inherited?t('platform.inherited'):t('platform.directResource')}}</span><span class="block font-mono text-[10px] text-muted-foreground" :title="item.owner.kind==='team'?item.owner.teamId:item.owner.projectId">{{(item.owner.kind==='team'?item.owner.teamId:item.owner.projectId).slice(0,12)}}…</span></td><td><div class="flex flex-wrap gap-1"><Button size="sm" variant="outline" :disabled="!canManage(item)" @click="begin('rename',item)">{{t('platform.renameResource')}}</Button><Button size="sm" variant="outline" :disabled="!canManage(item,'rotate')" @click="begin('rotate',item)">{{t('platform.rotateCredential')}}</Button><Button size="sm" variant="destructive" :disabled="!canManage(item,'revoke')" @click="toRemove=item">{{t('platform.revoke')}}</Button></div></td></tr>
      </tbody></table></div>
    </section>
    <AppDialog :open="!!mode" :title="mode==='create'?t('platform.newVariable'):mode==='rename'?t('platform.renameResource'):t('platform.rotateCredential')" width="580px" @close="clearForm">
      <form class="space-y-4" @submit.prevent="mode==='rotate'?askRotate():save()">
        <label class="block text-xs">{{t('platform.sourceOwner')}}<select v-model="ownerKind" class="field mt-1" :disabled="mode!=='create'||(command.state.busy || command.state.reconciliationRequired)"><option v-if="projectContext.state.scope==='project'" value="project">{{t('platform.projectOwned')}}</option><option v-if="teamId&&canManageTeam" value="team">{{t('platform.teamOwned')}}</option></select></label>
        <label class="block text-xs">{{t('platform.variableKey')}}<input v-model="form.key" class="field mt-1 font-mono" maxlength="128" required :disabled="mode==='rotate'||(command.state.busy || command.state.reconciliationRequired)" /></label>
        <label class="block text-xs">{{t('platform.variableType')}}<select v-model="form.kind" class="field mt-1" :disabled="mode==='rename'||(command.state.busy || command.state.reconciliationRequired)"><option value="plain">{{t('platform.plainVariable')}}</option><option value="secret">{{t('platform.encryptedSecret')}}</option></select></label>
        <p v-if="mode!=='rename'&&form.value&&!validCatalogValue(form.value)" role="alert" class="text-xs text-destructive">{{t('platform.catalogValueLength')}}</p>
        <label v-if="mode!=='rename'" class="block text-xs">{{t('platform.variableValue')}}<input v-model="form.value" class="field mt-1" :type="form.kind==='secret'?'password':'text'" maxlength="131072" autocomplete="off" :disabled="(command.state.busy || command.state.reconciliationRequired)" required /></label>
        <p v-if="editing" class="text-xs text-muted-foreground">{{t('platform.resourceOwnerImmutable')}}</p><p class="text-xs text-muted-foreground">{{mode==='rename'?t('platform.sourceRenameHint'):t('platform.variableNoPlaintext')}}</p><p v-if="!valid" role="status" class="text-xs text-destructive">{{t('platform.variableValidation')}}</p>
        <PlatformFeedback status="idle" :action-error="command.state.error" :reconciled="command.state.reconciliationNotice" :busy="command.state.busy" @reconcile="command.reconcile" />
      </form>
      <template #footer><Button variant="outline" :disabled="command.state.busy" @click="clearForm">{{t('common.cancel')}}</Button><Button :disabled="!valid||(command.state.busy || command.state.reconciliationRequired)" @click="mode==='rotate'?askRotate():save()">{{mode==='rotate'?t('platform.reviewRotation'):t('common.save')}}</Button></template>
    </AppDialog>
    <ConfirmAction :open="confirmRotation" :busy="command.state.busy" :title="t('platform.rotateCredential')" :detail="t('platform.teamResourceDeleteHint')" :target="editing?.id??''" @cancel="confirmRotation=false" @confirm="rotate" />
    <ConfirmAction :open="!!toRemove" :busy="command.state.busy" :title="t('platform.confirmDanger')" :detail="t('platform.teamResourceDeleteHint')" :target="toRemove?.id??''" @cancel="toRemove=null" @confirm="remove" />
    <PlatformFeedback status="idle" :action-error="command.state.error" :reconciled="command.state.reconciliationNotice" :busy="command.state.busy" @reconcile="command.reconcile" />
  </div>
</template>
