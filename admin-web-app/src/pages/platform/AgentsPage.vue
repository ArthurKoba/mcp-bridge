<script setup lang="ts">
import { computed, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useCommand, useDomain, sourceMutationReady } from "@/features/platform/model/use-domain"
import type { AgentView } from "@/features/platform/model/contracts"
import { projectContext } from "@/features/platform/model/project-context"
import PlatformFeedback from "@/features/platform/ui/PlatformFeedback.vue"
import ConfirmAction from "@/features/platform/ui/ConfirmAction.vue"
import Button from "@/shared/ui/Button.vue"
import PageHeader from "@/shared/ui/PageHeader.vue"
import ScopedSearch from "@/features/platform/ui/ScopedSearch.vue"
import { matchesLoaded } from "@/features/platform/model/scoped-search"
import { hasCurrentRecordRevision } from "@/features/platform/model/current-record"

const {t}=useI18n()
const agents=useDomain<AgentView>("agents","agents.read",(port,ctx)=>port.agents.list(ctx),["project"])
const command=useCommand(["project"])
const label=ref("")
const parent=ref("")
const renaming=ref("")
const renameLabel=ref("")
const stateCandidate=ref<AgentView|null>(null)
const can=projectContext.can
const createReady=computed(()=>sourceMutationReady("agents.manage","agent.create"))
function currentAgentWrite(item:AgentView,operation:"rename"|"state"):boolean {
  return Boolean(hasCurrentRecordRevision(item)&&item.projectId===projectContext.state.activeProjectKey&&
    agents.state.status==="ready"&&!agents.state.possiblyTruncated&&!agents.state.hasMore&&
    sourceMutationReady("agents.manage",`agent.${operation}:${item.id}`))
}
const currentProject=computed(()=>projectContext.state.activeProjectKey)
const currentRows=computed(()=>agents.state.items.filter(item=>item.projectId===currentProject.value))
const agentSearch=ref("")
const filteredAgents=computed(()=>currentRows.value.filter(item=>
  matchesLoaded(agentSearch.value,item.label,item.id,item.parentAgentId)))
const activeParents=computed(()=>currentRows.value.filter(item=>item.status==="active"))
function canChangeState(item:AgentView):boolean {
  if(item.projectId!==currentProject.value||!currentAgentWrite(item,"state"))return false
  if(item.status==="active") {
    // A4 rejects disabling a parent while an active child still references it.
    return !currentRows.value.some(child=>child.parentAgentId===item.id&&child.status==="active")
  }
  if(item.status==="disabled") {
    // A4 forbids enabling a child whose parent is missing or disabled.
    return !item.parentAgentId||activeParents.value.some(parent=>parent.id===item.parentAgentId)
  }
  return false
}
watch(()=>projectContext.state.revision,()=>{label.value="";parent.value="";renaming.value="";renameLabel.value="";stateCandidate.value=null})
watch(()=>agents.state.items,()=>{
  if(parent.value&&!activeParents.value.some(item=>item.id===parent.value))parent.value=""
  if(renaming.value&&!currentRows.value.some(item=>item.id===renaming.value)){
    renaming.value="";renameLabel.value=""
  }
})
async function createAgent() {
  if (!createReady.value||!currentProject.value || !label.value.trim() ||
      (parent.value&&!activeParents.value.some(item=>item.id===parent.value))) return
  const created=await command.submit("agents.manage",(port,ctx)=>port.agents.create(ctx,{label:label.value.trim(),parentAgentId:parent.value||null}),"agent.create")
  if (created) { label.value="";parent.value="";await agents.reload() }
}
function beginRename(agent:AgentView) {
  if(!currentAgentWrite(agent,"rename"))return
  renaming.value=agent.id;renameLabel.value=agent.label
}
watch(()=>agents.state.items,()=>{
  const item=stateCandidate.value
  if(item&&!agents.state.items.some(row=>row.id===item.id&&row.revision===item.revision&&row.status===item.status))
    stateCandidate.value=null
})
function askStateChange(agent:AgentView):void {
  if(!can("agents.manage")||agent.projectId!==currentProject.value||
     !canChangeState(agent)||command.state.busy||command.state.reconciliationRequired)return
  stateCandidate.value=agent
}
async function confirmStateChange():Promise<void> {
  const agent=stateCandidate.value
  if(!agent||!can("agents.manage")||agent.projectId!==currentProject.value)return
  const row=agents.state.items.find(item=>item.id===agent.id)
  if(!row||row.revision!==agent.revision||row.status!==agent.status||!canChangeState(row))return
  const updated=await command.submit("agents.manage",(port,ctx)=>port.agents.setEnabled(ctx,agent,agent.status!=="active"),`agent.state:${agent.id}`)
  if(updated){stateCandidate.value=null;await agents.reload()}
}
async function saveRename(agent:AgentView) {
  if (!currentAgentWrite(agent,"rename")||!renameLabel.value.trim() || renameLabel.value.trim()===agent.label ||
      !currentRows.value.some(row=>row.id===agent.id&&row.revision===agent.revision)) return
  const saved=await command.submit("agents.manage",(port,ctx)=>port.agents.rename(ctx,agent,renameLabel.value.trim()),`agent.rename:${agent.id}`)
  if (saved) { renaming.value="";renameLabel.value="";await agents.reload() }
}
</script>
<template>
  <div class="space-y-6">
    <p v-if="!createReady" role="status" class="rounded-md border border-border bg-muted/30 p-3 text-xs text-muted-foreground">{{t('platform.sourceCommandUnavailable')}}</p>
    <PageHeader :title="t('platform.agents')" :description="t('platform.agentsHint')"><Button variant="outline" size="sm" :disabled="!can('agents.read')" @click="agents.reload">{{t('common.refresh')}}</Button></PageHeader>
    <section class="settings-card space-y-4"><h2 class="font-semibold">{{t('platform.createAgent')}}</h2><p class="text-xs text-muted-foreground">{{t('platform.agentsProjectOwned')}}</p>
      <form class="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-end" @submit.prevent="createAgent">
        <label class="text-xs">{{t('platform.agentLabel')}}<input v-model="label" class="field mt-1" maxlength="255" :disabled="!createReady || !currentProject || (command.state.busy || command.state.reconciliationRequired)" required /></label>
        <label class="text-xs">{{t('platform.parentAgent')}}<select v-model="parent" class="field mt-1" :disabled="!createReady || !currentProject || (command.state.busy || command.state.reconciliationRequired)"><option value="">{{t('platform.none')}}</option><option v-for="agent in activeParents" :key="agent.id" :value="agent.id">{{agent.label}}</option></select></label>
        <Button type="submit" size="sm" :disabled="!createReady || !currentProject || (command.state.busy || command.state.reconciliationRequired) || !label.trim() || (!!parent && !activeParents.some(item=>item.id===parent))">{{t('common.add')}}</Button>
      </form>
    </section>
    <section class="settings-card space-y-3"><h2 class="font-semibold">{{t('platform.projectAgents')}}</h2><PlatformFeedback :status="agents.state.status" :error="agents.state.error" @retry="agents.reload" />
      <ScopedSearch v-if="agents.state.status==='ready'" v-model="agentSearch" :label="t('platform.searchAgents')" :total="currentRows.length" :visible="filteredAgents.length" :partial="agents.state.possiblyTruncated||agents.state.hasMore" />
      <p v-if="agents.state.status==='ready'&&agentSearch&&!filteredAgents.length" role="status" class="text-xs text-muted-foreground">{{t('platform.noSearchResults')}}</p>
      <div v-if="agents.state.items.length" class="overflow-x-auto"><table class="w-full min-w-[500px] text-left text-sm"><thead class="text-xs text-muted-foreground"><tr><th class="py-2">{{t('platform.agentLabel')}}</th><th>{{t('platform.parentAgent')}}</th><th>{{t('common.status')}}</th><th>{{t('common.actions')}}</th></tr></thead><tbody><tr v-for="agent in filteredAgents" :key="agent.id" class="border-t border-border"><td class="py-3"><template v-if="renaming===agent.id"><label class="sr-only" :for="`rename-${agent.id}`">{{t('platform.agentLabel')}}</label><input :id="`rename-${agent.id}`" v-model="renameLabel" class="field" maxlength="255" :disabled="!currentAgentWrite(agent,'rename')||command.state.busy||command.state.reconciliationRequired" @keydown.enter.prevent="saveRename(agent)" @keydown.esc.prevent="renaming=''" /></template><span v-else class="font-medium">{{agent.label}}</span></td><td>{{agents.state.items.find(item=>item.id===agent.parentAgentId)?.label??t('platform.none')}}</td><td>{{agent.status}}</td><td><div class="flex gap-2"><Button v-if="renaming===agent.id" size="sm" :disabled="!currentAgentWrite(agent,'rename') || !renameLabel.trim() || renameLabel.trim()===agent.label || (command.state.busy || command.state.reconciliationRequired)" @click="saveRename(agent)">{{t('common.save')}}</Button><Button v-else size="sm" variant="outline" :disabled="!currentAgentWrite(agent,'rename') || (command.state.busy || command.state.reconciliationRequired)" @click="beginRename(agent)">{{t('common.edit')}}</Button><Button v-if="renaming===agent.id" variant="ghost" size="sm" @click="renaming=''">{{t('common.cancel')}}</Button><Button v-if="renaming!==agent.id && ['active','disabled'].includes(agent.status)" size="sm" :variant="agent.status==='active'?'destructive':'outline'" :disabled="!canChangeState(agent) || (command.state.busy || command.state.reconciliationRequired)" :title="!canChangeState(agent)?t('platform.agentChildStateBlock'):undefined" @click="askStateChange(agent)">{{agent.status==='active'?t('platform.disableAgent'):t('platform.enableAgent')}}</Button></div></td></tr></tbody></table></div>
    </section>
    <p class="text-xs text-muted-foreground">{{t('platform.agentChildStateBlock')}} {{t('platform.agentSessionIndependence')}}</p>
    <PlatformFeedback status="idle" :action-error="command.state.error" :reconciled="command.state.reconciliationNotice" :busy="command.state.busy" @reconcile="command.reconcile" />
    <ConfirmAction :open="!!stateCandidate" :busy="command.state.busy" :title="stateCandidate?.status==='active'?t('platform.disableAgent'):t('platform.enableAgent')" :detail="t('platform.agentStateWarning')" :target="stateCandidate?.id??''" @cancel="stateCandidate=null" @confirm="confirmStateChange" />
  </div>
</template>
