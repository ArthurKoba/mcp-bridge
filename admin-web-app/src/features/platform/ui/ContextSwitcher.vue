<script setup lang="ts">
import { computed, nextTick, ref, watch } from "vue"
import { FolderKanban, LockKeyhole } from "lucide-vue-next"
import { useI18n } from "vue-i18n"

import { projectContext } from "@/features/platform/model/project-context"

const { t } = useI18n()
// Equal display names across Team/Project owners are not unique identities.
const shortId=(value:string):string=>value.slice(0,8)
const input=ref<HTMLSelectElement|null>(null)
const currentAuthority=computed(()=>projectContext.coreOwnerReady())
const staleScopeLabel=computed(()=>{
  if(!projectContext.state.user?.active)return ""
  if(projectContext.state.scope==="project"&&projectContext.state.activeProjectKey)
    return `${t('context.staleProjectSelection')} · ${shortId(projectContext.state.activeProjectKey)}`
  if(projectContext.state.scope==="team"&&projectContext.state.activeTeamKey)
    return `${t('context.staleTeamSelection')} · ${shortId(projectContext.state.activeTeamKey)}`
  if(projectContext.state.scope==="operator")return t('context.staleOperatorSelection')
  return ""
})
watch(currentAuthority,async allowed=>{
  if(allowed||!input.value||document.activeElement!==input.value)return
  // A select disappearing on grant revocation must not strand keyboard focus
  // on a removed control. The old label stays READ ONLY, not an ACL proof.
  await nextTick()
  document.getElementById("briareus-page-title")?.focus()
},{flush:"post"})
const personal = computed(() => projectContext.state.projects.filter(project => project.ownership === "personal"))
const teams = computed(() => projectContext.state.projects.filter(project => project.ownership === "team"))
const teamScopes = computed(() => projectContext.state.teams)
const selection = computed(() => {
  if (projectContext.state.scope === "operator") return "operator"
  if (projectContext.state.scope === "team") return `team:${projectContext.state.activeTeamKey}`
  if (projectContext.state.scope === "project") return `project:${projectContext.state.activeProjectKey}`
  return "account"
})

function choose(event:Event):void {
  const input=event.target as HTMLSelectElement
  const value=input.value
  let accepted=false
  if(value==="account"){
    projectContext.selectNone()
    accepted=projectContext.selection()?.kind==="account"
  }else if(value==="operator")accepted=projectContext.selectOperator()
  else if(value.startsWith("project:"))accepted=projectContext.selectProject(value.slice(8))
  else if(value.startsWith("team:"))accepted=projectContext.selectTeam(value.slice(5))
  // Native SELECT optimistically shows a newly chosen option even when a
  // permission was revoked synchronously. Undo it if current BFF rights reject
  // the change; never display an unselected, deleting or foreign Project.
  if(!accepted)input.value=selection.value
}
</script>

<template>
  <div class="flex min-w-0 items-center gap-2 text-xs">
    <FolderKanban class="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
    <label v-if="projectContext.state.user&&currentAuthority" class="min-w-0">
      <span class="sr-only">{{ t('context.selector') }}</span>
      <select ref="input" class="field max-w-36 py-1 text-xs sm:max-w-48 xl:max-w-64" :value="selection" :aria-label="t('context.selector')" @change="choose">
        <option value="account">{{ t('context.accountContext') }}</option>
        <optgroup v-if="personal.length" :label="t('context.personal')">
          <option v-for="project in personal" :key="project.key" :value="`project:${project.key}`" :disabled="project.lifecycleStatus!=='active'">{{ project.label }} · {{ shortId(project.key) }}</option>
        </optgroup>
        <optgroup v-if="teams.length" :label="t('context.teams')">
          <option v-for="project in teams" :key="project.key" :value="`project:${project.key}`" :disabled="project.lifecycleStatus!=='active'">{{ project.label }}{{ project.ownerLabel ? ` · ${project.ownerLabel}` : '' }} · {{shortId(project.key)}}</option>
        </optgroup>
        <optgroup v-if="teamScopes.length" :label="t('context.teamResources')">
          <option v-for="team in teamScopes" :key="team.key" :value="`team:${team.key}`">{{ team.label }} · {{shortId(team.key)}}</option>
        </optgroup>
        <option v-if="projectContext.state.user.isSuperuser" value="operator">{{ t('context.operator') }}</option>
      </select>
    </label>
    <span v-else class="inline-flex items-center gap-1.5 text-muted-foreground" :title="t('context.contractPending')">
      <LockKeyhole class="size-3.5 shrink-0" aria-hidden="true" />
      <span v-if="staleScopeLabel" class="max-w-36 truncate sm:max-w-48" role="status">{{staleScopeLabel}}</span>
      <span v-else class="hidden lg:inline">{{t('context.contractPending')}}</span>

    </span>
  </div>
</template>
