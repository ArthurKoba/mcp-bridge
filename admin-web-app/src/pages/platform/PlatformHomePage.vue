<script setup lang="ts">
import { computed } from "vue"
import { useI18n } from "vue-i18n"
import { platformPort } from "@/features/platform/api/port"
import { useDomain } from "@/features/platform/model/use-domain"
import PlatformFeedback from "@/features/platform/ui/PlatformFeedback.vue"
import { projectContext } from "@/features/platform/model/project-context"
import { scopedEvents } from "@/features/platform/model/project-events"
import PageHeader from "@/shared/ui/PageHeader.vue"
import Button from "@/shared/ui/Button.vue"
import OwnerReadinessPanel from "@/features/platform/ui/OwnerReadinessPanel.vue"

const {t}=useI18n()
const scopeLabel=computed(()=>projectContext.state.scope==="operator"?t('context.operator'):projectContext.state.scope==="team"?projectContext.state.teams.find(item=>item.key===projectContext.state.activeTeamKey)?.label??t('context.teamResources'):projectContext.state.projects.find(item=>item.key===projectContext.state.activeProjectKey)?.label??t('context.selectProject'))
const personal=computed(()=>projectContext.state.projects.filter(item=>item.ownership==="personal"))
const teams=computed(()=>projectContext.state.projects.filter(item=>item.ownership==="team"))
const wired=computed(()=>Boolean(platformPort.value?.bff))
interface OperatorSnapshot { users:number; teams:number; projects:number; agentSessions:number }
const globalSummary=useDomain<OperatorSnapshot>(
  "operations","users.read",async(port,ctx)=>{
    if(!port.operator||ctx.scope.kind!=="operator")return {items:[]}
    const counts=await port.operator.summary(ctx)
    return {items:[counts]}
  },["operator"],port=>Boolean(port.operator),
)
const totals=computed(()=>globalSummary.state.items[0]??null)
function openProjects(){ window.location.hash="platform/projects" }
</script>
<template>
  <div class="space-y-6">
    <PageHeader :title="t('platform.navigation.home')" :description="t('platform.homeHint')" />
    <div v-if="!wired" role="status" class="rounded-lg border border-border bg-muted/30 p-4 text-sm text-muted-foreground">{{t('platform.pendingContract')}}</div>
    <div v-if="projectContext.coreOwnerReady()" class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <section class="settings-card"><h2 class="mb-1 text-sm font-semibold">{{t('platform.user')}}</h2><p class="break-words text-sm">{{projectContext.state.user.label}}</p><p class="mt-1 text-xs text-muted-foreground">{{projectContext.state.user.isSuperuser?'superuser':'User'}}</p></section>
      <section class="settings-card"><h2 class="mb-1 text-sm font-semibold">{{t('platform.availableProjects')}}</h2><p class="text-2xl font-semibold tabular-nums">{{personal.length + teams.length}}</p><p class="text-xs text-muted-foreground">{{t('context.personal')}}: {{personal.length}} · {{t('context.teams')}}: {{teams.length}}</p></section>
      <section class="settings-card"><h2 class="mb-1 text-sm font-semibold">{{t('platform.currentScope')}}</h2><p class="break-words text-sm">{{scopeLabel}}</p><p class="mt-1 text-xs text-muted-foreground">{{t('platform.realtimeStatus')}}: {{t(`platform.scopedRealtime.${scopedEvents.state.status}`)}}</p></section>
    </div>
    <OwnerReadinessPanel v-if="projectContext.state.user?.active" />
    <section v-if="projectContext.coreOwnerReady()&&projectContext.state.scope==='operator'" class="settings-card space-y-4">
      <div class="flex flex-wrap items-center justify-between gap-2"><h2 class="font-semibold">{{t('platform.operatorSummary')}}</h2><Button variant="outline" size="sm" :disabled="globalSummary.state.status==='loading'||!projectContext.can('users.read')" @click="globalSummary.reload">{{t('common.refresh')}}</Button></div>
      <PlatformFeedback :status="globalSummary.state.status" :error="globalSummary.state.error" @retry="globalSummary.reload" />
      <div v-if="totals" class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div class="rounded-md border border-border p-3"><p class="text-xs text-muted-foreground">{{t('platform.users')}}</p><p class="text-xl font-semibold tabular-nums">{{totals.users}}</p></div>
        <div class="rounded-md border border-border p-3"><p class="text-xs text-muted-foreground">{{t('platform.teams')}}</p><p class="text-xl font-semibold tabular-nums">{{totals.teams}}</p></div>
        <div class="rounded-md border border-border p-3"><p class="text-xs text-muted-foreground">{{t('platform.projects')}}</p><p class="text-xl font-semibold tabular-nums">{{totals.projects}}</p></div>
        <div class="rounded-md border border-border p-3"><p class="text-xs text-muted-foreground">{{t('platform.agentSessions')}}</p><p class="text-xl font-semibold tabular-nums">{{totals.agentSessions}}</p></div>
      </div>
      <p class="text-xs text-muted-foreground">{{t('platform.operatorSummaryNotProject')}}</p>
    </section>
    <section class="settings-card space-y-3"><h2 class="font-semibold">{{t('platform.nextStep')}}</h2><p class="text-sm text-muted-foreground">{{projectContext.state.scope==='choose-project'?t('platform.chooseScope'):t('platform.homeScopeHint')}}</p><Button size="sm" variant="outline" @click="openProjects">{{t('platform.navigation.projects')}}</Button></section>
    <section v-if="!projectContext.state.projects.length && projectContext.coreOwnerReady()" class="rounded-lg border border-border p-4 text-sm text-muted-foreground">{{t('platform.noProjects')}}</section>
  </div>
</template>
