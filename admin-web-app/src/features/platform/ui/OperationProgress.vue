<script setup lang="ts">
import { computed, ref } from "vue"
import { useI18n } from "vue-i18n"
import { commandCoordinator } from "@/features/platform/model/command-coordinator"
import { projectContext } from "@/features/platform/model/project-context"
import { sameBffScope } from "@/features/platform/api/bff-boundary"
import Button from "@/shared/ui/Button.vue"
const props=defineProps<{activePage:string}>()
const {t}=useI18n()
const phase=computed(()=>commandCoordinator.activity.phase)
const visible=computed(()=>projectContext.state.user?.active && phase.value!=="idle")
const alert=computed(()=>["unknown","denied"].includes(phase.value))
const original=computed(()=>commandCoordinator.originalScope(projectContext.state.user?.key??"",projectContext.selection()))
const originalResource=computed(()=>commandCoordinator.originalResource(projectContext.state.user?.key??"",projectContext.selection()))
const needsReturn=computed(()=>Boolean(original.value&&projectContext.selection()&&
  (!sameBffScope(original.value,projectContext.selection()!)||
   (originalResource.value&&props.activePage!==targetPage[originalResource.value]))&&
  ["unknown","reconciling"].includes(phase.value)))
const navigationFailed=ref(false)
const targetPage:Record<string,string>={profile:"users",invitations:"users",users:"users",teams:"teams",projects:"projects",
  agents:"agents",sessions:"sessions",accounts:"integrations",variables:"variables"}
function returnToOriginal():void {
  const scope=original.value
  const resource=originalResource.value
  if(!scope||!resource)return
  let accepted=false
  if(scope.kind==="project")accepted=projectContext.selectProject(scope.projectId)
  else if(scope.kind==="team")accepted=projectContext.selectTeam(scope.teamId)
  else if(scope.kind==="operator")accepted=projectContext.selectOperator()
  else {projectContext.selectNone();accepted=projectContext.selection()?.kind==="account"}
  if(!accepted){navigationFailed.value=true;return}
  navigationFailed.value=false
  // A route switch is NOT a command retry. The destination screen's
  // explicit Reconcile action will inspect the ORIGINAL server key.
  location.hash=`#platform/${targetPage[resource]??"home"}`
}

</script>
<template>
  <div v-if="visible" :role="alert?'alert':'status'" class="mb-4 rounded-lg border border-border bg-muted/30 p-3 text-sm">
    <strong>{{t(`platform.commandPhase.${phase}`)}}</strong>
    <p class="mt-1 text-xs text-muted-foreground">{{t(`platform.commandPhaseHint.${phase}`)}}</p>
    <Button v-if="needsReturn" variant="outline" size="sm" class="mt-2" @click="returnToOriginal">{{t('platform.returnToOriginalCommand')}}</Button>
    <Button v-if="['confirmed','denied'].includes(phase)" variant="ghost" size="sm" class="mt-2" @click="commandCoordinator.dismissNotice()">{{t('common.close')}}</Button>
    <p v-if="navigationFailed" role="alert" class="mt-2 text-xs text-destructive">{{t('platform.originalScopeNoLongerAvailable')}}</p>
  </div>
</template>
