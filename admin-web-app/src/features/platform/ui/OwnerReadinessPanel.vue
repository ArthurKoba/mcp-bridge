<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue"
import { useI18n } from "vue-i18n"
import { BFF_OWNERS, type BffOwner } from "@/features/platform/api/bff-boundary"
import { projectContext } from "@/features/platform/model/project-context"
import { refreshAuthenticatedProjection } from "@/features/platform/model/refresh-identity"
import { platformPort } from "@/features/platform/api/port"
import Button from "@/shared/ui/Button.vue"
import InstantTime from "@/shared/ui/InstantTime.vue"

const {t}=useI18n()
const busy=ref(false)
const clock=ref(Date.now())
let timer:ReturnType<typeof setInterval>|null=null
onMounted(()=>{timer=setInterval(()=>{clock.value=Date.now()},15_000)})
onBeforeUnmount(()=>{if(timer)clearInterval(timer)})
const status=computed(()=>projectContext.ownerAvailability())
const evidence=computed(()=>projectContext.state.ownerEvidence)
const rows=computed(()=>BFF_OWNERS.map(owner=>({
  owner,
  availability:evidence.value?.owners[owner].availability??"unknown",
  revision:evidence.value?.owners[owner].revision??null,
})))
const ageSeconds=computed(()=>{
  if(!evidence.value)return null
  return Math.max(0,Math.floor((clock.value-Date.parse(evidence.value.observedAtUtc))/1_000))
})
const canRefresh=computed(()=>Boolean(platformPort.value?.bff&&projectContext.state.user?.active&&!busy.value))
async function refresh():Promise<void> {
  if(!canRefresh.value)return
  busy.value=true
  try {await refreshAuthenticatedProjection()}finally{busy.value=false}
}
function ownerLabel(owner:BffOwner):string{return t(`platform.ownerDomain.${owner}`)}
</script>
<template>
  <section class="settings-card space-y-3" :aria-label="t('platform.ownerBoundaryTitle')">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div><h2 class="font-semibold">{{t('platform.ownerBoundaryTitle')}}</h2><p class="text-xs text-muted-foreground">{{t('platform.ownerBoundaryHint')}}</p></div>
      <Button variant="outline" size="sm" :disabled="!canRefresh" @click="refresh">{{t('common.refresh')}}</Button>
    </div>
    <p role="status" class="text-sm" :class="status==='ready'?'text-foreground':'text-muted-foreground'">
      {{t(`platform.ownerBoundaryState.${status}`)}}
    </p>
    <ul class="grid gap-2 sm:grid-cols-2" :aria-label="t('platform.ownerBoundaryTitle')">
      <li v-for="item in rows" :key="item.owner" class="rounded-md border border-border p-3 text-xs">
        <strong>{{ownerLabel(item.owner)}}</strong>
        <span class="ml-2 text-muted-foreground">{{t(`platform.ownerBoundaryState.${item.availability}`)}}</span>
        <p v-if="item.revision" class="mt-1 font-mono text-muted-foreground">{{t('platform.ownerRevision')}}: {{item.revision.slice(0,16)}}</p>
      </li>
    </ul>
    <p v-if="evidence" class="text-xs text-muted-foreground">
      {{t('platform.ownerAttestedAt')}}: <InstantTime :value="evidence.observedAtUtc" />
      <span v-if="ageSeconds!==null"> · {{t('platform.ownerAgeSeconds',{count:ageSeconds})}}</span>
    </p>
    <p v-if="!projectContext.state.grantsFresh" role="alert" class="text-xs text-destructive">{{t('platform.permissionsNeedRefresh')}}</p>
    <p class="text-xs text-muted-foreground">{{t('platform.ownerReadinessNotDbHealth')}}</p>
  </section>
</template>
