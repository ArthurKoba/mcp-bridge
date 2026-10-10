<script setup lang="ts">
import { computed, ref, useId, watch } from "vue"
import { useI18n } from "vue-i18n"
import Button from "@/shared/ui/Button.vue"
import AppDialog from "@/shared/ui/AppDialog.vue"

const props = defineProps<{ open: boolean; title: string; detail: string; target: string; busy?: boolean }>()
const emit = defineEmits<{ cancel: []; confirm: [] }>()
const typed = ref("")
const {t}=useI18n()
const detailId=useId()
// A confirmation belongs to ONE source row/scope/operation. Updating the
// target while the dialog stays mounted must erase typed approval immediately.
watch([()=>props.open,()=>props.target,()=>props.detail],()=>{typed.value=""},{flush:"sync"})
const allowed=computed(()=>props.open&&props.target.trim().length>0&&
  typed.value===props.target&&!props.busy)
function confirm():void {
  if(!allowed.value)return
  // Fence rapid Enter/double-click while parent starts async permission check.
  typed.value=""
  emit("confirm")
}
</script>
<template>
  <AppDialog :open="open" :title="title" :description-id="detailId" width="520px" @close="!busy && emit('cancel')">
    <p :id="detailId" class="mb-4 text-sm text-muted-foreground">{{detail}}</p>
    <label class="block text-sm">
      <span>{{t('platform.typeToConfirm', { target })}}</span>
      <input v-model="typed" class="field mt-2" autofocus autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" :disabled="busy" @keydown.enter.prevent="confirm" />
    </label>
    <template #footer>
      <Button variant="outline" :disabled="busy" @click="emit('cancel')">{{t('common.cancel')}}</Button>
      <Button variant="destructive" :disabled="!allowed" @click="confirm">{{t('common.confirm')}}</Button>
    </template>
  </AppDialog>
</template>
