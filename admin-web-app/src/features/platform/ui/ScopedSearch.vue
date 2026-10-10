<script setup lang="ts">
import { useId } from "vue"
import { useI18n } from "vue-i18n"
import Button from "@/shared/ui/Button.vue"

const props=defineProps<{
  modelValue:string
  label:string
  total:number
  visible:number
  partial?:boolean
}>()
const emit=defineEmits<{ "update:modelValue":[value:string] }>()
const {t}=useI18n()
const id=useId()
function update(value:string):void {emit("update:modelValue",value.slice(0,120))}
</script>
<template>
  <div class="space-y-2">
    <div class="flex min-w-0 flex-wrap items-end gap-2">
      <label :for="id" class="min-w-40 flex-1 text-xs">
        {{label}}
        <input :id="id" type="search" class="field mt-1" :value="modelValue"
          autocomplete="off" spellcheck="false" maxlength="120"
          :placeholder="t('platform.searchLoadedHint')"
          @input="update(($event.target as HTMLInputElement).value)" @keydown.esc.prevent="update('')" />
      </label>
      <Button v-if="modelValue" size="sm" variant="outline" @click="update('')">{{t('platform.clearSearch')}}</Button>
    </div>
    <p role="status" class="text-xs text-muted-foreground">
      {{t('platform.loadedSearchCount',{shown:visible,total})}}
      <span v-if="partial"> · {{t('platform.searchMayBeIncomplete')}}</span>
    </p>
  </div>
</template>
