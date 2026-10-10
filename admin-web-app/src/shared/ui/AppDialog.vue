<script setup lang="ts">
import { nextTick, onBeforeUnmount, ref, useId, watch } from "vue"
import { Teleport } from "vue"
import { X } from "lucide-vue-next"
import { useI18n } from "vue-i18n"

const props = withDefaults(defineProps<{
  open: boolean
  title: string
  width?: string
  closeLabel?: string
  descriptionId?: string
}>(), {
  width: "760px",
})
const emit = defineEmits<{ close: [] }>()
const {t}=useI18n()
const closeText=()=>props.closeLabel??String(t("common.close"))
const panel = ref<HTMLElement | null>(null)
const titleId = useId()
let focusBeforeDialog: HTMLElement | null = null

function restoreFocus(): void {
  if (focusBeforeDialog?.isConnected) focusBeforeDialog.focus()
  focusBeforeDialog = null
}
watch(() => props.open, async (open) => {
  if (!open) { restoreFocus(); return }
  focusBeforeDialog = document.activeElement instanceof HTMLElement ? document.activeElement : null
  await nextTick()
  if (!props.open) return
  // Prefer the intentionally focused destructive-typed input over the
  // earlier header close button; native autofocus alone is unreliable when
  // Vue Teleport mounts the dialog in a post-flush render.
  const preferred=panel.value?.querySelector<HTMLElement>("[autofocus]:not(:disabled)")
  const first=panel.value?.querySelector<HTMLElement>(
    "input:not(:disabled), select:not(:disabled), textarea:not(:disabled), button:not(:disabled)",
  )
  ;(preferred??first??panel.value)?.focus()
}, { flush: "post", immediate: true })
onBeforeUnmount(restoreFocus)

function handleKeydown(event: KeyboardEvent): void {
  if (event.key === "Escape") { event.stopPropagation(); emit("close"); return }
  if (event.key !== "Tab" || !panel.value) return
  const candidates = [...panel.value.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex]:not([tabindex='-1'])")]
  const focusable = candidates.filter(item => item.getClientRects().length > 0 && !item.closest("[inert]"))
  const first = focusable[0]
  const last = focusable[focusable.length - 1]
  if (!first || !last) { event.preventDefault(); panel.value.focus(); return }
  if (event.shiftKey && (document.activeElement === first || !panel.value.contains(document.activeElement))) { event.preventDefault(); last.focus() }
  else if (!event.shiftKey && (document.activeElement === last || !panel.value.contains(document.activeElement))) { event.preventDefault(); first.focus() }
}
</script>

<template>
  <Teleport to="body">
    <div v-if="open" class="fixed inset-0 z-[900] grid place-items-center p-4">
      <button type="button" class="absolute inset-0 bg-black/60 backdrop-blur-[1px]" :aria-label="closeText()" tabindex="-1" @click="emit('close')" />
      <section
        ref="panel"
        class="relative z-10 max-h-[90vh] w-full overflow-hidden rounded-2xl border border-border bg-card text-foreground shadow-2xl"
        :style="{ maxWidth: width }"
        role="dialog"
        aria-modal="true"
        :aria-labelledby="titleId"
        :aria-describedby="descriptionId"
        tabindex="-1"
        @keydown="handleKeydown"
      >
        <header class="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 :id="titleId" class="text-base font-semibold tracking-tight">{{ title }}</h2>
          <button type="button" class="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2" :aria-label="closeText()" @click="emit('close')">
            <X class="size-4" />
          </button>
        </header>
        <div class="max-h-[calc(90vh-68px)] overflow-auto p-5">
          <slot />
        </div>
        <footer v-if="$slots.footer" class="flex items-center justify-end gap-2 border-t border-border px-5 py-3">
          <slot name="footer" />
        </footer>
      </section>
    </div>
  </Teleport>
</template>
