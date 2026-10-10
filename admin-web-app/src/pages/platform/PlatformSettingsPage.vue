<script setup lang="ts">
import { useI18n } from "vue-i18n"
import { setLocale } from "@/shared/i18n"
import { uiPreferences } from "@/shared/lib/preferences"
import { browserTelemetry } from "@/features/platform/model/browser-telemetry"
import { platformCutoverReadiness } from "@/features/platform/api/cutover-contract"
import PageHeader from "@/shared/ui/PageHeader.vue"
import Button from "@/shared/ui/Button.vue"
import OwnerReadinessPanel from "@/features/platform/ui/OwnerReadinessPanel.vue"
import { projectContext } from "@/features/platform/model/project-context"
const {t}=useI18n()
/** Bound in script setup so Vite replaces the compile-time manifest value;
 * template resolution must NOT look for a nonexistent _ctx global. */
const uiPackageVersion=__BRIAREUS_UI_PACKAGE_VERSION__
function onLocaleChange(event: Event): void {
  const value=(event.target as HTMLSelectElement).value
  if (value==="en" || value==="ru") setLocale(value)
}
</script>
<template>
  <div class="space-y-6"><PageHeader :title="t('platform.navigation.settings')" :description="t('platform.settingsHint')" />
    <section class="settings-card space-y-4"><h2 class="font-semibold">{{t('settings.interface')}}</h2>
      <label class="block max-w-sm text-xs">{{t('settings.language')}}<select :value="uiPreferences.locale.value" class="field mt-1" @change="onLocaleChange"><option value="en">English</option><option value="ru">Русский</option></select></label>
      <label class="block max-w-sm text-xs">{{t('settings.theme')}}<select v-model="uiPreferences.theme.value" class="field mt-1"><option value="system">{{t('common.system')}}</option><option value="light">{{t('common.light')}}</option><option value="dark">{{t('common.dark')}}</option></select></label>
      <label class="block max-w-sm text-xs">{{t('settings.density')}}<select v-model="uiPreferences.density.value" class="field mt-1"><option value="comfortable">{{t('common.comfortable')}}</option><option value="compact">{{t('common.compact')}}</option></select></label>
      <label class="block max-w-sm text-xs">{{t('platform.displayTimeZone')}}
        <select v-model="uiPreferences.displayTimeZone.value" class="field mt-1">
          <option value="system">{{t('platform.deviceTimeZone')}}</option>
          <option value="UTC">UTC</option>
        </select>
      </label>
      <p class="max-w-xl text-xs text-muted-foreground">{{t('platform.displayTimeZoneHint')}}</p>
    </section>
    <section class="settings-card space-y-3">
      <h2 class="font-semibold">{{t('platform.browserDiagnostics')}}</h2>
      <label class="flex items-start gap-3 text-sm">
        <input v-model="uiPreferences.diagnosticsConsent.value" type="checkbox" class="mt-0.5" />
        <span>{{t('platform.browserDiagnosticsConsent')}}</span>
      </label>
      <p class="text-xs text-muted-foreground">{{t('platform.browserDiagnosticsPrivacy')}}</p>
      <p class="text-xs text-muted-foreground" role="status">
        {{t('platform.browserDiagnosticsCount',{count:browserTelemetry.state.buffered})}}
        · {{t('platform.browserDiagnosticsNoRelay')}}
      </p>
      <Button variant="outline" size="sm" @click="browserTelemetry.clear()">{{t('platform.clearDiagnostics')}}</Button>
    </section>
    <OwnerReadinessPanel v-if="projectContext.state.user?.active" />
    <section class="settings-card space-y-3">
      <h2 class="font-semibold">{{t('platform.serverSettings')}}</h2>
      <p role="status" class="text-sm text-muted-foreground">{{t('platform.cutoverDisabled')}}</p>
      <p class="text-xs text-muted-foreground">{{t('platform.cutoverSource') }}: {{platformCutoverReadiness.acceptedSource}}</p>
      <p class="text-xs text-muted-foreground">{{t('platform.uiPackageVersion')}}: {{uiPackageVersion}}</p>
      <p class="text-xs text-muted-foreground">{{t('platform.environmentNotVerified')}}</p>
      <h3 class="text-sm font-medium">{{t('platform.cutoverRequirements')}}</h3>
      <ul class="list-inside list-disc space-y-1 text-xs text-muted-foreground">
        <li v-for="condition in platformCutoverReadiness.missing" :key="condition">{{t(`platform.cutoverPrerequisites.${condition}`)}}</li>
      </ul>
      <p class="text-xs text-muted-foreground">{{t('platform.cutoverNoLocalOverride')}}</p>
    </section>
  </div>
</template>
