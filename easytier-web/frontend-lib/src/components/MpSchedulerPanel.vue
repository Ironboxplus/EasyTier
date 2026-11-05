<script setup lang="ts">
// Plugin picker + parameter panel for one plugin kind (packet scheduler or
// congestion control). Options and every parameter control come from the
// plugin's `tunables` schema (generated/mp_plugins.json) — new plugins need
// zero UI changes here. Names and texts are localized under `mp_plugin` when a
// translation exists, else the schema's own English text is shown.
import { InputNumber, Select, Slider, ToggleSwitch } from 'primevue'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  defaultParams,
  getPlugin,
  listPlugins,
  missingRequiredParams,
  type MpPluginKind,
  type Tunable,
} from '../types/mpScheduler'

const props = withDefaults(defineProps<{
  kind?: MpPluginKind
  label?: string
  testid?: string
}>(), {
  kind: 'scheduler',
  label: 'Multipath scheduler',
  testid: 'mp-scheduler-select',
})

const model = defineModel<{ scheduler: string, params: Record<string, unknown> }>({
  default: () => ({ scheduler: 'min-rtt', params: {} }),
})

const { t, te } = useI18n()

function text(plugin: string, field: string, fallback: string): string {
  const key = `mp_plugin.${props.kind}.${plugin.replace(/-/g, '_')}.${field}`
  return te(key) ? t(key) : fallback
}

const pluginOptions = computed(() => listPlugins(props.kind).map(p => ({
  label: text(p.name, 'name', p.name),
  value: p.name,
})))

const current = computed(() => getPlugin(props.kind, model.value.scheduler))
const currentTunables = computed<Tunable[]>(() => current.value?.tunables ?? [])
const currentDescription = computed(() => current.value ? text(current.value.name, 'description', current.value.description) : '')
const missing = computed(() => new Set(missingRequiredParams(props.kind, model.value.scheduler, model.value.params)))

function tunableLabel(tn: Tunable): string {
  return text(model.value.scheduler, `${tn.key}.label`, tn.label)
}

function tunableHelp(tn: Tunable): string {
  return text(model.value.scheduler, `${tn.key}.help`, tn.help)
}

function onPluginChange(name: string) {
  // reset params to the new algorithm's defaults so stale keys don't leak
  model.value = { scheduler: name, params: defaultParams(name, props.kind) }
}

function paramValue(tn: Tunable): unknown {
  return model.value.params?.[tn.key] ?? tn.default
}

// Unbounded numbers (e.g. Brutal Mbps) get a slider over a soft range that
// grows with the value; the input next to it still accepts anything.
function sliderMax(tn: Tunable): number {
  if (tn.kind.type === 'number' && tn.kind.max !== undefined) return tn.kind.max
  const v = Number(paramValue(tn) ?? 0)
  return Math.max(1000, Math.ceil((Number.isFinite(v) ? v : 0) * 2))
}

function sliderStep(tn: Tunable): number {
  return sliderMax(tn) <= 10 ? 0.1 : 1
}

function setParam(key: string, val: unknown) {
  const params = { ...model.value.params }
  if (val === null || val === undefined) delete params[key]
  else params[key] = val
  model.value = { ...model.value, params }
}
</script>

<template>
  <div class="mp-scheduler-panel flex flex-col gap-4">
    <div class="flex flex-col gap-1">
      <label class="font-medium">{{ label }}</label>
      <Select
        :model-value="model.scheduler"
        :options="pluginOptions"
        option-label="label"
        option-value="value"
        :data-testid="testid"
        v-tooltip.bottom="currentDescription"
        @update:model-value="onPluginChange"
      />
    </div>

    <div v-for="tn in currentTunables" :key="tn.key" class="flex flex-col gap-1" data-testid="mp-tunable">
      <label class="font-medium" v-tooltip.top="tunableHelp(tn)">{{ tunableLabel(tn) }}<span v-if="tn.default === null" class="text-red-500"> *</span>
        <i v-if="tunableHelp(tn)" class="pi pi-question-circle ml-1 text-xs text-color-secondary" /></label>

      <div v-if="tn.kind.type === 'slider'" class="flex items-center gap-3">
        <Slider
          class="flex-1"
          :model-value="Number(paramValue(tn))"
          :min="tn.kind.min"
          :max="tn.kind.max"
          :step="tn.kind.step"
          @update:model-value="(v: number | number[]) => setParam(tn.key, Array.isArray(v) ? v[0] : v)"
        />
        <span class="w-12 text-right tabular-nums">{{ Number(paramValue(tn)).toFixed(2) }}</span>
      </div>

      <ToggleSwitch
        v-else-if="tn.kind.type === 'toggle'"
        :model-value="Boolean(paramValue(tn))"
        @update:model-value="(v: boolean) => setParam(tn.key, v)"
      />

      <div v-else-if="tn.kind.type === 'number'" class="flex items-center gap-3">
        <Slider
          class="flex-1"
          :model-value="paramValue(tn) == null ? (tn.kind.min ?? 0) : Number(paramValue(tn))"
          :min="tn.kind.min ?? 0"
          :max="sliderMax(tn)"
          :step="sliderStep(tn)"
          :data-testid="`mp-tunable-slider-${tn.key}`"
          @update:model-value="(v: number | number[]) => setParam(tn.key, Array.isArray(v) ? v[0] : v)"
        />
        <InputNumber
          class="w-32"
          input-class="w-full"
          :model-value="paramValue(tn) == null ? null : Number(paramValue(tn))"
          :min="tn.kind.min"
          :max="tn.kind.max"
          :max-fraction-digits="3"
          :invalid="missing.has(tn.key)"
          :data-testid="`mp-tunable-${tn.key}`"
          @update:model-value="(v: number | null) => setParam(tn.key, v)"
        />
      </div>

      <Select
        v-else-if="tn.kind.type === 'enum'"
        :model-value="paramValue(tn)"
        :options="tn.kind.options"
        @update:model-value="(v: string) => setParam(tn.key, v)"
      />
    </div>
  </div>
</template>
