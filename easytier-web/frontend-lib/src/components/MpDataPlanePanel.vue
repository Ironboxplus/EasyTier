<script setup lang="ts">
// Data-plane editor (MP_SQM_PLAN.md S2.9–S2.11, §9 MpDataPlaneConfig), embedded in MpConfigPanel.
// Defaults (TCP on its own reliable streams, everything else as QUIC DATAGRAM) need no rows; every
// non-default mode is an explicit per-class choice. ET's existing quic/kcp proxy flags are shown here because they are the
// per-TCP-connection reliable option, but they remain plain NetworkConfig flags.
import { Button, Checkbox, InputText, Select } from 'primevue'
import { AnimatePresence, motion } from 'motion-v'
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import MpEffectBadge from './MpEffectBadge.vue'
import MpNumberField from './MpNumberField.vue'
import {
  applyDataPlanePreset,
  classMode,
  dataPlaneClassNames,
  DEFAULT_MP_CLASS_POLICY,
  defaultClassMode,
  detectDataPlanePreset,
  MP_DATAPLANE_MODES,
  MP_OVERSIZE_POLICIES,
  MP_RULE_PROTOCOLS,
  moveClassRule,
  normalizePortRange,
  removeClassPolicy,
  removeClassRule,
  upsertClassPolicy,
  upsertClassRule,
  type MpClassRule,
  type MpConfig,
  type MpDataPlaneConfig,
  type MpDataPlaneMode,
  type MpDataPlanePresetName,
} from '../types/mpConfig'

export interface ProxyFlags {
  enable_quic_proxy: boolean
  disable_quic_input: boolean
  enable_kcp_proxy: boolean
  disable_kcp_input: boolean
}

const props = defineProps<{
  modelValue: MpConfig
  advanced: boolean
  proxyFlags: ProxyFlags
}>()

const emit = defineEmits<{
  'update:modelValue': [value: MpConfig]
  'update:proxyFlags': [value: ProxyFlags]
}>()

const { t } = useI18n()

const mp = computed(() => props.modelValue)
const dp = computed(() => mp.value.data_plane)

function commit(next: MpConfig) {
  emit('update:modelValue', next)
}

function patchDp(fields: Partial<MpDataPlaneConfig>) {
  commit({ ...mp.value, data_plane: { ...dp.value, ...fields } })
}

function setProxy(key: keyof ProxyFlags, value: boolean) {
  emit('update:proxyFlags', { ...props.proxyFlags, [key]: value })
}

// ---- presets ----

const preset = computed(() => detectDataPlanePreset(dp.value))
const presetOptions = computed(() => [
  { label: t('mp_dp.preset.default'), value: 'default' },
  { label: t('mp_dp.preset.rfc'), value: 'rfc' },
  ...(preset.value === 'custom' ? [{ label: t('mp_dp.preset.custom'), value: 'custom' }] : []),
])

function onPreset(value: string) {
  if (value !== 'custom') commit(applyDataPlanePreset(mp.value, value as MpDataPlanePresetName))
}

// ---- option lists ----

const modeOptions = computed(() => MP_DATAPLANE_MODES.map(m => ({ label: t(`mp_dp.mode.${m}`), value: m })))
const oversizeOptions = computed(() => MP_OVERSIZE_POLICIES.map(o => ({ label: t(`mp_dp.oversize.${o}`), value: o })))
const protocolOptions = MP_RULE_PROTOCOLS.map(p => ({ label: p, value: p }))

// ---- class policies: one row per class (built-in + user rule names) ----

const classes = computed(() => dataPlaneClassNames(dp.value))

function setMode(cls: string, mode: MpDataPlaneMode) {
  // The class's default mode needs no row: drop it instead of storing it.
  if (mode === defaultClassMode(cls)) commit(removeClassPolicy(mp.value, cls))
  else commit(upsertClassPolicy(mp.value, DEFAULT_MP_CLASS_POLICY(cls, mode)))
}

function builtin(cls: string): boolean {
  return !dp.value.class_rules.some(r => r.name === cls)
}

// ---- user classification rules ----

function emptyRule(): MpClassRule {
  return { name: '', protocol: 'any', port_range: '', dst_cidr: '', enabled: true }
}

const draftRule = ref<MpClassRule>(emptyRule())
const draftError = ref('')

function addRule() {
  const r = draftRule.value
  const name = r.name.trim()
  const port_range = normalizePortRange(r.port_range)
  if (!name || classes.value.includes(name)) {
    draftError.value = t('mp_dp.rule_name_invalid')
    return
  }
  if (port_range === null) {
    draftError.value = t('mp_dp.rule_port_invalid')
    return
  }
  commit(upsertClassRule(mp.value, { ...r, name, port_range }))
  draftRule.value = emptyRule()
  draftError.value = ''
}

function patchRule(rule: MpClassRule, fields: Partial<MpClassRule>) {
  if (fields.port_range !== undefined && normalizePortRange(fields.port_range) === null) return
  commit(upsertClassRule(mp.value, { ...rule, ...fields }))
}


const reveal = { initial: { opacity: 0, height: 0 }, animate: { opacity: 1, height: 'auto' }, exit: { opacity: 0, height: 0 } }
const row = { initial: { opacity: 0, y: -4 }, animate: { opacity: 1, y: 0 }, exit: { opacity: 0, x: 12 } }
</script>

<template>
  <fieldset class="flex flex-col gap-3 min-w-0 border rounded p-3" data-testid="mp-dataplane">
    <legend class="px-1 font-medium">{{ t('mp_dp.section') }}
      <MpEffectBadge field="mp.data_plane.enabled" /></legend>
    <small class="text-color-secondary">{{ t('mp_dp.help') }}</small>

    <!-- basic: switch, scenario preset, proxies -->
    <div class="flex min-w-0 flex-row flex-wrap items-center gap-4">
      <div class="flex items-center gap-2">
        <Checkbox :model-value="dp.enabled" input-id="mp-dp-enabled" :binary="true" data-testid="mp-dp-enabled"
          @update:model-value="(v: boolean) => patchDp({ enabled: v })" />
        <label for="mp-dp-enabled">{{ t('mp_dp.enabled') }}</label>
        <span class="pi pi-question-circle" v-tooltip="t('mp_dp.enabled_help')"></span>
      </div>
      <div class="flex flex-col gap-1 min-w-0 max-w-full sm:min-w-[16rem]">
        <label>{{ t('mp_dp.preset_label') }}
          <MpEffectBadge field="mp.data_plane.class_policies" /></label>
        <Select class="w-full min-w-0" :model-value="preset" :options="presetOptions" option-label="label" option-value="value"
          :disabled="!dp.enabled" data-testid="mp-dp-preset" @update:model-value="onPreset" />
      </div>
    </div>
    <small v-if="dp.enabled" class="text-color-secondary" data-testid="mp-dp-preset-help">
      {{ t(`mp_dp.preset_help.${preset}`) }}</small>

    <div class="flex flex-row flex-wrap gap-x-6 gap-y-2" data-testid="mp-dp-proxies">
      <div v-for="key in (['enable_quic_proxy', 'disable_quic_input', 'enable_kcp_proxy', 'disable_kcp_input'] as const)"
        :key="key" class="flex items-center gap-2">
        <Checkbox :model-value="proxyFlags[key]" :input-id="`mp-dp-${key}`" :binary="true" :data-testid="`mp-dp-${key}`"
          @update:model-value="(v: boolean) => setProxy(key, v)" />
        <label :for="`mp-dp-${key}`">{{ t(key) }}</label>
        <span class="pi pi-question-circle" v-tooltip="t(`${key}_help`)"></span>
        <MpEffectBadge :field="key" />
      </div>
    </div>
    <small class="text-color-secondary">{{ t('mp_dp.proxy_note') }}</small>

    <!-- advanced -->
    <AnimatePresence>
      <motion.div v-if="advanced && dp.enabled" key="dp-advanced" v-bind="reveal" class="flex flex-col gap-3 overflow-hidden"
        data-testid="mp-dp-advanced">
        <div class="flex flex-row flex-wrap gap-4">
          <div class="flex flex-col gap-1 min-w-0 max-w-full sm:min-w-[14rem]">
            <label>{{ t('mp_dp.oversize_label') }}
              <MpEffectBadge field="mp.data_plane.oversize" /></label>
            <Select class="w-full min-w-0" :model-value="dp.oversize" :options="oversizeOptions" option-label="label" option-value="value"
              data-testid="mp-dp-oversize" @update:model-value="(v) => patchDp({ oversize: v })" />
            <small class="text-color-secondary max-w-[28rem]">{{ t(`mp_dp.oversize_help.${dp.oversize}`) }}</small>
          </div>
          <div class="flex flex-col gap-1">
            <label>{{ t('mp_dp.stream_max') }}</label>
            <MpNumberField :model-value="dp.reliable_stream_max" :range="[1, 256]" :min="1" :max="1024"
              data-testid="mp-dp-stream-max"
              @update:model-value="(v: number | null) => v && patchDp({ reliable_stream_max: v })" />
          </div>
          <div class="flex flex-col gap-1">
            <label>{{ t('mp_dp.stream_idle_s') }}</label>
            <MpNumberField :model-value="dp.reliable_stream_idle_ms / 1000" :range="[1, 120]" unit="s" :min="1" :max="600"
              data-testid="mp-dp-stream-idle"
              @update:model-value="(v: number | null) => v && patchDp({ reliable_stream_idle_ms: Math.round(v * 1000) })" />
          </div>
        </div>

        <!-- class policies -->
        <div class="flex flex-col gap-1">
          <label class="font-medium">{{ t('mp_dp.classes_label') }}</label>
          <table class="w-full text-sm mp-edit-table" data-testid="mp-dp-classes">
            <thead>
              <tr>
                <th>{{ t('mp_dp.col.class') }}</th>
                <th>{{ t('mp_dp.col.mode') }}</th>
              </tr>
            </thead>
            <motion.tbody layout>
              <AnimatePresence>
                <motion.tr v-for="cls in classes" :key="cls" layout v-bind="row" :data-testid="`mp-dp-class-${cls}`">
                  <td class="font-mono whitespace-nowrap">{{ builtin(cls) ? t(`mp_dp.class.${cls}`) : cls }}</td>
                  <td>
                    <Select :model-value="classMode(dp, cls)" :options="modeOptions" option-label="label"
                      option-value="value" size="small" :data-testid="`mp-dp-mode-${cls}`"
                      @update:model-value="(v: MpDataPlaneMode) => setMode(cls, v)" />
                    <small class="block text-color-secondary max-w-[16rem]">{{ t(`mp_dp.mode_help.${classMode(dp, cls)}`) }}</small>
                  </td>
                </motion.tr>
              </AnimatePresence>
            </motion.tbody>
          </table>
        </div>

        <!-- user classification rules -->
        <div class="flex flex-col gap-1" data-testid="mp-dp-rules">
          <label class="font-medium">{{ t('mp_dp.rules_label') }}
            <MpEffectBadge field="mp.data_plane.class_rules" /></label>
          <small class="text-color-secondary">{{ t('mp_dp.rules_help') }}</small>
          <table v-if="dp.class_rules.length" class="w-full text-sm mp-edit-table">
            <thead>
              <tr>
                <th></th>
                <th>{{ t('mp_dp.col.name') }}</th>
                <th>{{ t('mp_dp.col.protocol') }}</th>
                <th>{{ t('mp_dp.col.ports') }}</th>
                <th>{{ t('mp_dp.col.dst') }}</th>
                <th>{{ t('mp_dp.col.enabled') }}</th>
                <th></th>
              </tr>
            </thead>
            <motion.tbody layout>
              <AnimatePresence>
                <motion.tr v-for="(r, i) in dp.class_rules" :key="r.name" layout v-bind="row" data-testid="mp-dp-rule-row">
                  <td class="whitespace-nowrap">
                    <Button icon="pi pi-arrow-up" text size="small" :disabled="i === 0" data-testid="mp-dp-rule-up"
                      @click="commit(moveClassRule(mp, r.name, -1))" />
                    <Button icon="pi pi-arrow-down" text size="small" :disabled="i === dp.class_rules.length - 1"
                      data-testid="mp-dp-rule-down" @click="commit(moveClassRule(mp, r.name, 1))" />
                  </td>
                  <td class="font-mono">{{ r.name }}</td>
                  <td><Select :model-value="r.protocol" :options="protocolOptions" option-label="label" option-value="value"
                    size="small" @update:model-value="(v: string) => patchRule(r, { protocol: v })" /></td>
                  <td><InputText :model-value="r.port_range" size="small" placeholder="*"
                    @change="(e: Event) => patchRule(r, { port_range: (e.target as HTMLInputElement).value })" /></td>
                  <td><InputText :model-value="r.dst_cidr" size="small" placeholder="*"
                    @change="(e: Event) => patchRule(r, { dst_cidr: (e.target as HTMLInputElement).value.trim() })" /></td>
                  <td><Checkbox :model-value="r.enabled" :binary="true"
                    @update:model-value="(v: boolean) => patchRule(r, { enabled: v })" /></td>
                  <td><Button icon="pi pi-trash" text severity="danger" size="small" data-testid="mp-dp-rule-remove"
                    @click="commit(removeClassRule(mp, r.name))" /></td>
                </motion.tr>
              </AnimatePresence>
            </motion.tbody>
          </table>
          <div class="flex flex-wrap items-center gap-2">
            <InputText v-model="draftRule.name" size="small" :placeholder="t('mp_dp.rule_name_placeholder')"
              data-testid="mp-dp-rule-name" />
            <Select v-model="draftRule.protocol" :options="protocolOptions" option-label="label" option-value="value"
              size="small" data-testid="mp-dp-rule-protocol" />
            <InputText v-model="draftRule.port_range" size="small" :placeholder="t('mp_dp.rule_ports_placeholder')"
              data-testid="mp-dp-rule-ports" />
            <InputText v-model="draftRule.dst_cidr" size="small" :placeholder="t('mp_dp.rule_dst_placeholder')"
              data-testid="mp-dp-rule-dst" />
            <Button :label="t('mp_dp.rule_add')" icon="pi pi-plus" size="small" severity="secondary"
              data-testid="mp-dp-rule-add" @click="addRule" />
          </div>
          <small v-if="draftError" class="text-red-500" data-testid="mp-dp-rule-error">{{ draftError }}</small>
        </div>
      </motion.div>
    </AnimatePresence>
  </fieldset>
</template>

<style scoped>
.mp-edit-table th {
  text-align: left;
  font-weight: 500;
  padding: 0.25rem;
  white-space: nowrap;
}

.mp-edit-table td {
  padding: 0.25rem;
  vertical-align: top;
}

</style>
