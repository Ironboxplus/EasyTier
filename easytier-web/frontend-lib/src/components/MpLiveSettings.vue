<script setup lang="ts">
// MP settings of a running instance, edited where the instance is watched.
// Every field shows when its change takes effect (MpEffectBadge, from the core's
// field-effect table); a field applies by itself when its edit is done, as a
// hot patch the owner can undo.
import { Button, Checkbox, InputNumber, Select } from 'primevue'
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { selectionValues } from '../modules/pathRunway'
import { DEFAULT_MP_SELECTION_CONFIG, fieldEffect, normalizeTcpHolePunchMode, type MpConfig, type MpSelectionConfig, type TcpHolePunchMode } from '../types/mpConfig'
import MpCard from './MpCard.vue'
import MpEffectBadge from './MpEffectBadge.vue'

export interface LiveFlagsChange {
  egress_wire_limit_bps?: number
  tcp_hole_punch_mode?: TcpHolePunchMode
}

export interface LiveChange {
  mp?: (mp: MpConfig) => MpConfig
  flags?: LiveFlagsChange
}

const props = defineProps<{
  mpConfig: MpConfig
  egressWireLimitBps?: number | string | null
  tcpHolePunchMode?: string | null
  /** True while a patch is in flight. */
  busy?: boolean
}>()

const emit = defineEmits<{
  apply: [label: string, change: LiveChange]
  reconnect: []
}>()

const { t } = useI18n()

const MBPS = 1_000_000

interface Draft {
  limitMbps: number | null
  sqmEnabled: boolean
  sqmTargetMs: number
  dataPlane: boolean
  holeMode: TcpHolePunchMode
  punchAttempts: number
  punchPps: number
  switchMinMs: number
  switchPercent: number
  lossyPercent: number
  unmeasuredMs: number
}

function fromProps(): Draft {
  const limit = Number(props.egressWireLimitBps ?? 0)
  // The path selection rules as they apply: a 0 in the config is the built-in value.
  const sel = selectionValues(props.mpConfig.selection)
  return {
    limitMbps: Number.isFinite(limit) && limit > 0 ? limit / MBPS : null,
    sqmEnabled: props.mpConfig.sqm.enabled,
    sqmTargetMs: props.mpConfig.sqm.target_ms,
    dataPlane: props.mpConfig.data_plane.enabled,
    holeMode: normalizeTcpHolePunchMode(props.tcpHolePunchMode),
    punchAttempts: props.mpConfig.punch_attempts,
    punchPps: props.mpConfig.punch_pps,
    switchMinMs: sel.switchMinMs,
    switchPercent: sel.switchPercent,
    lossyPercent: sel.lossyPercent,
    unmeasuredMs: sel.unmeasuredMs,
  }
}

const withSelection = (mp: MpConfig, change: Partial<MpSelectionConfig>): MpConfig =>
  ({ ...mp, selection: { ...(mp.selection ?? DEFAULT_MP_SELECTION_CONFIG()), ...change } })

const draft = ref<Draft>(fromProps())
const saved = computed(fromProps)
// Follow the saved values unless an edit is under way.
watch(saved, (next, before) => {
  sent.clear()
  if (JSON.stringify(draft.value) === JSON.stringify(before)) draft.value = { ...next }
})
/** Values applied and not yet reported back: Enter and then leaving the field must not apply twice. */
const sent = new Map<keyof Draft, unknown>()

const holeOptions = [
  { label: 'auto', value: 'auto' },
  { label: 'faketcp', value: 'faketcp' },
  { label: 'tcp', value: 'tcp' },
]

// A field applies by itself when its edit is done (a checkbox or a choice at once, a number when it
// loses focus or Enter is pressed), so there is no Apply button; the change toast can undo it.
const reconnectPending = ref(false)

function commit(field: keyof Draft, effectField: string) {
  const d = draft.value
  const s = saved.value
  if (d[field] === s[field] || (sent.has(field) && sent.get(field) === d[field])) return
  sent.set(field, d[field])
  const change: LiveChange = {}
  switch (field) {
    case 'limitMbps':
      change.flags = { egress_wire_limit_bps: d.limitMbps && d.limitMbps > 0 ? Math.round(d.limitMbps * MBPS) : 0 }
      break
    case 'holeMode':
      change.flags = { tcp_hole_punch_mode: d.holeMode }
      break
    case 'sqmEnabled':
      change.mp = mp => ({ ...mp, sqm: { ...mp.sqm, enabled: d.sqmEnabled } })
      break
    case 'sqmTargetMs':
      change.mp = mp => ({ ...mp, sqm: { ...mp.sqm, target_ms: d.sqmTargetMs } })
      break
    case 'dataPlane':
      change.mp = mp => ({ ...mp, data_plane: { ...mp.data_plane, enabled: d.dataPlane } })
      break
    case 'punchAttempts':
      change.mp = mp => ({ ...mp, punch_attempts: d.punchAttempts })
      break
    case 'punchPps':
      change.mp = mp => ({ ...mp, punch_pps: d.punchPps })
      break
    case 'switchMinMs':
      change.mp = mp => withSelection(mp, { switch_min_ms: d.switchMinMs })
      break
    case 'switchPercent':
      change.mp = mp => withSelection(mp, { switch_percent: d.switchPercent })
      break
    case 'lossyPercent':
      change.mp = mp => withSelection(mp, { lossy_percent: d.lossyPercent })
      break
    case 'unmeasuredMs':
      change.mp = mp => withSelection(mp, { unmeasured_rtt_ms: d.unmeasuredMs })
      break
  }
  if (fieldEffect(effectField) === 'reconnect') reconnectPending.value = true
  emit('apply', t('mp_live.applied'), change)
}

/**
 * Commit after a number field loses focus. PrimeVue's InputNumber emits `blur` before it writes the
 * typed value into the model (typing alone does not), so the commit waits until that has happened.
 */
function commitAfterBlur(field: keyof Draft, effectField: string) {
  queueMicrotask(() => commit(field, effectField))
}

/** A control that commits as soon as its value is set: checkboxes and choices. */
function set<K extends keyof Draft>(field: K, value: Draft[K], effectField: string) {
  draft.value = { ...draft.value, [field]: value }
  commit(field, effectField)
}

function reconnect() {
  reconnectPending.value = false
  emit('reconnect')
}
</script>

<template>
  <MpCard :title="t('mp_live.title')" icon="pi-sliders-h" data-testid="mp-live-settings">
    <template v-if="reconnectPending" #extra>
      <Button size="small" icon="pi pi-refresh" :label="t('mp_rt.apply_reconnect')" :disabled="busy" data-testid="mp-live-reconnect"
        @click="reconnect" />
    </template>
    <div class="grid gap-x-6 gap-y-4 md:grid-cols-2">
      <label class="flex min-w-0 flex-col gap-1">
        <span class="flex flex-wrap items-center gap-x-2 text-sm">{{ t('mp_live.egress_limit') }}<MpEffectBadge field="egress_wire_limit_bps" /></span>
        <InputNumber v-model="draft.limitMbps" :min="0" :max-fraction-digits="1" suffix=" Mbps" :placeholder="t('mp_rt.unlimited')"
          data-testid="mp-live-egress-limit" @blur="commit('limitMbps', 'egress_wire_limit_bps')"
          @keydown.enter="commit('limitMbps', 'egress_wire_limit_bps')" />
      </label>

      <label class="flex min-w-0 flex-col gap-1">
        <span class="flex flex-wrap items-center gap-x-2 text-sm">{{ t('mp_live.sqm_target') }}<MpEffectBadge field="mp.sqm.target_ms" /></span>
        <InputNumber v-model="draft.sqmTargetMs" :min="1" :max="1000" suffix=" ms" data-testid="mp-live-sqm-target"
          @blur="commit('sqmTargetMs', 'mp.sqm.target_ms')" @keydown.enter="commit('sqmTargetMs', 'mp.sqm.target_ms')" />
      </label>

      <label class="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-sm">
        <Checkbox :model-value="draft.sqmEnabled" binary data-testid="mp-live-sqm-enabled"
          @update:model-value="(v: boolean) => set('sqmEnabled', v, 'mp.sqm.enabled')" />
        {{ t('mp_live.sqm_enabled') }}<MpEffectBadge field="mp.sqm.enabled" />
      </label>

      <label class="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-sm">
        <Checkbox :model-value="draft.dataPlane" binary data-testid="mp-live-data-plane"
          @update:model-value="(v: boolean) => set('dataPlane', v, 'mp.data_plane.enabled')" />
        {{ t('mp_live.data_plane') }}<MpEffectBadge field="mp.data_plane.enabled" />
      </label>

      <label class="flex min-w-0 flex-col gap-1">
        <span class="flex flex-wrap items-center gap-x-2 text-sm">{{ t('mp_live.hole_mode') }}<MpEffectBadge field="tcp_hole_punch_mode" /></span>
        <Select :model-value="draft.holeMode" :options="holeOptions" option-label="label" option-value="value" data-testid="mp-live-hole-mode"
          @update:model-value="(v: TcpHolePunchMode) => set('holeMode', v, 'tcp_hole_punch_mode')" />
      </label>

      <label class="flex min-w-0 flex-col gap-1">
        <span class="flex flex-wrap items-center gap-x-2 text-sm">{{ t('mp_live.punch_attempts') }}<MpEffectBadge field="mp.punch_attempts" /></span>
        <InputNumber v-model="draft.punchAttempts" :min="1" :max="16" data-testid="mp-live-punch-attempts"
          @blur="commit('punchAttempts', 'mp.punch_attempts')" @keydown.enter="commit('punchAttempts', 'mp.punch_attempts')" />
      </label>

      <label class="flex min-w-0 flex-col gap-1">
        <span class="flex flex-wrap items-center gap-x-2 text-sm">{{ t('mp_live.punch_pps') }}<MpEffectBadge field="mp.punch_pps" /></span>
        <InputNumber v-model="draft.punchPps" :min="0" :placeholder="t('mp_rt.unlimited')" data-testid="mp-live-punch-pps"
          @blur="commit('punchPps', 'mp.punch_pps')" @keydown.enter="commit('punchPps', 'mp.punch_pps')" />
      </label>

      <!-- path selection: when a faster path replaces a sending one, and which paths stay out -->
      <fieldset class="flex min-w-0 flex-col gap-2 md:col-span-2" data-testid="mp-live-switch">
        <legend class="flex flex-wrap items-center gap-x-2 text-sm">{{ t('mp_live.switch') }}<MpEffectBadge field="mp.selection.switch_min_ms" /></legend>
        <small class="text-color-secondary">{{ t('mp_live.switch_help') }}</small>
        <div class="flex flex-wrap items-center gap-2 text-sm">
          {{ t('mp_live.switch_faster') }}
          <InputNumber v-model="draft.switchMinMs" :min="1" :max="1000" suffix=" ms" input-class="w-24" data-testid="mp-live-switch-min"
            @blur="commitAfterBlur('switchMinMs', 'mp.selection.switch_min_ms')" @keydown.enter="commit('switchMinMs', 'mp.selection.switch_min_ms')" />
          {{ t('mp_live.switch_and') }}
          <InputNumber v-model="draft.switchPercent" :min="1" :max="100" suffix=" %" input-class="w-20" data-testid="mp-live-switch-percent"
            @blur="commitAfterBlur('switchPercent', 'mp.selection.switch_percent')" @keydown.enter="commit('switchPercent', 'mp.selection.switch_percent')" />
        </div>
      </fieldset>

      <label class="flex min-w-0 flex-col gap-1">
        <span class="flex flex-wrap items-center gap-x-2 text-sm">{{ t('mp_live.lossy') }}<MpEffectBadge field="mp.selection.lossy_percent" /></span>
        <InputNumber v-model="draft.lossyPercent" :min="1" :max="100" suffix=" %" data-testid="mp-live-lossy"
          @blur="commitAfterBlur('lossyPercent', 'mp.selection.lossy_percent')" @keydown.enter="commit('lossyPercent', 'mp.selection.lossy_percent')" />
      </label>

      <label class="flex min-w-0 flex-col gap-1">
        <span class="flex flex-wrap items-center gap-x-2 text-sm">{{ t('mp_live.unmeasured') }}<MpEffectBadge field="mp.selection.unmeasured_rtt_ms" /></span>
        <InputNumber v-model="draft.unmeasuredMs" :min="1" :max="5000" suffix=" ms" data-testid="mp-live-unmeasured"
          @blur="commitAfterBlur('unmeasuredMs', 'mp.selection.unmeasured_rtt_ms')" @keydown.enter="commit('unmeasuredMs', 'mp.selection.unmeasured_rtt_ms')" />
      </label>
    </div>
  </MpCard>
</template>
