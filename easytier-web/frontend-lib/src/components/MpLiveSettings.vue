<script setup lang="ts">
// MP settings of a running instance, edited where the instance is watched.
// Every field shows when its change takes effect (MpEffectBadge, from the core's
// field-effect table); one Apply sends everything that changed as a single
// hot patch, which the owner can undo.
import { Button, Checkbox, InputNumber, Select } from 'primevue'
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { normalizeTcpHolePunchMode, type MpConfig, type TcpHolePunchMode } from '../types/mpConfig'
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
}

function fromProps(): Draft {
  const limit = Number(props.egressWireLimitBps ?? 0)
  return {
    limitMbps: Number.isFinite(limit) && limit > 0 ? limit / MBPS : null,
    sqmEnabled: props.mpConfig.sqm.enabled,
    sqmTargetMs: props.mpConfig.sqm.target_ms,
    dataPlane: props.mpConfig.data_plane.enabled,
    holeMode: normalizeTcpHolePunchMode(props.tcpHolePunchMode),
    punchAttempts: props.mpConfig.punch_attempts,
    punchPps: props.mpConfig.punch_pps,
  }
}

const draft = ref<Draft>(fromProps())
const saved = computed(fromProps)
const dirty = computed(() => JSON.stringify(draft.value) !== JSON.stringify(saved.value))
// Follow the saved values unless an edit is under way.
watch(saved, (next, before) => {
  if (JSON.stringify(draft.value) === JSON.stringify(before)) draft.value = { ...next }
})

const holeOptions = [
  { label: 'auto', value: 'auto' },
  { label: 'faketcp', value: 'faketcp' },
  { label: 'tcp', value: 'tcp' },
]

function discard() {
  draft.value = { ...saved.value }
}

function apply() {
  const d = draft.value
  const s = saved.value
  const change: LiveChange = {}
  const flags: LiveFlagsChange = {}
  if (d.limitMbps !== s.limitMbps) flags.egress_wire_limit_bps = d.limitMbps && d.limitMbps > 0 ? Math.round(d.limitMbps * MBPS) : 0
  if (d.holeMode !== s.holeMode) flags.tcp_hole_punch_mode = d.holeMode
  if (Object.keys(flags).length) change.flags = flags
  const mpChanged = d.sqmEnabled !== s.sqmEnabled || d.sqmTargetMs !== s.sqmTargetMs || d.dataPlane !== s.dataPlane
    || d.punchAttempts !== s.punchAttempts || d.punchPps !== s.punchPps
  if (mpChanged) {
    change.mp = mp => ({
      ...mp,
      sqm: { ...mp.sqm, enabled: d.sqmEnabled, target_ms: d.sqmTargetMs },
      data_plane: { ...mp.data_plane, enabled: d.dataPlane },
      punch_attempts: d.punchAttempts,
      punch_pps: d.punchPps,
    })
  }
  emit('apply', t('mp_live.applied'), change)
}
</script>

<template>
  <MpCard :title="t('mp_live.title')" icon="pi-sliders-h" :hint="t('mp_live.hint')" data-testid="mp-live-settings">
    <div class="grid gap-x-6 gap-y-4 md:grid-cols-2">
      <label class="flex flex-col gap-1">
        <span class="flex items-center gap-2 text-sm">{{ t('mp_live.egress_limit') }}<MpEffectBadge field="egress_wire_limit_bps" /></span>
        <InputNumber v-model="draft.limitMbps" :min="0" :max-fraction-digits="1" suffix=" Mbps" :placeholder="t('mp_rt.unlimited')"
          data-testid="mp-live-egress-limit" />
      </label>

      <label class="flex flex-col gap-1">
        <span class="flex items-center gap-2 text-sm">{{ t('mp_live.sqm_target') }}<MpEffectBadge field="mp.sqm.target_ms" /></span>
        <InputNumber v-model="draft.sqmTargetMs" :min="1" :max="1000" suffix=" ms" data-testid="mp-live-sqm-target" />
      </label>

      <label class="flex items-center gap-2 text-sm">
        <Checkbox v-model="draft.sqmEnabled" binary data-testid="mp-live-sqm-enabled" />
        {{ t('mp_live.sqm_enabled') }}<MpEffectBadge field="mp.sqm.enabled" />
      </label>

      <label class="flex items-center gap-2 text-sm">
        <Checkbox v-model="draft.dataPlane" binary data-testid="mp-live-data-plane" />
        {{ t('mp_live.data_plane') }}<MpEffectBadge field="mp.data_plane.enabled" />
      </label>

      <label class="flex flex-col gap-1">
        <span class="flex items-center gap-2 text-sm">{{ t('mp_live.hole_mode') }}<MpEffectBadge field="tcp_hole_punch_mode" /></span>
        <Select v-model="draft.holeMode" :options="holeOptions" option-label="label" option-value="value" data-testid="mp-live-hole-mode" />
      </label>

      <label class="flex flex-col gap-1">
        <span class="flex items-center gap-2 text-sm">{{ t('mp_live.punch_attempts') }}<MpEffectBadge field="mp.punch_attempts" /></span>
        <InputNumber v-model="draft.punchAttempts" :min="1" :max="16" data-testid="mp-live-punch-attempts" />
      </label>

      <label class="flex flex-col gap-1">
        <span class="flex items-center gap-2 text-sm">{{ t('mp_live.punch_pps') }}<MpEffectBadge field="mp.punch_pps" /></span>
        <InputNumber v-model="draft.punchPps" :min="0" data-testid="mp-live-punch-pps" />
      </label>
    </div>

    <div class="flex flex-wrap items-center gap-2">
      <Button size="small" icon="pi pi-check" :label="t('mp_live.apply')" :disabled="busy || !dirty" data-testid="mp-live-apply" @click="apply" />
      <Button v-if="dirty" size="small" text severity="secondary" :label="t('mp_live.discard')" :disabled="busy" data-testid="mp-live-discard"
        @click="discard" />
    </div>
  </MpCard>
</template>
