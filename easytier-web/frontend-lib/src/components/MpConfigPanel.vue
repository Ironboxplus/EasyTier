<script setup lang="ts">
// Full MpConfig editor bound only to backend common.MpConfig + the flags-level
// tcp_hole_punch_mode / egress_wire_limit_bps. Persistence goes through the same
// NetworkConfig path core already uses; a running instance is hot-patched by the
// owner (RemoteManagement) when every changed field allows it.
import {
  Button,
  Checkbox,
  InputNumber,
  InputText,
  Select,
  Textarea,
} from 'primevue'
import { AnimatePresence, motion } from 'motion-v'
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  applyCongestionModelToMpConfig,
  applySchedulerModelToMpConfig,
  DEFAULT_MP_CONFIG,
  MP_POLICY_ACTIONS,
  MP_PROVIDERS,
  mpConfigToCongestionModel,
  mpConfigToSchedulerModel,
  normalizeMpConfig,
  normalizeTcpHolePunchMode,
  type MpConfig,
  type MpEgressLimit,
  type MpPunchRateLimit,
  type MpPathPolicy,
  type MpResourceGroupConfig,
  type MpSqmConfig,
  type TcpHolePunchMode,
} from '../types/mpConfig'
import { missingRequiredParams } from '../types/mpScheduler'
import MpEffectBadge from './MpEffectBadge.vue'
import MpDataPlanePanel, { type ProxyFlags } from './MpDataPlanePanel.vue'
import MpNumberField from './MpNumberField.vue'
import MpSchedulerPanel from './MpSchedulerPanel.vue'

const props = defineProps<{
  modelValue?: MpConfig | null
  tcpHolePunchMode?: string | null
  /** Global MPQUIC egress wire limit (bits/s); null = unlimited. */
  egressWireLimitBps?: number | string | null
  /** ET's existing quic/kcp proxy NetworkConfig flags (shown in the data-plane section). */
  proxyFlags?: Partial<ProxyFlags> | null
}>()

const emit = defineEmits<{
  'update:modelValue': [value: MpConfig]
  'update:tcpHolePunchMode': [value: TcpHolePunchMode]
  'update:egressWireLimitBps': [value: number | null]
  'update:proxyFlags': [value: ProxyFlags]
}>()

const proxyFlags = computed<ProxyFlags>(() => ({
  enable_quic_proxy: Boolean(props.proxyFlags?.enable_quic_proxy),
  disable_quic_input: Boolean(props.proxyFlags?.disable_quic_input),
  enable_kcp_proxy: Boolean(props.proxyFlags?.enable_kcp_proxy),
  disable_kcp_input: Boolean(props.proxyFlags?.disable_kcp_input),
}))

const { t } = useI18n()

const showAdvanced = ref(false)

const mp = computed<MpConfig>({
  get: () => normalizeMpConfig(props.modelValue ?? DEFAULT_MP_CONFIG()),
  set: (value) => emit('update:modelValue', normalizeMpConfig(value)),
})

function patch(fields: Partial<MpConfig>) {
  mp.value = { ...mp.value, ...fields }
}

const holeMode = computed<TcpHolePunchMode>({
  get: () => normalizeTcpHolePunchMode(props.tcpHolePunchMode),
  set: (value) => emit('update:tcpHolePunchMode', value),
})

const schedulerModel = computed({
  get: () => mpConfigToSchedulerModel(mp.value),
  set: (model: { scheduler: string, params: Record<string, unknown> }) => {
    mp.value = applySchedulerModelToMpConfig(mp.value, model)
  },
})

const congestionModel = computed({
  get: () => mpConfigToCongestionModel(mp.value),
  set: (model: { scheduler: string, params: Record<string, unknown> }) => {
    mp.value = applyCongestionModelToMpConfig(mp.value, model)
  },
})

const ccMissing = computed(() =>
  missingRequiredParams('congestion_control', congestionModel.value.scheduler, congestionModel.value.params))

// ---- units: the backend stores bits/s, the GUI edits Mbps ----

const MBPS = 1_000_000

function bpsToMbps(bps: number | string | null | undefined): number | null {
  if (bps === null || bps === undefined || bps === '') return null
  const n = Number(bps)
  return Number.isFinite(n) && n > 0 ? n / MBPS : null
}

function mbpsToBps(mbps: number | null | undefined): number {
  return mbps === null || mbps === undefined || !Number.isFinite(mbps) || mbps <= 0 ? 0 : Math.round(mbps * MBPS)
}

const globalLimitMbps = computed(() => bpsToMbps(props.egressWireLimitBps))

function setGlobalLimit(mbps: number | null) {
  const bps = mbpsToBps(mbps)
  emit('update:egressWireLimitBps', bps > 0 ? bps : null)
}

const holeModeOptions = [
  { label: 'auto', value: 'auto' },
  { label: 'faketcp', value: 'faketcp' },
  { label: 'tcp', value: 'tcp' },
]

const policyActionOptions = computed(() => MP_POLICY_ACTIONS.map(a => ({ label: t(`mp_policy.${a}`), value: a })))

// ---- list-shaped fields ----

function splitCsv(value: string): string[] {
  return value.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean)
}

const egressCsv = computed({
  get: () => mp.value.egress_devices.join(','),
  set: (value: string) => patch({ egress_devices: splitCsv(value) }),
})

const manualPathsText = computed({
  get: () => mp.value.manual_paths.join('\n'),
  set: (value: string) => patch({ manual_paths: value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean) }),
})

function patchNumber(key: keyof MpConfig, value: number | null) {
  if (value == null || !Number.isFinite(value)) return
  patch({ [key]: value } as Partial<MpConfig>)
}

function providerChecked(name: string): boolean {
  return mp.value.providers.includes(name)
}

function setProvider(name: string, on: boolean) {
  const set = new Set(mp.value.providers)
  if (on) set.add(name)
  else set.delete(name)
  patch({ providers: Array.from(set) })
}

function patchSqm(fields: Partial<MpSqmConfig>) {
  patch({ sqm: { ...mp.value.sqm, ...fields } })
}

// Rows being typed are kept locally until they are complete enough to survive
// normalization (e.g. a limit row without a device name).
const draftLimit = ref<{ egress_device: string, mbps: number | null }>({ egress_device: '', mbps: null })

function addEgressLimit() {
  const d = draftLimit.value
  const limit_bps = mbpsToBps(d.mbps)
  if (!d.egress_device.trim() || limit_bps <= 0) return
  const others = mp.value.egress_limits.filter(l => l.egress_device !== d.egress_device.trim())
  patch({ egress_limits: [...others, { egress_device: d.egress_device.trim(), limit_bps }] })
  draftLimit.value = { egress_device: '', mbps: null }
}

function updateEgressLimit(index: number, fields: Partial<MpEgressLimit>) {
  const limits = mp.value.egress_limits.map((l, i) => (i === index ? { ...l, ...fields } : l))
  patch({ egress_limits: limits })
}

function removeEgressLimit(index: number) {
  patch({ egress_limits: mp.value.egress_limits.filter((_, i) => i !== index) })
}

const draftPunchDevice = ref('')

function addPunchRateLimit() {
  const egress_device = draftPunchDevice.value.trim()
  if (!egress_device) return
  const others = mp.value.punch_rate_limits.filter(l => l.egress_device !== egress_device)
  patch({ punch_rate_limits: [...others, { egress_device, pps: mp.value.punch_pps }] })
  draftPunchDevice.value = ''
}

function updatePunchRateLimit(index: number, fields: Partial<MpPunchRateLimit>) {
  patch({ punch_rate_limits: mp.value.punch_rate_limits.map((l, i) => (i === index ? { ...l, ...fields } : l)) })
}

function removePunchRateLimit(index: number) {
  patch({ punch_rate_limits: mp.value.punch_rate_limits.filter((_, i) => i !== index) })
}

function addPolicy() {
  patch({
    path_policies: [...mp.value.path_policies, {
      match_egress_device: '',
      match_carrier_kind: '',
      match_remote_endpoint: '',
      action: 'prefer',
      prefer_weight: 2,
      enabled: true,
      note: '',
    }],
  })
}

function updatePolicy(index: number, fields: Partial<MpPathPolicy>) {
  patch({ path_policies: mp.value.path_policies.map((p, i) => (i === index ? { ...p, ...fields } : p)) })
}

function removePolicy(index: number) {
  patch({ path_policies: mp.value.path_policies.filter((_, i) => i !== index) })
}

function policyIsWildcard(p: MpPathPolicy): boolean {
  return !p.match_egress_device && !p.match_carrier_kind && !p.match_remote_endpoint
}

const newGroupName = ref('')

function addResourceGroup() {
  const name = newGroupName.value.trim()
  if (!name || mp.value.resource_groups.some(g => g.name === name)) return
  patch({ resource_groups: [...mp.value.resource_groups, { name, egress_devices: [], capacity_bps: 0, remote_endpoints: [] }] })
  newGroupName.value = ''
}

function updateGroup(index: number, fields: Partial<MpResourceGroupConfig>) {
  patch({ resource_groups: mp.value.resource_groups.map((g, i) => (i === index ? { ...g, ...fields } : g)) })
}

function removeGroup(index: number) {
  patch({ resource_groups: mp.value.resource_groups.filter((_, i) => i !== index) })
}

const sqmRangeInvalid = computed(() =>
  mp.value.sqm.autorate_max_bps > 0 && mp.value.sqm.autorate_min_bps > mp.value.sqm.autorate_max_bps)

</script>

<template>
  <div class="mp-config-panel flex flex-col gap-4" data-testid="mp-config-panel">
    <!-- ================= basic ================= -->
    <div class="flex flex-row flex-wrap gap-4 items-center">
      <div class="flex flex-wrap items-center gap-x-2 gap-y-1 min-w-0">
        <Checkbox :model-value="mp.enabled" input-id="mp-enabled" :binary="true" data-testid="mp-enabled"
          @update:model-value="(v: boolean) => patch({ enabled: v })" />
        <label for="mp-enabled">{{ t('mp_enabled') }}</label>
        <MpEffectBadge field="mp.enabled" />
      </div>
      <div class="flex flex-wrap items-center gap-x-2 gap-y-1 min-w-0">
        <Checkbox :model-value="mp.sqm.enabled" input-id="mp-sqm-enabled" :binary="true" data-testid="mp-sqm-enabled"
          @update:model-value="(v: boolean) => patchSqm({ enabled: v })" />
        <label for="mp-sqm-enabled">{{ t('mp_sqm_enabled') }}</label>
        <span class="pi pi-question-circle" v-tooltip="t('mp_sqm_enabled_help')"></span>
        <MpEffectBadge field="mp.sqm.enabled" />
      </div>
    </div>

    <div class="flex flex-row flex-wrap gap-4">
      <div class="flex flex-col gap-1 min-w-0 sm:min-w-[14rem] max-w-full">
        <label>{{ t('mp_egress_wire_limit') }}
          <span class="pi pi-question-circle" v-tooltip="t('mp_egress_wire_limit_help')"></span>
          <MpEffectBadge field="egress_wire_limit_bps" /></label>
        <MpNumberField :model-value="globalLimitMbps" :range="[0, 1000]" unit="Mbps" :min="0" :max-fraction-digits="3"
          :placeholder="t('mp_unlimited')" data-testid="mp-egress-wire-limit" @update:model-value="setGlobalLimit" />
      </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div class="flex flex-col gap-1 min-w-0">
        <MpEffectBadge field="mp.packet_scheduler" />
        <MpSchedulerPanel v-model="schedulerModel" kind="scheduler" :label="t('mp_packet_scheduler')" />
      </div>
      <div class="flex flex-col gap-1 min-w-0" data-testid="mp-cc-panel">
        <MpEffectBadge field="mp.congestion_control" />
        <MpSchedulerPanel v-model="congestionModel" kind="congestion_control" :label="t('mp_congestion_control')"
          testid="mp-cc-select" />
        <small v-if="ccMissing.length" class="text-red-500" data-testid="mp-cc-missing">
          {{ t('mp_cc_required', [ccMissing.join(', ')]) }}</small>
      </div>
    </div>

    <MpDataPlanePanel :model-value="mp" :advanced="showAdvanced" :proxy-flags="proxyFlags"
      @update:model-value="(v: MpConfig) => { mp = v }"
      @update:proxy-flags="(v: ProxyFlags) => emit('update:proxyFlags', v)" />

    <Button :label="showAdvanced ? t('mp_hide_advanced') : t('mp_show_advanced')"
      :icon="showAdvanced ? 'pi pi-chevron-up' : 'pi pi-chevron-down'" severity="secondary" outlined size="small"
      class="self-start" data-testid="mp-advanced-toggle" @click="showAdvanced = !showAdvanced" />

    <!-- ================= advanced ================= -->
    <AnimatePresence>
    <motion.div v-show="showAdvanced" key="mp-advanced" :initial="{ opacity: 0, height: 0 }"
      :animate="{ opacity: 1, height: 'auto' }" :exit="{ opacity: 0, height: 0 }"
      class="flex flex-col gap-4 overflow-hidden" data-testid="mp-advanced">
      <fieldset class="flex flex-col gap-2 border rounded p-3">
        <legend class="px-1 font-medium">{{ t('mp_paths_section') }}
          <MpEffectBadge field="mp.kmax" /></legend>
        <div class="flex flex-row flex-wrap gap-4">
          <div class="flex flex-col gap-1">
            <label>{{ t('mp_kmax') }}
              <span class="pi pi-question-circle" v-tooltip="t('mp_kmax_help')"></span></label>
            <MpNumberField :model-value="mp.kmax" :range="[1, 16]" :min="1" :max="64" data-testid="mp-kmax"
              @update:model-value="(v: number | null) => v != null && patchNumber('kmax', v)" />
          </div>
          <div class="flex flex-col gap-1">
            <label>{{ t('mp_control_interval_ms') }}</label>
            <MpNumberField :model-value="mp.control_interval_ms" :range="[100, 5000]" :step="100" unit="ms" :min="1"
              data-testid="mp-control-interval-ms"
              @update:model-value="(v: number | null) => v != null && patchNumber('control_interval_ms', v)" />
          </div>
          <div class="flex flex-col gap-1">
            <label>{{ t('mp_establishment_timeout_ms') }}
              <MpEffectBadge field="mp.establishment_timeout_ms" /></label>
            <MpNumberField :model-value="mp.establishment_timeout_ms" :range="[1000, 60000]" :step="1000" unit="ms"
              :min="1000" :max="120000" data-testid="mp-establishment-timeout-ms"
              @update:model-value="(v: number | null) => v != null && patchNumber('establishment_timeout_ms', v)" />
          </div>
        </div>
      </fieldset>

      <fieldset class="flex flex-col gap-2 border rounded p-3">
        <legend class="px-1 font-medium">{{ t('mp_paths_section') }}
          <MpEffectBadge field="mp.providers" /></legend>
        <label>{{ t('mp_providers') }}</label>
        <div class="flex flex-row flex-wrap gap-3">
          <div v-for="name in MP_PROVIDERS" :key="name" class="flex items-center gap-2">
            <Checkbox :model-value="providerChecked(name)" :input-id="`mp-provider-${name}`" :binary="true"
              :data-testid="`mp-provider-${name}`" @update:model-value="(v: boolean) => setProvider(name, v)" />
            <label :for="`mp-provider-${name}`">{{ name }}</label>
          </div>
        </div>
        <div class="flex flex-row flex-wrap gap-4">
          <div class="flex flex-col gap-1 min-w-0 sm:min-w-[14rem] max-w-full">
            <label>{{ t('tcp_hole_punch_mode') }}
              <MpEffectBadge field="tcp_hole_punch_mode" /></label>
            <Select v-model="holeMode" :options="holeModeOptions" option-label="label" option-value="value"
              data-testid="mp-tcp-hole-mode" />
          </div>
          <div class="flex flex-col gap-1">
            <label>{{ t('mp_punch_attempts') }}
              <MpEffectBadge field="mp.punch_attempts" />
              <span class="pi pi-question-circle" v-tooltip="t('mp_punch_attempts_help')"></span></label>
            <MpNumberField :model-value="mp.punch_attempts" :range="[1, 8]" :min="1" :max="8" data-testid="mp-punch-attempts"
              @update:model-value="(v: number | null) => patch({ punch_attempts: v ?? 1 })" />
          </div>
          <div class="flex flex-col gap-1 grow">
            <label>{{ t('mp_egress_devices') }}</label>
            <InputText v-model="egressCsv" class="w-full" data-testid="mp-egress-devices"
              :placeholder="t('mp_egress_devices_placeholder')" />
          </div>
        </div>
        <div class="flex flex-col gap-1">
          <label>{{ t('mp_manual_paths') }}</label>
          <Textarea v-model="manualPathsText" rows="3" class="w-full font-mono text-sm" data-testid="mp-manual-paths"
            :placeholder="t('mp_manual_paths_placeholder')" />
        </div>
        <div class="flex items-center gap-2">
          <Checkbox :model-value="mp.disable_overlay_weighted_routing" input-id="mp-disable-overlay" :binary="true"
            data-testid="mp-disable-overlay"
            @update:model-value="(v: boolean) => patch({ disable_overlay_weighted_routing: v })" />
          <label for="mp-disable-overlay">{{ t('mp_disable_overlay_weighted_routing') }}</label>
        </div>
      </fieldset>

      <fieldset class="flex flex-col gap-2 border rounded p-3" data-testid="mp-policies">
        <legend class="px-1 font-medium">{{ t('mp_policies_section') }}
          <MpEffectBadge field="mp.path_policies" /></legend>
        <small class="text-color-secondary">{{ t('mp_policies_help') }}</small>
        <table v-if="mp.path_policies.length" class="w-full text-sm mp-edit-table">
          <thead>
            <tr>
              <th>{{ t('mp_policy_col.egress') }}</th>
              <th>{{ t('mp_policy_col.carrier') }}</th>
              <th>{{ t('mp_policy_col.remote') }}</th>
              <th>{{ t('mp_policy_col.action') }}</th>
              <th>{{ t('mp_policy_col.weight') }}</th>
              <th>{{ t('mp_policy_col.enabled') }}</th>
              <th>{{ t('mp_policy_col.note') }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(p, i) in mp.path_policies" :key="i" data-testid="mp-policy-row">
              <td><InputText :model-value="p.match_egress_device" size="small" placeholder="*"
                @update:model-value="(v?: string) => updatePolicy(i, { match_egress_device: v ?? '' })" /></td>
              <td><InputText :model-value="p.match_carrier_kind" size="small" placeholder="*"
                @update:model-value="(v?: string) => updatePolicy(i, { match_carrier_kind: v ?? '' })" /></td>
              <td><InputText :model-value="p.match_remote_endpoint" size="small" placeholder="*"
                @update:model-value="(v?: string) => updatePolicy(i, { match_remote_endpoint: v ?? '' })" /></td>
              <td><Select :model-value="p.action" :options="policyActionOptions" option-label="label" option-value="value"
                size="small" @update:model-value="(v: MpPathPolicy['action']) => updatePolicy(i, { action: v, prefer_weight: v === 'prefer' ? (p.prefer_weight || 2) : 0 })" /></td>
              <td><InputNumber v-if="p.action === 'prefer'" :model-value="p.prefer_weight" :min="0" :max-fraction-digits="2"
                size="small" @update:model-value="(v: number | null) => updatePolicy(i, { prefer_weight: v ?? 1 })" /></td>
              <td><Checkbox :model-value="p.enabled" :binary="true"
                @update:model-value="(v: boolean) => updatePolicy(i, { enabled: v })" /></td>
              <td><InputText :model-value="p.note" size="small"
                @update:model-value="(v?: string) => updatePolicy(i, { note: v ?? '' })" />
                <small v-if="policyIsWildcard(p)" class="block text-orange-500">{{ t('mp_policy_wildcard') }}</small></td>
              <td><Button icon="pi pi-trash" text severity="danger" size="small" data-testid="mp-policy-remove"
                @click="removePolicy(i)" /></td>
            </tr>
          </tbody>
        </table>
        <Button :label="t('mp_policy_add')" icon="pi pi-plus" size="small" severity="secondary" class="self-start"
          data-testid="mp-policy-add" @click="addPolicy" />
      </fieldset>

      <fieldset class="flex flex-col gap-2 border rounded p-3" data-testid="mp-egress-limits">
        <legend class="px-1 font-medium">{{ t('mp_limits_section') }}
          <MpEffectBadge field="mp.egress_limits" /></legend>
        <small class="text-color-secondary">{{ t('mp_limits_help') }}</small>
        <div v-for="(l, i) in mp.egress_limits" :key="l.egress_device" class="flex items-center gap-2"
          data-testid="mp-egress-limit-row">
          <span class="w-40 font-mono">{{ l.egress_device }}</span>
          <InputNumber :model-value="bpsToMbps(l.limit_bps)" :min="0" :max-fraction-digits="3" size="small"
            @update:model-value="(v: number | null) => mbpsToBps(v) > 0 && updateEgressLimit(i, { limit_bps: mbpsToBps(v) })" />
          <span>Mbps</span>
          <Button icon="pi pi-trash" text severity="danger" size="small" @click="removeEgressLimit(i)" />
        </div>
        <div class="flex items-center gap-2">
          <InputText v-model="draftLimit.egress_device" size="small" :placeholder="t('mp_limit_device_placeholder')"
            data-testid="mp-limit-device" />
          <InputNumber v-model="draftLimit.mbps" :min="0" :max-fraction-digits="3" size="small" placeholder="Mbps"
            data-testid="mp-limit-mbps" />
          <Button :label="t('mp_limit_add')" icon="pi pi-plus" size="small" severity="secondary"
            data-testid="mp-limit-add" @click="addEgressLimit" />
        </div>
      </fieldset>

      <fieldset class="flex flex-col gap-2 border rounded p-3" data-testid="mp-punch-rate">
        <legend class="px-1 font-medium">{{ t('mp_punch_rate_section') }}
          <MpEffectBadge field="mp.punch_pps" /></legend>
        <small class="text-color-secondary">{{ t('mp_punch_rate_help') }}</small>
        <div class="flex flex-col gap-1">
          <label>{{ t('mp_punch_pps') }}</label>
          <MpNumberField :model-value="mp.punch_pps" :range="[0, 2000]" :step="10" :min="0" :unit="t('mp_pps_unit')"
            data-testid="mp-punch-pps" @update:model-value="(v: number | null) => patch({ punch_pps: v ?? 0 })" />
        </div>
        <div v-for="(l, i) in mp.punch_rate_limits" :key="l.egress_device" class="flex items-center gap-2"
          data-testid="mp-punch-rate-row">
          <span class="w-40 font-mono">{{ l.egress_device }}</span>
          <div class="grow">
            <MpNumberField :model-value="l.pps" :range="[0, 2000]" :step="10" :min="0" :unit="t('mp_pps_unit')"
              @update:model-value="(v: number | null) => updatePunchRateLimit(i, { pps: v ?? 0 })" />
          </div>
          <Button icon="pi pi-trash" text severity="danger" size="small" @click="removePunchRateLimit(i)" />
        </div>
        <div class="flex items-center gap-2">
          <InputText v-model="draftPunchDevice" size="small" :placeholder="t('mp_limit_device_placeholder')"
            data-testid="mp-punch-rate-device" />
          <Button :label="t('mp_punch_rate_add')" icon="pi pi-plus" size="small" severity="secondary"
            data-testid="mp-punch-rate-add" @click="addPunchRateLimit" />
        </div>
      </fieldset>

      <fieldset class="flex flex-col gap-2 border rounded p-3" data-testid="mp-sqm">
        <legend class="px-1 font-medium">{{ t('mp_sqm_section') }}</legend>
        <div class="flex flex-row flex-wrap gap-4">
          <div class="flex flex-col gap-1">
            <label>{{ t('mp_sqm_target_ms') }} <MpEffectBadge field="mp.sqm.target_ms" /></label>
            <MpNumberField :model-value="mp.sqm.target_ms" :range="[1, 50]" unit="ms" :min="1" :max="1000"
              data-testid="mp-sqm-target" @update:model-value="(v: number | null) => v && patchSqm({ target_ms: v })" />
          </div>
          <div class="flex flex-col gap-1">
            <label>{{ t('mp_sqm_interval_ms') }} <MpEffectBadge field="mp.sqm.interval_ms" /></label>
            <MpNumberField :model-value="mp.sqm.interval_ms" :range="[10, 1000]" :step="10" unit="ms" :min="1" :max="10000"
              data-testid="mp-sqm-interval" @update:model-value="(v: number | null) => v && patchSqm({ interval_ms: v })" />
          </div>
          <div class="flex flex-col gap-1">
            <label>{{ t('mp_sqm_autorate_min') }}</label>
            <MpNumberField :model-value="bpsToMbps(mp.sqm.autorate_min_bps)" :range="[0, 1000]" unit="Mbps" :min="0"
              :max-fraction-digits="3" :placeholder="t('mp_auto')" :invalid="sqmRangeInvalid" data-testid="mp-sqm-autorate-min"
              @update:model-value="(v: number | null) => patchSqm({ autorate_min_bps: mbpsToBps(v) })" />
          </div>
          <div class="flex flex-col gap-1">
            <label>{{ t('mp_sqm_autorate_max') }}</label>
            <MpNumberField :model-value="bpsToMbps(mp.sqm.autorate_max_bps)" :range="[0, 1000]" unit="Mbps" :min="0"
              :max-fraction-digits="3" :placeholder="t('mp_auto')" :invalid="sqmRangeInvalid" data-testid="mp-sqm-autorate-max"
              @update:model-value="(v: number | null) => patchSqm({ autorate_max_bps: mbpsToBps(v) })" />
          </div>
        </div>
        <small v-if="sqmRangeInvalid" class="text-red-500">{{ t('mp_sqm_range_invalid') }}</small>
      </fieldset>

      <fieldset class="flex flex-col gap-2 border rounded p-3" data-testid="mp-resource-groups">
        <legend class="px-1 font-medium">{{ t('mp_resource_groups') }}
          <MpEffectBadge field="mp.resource_groups" /></legend>
        <small class="text-color-secondary">{{ t('mp_resource_groups_help') }}</small>
        <table v-if="mp.resource_groups.length" class="w-full text-sm mp-edit-table">
          <thead>
            <tr>
              <th>{{ t('mp_group_col.name') }}</th>
              <th>{{ t('mp_group_col.devices') }}</th>
              <th>{{ t('mp_group_col.capacity') }} (Mbps)</th>
              <th>{{ t('mp_group_col.remotes') }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(g, i) in mp.resource_groups" :key="g.name" data-testid="mp-group-row">
              <td class="font-mono">{{ g.name }}</td>
              <td><InputText :model-value="g.egress_devices.join(',')" size="small"
                @update:model-value="(v?: string) => updateGroup(i, { egress_devices: splitCsv(v ?? '') })" /></td>
              <td><InputNumber :model-value="bpsToMbps(g.capacity_bps)" :min="0" :max-fraction-digits="3" size="small"
                @update:model-value="(v: number | null) => updateGroup(i, { capacity_bps: mbpsToBps(v) })" /></td>
              <td><InputText :model-value="g.remote_endpoints.join(',')" size="small"
                @update:model-value="(v?: string) => updateGroup(i, { remote_endpoints: splitCsv(v ?? '') })" /></td>
              <td><Button icon="pi pi-trash" text severity="danger" size="small" @click="removeGroup(i)" /></td>
            </tr>
          </tbody>
        </table>
        <div class="flex items-center gap-2">
          <InputText v-model="newGroupName" size="small" :placeholder="t('mp_group_name_placeholder')"
            data-testid="mp-group-name" />
          <Button :label="t('mp_group_add')" icon="pi pi-plus" size="small" severity="secondary"
            data-testid="mp-group-add" @click="addResourceGroup" />
        </div>
      </fieldset>
    </motion.div>
    </AnimatePresence>

  </div>
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
}

</style>
