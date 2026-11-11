<script setup lang="ts">
// Live MP view bound to `NetworkInstanceRunningInfo.mp_runtime` (MP_SQM_PLAN.md §10).
// Per-session view (one peer row): traffic classification, congestion control
// and paths. NIC-level state (send limits, autorate, the CAKE send queue) is in
// MpEgressPanel. Rates are differenced from monotonic counters by MpRuntimeHistory. Path actions and the congestion control
// switch are emitted for the owner to hot-apply through `patch_network_config`.
import { AnimatePresence, motion } from 'motion-v'
import { Button, Message, Tag } from 'primevue'
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  classKey,
  formatBps,
  formatBytes,
  formatUs,
  MpRuntimeHistory,
  nicPathFlows,
  pathKey,
  pathNic,
  toNum,
  type PathFlow,
  type ClassRates,
  type MpRuntimeView,
} from '../modules/mpRuntime'
import {
  mpConfigToCongestionModel,
  type CongestionModel,
  policyMatchForPath,
  type MpClassStatus,
  type MpConfig,
  type MpDataPlaneStatus,
  type MpPathStatus,
  type MpPeerStatus,
  type MpPolicyAction,
  type MpPolicyMatch,
  type MpRuntimeInfo,
} from '../types/mpConfig'
import MpFlowSankey from './MpFlowSankey.vue'
import MpSchedulerPanel from './MpSchedulerPanel.vue'
import MpStat from './MpStat.vue'
import PathRunway from './runway/PathRunway.vue'

type Step = 'classify' | 'cc' | 'paths'

const props = defineProps<{
  runtime?: MpRuntimeInfo | null
  /** Saved config of the instance: MP switch and the congestion control to edit. */
  mpConfig?: MpConfig | null
  /** True while a hot patch is in flight; disables the action buttons. */
  busy?: boolean
  /** Saved instance MTU, compared against the data plane's recommendation. */
  currentMtu?: number | null
  /** Scope the panel to one peer, for the Status peer-row expansion. */
  peerId?: number | string
  /** Step shown first; the paths by default. */
  initialStep?: Step
  /** Host names by peer id, to name relay nodes. */
  peerNames?: Record<string, string>
}>()

const emit = defineEmits<{
  'set-policy': [match: MpPolicyMatch, action: MpPolicyAction | null]
  /** A selection handle was released: `update` turns the saved MpConfig into the edited one. */
  'edit-mp': [label: string, update: (mp: MpConfig) => MpConfig]
  'reconnect': []
  /** Save `mtu`; takes effect after the instance restarts. */
  'apply-mtu': [mtu: number]
  /** Switch the congestion control of every MP session (applied with a reconnect). */
  'set-congestion-control': [model: CongestionModel]
}>()

const { t, te } = useI18n()

const fade = { initial: { opacity: 0, y: -4 }, animate: { opacity: 1, y: 0 }, exit: { opacity: 0, y: -4 } }
const stepFade = {
  initial: { opacity: 0, y: 6 },
  animate: { opacity: 1, y: 0, transition: { duration: 0.18 } },
  exit: { opacity: 0, y: -6, transition: { duration: 0.12 } },
}
const rowFade = { initial: { opacity: 0 }, animate: { opacity: 1 }, exit: { opacity: 0, x: 12 } }

const history = new MpRuntimeHistory()
const view = ref<MpRuntimeView>(history.ingest(props.runtime))
watch(() => props.runtime, (info) => {
  view.value = history.ingest(info)
})

// mp_peers entries are keyed by peer_id; a peerId prop scopes the whole panel
// to one peer (used to expand a single row of the upstream peer list), and is
// undefined for the unfiltered legacy view.
const peers = computed<MpPeerStatus[]>(() => {
  const all = view.value.peers
  return props.peerId === undefined ? all : all.filter(p => String(p.peer_id) === String(props.peerId))
})
/** False only when scoped to a peer that has no MP session at all. */
const hasPeerSession = computed(() => props.peerId === undefined || peers.value.length > 0)
const reconnectPeers = computed(() => peers.value.filter(p => p.reconnect_required))

// The saved config is unavailable for instances not started through this
// client (e.g. CLI/TOML); fall back to what the runtime proves, never guess "off".
const mpState = computed<'on' | 'off' | 'unknown'>(() => {
  if (props.mpConfig) return props.mpConfig.enabled ? 'on' : 'off'
  return peers.value.some(p => !p.standalone) ? 'on' : 'unknown'
})
// ---- congestion control switch ----------------------------------------------
// Only MP-managed sessions follow MpConfig; a standalone mpquic:// tunnel keeps
// the CC of its URL.
const ccSwitchable = computed(() => !!props.mpConfig && peers.value.some(p => !p.standalone))
const savedCc = computed<CongestionModel | undefined>(() => props.mpConfig ? mpConfigToCongestionModel(props.mpConfig) : undefined)
const ccDraft = ref<CongestionModel>({ scheduler: 'engine-default', params: {} })
const ccDirty = computed(() => !!savedCc.value && JSON.stringify(ccDraft.value) !== JSON.stringify(savedCc.value))
function copyCc(model: CongestionModel): CongestionModel {
  return { scheduler: model.scheduler, params: { ...model.params } }
}
watch(savedCc, (saved, before) => {
  // Follow the saved value unless the user is in the middle of an edit.
  if (saved && (!before || JSON.stringify(ccDraft.value) === JSON.stringify(before) || !ccDirty.value))
    ccDraft.value = copyCc(saved)
}, { immediate: true })

function applyCc() {
  emit('set-congestion-control', copyCc(ccDraft.value))
}

function resetCc() {
  if (savedCc.value) ccDraft.value = copyCc(savedCc.value)
}

// ---- per-session steps ------------------------------------------------------
// A session reads in the order a packet takes: classification → congestion
// control → paths → egress NIC. The step bar is also the navigation; the NIC
// step jumps to MpEgressPanel, where NIC-level state lives.
const stepOf = ref<Record<string, Step>>({})

function step(peer: MpPeerStatus): Step {
  return stepOf.value[peerKey(peer)] ?? props.initialStep ?? 'paths'
}

function setStep(peer: MpPeerStatus, s: Step) {
  stepOf.value = { ...stepOf.value, [peerKey(peer)]: s }
}

function showEgress() {
  document.querySelector('[data-testid="mp-egress-panel"]')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

function peerName(peerId?: number | string): string {
  if (peerId === undefined || peerId === null) return '-'
  return props.peerNames?.[String(peerId)] || t('mp_rt.peer_fallback', [peerId])
}

/** Where a path goes: the first relay node, or the peer's address. */
function routeName(path: MpPathStatus): string {
  if (path.carrier_kind === 'relay-next-hop') return peerName(path.first_hop_peer_id)
  return path.path?.remote_addr ?? '-'
}

/** The NIC a path leaves by; a relay path's resource id is no NIC name. */
function egressName(path: MpPathStatus): string {
  return pathNic(path) || '-'
}

function activePathsOf(peer: MpPeerStatus): MpPathStatus[] {
  return (peer.paths ?? []).filter(p => isActive(peer, p))
}

/** Lowest smoothed RTT among the paths carrying data. */
function bestRtt(peer: MpPeerStatus): number | undefined {
  const rtts = activePathsOf(peer).map(p => toNum(p.srtt_micros)).filter((v): v is number => v !== undefined)
  return rtts.length ? Math.min(...rtts) : undefined
}

function egressDevices(peer: MpPeerStatus): string {
  const devices = [...new Set((peer.paths ?? []).map(p => p.egress_device || p.local_resource).filter(Boolean))]
  return devices.length ? devices.join(' / ') : '-'
}

function sessionTotals(peer: MpPeerStatus): { send?: number, recv?: number } {
  let send: number | undefined
  let recv: number | undefined
  for (const path of peer.paths ?? []) {
    const r = rates(peer, path)
    if (r.sendBps !== undefined) send = (send ?? 0) + r.sendBps
    if (r.recvBps !== undefined) recv = (recv ?? 0) + r.recvBps
  }
  return { send, recv }
}

// ---- paths ------------------------------------------------------------------
function peerKey(peer: MpPeerStatus): string {
  // A peer can have both an MP-managed and a standalone mpquic:// session.
  return `${peer.peer_id}|${peer.standalone ? 'standalone' : 'mp'}`
}

function lifecycleSeverity(state?: string): 'success' | 'warn' | 'danger' | 'info' | 'secondary' {
  const s = (state ?? '').toLowerCase()
  if (!s || s === '-') return 'secondary'
  if (s === 'available' || s.includes('validated')) return 'success'
  if (s === 'standby') return 'info'
  if (s.includes('validat') || s.includes('pending')) return 'warn'
  if (s.includes('dead') || s.includes('fail') || s.includes('closed')) return 'danger'
  return 'info'
}

/** Localized name of a kebab-case core enum value (`standby`, `fake-tcp-punch`), else the raw value. */
function enumName(group: string, value?: string): string {
  if (!value) return '-'
  const key = `mp_rt.${group}.${value.replace(/-/g, '_')}`
  return te(key) ? t(key) : value
}

/** Localized congestion control name (`engine-default` → `默认（BBR）`). */
function ccName(name?: string): string {
  return enumName('cc_name', name)
}

function stateName(state?: string): string {
  return enumName('state', state)
}

function policySeverity(action?: string): 'info' | 'warn' | 'danger' | 'success' | 'secondary' {
  switch (action) {
    case 'pin': return 'success'
    case 'exclude': return 'danger'
    case 'pause': return 'warn'
    case 'prefer': return 'info'
    default: return 'secondary'
  }
}

function isActive(peer: MpPeerStatus, path: MpPathStatus): boolean {
  const id = path.path
  return !!id && (peer.active_paths ?? []).some(a =>
    String(a.carrier_id) === String(id.carrier_id) && a.local_addr === id.local_addr && a.remote_addr === id.remote_addr)
}

function rates(peer: MpPeerStatus, path: MpPathStatus) {
  return view.value.pathRates.get(pathKey(peer.peer_id, path)) ?? {}
}

function lossPct(v?: number): string {
  // proto3 JSON omits zero values, so an absent loss_rate on a reported path is 0.
  return `${((v ?? 0) * 100).toFixed(1)}%`
}

function setPolicy(path: MpPathStatus, action: MpPolicyAction | null) {
  emit('set-policy', policyMatchForPath(path), action)
}

/** The rate the paths carrying data were given (their share of the NIC's Autorate budget), summed. */
function brutalAllocated(peer: MpPeerStatus): number | undefined {
  const rates = activePathsOf(peer).map(p => toNum(p.target_rate_bps)).filter((v): v is number => v !== undefined)
  return rates.length ? rates.reduce((sum, v) => sum + v, 0) : undefined
}

/**
 * Each path carrying data runs its own Brutal at its share of the NIC's
 * Autorate budget under the peer's download; the local up rate is only where a
 * path starts before it has a share.
 */
function brutalActual(peer: MpPeerStatus): number | undefined {
  const start = toNum(peer.brutal_tx_bps)
  const rx = toNum(peer.peer_advertised_rx_bps)
  if (start === undefined) return undefined
  const capped = (rate: number) => (rx ? Math.min(rate, rx) : rate)
  const paths = activePathsOf(peer)
  if (!paths.length) return capped(start)
  return paths.reduce((sum, p) => sum + capped(toNum(p.target_rate_bps) ?? start), 0)
}

// ---- data plane -------------------------------------------------------------
function dpSeverity(dp: MpDataPlaneStatus): 'success' | 'warn' | 'secondary' {
  return dp.negotiated === 'datagram' ? 'success' : dp.negotiated === 'stream_fallback' ? 'warn' : 'secondary'
}

// Reasons the core reports in English that have a plain-language wording.
const DP_REASON_KEYS: Record<string, string> = {
  'session built without the data plane; reconnect to enable': 'mp_dp.rt.reason.not_built',
}

function dpReason(dp: MpDataPlaneStatus): string {
  const reason = dp.fallback_reason ?? ''
  const key = DP_REASON_KEYS[reason]
  return key ? t(key) : `${t('mp_dp.rt.fallback_reason')}: ${reason}`
}

function className(cls: string): string {
  return te(`mp_dp.class.${cls}`) ? t(`mp_dp.class.${cls}`) : cls
}

function modeName(mode?: string): string {
  return mode && te(`mp_dp.mode.${mode}`) ? t(`mp_dp.mode.${mode}`) : (mode || '-')
}

function classRates(peer: MpPeerStatus, cls: MpClassStatus): ClassRates {
  return view.value.classRates.get(classKey(peer, cls.class)) ?? {}
}

/** Received bytes are not classifiable (the frames are still encrypted), so only their sum is shown. */
function dpRx(peer: MpPeerStatus): { bps?: number, bytes: number } {
  let bps: number | undefined
  let bytes = 0
  for (const cls of peer.data_plane?.classes ?? []) {
    bytes += toNum(cls.rx_bytes) ?? 0
    const r = classRates(peer, cls).rxBps
    if (r !== undefined) bps = (bps ?? 0) + r
  }
  return { bps, bytes }
}

function count(v: unknown): number {
  return toNum(v) ?? 0
}

/** Offer the recommended MTU only when the saved one is larger, i.e. packets would not fit one datagram. */
function mtuApplicable(dp: MpDataPlaneStatus): boolean {
  const rec = toNum(dp.recommended_mtu)
  const cur = toNum(props.currentMtu)
  return rec !== undefined && rec > 0 && cur !== undefined && cur > rec
}

// ---- path selection ---------------------------------------------------------
/** How many paths carry data and how many stand by. */
function selectionText(peer: MpPeerStatus): string {
  const standby = (peer.paths ?? []).filter(p => p.lifecycle_state === 'standby').length
  return t('mp_rt.selection', [(peer.active_paths ?? []).length, standby])
}

/** Send rate by network card and path, for the Sankey chart. */
function flows(peer: MpPeerStatus) {
  return nicPathFlows(view.value, peer)
}

function nicName(nic: string): string {
  return nic || t('mp_rt.sankey.no_nic')
}

function pathFlowName(flow: PathFlow): string {
  return `${enumName('carrier', flow.path.carrier_kind)} · ${routeName(flow.path)} · ${stateName(flow.path.lifecycle_state)}`
}

/** Bytes between one datagram and the inner packet that fits in it. */
function mtuOverhead(dp: MpDataPlaneStatus): number | undefined {
  const max = toNum(dp.max_datagram_bytes)
  const rec = toNum(dp.recommended_mtu)
  return max !== undefined && rec !== undefined ? max - rec : undefined
}
</script>

<template>
  <div class="mp-runtime-panel flex flex-col gap-3" data-testid="mp-runtime-panel">
  <template v-if="hasPeerSession">
    <AnimatePresence>
      <motion.div v-if="reconnectPeers.length" key="mp-reconnect" v-bind="fade">
        <Message severity="warn" data-testid="mp-runtime-reconnect">
          <div class="flex flex-wrap items-center gap-3">
            <span>{{ t('mp_rt.reconnect_required', [reconnectPeers.map(p => p.peer_id).join(', ')]) }}</span>
            <Button size="small" :label="t('mp_rt.apply_reconnect')" :disabled="busy" data-testid="mp-runtime-reconnect-btn"
              @click="emit('reconnect')" />
          </div>
        </Message>
      </motion.div>
    </AnimatePresence>

    <section v-for="peer in peers" :key="peerKey(peer)" class="mp-session" data-testid="mp-runtime-peer">
      <!-- session header: what it is and how much it moves -->
      <header class="flex flex-wrap items-center gap-x-5 gap-y-1 px-4 py-2">
        <span v-if="peerId === undefined || peers.length > 1" class="font-semibold">
          {{ peer.standalone ? t('mp_rt.session_standalone', [peer.peer_id]) : t('mp_rt.session_mp', [peer.peer_id]) }}
        </span>
        <Tag :value="`MP ${t(`mp_rt.mp_${mpState}`)}`" :severity="mpState === 'on' ? 'success' : mpState === 'off' ? 'secondary' : 'warn'"
          data-testid="mp-runtime-mp-state" />
        <span class="ml-auto flex items-center gap-4 font-semibold tabular-nums" data-testid="mp-runtime-overview">
          <small class="font-normal text-color-secondary">QUIC</small>
          <span class="text-green-600 dark:text-green-400" data-testid="mp-runtime-total-send">↑ {{ formatBps(sessionTotals(peer).send) }}</span>
          <span class="text-sky-600 dark:text-sky-400">↓ {{ formatBps(sessionTotals(peer).recv) }}</span>
        </span>
      </header>

      <!-- the send pipeline; each step opens its detail below -->
      <nav class="mp-steps" data-testid="mp-runtime-pipeline">
        <button type="button" class="mp-step" :class="{ 'mp-step-on': step(peer) === 'classify' }" data-testid="mp-step-classify" :title="t('mp_rt.pipe.classify')"
          @click="setStep(peer, 'classify')">
          <span class="mp-step-name"><i class="mp-step-no">1</i><span class="mp-step-label">{{ t('mp_rt.pipe.classify') }}</span></span>
          <b class="truncate"><Tag :value="t(`mp_dp.rt.negotiated.${peer.data_plane?.negotiated || 'disabled'}`)"
            :severity="peer.data_plane ? dpSeverity(peer.data_plane) : 'secondary'" data-testid="mp-dp-negotiated" /></b>
          <motion.span v-if="step(peer) === 'classify'" :layout-id="`mp-step-${peerKey(peer)}`" class="mp-step-bar" />
        </button>
        <button type="button" class="mp-step" :class="{ 'mp-step-on': step(peer) === 'cc' }" data-testid="mp-step-cc" :title="t('mp_rt.pipe.cc')"
          @click="setStep(peer, 'cc')">
          <span class="mp-step-name"><i class="mp-step-no">2</i><span class="mp-step-label">{{ t('mp_rt.pipe.cc') }}</span></span>
          <b class="truncate">{{ ccName(peer.effective_congestion_control) }}</b>
          <motion.span v-if="step(peer) === 'cc'" :layout-id="`mp-step-${peerKey(peer)}`" class="mp-step-bar" />
        </button>
        <button type="button" class="mp-step" :class="{ 'mp-step-on': step(peer) === 'paths' }" data-testid="mp-step-paths" :title="t('mp_rt.pipe.paths')"
          @click="setStep(peer, 'paths')">
          <span class="mp-step-name"><i class="mp-step-no">3</i><span class="mp-step-label">{{ t('mp_rt.pipe.paths') }}</span></span>
          <b class="truncate"><span data-testid="mp-runtime-path-count">{{ activePathsOf(peer).length }} / {{ peer.paths?.length ?? 0 }}</span>
            <small v-if="bestRtt(peer) !== undefined" class="font-normal text-color-secondary"> · RTT {{ formatUs(bestRtt(peer)) }}</small></b>
          <motion.span v-if="step(peer) === 'paths'" :layout-id="`mp-step-${peerKey(peer)}`" class="mp-step-bar" />
        </button>
        <button type="button" class="mp-step" data-testid="mp-step-egress" :title="t('mp_rt.pipe.egress')" @click="showEgress">
          <span class="mp-step-name"><i class="mp-step-no">4</i><span class="mp-step-label">{{ t('mp_rt.pipe.egress') }}</span><i class="pi pi-arrow-up-right text-xs" /></span>
          <b class="truncate">{{ egressDevices(peer) }}</b>
        </button>
      </nav>

      <div class="p-4">
        <AnimatePresence mode="wait">
          <!-- 1. classification -->
          <motion.div v-if="step(peer) === 'classify'" key="classify" v-bind="stepFade" class="flex flex-col gap-5">
            <template v-if="peer.data_plane">
              <div class="flex flex-col gap-5" data-testid="mp-runtime-dataplane">
                <Message v-if="peer.data_plane.fallback_reason" severity="warn" size="small">
                  <span data-testid="mp-dp-fallback-reason">{{ dpReason(peer.data_plane) }}</span>
                </Message>

                <div v-if="peer.data_plane.classes?.length" class="overflow-x-auto rounded-lg border border-surface-200 dark:border-surface-700">
                  <table class="w-full text-sm mp-table" data-testid="mp-dp-class-status">
                    <thead>
                      <tr>
                        <th>{{ t('mp_dp.rt.col.class') }}</th>
                        <th>{{ t('mp_dp.rt.col.mode') }}</th>
                        <th>{{ t('mp_dp.rt.col.rate') }}</th>
                        <th>{{ t('mp_dp.rt.col.streams') }}</th>
                      </tr>
                    </thead>
                    <tbody>
                      <AnimatePresence>
                      <motion.tr v-for="cls in peer.data_plane.classes" :key="cls.class" layout v-bind="rowFade"
                        data-testid="mp-dp-class-row">
                        <td>{{ className(cls.class) }}</td>
                        <td><Tag :value="modeName(cls.mode)" :severity="cls.mode === 'reliable_stream' ? 'info' : 'secondary'" /></td>
                        <td class="whitespace-nowrap tabular-nums" data-testid="mp-dp-class-tx">↑ {{ formatBps(classRates(peer, cls).txBps) }}
                          <small class="text-color-secondary">{{ formatBytes(toNum(cls.tx_bytes)) }}</small></td>
                        <td class="tabular-nums">{{ cls.open_streams ?? 0 }}
                          <small class="text-color-secondary" v-tooltip.top="t('mp_dp.rt.recycled_help')">↻{{ count(cls.streams_recycled) }}</small></td>
                      </motion.tr>
                      </AnimatePresence>
                    </tbody>
                    <tfoot>
                      <tr class="mp-foot" v-tooltip.top="t('mp_dp.rt.rx_help')">
                        <td>{{ t('mp_dp.rt.rx_all') }}</td>
                        <td></td>
                        <td class="whitespace-nowrap tabular-nums">↓ {{ formatBps(dpRx(peer).bps) }}
                          <small class="text-color-secondary">{{ formatBytes(dpRx(peer).bytes) }}</small></td>
                        <td></td>
                      </tr>
                    </tfoot>
                  </table>
                </div>

                <!-- one datagram minus the tunnel's own headers is the largest inner packet -->
                <div v-if="peer.data_plane.max_datagram_bytes" class="flex flex-wrap items-stretch gap-2 mp-equation" data-testid="mp-dp-size">
                  <MpStat :label="t('mp_dp.rt.max_datagram')">{{ peer.data_plane.max_datagram_bytes }} B</MpStat>
                  <span class="mp-op">−</span>
                  <MpStat :label="t('mp_dp.rt.overhead')" :help="t('mp_dp.rt.overhead_help')">{{ mtuOverhead(peer.data_plane) ?? '-' }} B</MpStat>
                  <span class="mp-op">=</span>
                  <MpStat :label="t('mp_dp.rt.recommended_mtu')">
                    <span data-testid="mp-dp-recommended-mtu">{{ peer.data_plane.recommended_mtu }}</span></MpStat>
                  <template v-if="toNum(currentMtu) !== undefined">
                    <span class="mp-op" :class="mtuApplicable(peer.data_plane) ? 'text-amber-500' : 'text-green-500'">
                      {{ mtuApplicable(peer.data_plane) ? '<' : '≥' }}</span>
                    <MpStat :label="t('mp_dp.rt.current_mtu')" :tone="mtuApplicable(peer.data_plane) ? 'warn' : 'good'">{{ currentMtu }}</MpStat>
                    <Button v-if="mtuApplicable(peer.data_plane)" class="self-center" size="small" icon="pi pi-check" :disabled="busy"
                      :label="t('mp_dp.rt.apply_mtu', [peer.data_plane.recommended_mtu])" v-tooltip.top="t('mp_dp.rt.apply_mtu_note')"
                      data-testid="mp-dp-apply-mtu" @click="emit('apply-mtu', peer.data_plane.recommended_mtu!)" />
                  </template>
                </div>

                <div class="grid gap-2 grid-cols-2 lg:grid-cols-4 pt-4 border-t border-dashed border-surface-200 dark:border-surface-700">
                  <MpStat :label="t('mp_dp.rt.oversize')" :help="t('mp_dp.rt.oversize_help')"
                    :tone="count(peer.data_plane.oversize_dropped) + count(peer.data_plane.oversize_ptb) > 0 ? 'warn' : 'default'">
                    {{ count(peer.data_plane.oversize_dropped) }} / {{ count(peer.data_plane.oversize_ptb) }}
                  </MpStat>
                  <MpStat :label="t('mp_dp.rt.frag')" :help="t('mp_dp.rt.frag_help')"
                    :tone="count(peer.data_plane.frag_timeout) > 0 ? 'warn' : 'default'">
                    {{ count(peer.data_plane.frag_sent) }} / {{ count(peer.data_plane.frag_reassembled) }} / {{ count(peer.data_plane.frag_timeout) }}
                  </MpStat>
                  <MpStat :label="t('mp_dp.rt.queue_dropped')" :help="t('mp_dp.rt.queue_dropped_help')"
                    :tone="count(peer.data_plane.dgram_queue_dropped) > 0 ? 'warn' : 'default'">
                    {{ count(peer.data_plane.dgram_queue_dropped) }}
                  </MpStat>
                  <MpStat :label="t('mp_dp.rt.breaker')" :help="t('mp_dp.rt.breaker_help')"
                    :tone="count(peer.data_plane.circuit_breaker_trips) > 0 ? 'bad' : 'default'">
                    <span data-testid="mp-dp-breaker">{{ count(peer.data_plane.circuit_breaker_trips) }}</span>
                  </MpStat>
                </div>
              </div>
            </template>
            <span v-else class="text-sm text-color-secondary">{{ t('mp_dp.rt.negotiated.disabled') }}</span>
          </motion.div>

          <!-- 2. congestion control: what runs now → what to switch to -->
          <motion.div v-else-if="step(peer) === 'cc'" key="cc" v-bind="stepFade"
            class="grid gap-4 items-start" :class="ccSwitchable && !peer.standalone ? 'lg:grid-cols-[minmax(0,1fr)_auto_minmax(0,1.4fr)]' : ''">
            <div class="flex flex-col gap-3">
              <span class="text-xs text-color-secondary">{{ t('mp_rt.cc.running') }}</span>
              <div class="flex flex-wrap items-baseline gap-3">
                <span class="text-2xl font-semibold">{{ ccName(peer.effective_congestion_control) }}</span>
                <Tag v-if="peer.desired_congestion_control && peer.desired_congestion_control !== peer.effective_congestion_control"
                  :value="`→ ${ccName(peer.desired_congestion_control)}`" severity="warn" v-tooltip="t('mp_rt.cc.pending_help')" />
              </div>
              <span class="text-sm text-color-secondary">{{ t('mp_rt.recovery') }}: {{ enumName('recovery_kind', peer.effective_recovery) }}</span>
              <div v-if="toNum(peer.brutal_tx_bps) !== undefined" class="flex flex-wrap items-stretch gap-2 mp-equation" data-testid="mp-runtime-brutal">
                <MpStat :label="t('mp_rt.brutal_local_tx')">{{ formatBps(toNum(peer.brutal_tx_bps)) }}</MpStat>
                <span class="mp-op">∧</span>
                <MpStat :label="t('mp_rt.brutal_peer_rx')">
                  {{ toNum(peer.peer_advertised_rx_bps) ? formatBps(toNum(peer.peer_advertised_rx_bps)) : t('mp_rt.unlimited') }}</MpStat>
                <template v-if="brutalAllocated(peer) !== undefined">
                  <span class="mp-op">∧</span>
                  <MpStat :label="t('mp_rt.brutal_allocated')" v-tooltip.top="t('mp_rt.brutal_allocated_help')">
                    {{ formatBps(brutalAllocated(peer)) }}</MpStat>
                </template>
                <span class="mp-op">=</span>
                <MpStat :label="t('mp_rt.brutal_actual')" tone="good" v-tooltip.top="t('mp_rt.brutal_actual_help')">
                  {{ formatBps(brutalActual(peer)) }}</MpStat>
              </div>
              <small v-if="toNum(peer.brutal_tx_bps) !== undefined" class="text-color-secondary" data-testid="mp-runtime-target-note">
                {{ t('mp_rt.brutal_target_note') }}
              </small>
              <span v-if="peer.standalone" class="text-sm text-color-secondary">{{ t('mp_rt.cc.standalone_note') }}</span>
            </div>
            <template v-if="ccSwitchable && !peer.standalone">
              <i class="pi pi-arrow-right hidden lg:block self-center text-color-secondary" />
              <div class="flex flex-col gap-3 rounded-lg border border-surface-200 dark:border-surface-700 p-3" data-testid="mp-runtime-cc">
                <MpSchedulerPanel v-model="ccDraft" kind="congestion_control" :label="t('mp_rt.cc.switch_to')"
                  testid="mp-runtime-cc-select" />
                <div class="flex flex-wrap items-center gap-2">
                  <Button size="small" icon="pi pi-refresh" :label="t('mp_rt.cc.apply')" :disabled="busy || !ccDirty"
                    v-tooltip.top="t('mp_rt.cc.apply_help')" data-testid="mp-runtime-cc-apply" @click="applyCc" />
                  <Button v-if="ccDirty" size="small" text severity="secondary" :label="t('mp_rt.cc.discard')" :disabled="busy"
                    data-testid="mp-runtime-cc-discard" @click="resetCc" />
                </div>
              </div>
            </template>
          </motion.div>

          <!-- 3. paths -->
          <motion.div v-else key="paths" v-bind="stepFade" class="flex flex-col gap-4">
            <div class="flex flex-wrap items-center gap-2">
              <i class="pi pi-directions text-color-secondary" />
              <span class="text-sm" data-testid="mp-runtime-selection">{{ selectionText(peer) }}</span>
            </div>
            <Message v-if="peer.unsupported_reason" severity="error" size="small">{{ peer.unsupported_reason }}</Message>
            <Message v-if="toNum(peer.faketcp_upgrade?.failures)" severity="warn" size="small">
              <span :title="peer.faketcp_upgrade?.last_error" data-testid="mp-runtime-faketcp-upgrade">
                {{ t('mp_rt.faketcp_upgrade_failures', [toNum(peer.faketcp_upgrade?.failures)]) }}
                <template v-if="peer.faketcp_upgrade?.plain_tcp_fallback">· {{ t('mp_rt.faketcp_plain_tcp_fallback') }}</template>
              </span>
            </Message>

            <PathRunway :peer="peer" :mp-config="mpConfig" :peer-name="peerName(peer.peer_id)" :peer-names="peerNames"
              :busy="busy || !mpConfig" @edit="(label, update) => emit('edit-mp', label, update)"
              @set-policy="(m, a) => emit('set-policy', m, a)" />

            <details class="mp-details" data-testid="mp-runtime-path-details">
            <summary>{{ t('mp_runway.details') }}</summary>
            <div class="mt-3 overflow-x-auto rounded-lg border border-surface-200 dark:border-surface-700">
              <table class="w-full text-sm mp-table" data-testid="mp-runtime-paths">
                <thead>
                  <tr>
                    <th>{{ t('mp_rt.col.carrier') }}</th>
                    <th>{{ t('mp_rt.col.egress') }}</th>
                    <th v-tooltip.top="t('mp_rt.col.route_help')">{{ t('mp_rt.col.route') }}</th>
                    <th>{{ t('mp_rt.col.state') }}</th>
                    <th v-tooltip.top="t('mp_rt.col.rtt_help')">{{ t('mp_rt.col.rtt') }}</th>
                    <th>{{ t('mp_rt.col.loss') }}</th>
                    <th>{{ t('mp_rt.col.rates') }}</th>
                    <th v-tooltip.top="t('mp_rt.col.target_help')">{{ t('mp_rt.col.target') }}</th>
                    <th v-tooltip.top="t('mp_rt.col.btlbw_help')">{{ t('mp_rt.col.btlbw') }}</th>
                    <th v-tooltip.top="t('mp_rt.col.pacing_help')">{{ t('mp_rt.col.pacing') }}</th>
                    <th v-tooltip.top="t('mp_rt.col.cwnd_help')">{{ t('mp_rt.col.cwnd') }}</th>
                    <th v-if="peer.effective_congestion_control === 'brutal'" v-tooltip.top="t('mp_rt.col.ack_rate_help')">
                      {{ t('mp_rt.col.ack_rate') }}</th>
                    <th>{{ t('mp_rt.col.policy') }}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  <AnimatePresence>
                  <motion.tr v-for="path in peer.paths ?? []" :key="pathKey(peer.peer_id, path)" layout v-bind="rowFade"
                    :class="{ 'mp-row-active': isActive(peer, path) }" data-testid="mp-runtime-path-row">
                    <td class="whitespace-nowrap font-medium">{{ enumName('carrier', path.carrier_kind) }}</td>
                    <td>{{ egressName(path) }}
                      <small v-if="path.observed_public_addr && path.carrier_kind !== 'relay-next-hop'"
                        class="block whitespace-nowrap text-color-secondary" data-testid="mp-path-wan">WAN {{ path.observed_public_addr }}</small></td>
                    <td class="whitespace-nowrap" data-testid="mp-path-route"
                      v-tooltip.top="t('mp_rt.route_tip', [path.path?.local_addr ?? '-', path.path?.remote_addr ?? '-'])">
                      {{ routeName(path) }}</td>
                    <td class="whitespace-nowrap">
                      <Tag :value="stateName(path.lifecycle_state)" :severity="lifecycleSeverity(path.lifecycle_state)" />
                      <small v-if="path.validation_state" class="block text-color-secondary">{{ stateName(path.validation_state) }}</small>
                      <small v-if="path.not_selected_reason" class="block text-color-secondary" data-testid="mp-path-not-selected">
                        {{ t(`mp_rt.not_selected.${path.not_selected_reason}`) }}</small>
                      <small v-if="path.backed_off" class="block text-color-secondary" data-testid="mp-path-backed-off">{{ t('mp_rt.backed_off') }}</small>
                    </td>
                    <td class="whitespace-nowrap tabular-nums">{{ formatUs(toNum(path.srtt_micros)) }} / {{ formatUs(toNum(path.min_rtt_micros)) }}
                      <small v-if="toNum(path.windowed_min_rtt_micros)" class="block text-color-secondary" v-tooltip.top="t('mp_rt.lowest_rtt_help')">
                        {{ t('mp_rt.lowest_rtt', [formatUs(toNum(path.windowed_min_rtt_micros))]) }}</small>
                      <small v-if="path.first_hop_loss != null" class="block text-color-secondary">{{ t('mp_rt.first_hop_loss', [lossPct(path.first_hop_loss)]) }}</small></td>
                    <td class="tabular-nums">{{ lossPct(path.loss_rate) }}</td>
                    <td class="whitespace-nowrap tabular-nums" data-testid="mp-path-rates">↑ {{ formatBps(rates(peer, path).sendBps) }} · ↓ {{ formatBps(rates(peer, path).recvBps) }}</td>
                    <td class="whitespace-nowrap tabular-nums">{{ toNum(path.target_rate_bps) === 0 ? t('mp_rt.paused') : formatBps(toNum(path.target_rate_bps)) }}</td>
                    <td class="whitespace-nowrap tabular-nums">{{ formatBps(toNum(path.btlbw_bps)) }}</td>
                    <td class="whitespace-nowrap tabular-nums">{{ formatBps(toNum(path.pacing_rate_bps)) }}</td>
                    <td class="whitespace-nowrap tabular-nums">{{ formatBytes(toNum(path.cwnd_bytes)) }} / {{ formatBytes(toNum(path.bytes_in_flight)) }}</td>
                    <td v-if="peer.effective_congestion_control === 'brutal'">{{ path.brutal_ack_rate == null ? '-' : path.brutal_ack_rate.toFixed(2) }}</td>
                    <td>
                      <Tag v-if="path.user_policy" :value="t(`mp_policy.${path.user_policy}`)" :severity="policySeverity(path.user_policy)"
                        data-testid="mp-path-policy" />
                    </td>
                    <td class="whitespace-nowrap">
                      <div class="flex gap-1">
                        <Button size="small" text icon="pi pi-thumbtack" :disabled="busy" v-tooltip="t('mp_policy.pin_help')"
                          data-testid="mp-path-pin" @click="setPolicy(path, 'pin')" />
                        <Button size="small" text icon="pi pi-star" :disabled="busy" v-tooltip="t('mp_policy.prefer_help')"
                          data-testid="mp-path-prefer" @click="setPolicy(path, 'prefer')" />
                        <Button size="small" text icon="pi pi-pause" :disabled="busy" v-tooltip="t('mp_policy.pause_help')"
                          data-testid="mp-path-pause" @click="setPolicy(path, 'pause')" />
                        <Button size="small" text severity="danger" icon="pi pi-ban" :disabled="busy"
                          v-tooltip="t('mp_policy.exclude_help')" data-testid="mp-path-exclude" @click="setPolicy(path, 'exclude')" />
                        <Button v-if="path.user_policy" size="small" text severity="secondary" icon="pi pi-times" :disabled="busy"
                          v-tooltip="t('mp_policy.clear_help')" data-testid="mp-path-clear" @click="setPolicy(path, null)" />
                      </div>
                    </td>
                  </motion.tr>
                  </AnimatePresence>
                </tbody>
              </table>
            </div>
            </details>

            <!-- actual send rate by network card and path, with each card's Autorate budget -->
            <details v-if="flows(peer).paths.length" class="mp-details">
              <summary>{{ t('mp_rt.decision_details') }}</summary>
              <div class="flex flex-col gap-3 pt-3">
                <small class="text-color-secondary">{{ t('mp_rt.sankey.help') }}</small>
                <MpFlowSankey :nics="flows(peer).nics" :paths="flows(peer).paths" :nic-name="nicName" :path-name="pathFlowName" />
              </div>
            </details>
          </motion.div>
        </AnimatePresence>
      </div>
    </section>

    <small v-if="!peers.length" class="text-color-secondary">{{ t('mp_runtime_empty') }}</small>
  </template>
  <small v-else class="text-color-secondary" data-testid="mp-runtime-peer-inactive">{{ t('mp_rt.peer_not_active') }}</small>
  </div>
</template>

<style scoped>
.mp-session {
  display: flex;
  flex-direction: column;
  border-radius: 0.75rem;
  border: 1px solid var(--p-content-border-color, rgba(0, 0, 0, 0.1));
  background: var(--p-content-background, #fff);
  overflow: hidden;
  min-width: 0;
}

.mp-steps {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  border-top: 1px solid var(--p-content-border-color, rgba(0, 0, 0, 0.1));
  border-bottom: 1px solid var(--p-content-border-color, rgba(0, 0, 0, 0.1));
}

.mp-step {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
  min-width: 0;
  padding: 0.55rem 1rem 0.65rem;
  text-align: left;
  background: transparent;
  border: 0;
  color: inherit;
  cursor: pointer;
  transition: background-color 0.15s;
}

.mp-step + .mp-step::before {
  content: '';
  position: absolute;
  left: -0.45rem;
  top: 50%;
  width: 0.9rem;
  height: 0.9rem;
  transform: translateY(-50%) rotate(45deg);
  border-top: 1px solid var(--p-content-border-color, rgba(0, 0, 0, 0.15));
  border-right: 1px solid var(--p-content-border-color, rgba(0, 0, 0, 0.15));
  background: inherit;
}

.mp-step:hover {
  background: var(--p-content-hover-background, rgba(0, 0, 0, 0.03));
}

.mp-step-on {
  background: var(--p-highlight-background, rgba(16, 185, 129, 0.08));
}

.mp-step-name {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.75rem;
  color: var(--p-text-muted-color, #64748b);
}

.mp-step-no {
  font-style: normal;
  width: 1.1rem;
  height: 1.1rem;
  border-radius: 999px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 0.65rem;
  font-weight: 700;
  color: var(--p-primary-contrast-color, #fff);
  background: var(--p-primary-color, #10b981);
}

/* On a phone the four steps form two rows of two, wide enough for a value such as
   "Default (BBR)"; a value that is still longer wraps, nothing is cut. */
@media (max-width: 480px) {
  .mp-steps {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .mp-step {
    padding: 0.5rem 0.75rem 0.6rem;
  }

  .mp-step + .mp-step::before {
    display: none;
  }

  .mp-step:nth-child(n + 3) {
    border-top: 1px solid var(--p-content-border-color, rgba(0, 0, 0, 0.1));
  }

  .mp-step b {
    white-space: normal;
    overflow: visible;
    text-overflow: clip;
    overflow-wrap: anywhere;
  }
}

.mp-step-bar {
  position: absolute;
  left: 0;
  right: 0;
  bottom: -1px;
  height: 2px;
  background: var(--p-primary-color, #10b981);
}

.mp-equation .mp-op {
  align-self: center;
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--p-text-muted-color, #64748b);
}

.mp-chain {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto minmax(0, 1.4fr) auto minmax(0, 1fr);
  gap: 0.5rem;
}

.mp-hop {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  min-width: 0;
  padding: 0.5rem 0.6rem;
  border-radius: 0.5rem;
  background: var(--p-content-hover-background, rgba(0, 0, 0, 0.03));
}

.mp-details > summary {
  cursor: pointer;
  user-select: none;
  font-size: 0.875rem;
  color: var(--p-text-muted-color, #64748b);
}

.mp-table th {
  text-align: left;
  font-weight: 500;
  white-space: nowrap;
  padding: 0.45rem 0.6rem;
  background: var(--p-content-hover-background, rgba(0, 0, 0, 0.03));
}

.mp-table td {
  padding: 0.45rem 0.6rem;
  vertical-align: middle;
}

.mp-table tbody tr,
.mp-table tfoot tr {
  border-top: 1px solid var(--p-content-border-color, rgba(0, 0, 0, 0.08));
}

.mp-foot td {
  background: var(--p-content-hover-background, rgba(0, 0, 0, 0.03));
}

.mp-row-active td:first-child {
  box-shadow: inset 3px 0 0 var(--p-green-500, #22c55e);
}
</style>
