<script setup lang="ts">
// NIC-level MP state, independent of any peer: each egress NIC (or WAN uplink
// scope) with its send limit, autorate estimate and queue delay, and its one
// send queue (Linux CAKE), which every session leaving through it shares.
import { motion } from 'motion-v'
import { Tag } from 'primevue'
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  formatBps,
  formatBytes,
  formatUs,
  groupEgressByNic,
  MpRuntimeHistory,
  toNum,
  type EgressView,
  type MpRuntimeView,
  type NicView,
} from '../modules/mpRuntime'
import type { MpCakeStatus, MpConfig, MpRuntimeInfo } from '../types/mpConfig'
import MpCard from './MpCard.vue'
import MpStat from './MpStat.vue'
import NetworkChart, { type ChartSeries } from './NetworkChart.vue'

const props = defineProps<{
  runtime?: MpRuntimeInfo | null
  mpConfig?: MpConfig | null
  egressWireLimitBps?: number | string | null
}>()

const { t } = useI18n()

const fade = { initial: { opacity: 0, y: -4 }, animate: { opacity: 1, y: 0 }, exit: { opacity: 0, y: -4 } }

const history = new MpRuntimeHistory()
const view = ref<MpRuntimeView>(history.ingest(props.runtime))
watch(() => props.runtime, (info) => {
  view.value = history.ingest(info)
})

// The saved config is unavailable for instances not started through this
// client (e.g. CLI/TOML); fall back to what the runtime proves, never guess "off".
const sqmState = computed<'on' | 'off' | 'unknown'>(() => {
  if (props.mpConfig) return props.mpConfig.sqm?.enabled ? 'on' : 'off'
  return view.value.egress.some(e => e.status.cake) ? 'on' : 'unknown'
})

const globalLimit = computed(() => toNum(props.egressWireLimitBps))
const limitText = computed(() => {
  if (globalLimit.value) return formatBps(globalLimit.value)
  if (props.mpConfig) return t('mp_rt.unlimited')
  const ceilings = view.value.egress.map(e => e.current.ceilingBps).filter((c): c is number => c !== undefined)
  return ceilings.length ? ceilings.map(c => formatBps(c)).join(' / ') : t('mp_rt.unknown')
})

const nics = computed<NicView[]>(() => groupEgressByNic(view.value.egress))

function sumCounter(nic: NicView, pick: (e: EgressView) => unknown): number {
  return nic.scopes.reduce((acc, e) => acc + (toNum(pick(e)) ?? 0), 0)
}

/** The start value of an estimate no measurement has moved yet. */
function unmeasuredStart(nic: NicView): number | undefined {
  if (nic.current.estimateBps !== undefined) return undefined
  const starts = nic.scopes.map(s => toNum(s.status.autorate_estimate_bps)).filter((v): v is number => v !== undefined)
  return starts.length ? Math.max(...starts) : undefined
}

function ceilingSources(nic: NicView): string[] {
  return [...new Set(nic.scopes.map(e => ceilingSourceLabel(e.status.ceiling_source)))]
}

function aligned<T>(hist: T[], pick: (p: T) => number | undefined): Array<number | null> {
  const pad = Math.max(0, view.value.labels.length - hist.length)
  return [...Array(pad).fill(null), ...hist.map(p => pick(p) ?? null)]
}

function egressSeries(e: NicView): ChartSeries[] {
  const out: ChartSeries[] = [
    { label: t('mp_rt.send_rate'), color: 'rgb(34, 197, 94)', data: aligned(e.history, p => p.sendBps) },
  ]
  if (e.history.some(p => p.estimateBps !== undefined))
    out.push({ label: t('mp_rt.autorate_estimate'), color: 'rgb(59, 130, 246)', dashed: true, data: aligned(e.history, p => p.estimateBps) })
  if (e.history.some(p => p.ceilingBps !== undefined))
    out.push({ label: t('mp_rt.ceiling'), color: 'rgb(239, 68, 68)', dashed: true, data: aligned(e.history, p => p.ceilingBps) })
  if (e.history.some(p => p.queueDelayMs !== undefined))
    out.push({ label: t('mp_rt.queue_delay'), color: 'rgb(249, 115, 22)', axis: 'y1', unit: 'ms', data: aligned(e.history, p => p.queueDelayMs) })
  return out
}

/** The CAKE queues of a NIC's send scopes (the NIC and its WANs) added up. */
interface CakeTotals {
  bandwidthBps: number
  backlogBytes: number
  qlen: number
  memoryUsed: number
  memoryLimit: number
  droppedAqm: number
  droppedOverlimit: number
  streamAqm: number
  streamOverlimit: number
  peakDelayUs: number
  avgDelayUs: number
  baseDelayUs: number
  sparse: number
  bulk: number
  unresponsive: number
  targetUs: number
  intervalUs: number
}

function cakeOf(nic: NicView): CakeTotals | undefined {
  const cakes = nic.scopes.map(s => s.status.cake).filter((c): c is MpCakeStatus => !!c)
  if (!cakes.length) return undefined
  const sum = (pick: (c: MpCakeStatus) => unknown) => cakes.reduce((acc, c) => acc + (toNum(pick(c)) ?? 0), 0)
  const max = (pick: (c: MpCakeStatus) => unknown) => Math.max(...cakes.map(c => toNum(pick(c)) ?? 0))
  return {
    bandwidthBps: sum(c => c.bandwidth_bps),
    backlogBytes: sum(c => c.backlog_bytes),
    qlen: sum(c => c.qlen_packets),
    memoryUsed: sum(c => c.memory_used),
    memoryLimit: sum(c => c.memory_limit),
    droppedAqm: sum(c => c.dropped_packets),
    droppedOverlimit: sum(c => c.overlimit_drops),
    streamAqm: sum(c => c.stream_aqm_drops),
    streamOverlimit: sum(c => c.stream_overlimit_drops),
    peakDelayUs: max(c => c.peak_delay_us),
    avgDelayUs: max(c => c.avg_delay_us),
    baseDelayUs: max(c => c.base_delay_us),
    sparse: sum(c => c.sparse_flows),
    bulk: sum(c => c.bulk_flows),
    unresponsive: sum(c => c.unresponsive_flows),
    targetUs: max(c => c.target_us),
    intervalUs: max(c => c.interval_us),
  }
}

function cakeSeries(nic: NicView): ChartSeries[] {
  return [
    { label: t('mp_rt.cake_backlog'), color: 'rgb(168, 85, 247)', unit: 'bytes', data: aligned(nic.history, p => p.backlogBytes) },
    { label: t('mp_rt.cake_delay_avg'), color: 'rgb(249, 115, 22)', axis: 'y1', unit: 'ms', data: aligned(nic.history, p => p.cakeDelayMs) },
  ]
}

function ceilingSourceLabel(src?: string): string {
  return t(`mp_rt.ceiling_source.${src || 'none'}`)
}
</script>

<template>
  <MpCard :title="t('mp_rt.egress_title')" icon="pi-wifi" data-testid="mp-egress-panel">
    <template #extra>
      <span class="text-sm text-color-secondary">SQM</span>
      <Tag :value="t(`mp_rt.sqm_${sqmState}`)" :severity="sqmState === 'on' ? 'success' : sqmState === 'off' ? 'secondary' : 'warn'"
        data-testid="mp-egress-sqm-state" />
      <span class="text-sm text-color-secondary ml-2" v-tooltip.top="t('mp_rt.global_limit_help')">{{ t('mp_rt.global_limit') }}</span>
      <b data-testid="mp-runtime-limit">{{ limitText }}</b>
    </template>

    <small v-if="sqmState === 'off'" class="text-color-secondary">{{ t('mp_rt.sqm_off_note') }}</small>

    <div v-if="view.egress.length" class="mp-nic-grid">
      <motion.div v-for="e in nics" :key="e.key" layout v-bind="fade"
        class="flex flex-col gap-3 rounded-lg border border-surface-200 dark:border-surface-700 p-3" data-testid="mp-runtime-egress-card">
        <div class="flex flex-wrap items-center gap-2">
          <i class="pi pi-server text-color-secondary" />
          <span class="font-semibold">{{ e.device }}</span>
          <Tag v-for="src in ceilingSources(e)" :key="src" :value="src" severity="secondary" />
          <Tag v-if="e.scopes.some(s => s.status.fallback_scope)" :value="t('mp_rt.fallback_scope')" severity="warn"
            v-tooltip="t('mp_rt.fallback_scope_help')" />
        </div>

        <div class="grid gap-2 grid-cols-2 md:grid-cols-4">
          <MpStat :label="t('mp_rt.send_rate')"><span data-testid="mp-egress-send">{{ formatBps(e.current.sendBps) }}</span></MpStat>
          <MpStat :label="t('mp_rt.ceiling')" :help="t('mp_rt.ceiling_help')">
            {{ e.current.ceilingBps === undefined ? t('mp_rt.unlimited') : formatBps(e.current.ceilingBps) }}</MpStat>
          <MpStat :label="t('mp_rt.autorate_estimate')" :help="t('mp_rt.autorate_estimate_help')">
            <span v-if="unmeasuredStart(e) !== undefined" data-testid="mp-egress-estimate-unmeasured"
              v-tooltip.top="t('mp_rt.autorate_unmeasured_help', [formatBps(unmeasuredStart(e))])">{{ t('mp_rt.autorate_unmeasured') }}</span>
            <template v-else>{{ formatBps(e.current.estimateBps) }}</template></MpStat>
          <MpStat :label="t('mp_rt.queue_delay')" :help="t('mp_rt.queue_delay_help')">
            {{ e.current.queueDelayMs === undefined ? '-' : formatUs(e.current.queueDelayMs * 1000) }}</MpStat>
        </div>
        <NetworkChart :series="egressSeries(e)" :labels="view.labels" />
        <div class="flex flex-wrap gap-x-5 gap-y-1 text-xs text-color-secondary">
          <span>{{ t('mp_rt.paths') }}: {{ sumCounter(e, s => s.status.path_count) }}</span>
        </div>

        <!-- The one send queue of this NIC: Linux CAKE, shared by every session leaving through it. -->
        <div v-if="cakeOf(e)" class="flex flex-col gap-2 border-t border-surface-200 dark:border-surface-700 pt-3"
          data-testid="mp-egress-cake">
          <h5 class="m-0 text-sm font-semibold" v-tooltip.top="t('mp_rt.cake_hint')">{{ t('mp_rt.cake_title') }}</h5>
          <template v-for="c in [cakeOf(e)!]" :key="e.key">
            <div class="grid gap-2 grid-cols-2 md:grid-cols-4">
              <MpStat :label="t('mp_rt.cake_rate')" :help="t('mp_rt.cake_rate_help')">
                <span data-testid="mp-cake-rate">{{ formatBps(c.bandwidthBps) }}</span></MpStat>
              <MpStat :label="t('mp_rt.cake_backlog')" :help="t('mp_rt.cake_backlog_help')">
                <span data-testid="mp-cake-backlog">{{ formatBytes(c.backlogBytes) }}</span>
                <small class="font-normal"> / {{ t('mp_rt.cake_packets', [c.qlen]) }}</small></MpStat>
              <MpStat :label="t('mp_rt.cake_memory')" :help="t('mp_rt.cake_memory_help')">
                {{ formatBytes(c.memoryUsed) }} <small class="font-normal">/ {{ formatBytes(c.memoryLimit) }}</small></MpStat>
              <MpStat :label="t('mp_rt.cake_target')" :help="t('mp_rt.cake_target_help')">
                {{ formatUs(c.targetUs) }} <small class="font-normal">/ {{ formatUs(c.intervalUs) }}</small></MpStat>
            </div>
            <div class="grid gap-2 grid-cols-2 md:grid-cols-4" data-testid="mp-cake-drops">
              <MpStat :label="t('mp_rt.cake_drops_aqm')" :help="t('mp_rt.cake_drops_aqm_help')">
                {{ c.droppedAqm }}<template v-if="e.current.dropsPerSec !== undefined">
                  <small class="font-normal"> ({{ e.current.dropsPerSec.toFixed(1) }}/s)</small></template></MpStat>
              <MpStat :label="t('mp_rt.cake_drops_overlimit')" :help="t('mp_rt.cake_drops_overlimit_help')">{{ c.droppedOverlimit }}</MpStat>
              <MpStat :label="t('mp_rt.cake_stream_drops_aqm')" :help="t('mp_rt.cake_stream_drops_aqm_help')">{{ c.streamAqm }}</MpStat>
              <MpStat :label="t('mp_rt.cake_stream_drops_overlimit')" :help="t('mp_rt.cake_stream_drops_overlimit_help')">{{ c.streamOverlimit }}</MpStat>
            </div>
            <div class="grid gap-2 grid-cols-2 md:grid-cols-4">
              <MpStat :label="t('mp_rt.cake_delay_peak')" :help="t('mp_rt.cake_delay_help')">{{ formatUs(c.peakDelayUs) }}</MpStat>
              <MpStat :label="t('mp_rt.cake_delay_avg')">{{ formatUs(c.avgDelayUs) }}</MpStat>
              <MpStat :label="t('mp_rt.cake_delay_base')">{{ formatUs(c.baseDelayUs) }}</MpStat>
              <MpStat :label="t('mp_rt.cake_flows')" :help="t('mp_rt.cake_flows_help')">
                <span data-testid="mp-cake-flows">{{ c.sparse }} / {{ c.bulk }} / {{ c.unresponsive }}</span></MpStat>
            </div>
          </template>
          <NetworkChart :series="cakeSeries(e)" :labels="view.labels" />
        </div>
      </motion.div>
    </div>

    <small v-if="!view.egress.length" class="text-color-secondary">{{ t('mp_rt.egress_empty') }}</small>
  </MpCard>
</template>

<style scoped>
/* one NIC fills the row; more NICs share it, each at least ~26rem wide */
.mp-nic-grid {
  display: grid;
  gap: 0.75rem;
  grid-template-columns: repeat(auto-fit, minmax(min(26rem, 100%), 1fr));
}
</style>
