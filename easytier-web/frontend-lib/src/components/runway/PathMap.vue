<script setup lang="ts">
// The paths of one peer as a map: this machine on the left, the peer on the
// right, one row per direct path between them. Each row has two lanes of equal
// weight: above, what we send (we chose the path), below, what the peer sends
// back (it chose the path). Lane width follows the rate. Relays are folded into
// one line under the map. A path's numbers sit on it; clicking them opens its
// policy and the rule of its kind. Every edit is emitted as a changed MpConfig,
// and the core's next report replaces the preview shown meanwhile.
import { useElementSize } from '@vueuse/core'
import { ChevronDown, Minus, Pin, Plus } from 'lucide-vue-next'
import { computed, onBeforeUnmount, ref, useId, useTemplateRef, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { cn } from '../../lib/utils'
import type { PathRates } from '../../modules/mpRuntime'
import { pathNic } from '../../modules/mpRuntime'
import type { Tier } from '../../modules/mpSelection'
import {
  ACTIVE_BPS,
  fmtLoss,
  fmtMs,
  hostOf,
  laneRate,
  laneWidth,
  pathMap,
  type MapPort,
  type MapRow,
} from '../../modules/pathMap'
import {
  kindRuleValues,
  previewView,
  reportedView,
  withKindRule,
  type PathKind,
  type RunwayPath,
} from '../../modules/pathRunway'
import {
  DEFAULT_MP_SELECTION_CONFIG,
  policyMatchForPath,
  type MpConfig,
  type MpPeerStatus,
  type MpPolicyAction,
  type MpPolicyMatch,
  type MpSelectionConfig,
} from '../../types/mpConfig'
import { Popover, PopoverAnchor, PopoverContent } from '../ui/popover'
import PathDetail from './PathDetail.vue'

const props = defineProps<{
  peer: MpPeerStatus
  /** Saved config of the instance; the rules the controls edit. */
  mpConfig?: MpConfig | null
  /** Name of the peer, drawn over its column. */
  peerName: string
  /** Per-path rates by `pathKey`. */
  rates: Map<string, PathRates>
  /** Host names by peer id, to name relay nodes. */
  peerNames?: Record<string, string>
  busy?: boolean
}>()

const emit = defineEmits<{
  /** A control was used: `update` turns the saved MpConfig into the edited one. */
  'edit': [label: string, update: (mp: MpConfig) => MpConfig]
  'set-policy': [match: MpPolicyMatch, action: MpPolicyAction | null]
}>()

const { t, te } = useI18n()

// ---- what is shown: the core's report, or a preview until the core reports the edit ----
const savedSelection = computed<MpSelectionConfig>(() => props.mpConfig?.selection ?? DEFAULT_MP_SELECTION_CONFIG())
const savedKmax = computed(() => props.mpConfig?.kmax ?? 1)
const draft = ref<{ selection: MpSelectionConfig, kmax: number } | null>(null)
const view = computed(() => draft.value
  ? previewView(props.peer, draft.value.selection, draft.value.kmax)
  : reportedView(props.peer, savedSelection.value))
const kmaxShown = computed(() => draft.value?.kmax ?? savedKmax.value)

let settle: ReturnType<typeof setTimeout> | undefined
const settling = ref(false)
watch(() => props.peer, () => {
  if (!settling.value) return
  settling.value = false
  draft.value = null
})
function release(label: string, selection: MpSelectionConfig, kmax: number) {
  draft.value = { selection, kmax }
  settling.value = true
  clearTimeout(settle)
  settle = setTimeout(() => { settling.value = false; draft.value = null }, 4000)
  emit('edit', label, mp => ({ ...mp, selection, kmax }))
}
onBeforeUnmount(() => clearTimeout(settle))

const KMAX_MAX = 16
function stepKmax(delta: number) {
  const k = Math.min(KMAX_MAX, Math.max(1, kmaxShown.value + delta))
  if (k === kmaxShown.value || props.busy) return
  release(t('mp_runway.edit.kmax', [k]), draft.value?.selection ?? savedSelection.value, k)
}

// ---- names ---------------------------------------------------------------------
function relayName(p: RunwayPath): string {
  const id = p.status.first_hop_peer_id
  return props.peerNames?.[String(id)] || t('mp_rt.peer_fallback', [id ?? '-'])
}
function pathName(p: RunwayPath): string {
  return p.kind.carrierKind === 'relay-next-hop' ? relayName(p) : hostOf(p.status.path?.remote_addr) || '-'
}
function kindName(kind: PathKind): string {
  const key = `mp_rt.carrier.${kind.carrierKind.replace(/-/g, '_')}`
  const base = te(key) ? t(key) : kind.carrierKind
  return kind.family === 'v6' ? t('mp_runway.kind_v6', [base]) : base
}
const laneName = (tier: Tier) => t(`mp_runway.lane.${tier}`)
const signed = (n: number) => `${n > 0 ? '+' : ''}${n}`

// ---- the model -------------------------------------------------------------------
const model = computed(() => pathMap(view.value, props.peer.peer_id, props.rates, s => t(`mp_map.scope.${s}`)))
const relays = computed(() => model.value.relays)
const relayCarries = computed(() => relays.value.some(r => r.path.state === 'sending' || r.recvBps >= ACTIVE_BPS))
const relayOpen = ref<boolean | null>(null)
const relaysShown = computed(() => relays.value.length > 0 && (relayOpen.value ?? relayCarries.value))
const fastestRelay = computed(() => {
  const ms = relays.value.map(r => r.path.measuredMs).filter((v): v is number => v !== null)
  return ms.length ? Math.min(...ms) : null
})

// ---- geometry ------------------------------------------------------------------
const boxEl = useTemplateRef<HTMLElement>('box')
const { width: measured } = useElementSize(boxEl)
// The drawn width is the box's real width: the ports sit at the box's CSS edges, so any other width
// puts the pills and the remote ports out of step. 300 only stands in before the first measurement.
const W = computed(() => measured.value || 300)
const narrow = computed(() => W.value < 560)
// Too narrow for a rate beside the pill on the same line (the status drawer on a phone): the lanes
// move apart, the send lane above the pill and the receive lane below it.
const tight = computed(() => W.value < 400)
const PORT = computed(() => (narrow.value ? 58 : 108))
const XL = computed(() => PORT.value)
const XR = computed(() => W.value - PORT.value)
const CX = computed(() => W.value / 2)
const HEAD = 30
const ROWH = computed(() => (tight.value ? 78 : 56))
const HALF = computed(() => (tight.value ? 36 : 26))
/** Distance of each lane from the row's middle. */
const OFF = computed(() => (tight.value ? 25 : 9))
const rowY = (i: number) => HEAD + HALF.value + 2 + i * ROWH.value
const directBottom = computed(() => (model.value.rows.length ? rowY(model.value.rows.length - 1) + HALF.value : HEAD + 40))
const foldY = computed(() => directBottom.value + 30)
const relayY = (j: number) => foldY.value + 30 + HALF.value + j * ROWH.value
const height = computed(() => {
  if (!relays.value.length) return directBottom.value + 12
  return relaysShown.value ? relayY(relays.value.length - 1) + HALF.value + 12 : foldY.value + 26
})

interface Drawn { row: MapRow, y: number, relay: boolean }
const drawn = computed<Drawn[]>(() => [
  ...model.value.rows.map((row, i) => ({ row, y: rowY(i), relay: false })),
  ...(relaysShown.value ? relays.value.map((row, j) => ({ row, y: relayY(j), relay: true })) : []),
])

function portBox(p: MapPort, y: (i: number) => number) {
  const top = y(p.from) - HALF.value
  return { top, height: y(p.to) - y(p.from) + 2 * HALF.value }
}
const relayPortBox = computed(() => portBox({ key: '', from: 0, to: relays.value.length - 1, label: '', sub: '' }, relayY))

// ---- lanes -----------------------------------------------------------------------
type LaneKind = 'up' | 'down' | 'idle' | 'off' | 'lossy'
interface Lane { kind: LaneKind, y: number, x1: number, x2: number, w: number, bps: number }
const OUT = new Set(['silent', 'paused', 'excluded'])
function lanes(d: Drawn): Lane[] {
  const { row, y } = d
  const state = row.path.state
  const recv = row.recvBps >= ACTIVE_BPS
  const idle = (yy: number): Lane => ({ kind: OUT.has(state) ? 'off' : 'idle', y: yy, x1: XL.value + 6, x2: XR.value - 6, w: 2, bps: 0 })
  if (state === 'lossy' && !recv)
    return [{ kind: 'lossy', y, x1: XL.value + 6, x2: XR.value - 6, w: 2.5, bps: 0 }]
  const up: Lane = state === 'sending'
    ? { kind: 'up', y: y - OFF.value, x1: XL.value + 4, x2: XR.value - 8, w: laneWidth(row.sendBps), bps: row.sendBps }
    : state === 'lossy' ? { kind: 'lossy', y: y - OFF.value, x1: XL.value + 6, x2: XR.value - 6, w: 2.5, bps: 0 } : idle(y - OFF.value)
  const down: Lane = recv
    ? { kind: 'down', y: y + OFF.value, x1: XR.value - 4, x2: XL.value + 8, w: laneWidth(row.recvBps), bps: row.recvBps }
    : idle(y + OFF.value)
  return [up, down]
}
const CHIP = computed(() => (narrow.value ? 24 : 62))
const chipX = (l: Lane) => (l.kind === 'up' ? XR.value - CHIP.value : XL.value + CHIP.value)

const uid = useId()
const markerUp = `pm-up-${uid}`
const markerDown = `pm-down-${uid}`

// ---- popover edits -----------------------------------------------------------------
const openKey = ref<string | null>(null)
function setPolicy(p: RunwayPath, action: MpPolicyAction | null) {
  emit('set-policy', policyMatchForPath(p.status), action)
}
function setKind(p: RunwayPath, change: Partial<{ tier: Tier, biasMs: number }>) {
  const selection = withKindRule(savedSelection.value, p.kind, change)
  const k = kindRuleValues(selection, p.kind)
  release(t('mp_runway.edit.kind', [kindName(p.kind), laneName(k.tier), signed(k.biasMs)]), selection, savedKmax.value)
}
const kindTier = (p: RunwayPath) => kindRuleValues(savedSelection.value, p.kind)
const stateWord = (p: RunwayPath) => (OUT.has(p.state) ? t(`mp_runway.state.${p.state}`) : '')
</script>

<template>
  <section class="path-map min-w-0 rounded-xl border border-surface-200 dark:border-surface-700" data-testid="path-map"
    :aria-busy="busy ? 'true' : 'false'">
    <header class="flex flex-wrap items-center gap-x-5 gap-y-2 px-4 pt-3 text-sm">
      <span class="flex items-baseline gap-1.5" data-testid="path-map-legend-up">
        <b class="text-base text-emerald-600 dark:text-emerald-400">↑</b>{{ t('mp_map.send') }}
        <small class="text-color-secondary">{{ t('mp_map.send_note') }}</small></span>
      <span class="flex items-baseline gap-1.5" data-testid="path-map-legend-down">
        <b class="text-base text-blue-600 dark:text-blue-400">↓</b>{{ t('mp_map.recv') }}
        <small class="text-color-secondary">{{ t('mp_map.recv_note') }}</small></span>
      <small class="text-color-secondary">{{ t('mp_map.unit') }}</small>
      <div class="ml-auto flex items-center gap-1.5 rounded-lg border border-surface-200 px-2 py-1 dark:border-surface-700"
        :title="t('mp_map.kmax_tip')" data-testid="path-map-kmax">
        <span class="text-color-secondary">{{ t('mp_map.kmax_before') }}</span>
        <button type="button" class="pm-step" :disabled="busy || kmaxShown <= 1" :aria-label="t('mp_map.kmax_less')"
          data-testid="path-map-kmax-minus" @click="stepKmax(-1)"><Minus class="size-3.5" /></button>
        <b class="w-5 text-center tabular-nums" data-testid="path-map-kmax-value">{{ kmaxShown }}</b>
        <button type="button" class="pm-step" :disabled="busy || kmaxShown >= KMAX_MAX" :aria-label="t('mp_map.kmax_more')"
          data-testid="path-map-kmax-plus" @click="stepKmax(1)"><Plus class="size-3.5" /></button>
        <span class="text-color-secondary">{{ t('mp_map.kmax_after') }}</span>
      </div>
    </header>

    <div ref="box" class="relative mx-3 mb-3 mt-2" :style="{ height: `${height}px` }">
      <svg class="pointer-events-none absolute inset-0" :width="W" :height="height" :viewBox="`0 0 ${W} ${height}`" aria-hidden="true">
        <defs>
          <marker :id="markerUp" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="12" markerHeight="12" markerUnits="userSpaceOnUse" orient="auto-start-reverse">
            <path d="M0 0 L10 5 L0 10 z" class="fill-emerald-500 dark:fill-emerald-400" /></marker>
          <marker :id="markerDown" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="12" markerHeight="12" markerUnits="userSpaceOnUse" orient="auto-start-reverse">
            <path d="M0 0 L10 5 L0 10 z" class="fill-blue-500 dark:fill-blue-400" /></marker>
        </defs>
        <g v-for="d in drawn" :key="d.row.path.key">
          <template v-for="(l, li) in lanes(d)" :key="li">
            <line v-if="l.kind === 'up' || l.kind === 'down'" :x1="l.x1" :x2="l.x2" :y1="l.y" :y2="l.y" :stroke-width="l.w" stroke-linecap="round"
              :class="l.kind === 'up' ? 'stroke-emerald-500 dark:stroke-emerald-400' : 'stroke-blue-500 dark:stroke-blue-400'"
              :marker-end="`url(#${l.kind === 'up' ? markerUp : markerDown})`" :data-lane="l.kind" />
            <line v-if="(l.kind === 'up' || l.kind === 'down') && l.bps >= ACTIVE_BPS" class="pm-flow stroke-white" :x1="l.x1"
              :x2="l.x2 - (l.kind === 'up' ? 14 : -14)" :y1="l.y" :y2="l.y" :stroke-width="Math.min(2, l.w - 1)" />
            <line v-else-if="l.kind === 'lossy'" :x1="l.x1" :x2="l.x2" :y1="l.y" :y2="l.y" :stroke-width="l.w" stroke-linecap="round"
              stroke-dasharray="1 7" class="stroke-orange-500 dark:stroke-orange-400" data-lane="lossy" />
            <line v-else-if="l.kind === 'idle' || l.kind === 'off'" :x1="l.x1" :x2="l.x2" :y1="l.y" :y2="l.y" :stroke-width="l.w"
              :stroke-dasharray="l.kind === 'off' ? '4 5' : undefined" class="stroke-zinc-300 dark:stroke-zinc-700" :data-lane="l.kind" />
          </template>
        </g>
        <!-- the relays: a detour under the two columns -->
        <template v-if="relays.length">
          <path :d="`M${XL / 2} ${directBottom} V ${foldY - 8} Q ${XL / 2} ${foldY} ${XL / 2 + 8} ${foldY} H ${CX - 60}`"
            fill="none" stroke-width="2" stroke-dasharray="6 5" class="stroke-zinc-300 dark:stroke-zinc-600" />
          <path :d="`M${CX + 60} ${foldY} H ${XR + PORT / 2 - 8} Q ${XR + PORT / 2} ${foldY} ${XR + PORT / 2} ${foldY - 8} V ${directBottom}`"
            fill="none" stroke-width="2" stroke-dasharray="6 5" class="stroke-zinc-300 dark:stroke-zinc-600" />
        </template>
      </svg>

      <!-- column titles -->
      <div class="absolute left-0 top-0 truncate text-sm font-semibold" :style="{ width: `${W / 2 - 8}px` }">{{ t('mp_map.you') }}</div>
      <div class="absolute right-0 top-0 truncate text-right text-sm font-semibold" :style="{ width: `${W / 2 - 8}px` }"
        data-testid="path-map-peer">{{ peerName }}</div>

      <!-- exits: the network cards here, the addresses there -->
      <div v-for="p in model.localPorts" :key="`l-${p.key}-${p.from}`" class="pm-port left-0" data-testid="path-map-port-local"
        :style="{ top: `${portBox(p, rowY).top}px`, height: `${portBox(p, rowY).height}px`, width: `${PORT}px` }" :title="`${p.label} ${p.sub}`">
        <span class="pm-port-label">{{ p.label }}</span><span v-if="!narrow && p.sub" class="pm-port-sub">{{ p.sub }}</span>
      </div>
      <div v-for="p in model.remotePorts" :key="`r-${p.key}-${p.from}`" class="pm-port right-0" data-testid="path-map-port-remote"
        :style="{ top: `${portBox(p, rowY).top}px`, height: `${portBox(p, rowY).height}px`, width: `${PORT}px` }" :title="`${p.label} ${p.sub}`">
        <span class="pm-port-label">{{ p.label }}</span><span v-if="!narrow && p.sub" class="pm-port-sub">{{ p.sub }}</span>
      </div>
      <template v-if="relaysShown">
        <div class="pm-port left-0 border-dashed" :style="{ top: `${relayPortBox.top}px`, height: `${relayPortBox.height}px`, width: `${PORT}px` }">
          <span class="pm-port-label">{{ t('mp_map.relay_port') }}</span>
        </div>
        <div v-for="(r, j) in relays" :key="`rr-${r.path.key}`" class="pm-port right-0 border-dashed"
          :style="{ top: `${relayY(j) - HALF}px`, height: `${2 * HALF}px`, width: `${PORT}px` }" :title="relayName(r.path)">
          <span class="pm-port-label">{{ relayName(r.path) }}</span>
        </div>
      </template>

      <!-- rates, on each lane before its arrowhead -->
      <template v-for="d in drawn" :key="`c-${d.row.path.key}`">
        <template v-for="(l, li) in lanes(d)" :key="li">
          <span v-if="(l.kind === 'up' || l.kind === 'down') && l.bps >= ACTIVE_BPS"
            :class="cn('pm-chip', l.kind === 'up' ? 'border-emerald-500 text-emerald-700 dark:border-emerald-400 dark:text-emerald-300'
                                                 : 'border-blue-500 text-blue-700 dark:border-blue-400 dark:text-blue-300')"
            :style="{ left: `${chipX(l)}px`, top: `${l.y}px` }" :data-testid="`path-map-rate-${l.kind}`">{{ laneRate(l.bps) }}</span>
        </template>
      </template>

      <!-- each path's numbers in the middle of its row; they open the path -->
      <Popover v-for="d in drawn" :key="`p-${d.row.path.key}`" :open="openKey === d.row.path.key"
        @update:open="(v: boolean) => { if (!v) openKey = null }">
        <PopoverAnchor as-child>
          <button type="button" data-testid="path-map-path" :data-state="d.row.path.state" :data-relay="d.relay ? 'true' : 'false'"
            :class="cn('pm-pill', narrow ? 'px-2 text-[11px]' : 'px-3 text-[12.5px]',
                       d.row.path.state === 'lossy' ? 'pm-pill-lossy' : OUT.has(d.row.path.state) ? 'pm-pill-off' : '')"
            :style="{ left: `${CX}px`, top: `${d.y}px` }" :title="t(`mp_runway.state.${d.row.path.state}`)"
            @click="openKey = openKey === d.row.path.key ? null : d.row.path.key">
            <Pin v-if="d.row.path.status.user_policy === 'pin'" class="size-3 shrink-0" />
            <b class="tabular-nums">{{ d.row.path.measuredMs === null ? t('mp_map.unmeasured') : `${fmtMs(d.row.path.measuredMs)} ms` }}</b>
            <span class="pm-loss tabular-nums">{{ t('mp_map.loss', [fmtLoss(d.row.path.lossPct)]) }}</span>
            <span v-if="stateWord(d.row.path)" class="pm-loss">{{ stateWord(d.row.path) }}</span>
          </button>
        </PopoverAnchor>
        <PopoverContent class="w-80" side="bottom" align="center">
          <PathDetail :placed="d.row.path" :name="pathName(d.row.path)" :via="pathNic(d.row.path.status)" :kind-name="kindName(d.row.path.kind)"
            :tier="kindTier(d.row.path).tier" :bias-ms="kindTier(d.row.path).biasMs" :policy="d.row.path.status.user_policy ?? ''" :busy="busy"
            :send-bps="d.row.sendBps" :recv-bps="d.row.recvBps"
            @policy="setPolicy(d.row.path, $event)" @bias="setKind(d.row.path, { biasMs: $event })" @tier="setKind(d.row.path, { tier: $event })" />
        </PopoverContent>
      </Popover>

      <!-- the folded relays -->
      <button v-if="relays.length" type="button" class="pm-pill pm-fold px-3 text-[12.5px]" data-testid="path-map-relays"
        :aria-expanded="relaysShown ? 'true' : 'false'" :style="{ left: `${CX}px`, top: `${foldY}px` }"
        @click="relayOpen = !relaysShown">
        <b v-if="relays.some(r => r.path.state === 'sending')" class="text-emerald-600 dark:text-emerald-400">↑</b>
        <b v-if="relays.some(r => r.recvBps >= ACTIVE_BPS)" class="text-blue-600 dark:text-blue-400">↓</b>
        <span>{{ fastestRelay === null ? t('mp_map.relays_unmeasured', [relays.length]) : t('mp_map.relays', [relays.length, fmtMs(fastestRelay)]) }}</span>
        <ChevronDown :class="cn('size-3.5 transition-transform', relaysShown && 'rotate-180')" />
      </button>

      <div v-if="!model.rows.length && !relays.length" class="absolute inset-x-0 text-center text-sm text-color-secondary"
        :style="{ top: `${HEAD + 12}px` }">{{ t('mp_map.empty') }}</div>
    </div>
  </section>
</template>

<style scoped>
.pm-port {
  position: absolute;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.15rem;
  padding: 0 0.3rem;
  border-radius: 0.6rem;
  border: 1px solid rgb(212 212 216);
  background: rgb(250 250 250);
  overflow: hidden;
}

.pm-port-label {
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 0.78rem;
}

.pm-port-sub {
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-family: ui-monospace, Consolas, monospace;
  font-size: 0.62rem;
  color: var(--p-text-muted-color, #71717a);
}

.pm-pill {
  position: absolute;
  z-index: 1;
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  height: 1.75rem;
  white-space: nowrap;
  transform: translate(-50%, -50%);
  border-radius: 999px;
  border: 1px solid rgb(212 212 216);
  background: var(--p-content-background, #fff);
  cursor: pointer;
  transition: border-color 0.15s;
}

.pm-pill:hover {
  border-color: rgb(161 161 170);
}

.pm-pill:focus-visible {
  outline: 2px solid rgb(16 185 129);
  outline-offset: 1px;
}

.pm-loss {
  color: var(--p-text-muted-color, #71717a);
}

.pm-pill-lossy {
  border-color: rgb(249 115 22);
  background: rgb(255 247 237);
  color: rgb(154 52 18);
}

.pm-pill-lossy .pm-loss {
  color: rgb(194 65 12);
  font-weight: 700;
}

.pm-pill-off {
  border-style: dashed;
  color: var(--p-text-muted-color, #71717a);
}

.pm-fold {
  color: var(--p-text-muted-color, #71717a);
}

.pm-chip {
  position: absolute;
  z-index: 1;
  transform: translate(-50%, -50%);
  min-width: 2.25rem;
  padding: 0 0.35rem;
  line-height: 1rem;
  text-align: center;
  border-radius: 999px;
  border-width: 1px;
  background: var(--p-content-background, #fff);
  font-family: ui-monospace, Consolas, monospace;
  font-size: 0.68rem;
  font-weight: 700;
}

.pm-step {
  display: grid;
  place-items: center;
  width: 1.3rem;
  height: 1.3rem;
  border-radius: 0.3rem;
  background: rgb(244 244 245);
}

.pm-step:disabled {
  opacity: 0.4;
}

.pm-flow {
  stroke-dasharray: 2 16;
  opacity: 0.6;
  animation: pm-flow 0.9s linear infinite;
}

@keyframes pm-flow {
  to {
    stroke-dashoffset: -18;
  }
}

@media (prefers-reduced-motion: reduce) {
  .pm-flow {
    animation: none;
  }
}

@media (prefers-color-scheme: dark) {
  .pm-port {
    border-color: rgb(69 69 77);
    background: rgb(42 42 48);
  }

  .pm-pill {
    border-color: rgb(69 69 77);
    background: rgb(38 38 43);
  }

  .pm-pill:hover {
    border-color: rgb(113 113 122);
  }

  .pm-pill-lossy {
    border-color: rgb(251 146 60);
    background: rgb(45 33 24);
    color: rgb(254 215 170);
  }

  .pm-pill-lossy .pm-loss {
    color: rgb(253 186 116);
  }

  .pm-chip {
    background: rgb(31 31 35);
  }

  .pm-step {
    background: rgb(51 51 58);
  }
}
</style>
