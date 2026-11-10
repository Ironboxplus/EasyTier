<script setup lang="ts">
// The path selection of one peer as a latency runway: the peer sits at 0 ms,
// every path sits at the RTT it is ranked by, the closest ones in the best
// lane carry data. Every rule is a handle on the shape it governs; releasing
// a handle emits the changed MpConfig, and the core's next report replaces
// the preview that was shown while dragging.
import { useElementSize } from '@vueuse/core'
import { Ban, Droplet, EarOff, EthernetPort, Monitor, Pause, ShieldHalf, Wifi } from 'lucide-vue-next'
import { motion } from 'motion-v'
import { computed, onBeforeUnmount, ref, useTemplateRef, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { cn } from '../../lib/utils'
import { pathNic } from '../../modules/mpRuntime'
import type { Tier } from '../../modules/mpSelection'
import {
  kindRuleValues,
  kmaxAfterDrag,
  previewView,
  reportedView,
  runwayAxis,
  selectionValues,
  withKindRule,
  withLossyPercent,
  withSwitchThreshold,
  withUnmeasuredMs,
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
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '../ui/tooltip'
import KindDisc from './KindDisc.vue'
import PathDetail from './PathDetail.vue'

const props = defineProps<{
  peer: MpPeerStatus
  /** Saved config of the instance; the rules the handles edit. */
  mpConfig?: MpConfig | null
  /** Name of the peer at the origin of the runway. */
  peerName: string
  /** Virtual address of the peer. */
  peerAddress?: string
  /** Host names by peer id, to name relay nodes. */
  peerNames?: Record<string, string>
  busy?: boolean
}>()

const emit = defineEmits<{
  /** A handle was released: `update` turns the saved MpConfig into the edited one. */
  'edit': [label: string, update: (mp: MpConfig) => MpConfig]
  'set-policy': [match: MpPolicyMatch, action: MpPolicyAction | null]
}>()

const { t, te } = useI18n()

// ---- what is shown: the core's report, or a preview while a handle moves -----
const savedSelection = computed<MpSelectionConfig>(() => props.mpConfig?.selection ?? DEFAULT_MP_SELECTION_CONFIG())
const savedKmax = computed(() => props.mpConfig?.kmax ?? 1)
const draft = ref<{ selection: MpSelectionConfig, kmax: number } | null>(null)
const view = computed(() => draft.value
  ? previewView(props.peer, draft.value.selection, draft.value.kmax)
  : reportedView(props.peer, savedSelection.value))
const values = computed(() => selectionValues(draft.value?.selection ?? savedSelection.value))
const kmaxShown = computed(() => draft.value?.kmax ?? savedKmax.value)

// After a release the draft stays until the core reports again (or a moment passes).
let settle: ReturnType<typeof setTimeout> | undefined
watch(() => props.peer, () => {
  if (!settling.value) return
  settling.value = false
  draft.value = null
})
const settling = ref(false)
function release(label: string, selection: MpSelectionConfig, kmax: number) {
  settling.value = true
  clearTimeout(settle)
  settle = setTimeout(() => { settling.value = false; draft.value = null }, 4000)
  emit('edit', label, mp => ({ ...mp, selection, kmax }))
}
onBeforeUnmount(() => clearTimeout(settle))

function begin() {
  clearTimeout(settle)
  settling.value = false
  draft.value ??= { selection: JSON.parse(JSON.stringify(savedSelection.value)), kmax: savedKmax.value }
}
function cancel() {
  draft.value = null
}

// ---- geometry ------------------------------------------------------------------
const ROW = 40
const trackEl = useTemplateRef<HTMLElement[]>('track')
const firstTrack = computed(() => trackEl.value?.[0] ?? null)
const { width } = useElementSize(firstTrack)
const narrow = computed(() => width.value < 420)
const axis = computed(() => runwayAxis(width.value))
const x = (ms: number) => axis.value.x(ms)
const ticks = computed(() => (narrow.value ? [0, 1, 10, 100] : [0, 1, 2, 5, 10, 20, 50, 100, 200]))
const fmt = (ms: number) => (ms < 10 ? ms.toFixed(1) : Math.round(ms).toString())

const tiers: Tier[] = ['primary', 'backup']
const lanePaths = (tier: Tier) => view.value.lanes[tier]
const laneRows = (tier: Tier) => Math.max(1, lanePaths(tier).length)
const sendingIn = (tier: Tier) => lanePaths(tier).filter(p => p.state === 'sending').length
const dimLane = (tier: Tier) => view.value.activeTier !== null && view.value.activeTier !== tier

// ---- names ---------------------------------------------------------------------
function hostOf(addr: string): string {
  if (addr.startsWith('[')) return addr.slice(1, addr.indexOf(']'))
  return (addr.match(/:/g)?.length ?? 0) === 1 ? addr.slice(0, addr.indexOf(':')) : addr
}
function pathName(p: RunwayPath): string {
  if (p.kind.carrierKind === 'relay-next-hop') {
    const id = p.status.first_hop_peer_id
    return props.peerNames?.[String(id)] || t('mp_rt.peer_fallback', [id ?? '-'])
  }
  return hostOf(p.status.path?.remote_addr ?? '') || '-'
}
function kindName(kind: PathKind): string {
  const key = `mp_rt.carrier.${kind.carrierKind.replace(/-/g, '_')}`
  const base = te(key) ? t(key) : kind.carrierKind
  return kind.family === 'v6' ? t('mp_runway.kind_v6', [base]) : base
}
const wireless = (via: string) => /wlan|wi-?fi|wireless|^wl/i.test(via)
const viaOf = (p: RunwayPath) => pathNic(p.status)
const laneName = (tier: Tier) => t(`mp_runway.lane.${tier}`)
const signed = (n: number) => `${n > 0 ? '+' : ''}${n}`

// ---- drag a path: sideways = its kind's RTT bias, across lanes = its kind's tier -----
const laneEl = useTemplateRef<HTMLElement[]>('lane')
const drag = ref<{ key: string, kind: PathKind, x0: number, cx0: number, rttMs: number, moved: boolean } | null>(null)
const openKey = ref<string | null>(null)
const capture = (e: PointerEvent) => (e.currentTarget as HTMLElement | null)?.setPointerCapture?.(e.pointerId)

function laneAt(cy: number): Tier | null {
  for (const [i, el] of (laneEl.value ?? []).entries()) {
    const r = el.getBoundingClientRect()
    if (cy >= r.top && cy <= r.bottom) return tiers[i]
  }
  return null
}
function pathDown(e: PointerEvent, p: RunwayPath) {
  if (e.button !== 0 || props.busy) return
  capture(e)
  drag.value = { key: p.key, kind: p.kind, x0: x(p.biasedMs), cx0: e.clientX, rttMs: p.rttMs, moved: false }
}
function pathMove(e: PointerEvent) {
  const d = drag.value
  if (!d) return
  const dx = e.clientX - d.cx0
  const over = laneAt(e.clientY)
  const current = kindRuleValues(draft.value?.selection ?? savedSelection.value, d.kind).tier
  if (!d.moved && Math.abs(dx) < 4 && !(over !== null && over !== current)) return
  if (!d.moved) { d.moved = true; begin(); openKey.value = null }
  const change: { biasMs: number, tier?: Tier } = { biasMs: Math.round(axis.value.ms(d.x0 + dx) - d.rttMs) }
  if (over) change.tier = over
  draft.value!.selection = withKindRule(draft.value!.selection, d.kind, change)
}
function pathUp(p: RunwayPath) {
  const d = drag.value
  drag.value = null
  if (!d) return
  if (!d.moved) { openKey.value = openKey.value === p.key ? null : p.key; return }
  const sel = draft.value!.selection
  const k = kindRuleValues(sel, d.kind)
  release(t('mp_runway.edit.kind', [kindName(d.kind), laneName(k.tier), signed(k.biasMs)]), sel, draft.value!.kmax)
}
const isDragging = (key: string) => drag.value?.key === key && drag.value.moved

// ---- the cut under the sending paths: how many paths carry data -----------------
const cut = ref<{ cy0: number, k0: number } | null>(null)
function cutDown(e: PointerEvent) {
  if (props.busy) return
  capture(e)
  cut.value = { cy0: e.clientY, k0: kmaxShown.value }
  begin()
}
function cutMove(e: PointerEvent) {
  if (!cut.value || !view.value.activeTier || !draft.value) return
  const n = lanePaths(view.value.activeTier).length
  draft.value.kmax = kmaxAfterDrag(cut.value.k0, Math.round((e.clientY - cut.value.cy0) / ROW), n)
}
function cutUp() {
  const c = cut.value
  cut.value = null
  if (!c || !draft.value) return
  if (c.k0 === draft.value.kmax) return cancel()
  release(t('mp_runway.edit.kmax', [draft.value.kmax]), draft.value.selection, draft.value.kmax)
}

// ---- the shield: how much faster a challenger must be -----------------------------
const shieldDrag = ref<{ cx0: number, x0: number } | null>(null)
function shieldDown(e: PointerEvent) {
  if (!view.value.shield || props.busy) return
  capture(e)
  shieldDrag.value = { cx0: e.clientX, x0: x(view.value.shield.fromMs) }
  begin()
}
function shieldMove(e: PointerEvent) {
  const d = shieldDrag.value
  const s = view.value.shield
  if (!d || !s || !draft.value) return
  draft.value.selection = withSwitchThreshold(
    draft.value.selection,
    { ...s, worstRttMs: s.toMs },
    axis.value.ms(d.x0 + e.clientX - d.cx0),
  )
}
function shieldUp() {
  if (!shieldDrag.value || !draft.value) return
  shieldDrag.value = null
  const v = selectionValues(draft.value.selection)
  release(t('mp_runway.edit.switch', [v.switchMinMs, v.switchPercent]), draft.value.selection, draft.value.kmax)
}

// ---- the edge of the unmeasured zone ---------------------------------------------
const unDrag = ref<{ cx0: number, x0: number } | null>(null)
function unDown(e: PointerEvent) {
  if (props.busy) return
  capture(e)
  unDrag.value = { cx0: e.clientX, x0: x(values.value.unmeasuredMs) }
  begin()
}
function unMove(e: PointerEvent) {
  if (!unDrag.value || !draft.value) return
  const ms = Math.min(600, Math.max(20, axis.value.ms(unDrag.value.x0 + e.clientX - unDrag.value.cx0)))
  draft.value.selection = withUnmeasuredMs(draft.value.selection, ms)
}
function unUp() {
  if (!unDrag.value || !draft.value) return
  unDrag.value = null
  release(t('mp_runway.edit.unmeasured', [selectionValues(draft.value.selection).unmeasuredMs]), draft.value.selection, draft.value.kmax)
}

// ---- loss meter in the tray ------------------------------------------------------
const LOSS_MAX = 40
const meterEl = useTemplateRef<HTMLElement>('meter')
const lossDrag = ref(false)
const lossX = (pct: number) => `${Math.min(pct, LOSS_MAX) / LOSS_MAX * 100}%`
const everyPath = computed(() => [...view.value.lanes.primary, ...view.value.lanes.backup, ...view.value.out])
function lossDown(e: PointerEvent) {
  if (props.busy) return
  capture(e)
  lossDrag.value = true
  begin()
}
function lossMove(e: PointerEvent) {
  if (!lossDrag.value || !meterEl.value || !draft.value) return
  const r = meterEl.value.getBoundingClientRect()
  draft.value.selection = withLossyPercent(draft.value.selection, Math.min(LOSS_MAX, ((e.clientX - r.left) / Math.max(1, r.width)) * LOSS_MAX))
}
function lossUp() {
  if (!lossDrag.value || !draft.value) return
  lossDrag.value = false
  release(t('mp_runway.edit.lossy', [selectionValues(draft.value.selection).lossyPercent]), draft.value.selection, draft.value.kmax)
}

// ---- popover edits ---------------------------------------------------------------
function setPolicy(p: RunwayPath, action: MpPolicyAction | null) {
  emit('set-policy', policyMatchForPath(p.status), action)
}
function setKind(p: RunwayPath, change: Partial<{ tier: Tier, biasMs: number }>) {
  const selection = withKindRule(savedSelection.value, p.kind, change)
  const k = kindRuleValues(selection, p.kind)
  release(t('mp_runway.edit.kind', [kindName(p.kind), laneName(k.tier), signed(k.biasMs)]), selection, savedKmax.value)
}

const labelLeft = (p: RunwayPath) => x(p.biasedMs) > width.value * 0.62
const outIcon = { lossy: Droplet, silent: EarOff, paused: Pause, excluded: Ban } as const
const spring = { type: 'spring', stiffness: 420, damping: 34 } as const
const kindTier = (p: RunwayPath) => kindRuleValues(savedSelection.value, p.kind)
</script>

<template>
  <TooltipProvider :delay-duration="200">
    <section class="overflow-hidden rounded-2xl border border-zinc-200 bg-white text-zinc-900 shadow-sm" data-testid="path-runway">
      <!-- the peer: the origin of the runway -->
      <header class="flex items-center gap-3 border-b border-zinc-200 bg-gradient-to-b from-zinc-50 to-white px-4 py-3">
        <span class="grid size-9 shrink-0 place-items-center rounded-xl bg-zinc-900 text-white shadow-sm"><Monitor class="size-[18px]" /></span>
        <div class="min-w-0">
          <div class="truncate font-semibold leading-tight">{{ peerName }}</div>
          <div v-if="peerAddress" class="font-mono text-xs text-zinc-500">{{ peerAddress }}</div>
        </div>
        <div v-if="!narrow" class="ml-auto flex items-center gap-4 text-xs text-zinc-500">
          <span class="flex items-center gap-1.5"><span class="size-2.5 rounded-full bg-emerald-600" />{{ t('mp_runway.state.sending') }}</span>
          <span class="flex items-center gap-1.5"><span class="size-2.5 rounded-full border-2 border-violet-500" />{{ t('mp_runway.state.held') }}</span>
          <span class="flex items-center gap-1.5"><span class="size-2.5 rounded-full border-2 border-zinc-300" />{{ t('mp_runway.state.standby') }}</span>
        </div>
      </header>

      <div class="relative px-2 pt-3 sm:px-3">
        <div v-for="(tier, ti) in tiers" ref="lane" :key="tier" :data-testid="`runway-lane-${tier}`"
          :class="cn('relative grid', narrow ? 'grid-cols-[22px_1fr]' : 'grid-cols-[40px_1fr]', ti > 0 && 'mt-1.5')">
          <!-- lane name and the handle of the send count -->
          <div class="relative">
            <span :class="cn('absolute left-0 top-2 text-[11px] font-medium tracking-widest [writing-mode:vertical-rl]',
                             dimLane(tier) ? 'text-zinc-400' : 'text-zinc-700')">{{ laneName(tier) }}</span>
            <Tooltip v-if="view.activeTier === tier && sendingIn(tier) > 0">
              <TooltipTrigger as-child>
                <motion.button type="button" data-testid="runway-kmax"
                  class="absolute right-1 z-20 flex h-5 cursor-ns-resize touch-none select-none items-center gap-0.5 rounded-full bg-emerald-600 pl-1 pr-1.5 text-[11px] font-semibold text-white shadow-md ring-2 ring-white"
                  :animate="{ top: sendingIn(tier) * ROW + 6 - 10 }" :transition="spring"
                  @pointerdown="cutDown" @pointermove="cutMove" @pointerup="cutUp" @pointercancel="cancel">
                  <span class="text-[9px] leading-none opacity-80">⇅</span>{{ kmaxShown }}
                </motion.button>
              </TooltipTrigger>
              <TooltipContent side="left">{{ t('mp_runway.tip.kmax') }}</TooltipContent>
            </Tooltip>
          </div>

          <!-- the runway -->
          <div ref="track"
            :class="cn('relative rounded-xl transition-colors duration-300',
                       dimLane(tier) ? 'runway-hatch bg-zinc-50/80' : 'bg-gradient-to-r from-emerald-50/70 via-white to-white ring-1 ring-zinc-100',
                       drag?.moved && 'ring-2 ring-violet-200')"
            :style="{ height: `${laneRows(tier) * ROW + 12}px` }">
            <!-- grid -->
            <div v-for="tk in ticks" :key="tk" class="pointer-events-none absolute inset-y-0 w-px"
              :class="[1, 10, 100].includes(tk) ? 'bg-zinc-200/90' : 'bg-zinc-100'" :style="{ left: `${x(tk)}px` }" />
            <!-- the peer -->
            <div class="pointer-events-none absolute inset-y-1.5 w-[3px] rounded-full"
              :class="dimLane(tier) ? 'bg-zinc-300' : 'bg-gradient-to-b from-emerald-400 to-emerald-600'" :style="{ left: `${x(0) - 1.5}px` }" />
            <!-- unmeasured zone -->
            <div class="runway-hatch absolute inset-y-0 right-0 rounded-r-xl bg-zinc-50/60" :style="{ left: `${x(values.unmeasuredMs)}px` }">
              <div v-if="ti === 0" class="absolute -top-0.5 left-1 font-mono text-[10px] text-zinc-400">?</div>
            </div>
            <Tooltip v-if="ti === 0">
              <TooltipTrigger as-child>
                <div class="group absolute inset-y-0 z-10 w-3 -translate-x-1/2 cursor-ew-resize touch-none" data-testid="runway-unmeasured"
                  :style="{ left: `${x(values.unmeasuredMs)}px` }"
                  @pointerdown="unDown" @pointermove="unMove" @pointerup="unUp" @pointercancel="cancel">
                  <div class="mx-auto h-full w-px bg-zinc-300 transition-all group-hover:w-0.5 group-hover:bg-zinc-500" />
                </div>
              </TooltipTrigger>
              <TooltipContent>{{ t('mp_runway.tip.unmeasured', [values.unmeasuredMs]) }}</TooltipContent>
            </Tooltip>

            <!-- the shield in front of the slowest sending path -->
            <motion.div v-if="view.activeTier === tier && view.shield"
              class="pointer-events-none absolute inset-y-0 border-l-2 border-dashed border-violet-400 bg-gradient-to-r from-violet-500/15 to-violet-500/5"
              :animate="{ left: x(view.shield.fromMs), width: Math.max(2, x(view.shield.toMs) - x(view.shield.fromMs)) }" :transition="spring" />
            <motion.div v-if="view.activeTier === tier && view.shield" class="absolute -top-2.5 z-20 -translate-x-1/2"
              :animate="{ left: x(view.shield.fromMs) }" :transition="spring">
              <Tooltip>
                <TooltipTrigger as-child>
                  <button type="button" data-testid="runway-shield"
                    class="grid size-5 cursor-ew-resize touch-none place-items-center rounded-full bg-violet-600 text-white shadow-md ring-2 ring-white"
                    @pointerdown="shieldDown" @pointermove="shieldMove" @pointerup="shieldUp" @pointercancel="cancel">
                    <ShieldHalf class="size-3" />
                  </button>
                </TooltipTrigger>
                <TooltipContent>{{ t('mp_runway.tip.switch', [values.switchMinMs, values.switchPercent]) }}</TooltipContent>
              </Tooltip>
            </motion.div>

            <!-- the cut under the sending paths -->
            <motion.div v-if="view.activeTier === tier && sendingIn(tier) > 0 && sendingIn(tier) < lanePaths(tier).length"
              class="runway-cut pointer-events-none absolute left-0 right-2 h-px"
              :animate="{ top: sendingIn(tier) * ROW + 6 }" :transition="spring" />

            <!-- paths -->
            <motion.div v-for="(p, i) in lanePaths(tier)" :key="p.key" class="absolute inset-x-0 h-10" data-testid="runway-path"
              :data-state="p.state" :initial="false" :animate="{ top: i * ROW + 6 }" :transition="spring">
              <!-- data flowing to the peer -->
              <motion.div v-if="p.state === 'sending'" class="pointer-events-none absolute top-1/2 h-[2px] -translate-y-1/2 rounded-full bg-emerald-500 opacity-80"
                :animate="{ left: x(0), width: Math.max(0, x(p.biasedMs) - x(0)) }" :transition="spring" />
              <!-- where the path really is, when a bias moves it -->
              <template v-if="p.biasMs !== 0">
                <motion.div class="pointer-events-none absolute top-1/2 h-px -translate-y-1/2 border-t border-dotted border-zinc-400"
                  :animate="{ left: Math.min(x(p.rttMs), x(p.biasedMs)), width: Math.abs(x(p.rttMs) - x(p.biasedMs)) }" :transition="spring" />
                <motion.div class="pointer-events-none absolute top-1/2 size-2 -translate-x-1/2 -translate-y-1/2 rounded-full border border-zinc-400 bg-white"
                  :animate="{ left: x(p.rttMs) }" :transition="spring" />
              </template>

              <motion.div class="absolute top-1/2 z-10 -translate-y-1/2"
                :animate="{ left: x(p.biasedMs) - 13 }" :transition="isDragging(p.key) ? { duration: 0 } : spring">
                <Popover :open="openKey === p.key" @update:open="(v: boolean) => { if (!v) openKey = null }">
                  <PopoverAnchor as-child>
                    <button type="button" data-testid="runway-dot"
                      :class="cn('relative block cursor-grab touch-none rounded-full outline-none focus-visible:ring-2 focus-visible:ring-violet-400',
                                 isDragging(p.key) && 'scale-110 cursor-grabbing')"
                      @pointerdown="pathDown($event, p)" @pointermove="pathMove" @pointerup="pathUp(p)" @pointercancel="cancel">
                      <motion.span v-if="p.state === 'sending'" class="absolute inset-0 rounded-full bg-emerald-500"
                        :animate="{ scale: [1, 1.9], opacity: [0.35, 0] }" :transition="{ duration: 1.8, repeat: Infinity, ease: 'easeOut' }" />
                      <KindDisc :kind="p.kind" :state="p.state" :dim="dimLane(tier)" />
                    </button>
                  </PopoverAnchor>
                  <PopoverContent class="w-80" side="bottom" align="start">
                    <PathDetail :placed="p" :name="pathName(p)" :via="viaOf(p)" :kind-name="kindName(p.kind)" :tier="kindTier(p).tier"
                      :bias-ms="kindTier(p).biasMs" :policy="p.status.user_policy ?? ''" :busy="busy"
                      @policy="setPolicy(p, $event)" @bias="setKind(p, { biasMs: $event })" @tier="setKind(p, { tier: $event })" />
                  </PopoverContent>
                </Popover>
                <!-- direct label -->
                <div :class="cn('pointer-events-none absolute top-1/2 flex -translate-y-1/2 items-center gap-1.5 whitespace-nowrap',
                                labelLeft(p) ? 'right-full mr-2 flex-row-reverse' : 'left-full ml-2')"
                  :style="labelLeft(p) ? {} : { marginLeft: `${8 + Math.max(0, x(p.rttMs) - x(p.biasedMs))}px` }">
                  <span class="font-mono text-[13px] tabular-nums" :class="dimLane(tier) ? 'text-zinc-400' : 'text-zinc-800'">
                    {{ p.measuredMs === null ? '?' : fmt(p.measuredMs) }}</span>
                  <component :is="wireless(viaOf(p)) ? Wifi : EthernetPort" class="size-3 text-zinc-400" />
                  <span :class="cn('truncate text-xs', narrow ? 'max-w-[84px]' : 'max-w-[160px]', dimLane(tier) ? 'text-zinc-400' : 'text-zinc-500')">{{ pathName(p) }}</span>
                </div>
              </motion.div>
            </motion.div>

            <div v-if="!lanePaths(tier).length" class="absolute inset-1.5 grid place-items-center rounded-lg border border-dashed border-zinc-300 text-xs text-zinc-400">
              {{ t('mp_runway.drop_here') }}
            </div>
          </div>
        </div>

        <!-- axis -->
        <div :class="cn('relative mt-1 h-5', narrow ? 'ml-[22px]' : 'ml-[40px]')">
          <span v-for="tk in ticks" :key="tk" class="absolute -translate-x-1/2 font-mono text-[10px] text-zinc-400" :style="{ left: `${x(tk)}px` }">{{ tk }}</span>
          <span class="absolute right-0 font-mono text-[10px] text-zinc-400">ms</span>
        </div>
      </div>

      <!-- not taking part -->
      <footer class="mt-2 flex flex-col gap-3 border-t border-zinc-200 bg-zinc-50/70 px-4 py-3 sm:flex-row sm:items-center">
        <div class="flex min-w-0 flex-1 flex-wrap items-center gap-2" data-testid="runway-out">
          <Popover v-for="p in view.out" :key="p.key" :open="openKey === p.key" @update:open="(v: boolean) => { if (!v) openKey = null }">
            <PopoverAnchor as-child>
              <button type="button" data-testid="runway-out-item" :data-state="p.state"
                class="flex items-center gap-1.5 rounded-full border border-zinc-200 bg-white py-0.5 pl-0.5 pr-2.5 text-xs shadow-sm hover:border-zinc-300"
                @click="openKey = openKey === p.key ? null : p.key">
                <KindDisc :kind="p.kind" :state="p.state" size="sm" />
                <span class="max-w-[120px] truncate text-zinc-600">{{ pathName(p) }}</span>
                <component :is="outIcon[p.state as keyof typeof outIcon]" :class="cn('size-3', p.state === 'lossy' ? 'text-amber-600' : 'text-zinc-400')" />
                <span v-if="p.state === 'lossy'" class="font-mono tabular-nums text-amber-700">{{ Math.round(p.lossPct) }}%</span>
              </button>
            </PopoverAnchor>
            <PopoverContent class="w-80" side="top" align="start">
              <PathDetail :placed="p" :name="pathName(p)" :via="viaOf(p)" :kind-name="kindName(p.kind)" :tier="kindTier(p).tier"
                :bias-ms="kindTier(p).biasMs" :policy="p.status.user_policy ?? ''" :busy="busy"
                @policy="setPolicy(p, $event)" @bias="setKind(p, { biasMs: $event })" @tier="setKind(p, { tier: $event })" />
            </PopoverContent>
          </Popover>
        </div>

        <!-- loss meter: the loss of every path, and where the line is -->
        <div class="flex items-center gap-2 sm:w-56">
          <Droplet class="size-3.5 shrink-0 text-amber-600" />
          <div ref="meter" class="relative h-6 flex-1">
            <div class="absolute inset-x-0 top-1/2 h-1.5 -translate-y-1/2 rounded-full bg-zinc-200" />
            <div class="runway-hatch-amber absolute right-0 top-1/2 h-1.5 -translate-y-1/2 rounded-r-full bg-amber-100" :style="{ left: lossX(values.lossyPercent) }" />
            <span v-for="p in everyPath" :key="p.key" class="absolute top-1/2 size-2 -translate-x-1/2 -translate-y-1/2 rounded-full ring-2 ring-white"
              :class="p.lossPct > values.lossyPercent ? 'bg-amber-500' : 'bg-zinc-400'" :style="{ left: lossX(p.lossPct) }" />
            <button type="button" data-testid="runway-loss"
              class="absolute top-1/2 z-10 h-[18px] w-2.5 -translate-x-1/2 -translate-y-1/2 cursor-ew-resize touch-none rounded-full bg-amber-500 shadow ring-2 ring-white"
              :style="{ left: lossX(values.lossyPercent) }" @pointerdown="lossDown" @pointermove="lossMove" @pointerup="lossUp" @pointercancel="cancel" />
          </div>
          <span class="w-8 text-right font-mono text-xs tabular-nums text-amber-700">{{ values.lossyPercent }}%</span>
        </div>
      </footer>
    </section>
  </TooltipProvider>
</template>

<style scoped>
.runway-hatch {
  background-image: repeating-linear-gradient(135deg, rgb(161 161 170 / 0.18) 0 1px, transparent 1px 7px);
}

.runway-hatch-amber {
  background-image: repeating-linear-gradient(135deg, rgb(217 119 6 / 0.3) 0 1px, transparent 1px 6px);
}

.runway-cut {
  background-image: repeating-linear-gradient(90deg, rgb(16 185 129) 0 6px, transparent 6px 10px);
}
</style>
