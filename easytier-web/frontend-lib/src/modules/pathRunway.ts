// Model of the path runway: the paths of one peer placed by the RTT they are
// ranked by, and the edits a drag makes to the selection rules. At rest the
// view shows what the core reported (`tier`, `ranked_rtt_micros`, `selected`,
// ...); while a handle is dragged it is recomputed with the TS port of the
// selection (`mpSelection.ts`) under the draft rules.

import type { MpConfig, MpPathStatus, MpPeerStatus, MpSelectionConfig, MpSelectionKindRule } from '../types/mpConfig'
import { DEFAULT_MP_SELECTION_CONFIG, MP_SELECTION_DEFAULTS } from '../types/mpConfig'
import { pathKey, toNum } from './mpRuntime'
import {
  selectionInput,
  selectionParams,
  selectPaths,
  switchingThresholdMicros,
  transportBias,
  LEFT_OUT_LOSSY_FIRST_HOP,
  LEFT_OUT_LOSSY_PATH,
  LEFT_OUT_POLICY,
  LEFT_OUT_UNACKED,
  type Candidate,
  type SelectionParams,
  type Tier,
} from './mpSelection'

export type PathState = 'sending' | 'held' | 'standby' | 'lossy' | 'silent' | 'paused' | 'excluded'

/** What a kind rule is about: the carrier and, where it matters, the IP family of the far end. */
export interface PathKind {
  carrierKind: string
  family: '' | 'v4' | 'v6'
  /** Stable text form, for keys and comparisons. */
  id: string
}

export interface RunwayPath {
  key: string
  kind: PathKind
  status: MpPathStatus
  tier: Tier
  /** The RTT the path is ranked by (an unmeasured path counted at the stand-in), in ms. */
  rttMs: number
  /** Measured RTT in ms, null = no sample yet. */
  measuredMs: number | null
  biasMs: number
  /** Where the path sits on the axis: ranked RTT plus bias, in ms. */
  biasedMs: number
  lossPct: number
  state: PathState
}

export interface RunwayView {
  lanes: Record<Tier, RunwayPath[]>
  /** Paths that do not take part in the selection (lossy, silent, paused, excluded). */
  out: RunwayPath[]
  activeTier: Tier | null
  /** The span a challenger must clear to replace the slowest sending path, in ms of the axis. */
  shield: { fromMs: number, toMs: number } | null
  sending: number
}

export const NOT_ESTABLISHED = 'not-established'

const micros = (v: unknown) => toNum(v) ?? 0

export function isIpv6Endpoint(addr: string | undefined): boolean {
  if (!addr) return false
  return addr.startsWith('[') || (addr.match(/:/g)?.length ?? 0) > 1
}

export function kindOf(path: MpPathStatus): PathKind {
  const carrierKind = path.carrier_kind ?? ''
  const family = carrierKind === 'relay-next-hop' ? '' : isIpv6Endpoint(path.path?.remote_addr) ? 'v6' : 'v4'
  return { carrierKind, family, id: `${carrierKind}|${family}` }
}

const biasMs = (microsValue: number) => microsValue / 1000

function leftOutState(reason: string, userPolicy: string | undefined): PathState {
  switch (reason) {
    case LEFT_OUT_POLICY: return userPolicy === 'exclude' ? 'excluded' : 'paused'
    case LEFT_OUT_LOSSY_PATH:
    case LEFT_OUT_LOSSY_FIRST_HOP: return 'lossy'
    case LEFT_OUT_UNACKED: return 'silent'
    default: return 'standby'
  }
}

function candidateOf(peerId: number | string, p: MpPathStatus): Candidate {
  const id = p.path
  const kind = kindOf(p)
  const action = p.user_policy
  return {
    key: pathKey(peerId, p),
    carrierId: Number(id?.carrier_id ?? 0),
    localAddr: id?.local_addr ?? '',
    remoteAddr: id?.remote_addr ?? '',
    carrierKind: kind.carrierKind,
    remoteIsV6: kind.family === 'v6',
    propagationRttMicros: micros(p.windowed_min_rtt_micros) || micros(p.min_rtt_micros),
    recentLoss: p.recent_loss ?? null,
    firstHopLoss: p.first_hop_loss ?? null,
    unacked: p.not_selected_reason === LEFT_OUT_UNACKED,
    policy: action ? { action: action as 'pin', prefer_weight: 2 } : null,
  }
}

/** Paths the runway shows: every established one. */
export function runwayPaths(peer: MpPeerStatus): MpPathStatus[] {
  return (peer.paths ?? []).filter(p => p.path && p.not_selected_reason !== NOT_ESTABLISHED)
}

function place(
  peer: MpPeerStatus,
  params: SelectionParams,
  state: (c: Candidate, p: MpPathStatus) => { state: PathState, selected: boolean },
  reported: boolean,
): RunwayPath[] {
  const placed: RunwayPath[] = []
  for (const p of runwayPaths(peer)) {
    const c = candidateOf(peer.peer_id, p)
    const kind = kindOf(p)
    const [tier, bias] = transportBias(kind.carrierKind, kind.family === 'v6', params)
    const measured = c.propagationRttMicros || null
    const useReport = reported && !!p.tier
    const rttMicros = useReport ? micros(p.ranked_rtt_micros) : (c.propagationRttMicros || params.unmeasuredRttMicros)
    const biasMicros = useReport ? micros(p.rtt_bias_micros) : bias
    const s = state(c, p)
    placed.push({
        key: c.key,
        kind,
        status: p,
        tier: useReport ? (p.tier === 'backup' ? 'backup' : 'primary') : tier,
        rttMs: biasMs(rttMicros),
        measuredMs: measured === null ? null : biasMs(measured),
        biasMs: biasMs(biasMicros),
        biasedMs: biasMs(rttMicros + biasMicros),
        lossPct: (p.loss_rate ?? 0) * 100,
        state: s.state,
    })
  }
  return placed
}

function arrange(placed: RunwayPath[], thresholdMicros: number, activeTierHint: Tier | null): RunwayView {
  const byRank = (a: RunwayPath, b: RunwayPath) =>
    (a.tier === b.tier ? 0 : a.tier === 'primary' ? -1 : 1) || a.biasedMs - b.biasedMs
  const sending = placed.filter(p => p.state === 'sending').sort(byRank)
  const out = placed.filter(p => ['lossy', 'silent', 'paused', 'excluded'].includes(p.state))
  const rest = placed.filter(p => p.state === 'standby').sort(byRank)
  const activeTier = sending[0]?.tier ?? activeTierHint ?? rest[0]?.tier ?? null
  const worst = sending.length ? sending[sending.length - 1] : null
  if (worst) {
    for (const p of rest) if (p.tier === worst.tier && p.biasedMs < worst.biasedMs) p.state = 'held'
  }
  const lane = (t: Tier) => [...sending.filter(p => p.tier === t), ...rest.filter(p => p.tier === t)]
  return {
    lanes: { primary: lane('primary'), backup: lane('backup') },
    out,
    activeTier,
    shield: worst ? { fromMs: worst.biasedMs - thresholdMicros / 1000, toMs: worst.biasedMs } : null,
    sending: sending.length,
  }
}

/** The view of what the core reported for `peer`, positions from the saved rules. */
export function reportedView(peer: MpPeerStatus, selection?: MpSelectionConfig | null): RunwayView {
  const params = selectionParams(selection)
  const placed = place(peer, params, (_c, p) => {
    if (p.selected) return { state: 'sending', selected: true }
    return { state: p.not_selected_reason ? leftOutState(p.not_selected_reason, p.user_policy) : 'standby', selected: false }
  }, true)
  const tier = peer.active_tier === 'backup' ? 'backup' : peer.active_tier === 'primary' ? 'primary' : null
  return arrange(placed, micros(peer.switch_threshold_micros), tier)
}

/** What the selection would do under the draft `selection` and `kmax`: a preview while a handle moves. */
export function previewView(peer: MpPeerStatus, selection: MpSelectionConfig, kmax: number): RunwayView {
  const params = selectionParams(selection)
  const statuses = runwayPaths(peer)
  const input = selectionInput(statuses.map(p => candidateOf(peer.peer_id, p)), params)
  const current = statuses.filter(p => p.selected).map(p => pathKey(peer.peer_id, p))
  const chosen = new Set(selectPaths(input.paths, current, kmax, input.pinned, params))
  const placed = place(peer, params, (c, p) => {
    if (chosen.has(c.key)) return { state: 'sending', selected: true }
    const reason = input.leftOut.get(c.key)
    return { state: reason ? leftOutState(reason, p.user_policy) : 'standby', selected: false }
  }, false)
  const paths = placed
  const worst = paths.filter(p => p.state === 'sending').sort((a, b) => b.biasedMs - a.biasedMs)[0]
  return arrange(paths, worst ? switchingThresholdMicros(worst.rttMs * 1000, params) : 0, null)
}

// ---- axis -------------------------------------------------------------------

export const AXIS_MAX_MS = 600
const f = (v: number) => Math.log10(1 + Math.max(0, v))

/** The logarithmic latency axis: 0 ms at the left pad, `AXIS_MAX_MS` at the right. */
export function runwayAxis(width: number, leftPad = 14, rightPad = 18) {
  const span = Math.max(1, width - leftPad - rightPad)
  return {
    x: (ms: number) => leftPad + f(Math.min(ms, AXIS_MAX_MS)) / f(AXIS_MAX_MS) * span,
    ms: (px: number) => 10 ** (Math.max(0, px - leftPad) / span * f(AXIS_MAX_MS)) - 1,
  }
}

// ---- edits ------------------------------------------------------------------

const clamp = (n: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, n))

/** The tier and bias a kind has under `selection`. */
export function kindRuleValues(selection: MpSelectionConfig | null | undefined, kind: PathKind): { tier: Tier, biasMs: number } {
  const [tier, bias] = transportBias(kind.carrierKind, kind.family === 'v6', selectionParams(selection))
  return { tier, biasMs: Math.round(bias / 1000) }
}

/** `selection` with the rule of `kind` set to `change`; a rule equal to the built-in one is dropped. */
export function withKindRule(
  selection: MpSelectionConfig | null | undefined,
  kind: PathKind,
  change: Partial<{ tier: Tier, biasMs: number }>,
): MpSelectionConfig {
  const base = selection ?? DEFAULT_MP_SELECTION_CONFIG()
  const current = kindRuleValues(base, kind)
  const rule: MpSelectionKindRule = {
    carrier_kind: kind.carrierKind,
    ip_family: kind.family,
    tier: change.tier ?? current.tier,
    rtt_bias_ms: clamp(Math.round(change.biasMs ?? current.biasMs), -1000, 1000),
  }
  const others = base.kind_rules.filter(r => !(r.carrier_kind === rule.carrier_kind && r.ip_family === rule.ip_family))
  const builtIn = kindRuleValues(DEFAULT_MP_SELECTION_CONFIG(), kind)
  const isBuiltIn = rule.tier === builtIn.tier && rule.rtt_bias_ms === builtIn.biasMs
  // A kind-wide rule ('' family) that already covers this one needs no entry of its own.
  const wide = others.find(r => r.carrier_kind === rule.carrier_kind && r.ip_family === '')
  const coveredByWide = wide && wide.tier === rule.tier && wide.rtt_bias_ms === rule.rtt_bias_ms && kind.family !== ''
  return { ...base, kind_rules: isBuiltIn || coveredByWide ? others : [...others, rule] }
}

/** The shield handle moved to `handleMs` on the axis: a wider shield is a larger threshold. */
export function withSwitchThreshold(
  selection: MpSelectionConfig | null | undefined,
  view: { fromMs: number, toMs: number, worstRttMs: number },
  handleMs: number,
): MpSelectionConfig {
  const base = selection ?? DEFAULT_MP_SELECTION_CONFIG()
  const params = selectionParams(base)
  const width = Math.max(0, view.toMs - handleMs)
  const minMs = params.switchMinMicros / 1000
  // The percentage governs when it is the larger of the two (it is what the shield shows).
  const percentGoverns = view.toMs - view.fromMs > minMs + 1e-9
  return percentGoverns
    ? { ...base, switch_percent: clamp(Math.round(width / Math.max(1, view.worstRttMs) * 100), 1, 100) }
    : { ...base, switch_min_ms: clamp(Math.round(width), 1, 1000) }
}

export const withLossyPercent = (selection: MpSelectionConfig | null | undefined, pct: number): MpSelectionConfig =>
  ({ ...(selection ?? DEFAULT_MP_SELECTION_CONFIG()), lossy_percent: clamp(Math.round(pct), 1, 100) })

export const withUnmeasuredMs = (selection: MpSelectionConfig | null | undefined, ms: number): MpSelectionConfig =>
  ({ ...(selection ?? DEFAULT_MP_SELECTION_CONFIG()), unmeasured_rtt_ms: clamp(Math.round(ms), 1, 5000) })

/** The number of paths sending at once after the cut handle moved by `rows` rows. */
export function kmaxAfterDrag(start: number, rows: number, tierPaths: number): number {
  return clamp(start + rows, 1, Math.max(1, tierPaths))
}

/** MpConfig with a changed selection section. */
export const withSelection = (mp: MpConfig, selection: MpSelectionConfig): MpConfig => ({ ...mp, selection })

/** The values behind the handles, defaults resolved. */
export function selectionValues(selection?: MpSelectionConfig | null) {
  const p = selectionParams(selection)
  return {
    switchMinMs: p.switchMinMicros / 1000,
    switchPercent: p.switchPercent,
    lossyPercent: Math.round(p.lossyLoss * 100),
    unmeasuredMs: p.unmeasuredRttMicros / 1000,
  }
}

export { MP_SELECTION_DEFAULTS }
