// TypeScript port of the core's path selection (`connector/mp_optimizer.rs`
// `select_paths` and `connector/mp_session.rs` `selection_input`). It runs
// only to preview a drag; the core's report decides what is shown once the
// handle is released. `tests/vectors/select_paths.json` is read by both this
// port's tests and the Rust tests, so the two cannot drift apart.

import type { MpPathPolicy, MpSelectionConfig } from '../types/mpConfig'
import { MP_SELECTION_DEFAULTS } from '../types/mpConfig'

export type Tier = 'primary' | 'backup'

export interface KindRule {
  carrierKind: string
  /** null = either family */
  ipv6: boolean | null
  tier: Tier
  biasMicros: number
}

export interface SelectionParams {
  /** Empty = the built-in table of `transportBias`. */
  kindRules: KindRule[]
  switchMinMicros: number
  switchPercent: number
  /** Loss above which a path gives way to a cleaner one, 0..1. */
  lossyLoss: number
  unmeasuredRttMicros: number
}

/** A zero field or an absent section is the default; a rule that does not parse is skipped. */
export function selectionParams(config?: Partial<MpSelectionConfig> | null): SelectionParams {
  const params: SelectionParams = {
    kindRules: [],
    switchMinMicros: MP_SELECTION_DEFAULTS.switch_min_ms * 1000,
    switchPercent: MP_SELECTION_DEFAULTS.switch_percent,
    lossyLoss: MP_SELECTION_DEFAULTS.lossy_percent / 100,
    unmeasuredRttMicros: MP_SELECTION_DEFAULTS.unmeasured_rtt_ms * 1000,
  }
  if (!config) return params
  for (const rule of config.kind_rules ?? []) {
    const family = String(rule.ip_family ?? '')
    if (family !== '' && family !== 'v4' && family !== 'v6') continue
    if (rule.tier !== 'primary' && rule.tier !== 'backup') continue
    params.kindRules.push({
      carrierKind: rule.carrier_kind,
      ipv6: family === '' ? null : family === 'v6',
      tier: rule.tier,
      biasMicros: Math.round(Number(rule.rtt_bias_ms)) * 1000,
    })
  }
  if (config.switch_min_ms) params.switchMinMicros = config.switch_min_ms * 1000
  if (config.switch_percent) params.switchPercent = config.switch_percent
  if (config.lossy_percent) params.lossyLoss = config.lossy_percent / 100
  if (config.unmeasured_rtt_ms) params.unmeasuredRttMicros = config.unmeasured_rtt_ms * 1000
  return params
}

/** The tier and RTT bias of a kind of path: a rule for kind+family, else for the kind, else the built-in row. */
export function transportBias(carrierKind: string, remoteIsV6: boolean, params: SelectionParams): [Tier, number] {
  const rule = params.kindRules.find(r => r.carrierKind === carrierKind && r.ipv6 === remoteIsV6)
    ?? params.kindRules.find(r => r.carrierKind === carrierKind && r.ipv6 === null)
  if (rule) return [rule.tier, rule.biasMicros]
  if (carrierKind === 'relay-next-hop') return ['backup', 0]
  return remoteIsV6 ? ['primary', -3000] : ['primary', 0]
}

// Rust's f64::round: halves go away from zero (Math.round sends -2.5 to -2).
const roundHalfAwayFromZero = (n: number) => (n < 0 ? -Math.round(-n) : Math.round(n))

/** The RTT advantage a `prefer` policy gives: weight 2 ranks as if twice as fast. */
export function preferBiasMicros(rttMicros: number, weight: number): number {
  if (!(Number.isFinite(weight) && weight > 0)) return 0
  return roundHalfAwayFromZero(rttMicros * (1 / weight - 1))
}

export interface SelectorPath {
  /** Opaque, unique; the carrier id keeps ties in a fixed order. */
  key: string
  carrierId: number
  localAddr: string
  remoteAddr: string
  tier: Tier
  /** Propagation RTT, the stand-in for "no sample" already applied. */
  rttMicros: number
  biasMicros: number
}

export function newSelectorPath(
  base: Pick<SelectorPath, 'key' | 'carrierId' | 'tier' | 'biasMicros'> & Partial<Pick<SelectorPath, 'localAddr' | 'remoteAddr'>>,
  windowedMinRttMicros: number,
  params: SelectionParams,
): SelectorPath {
  return {
    localAddr: '',
    remoteAddr: '',
    ...base,
    rttMicros: windowedMinRttMicros === 0 ? params.unmeasuredRttMicros : windowedMinRttMicros,
  }
}

export const biasedRtt = (path: SelectorPath) => path.rttMicros + path.biasMicros

const compare = (a: string | number, b: string | number) => (a < b ? -1 : a > b ? 1 : 0)

export function compareSelectorPaths(a: SelectorPath, b: SelectorPath): number {
  return compare(a.tier === 'primary' ? 0 : 1, b.tier === 'primary' ? 0 : 1)
    || compare(biasedRtt(a), biasedRtt(b))
    || compare(a.carrierId, b.carrierId)
    || compare(a.localAddr, b.localAddr)
    || compare(a.remoteAddr, b.remoteAddr)
}

/** How much better than `incumbent` a path of its tier must be to replace it. */
export function switchingThresholdMicros(incumbentRttMicros: number, params: SelectionParams): number {
  const proportional = Math.floor(incumbentRttMicros * params.switchPercent / 100)
  return Math.max(params.switchMinMicros, proportional)
}

/** The paths that carry data, best first. */
export function selectPaths(
  paths: SelectorPath[],
  current: string[],
  kmax: number,
  pinned: Set<string>,
  params: SelectionParams,
): string[] {
  let ranked = [...paths].sort(compareSelectorPaths)
  const pinnedPaths = ranked.filter(p => pinned.has(p.key))
  if (pinnedPaths.length) return pinnedPaths.map(p => p.key)
  const bestTier = ranked[0]?.tier
  if (bestTier === undefined) return []
  ranked = ranked.filter(p => p.tier === bestTier)
  const places = Math.max(1, kmax)

  // Incumbents that are still candidates, best first, keep their places.
  const chosen = ranked.filter(p => current.includes(p.key)).slice(0, places)
  // A free place goes to the best path not chosen yet.
  for (const p of ranked) {
    if (chosen.length >= places) break
    if (!chosen.includes(p)) chosen.push(p)
  }
  // The best path outside the set takes the worst member's place only if it
  // is better by the switching threshold; the paths after it are worse.
  for (const challenger of ranked) {
    if (chosen.includes(challenger)) continue
    if (!chosen.length) break
    let worstIndex = 0
    for (let i = 1; i < chosen.length; i++) {
      if (compareSelectorPaths(chosen[i], chosen[worstIndex]) > 0) worstIndex = i
    }
    const worst = chosen[worstIndex]
    if (biasedRtt(challenger) + switchingThresholdMicros(worst.rttMicros, params) <= biasedRtt(worst)) chosen[worstIndex] = challenger
    else break
  }
  chosen.sort(compareSelectorPaths)
  return chosen.map(p => p.key)
}

// ---- selection_input ------------------------------------------------------

export const LEFT_OUT_POLICY = 'policy'
export const LEFT_OUT_LOSSY_PATH = 'lossy-path'
export const LEFT_OUT_LOSSY_FIRST_HOP = 'lossy-first-hop'
export const LEFT_OUT_UNACKED = 'unacked'

/** EasyTier ping loss at which a first hop counts as unreachable. */
const UNREACHABLE_FIRST_HOP_LOSS = 1

/** One established path with what `selection_input` reads of it. */
export interface Candidate {
  key: string
  carrierId: number
  localAddr: string
  remoteAddr: string
  carrierKind: string
  remoteIsV6: boolean
  /** Windowed minimum RTT; 0 = no sample yet. */
  propagationRttMicros: number
  recentLoss: number | null
  /** Loss of a relay path's physical first hop. */
  firstHopLoss: number | null
  unacked: boolean
  policy: Pick<MpPathPolicy, 'action' | 'prefer_weight'> | null
}

export interface SelectionInput {
  paths: SelectorPath[]
  pinned: Set<string>
  /** The established paths kept out of `paths`, and why. */
  leftOut: Map<string, string>
}

type Health = 0 | 1 | 2 // clean, lossy, unreachable

const firstHopHealth = (loss: number, lossyLoss: number): Health =>
  loss >= UNREACHABLE_FIRST_HOP_LOSS ? 2 : loss > lossyLoss ? 1 : 0

/**
 * The established paths the selector may choose: `exclude`/`pause` take a
 * path out, `pin` goes to the selector, `prefer` becomes an RTT advantage; a
 * lossy, unacked or unreachable-first-hop path stays out while a better class
 * of path is selectable.
 */
export function selectionInput(candidates: Candidate[], params: SelectionParams): SelectionInput {
  const input: SelectionInput = { paths: [], pinned: new Set(), leftOut: new Map() }
  const selectable: { path: SelectorPath, cls: Health, reason: string }[] = []
  for (const c of candidates) {
    let preferWeight = 1
    if (c.policy) {
      if (c.policy.action === 'exclude' || c.policy.action === 'pause') {
        input.leftOut.set(c.key, LEFT_OUT_POLICY)
        continue
      }
      if (c.policy.action === 'pin') input.pinned.add(c.key)
      else if (c.policy.action === 'prefer') preferWeight = c.policy.prefer_weight
    }
    const [tier, bias] = transportBias(c.carrierKind, c.remoteIsV6, params)
    const path = newSelectorPath(
      { key: c.key, carrierId: c.carrierId, localAddr: c.localAddr, remoteAddr: c.remoteAddr, tier, biasMicros: bias },
      c.propagationRttMicros,
      params,
    )
    path.biasMicros += preferBiasMicros(path.rttMicros, preferWeight)
    const firstHop: Health = c.firstHopLoss == null ? 0 : firstHopHealth(c.firstHopLoss, params.lossyLoss)
    let cls: Health
    let reason: string
    if (firstHop === 2) [cls, reason] = [2, LEFT_OUT_LOSSY_FIRST_HOP]
    else if (c.unacked) [cls, reason] = [2, LEFT_OUT_UNACKED]
    else if (c.recentLoss != null && c.recentLoss > params.lossyLoss) [cls, reason] = [1, LEFT_OUT_LOSSY_PATH]
    else [cls, reason] = [firstHop, LEFT_OUT_LOSSY_FIRST_HOP]
    selectable.push({ path, cls, reason })
  }
  const bestClass = selectable.length ? Math.min(...selectable.map(s => s.cls)) : null
  for (const { path, cls, reason } of selectable) {
    if (bestClass !== null && cls > bestClass && !input.pinned.has(path.key)) input.leftOut.set(path.key, reason)
    else input.paths.push(path)
  }
  return input
}

