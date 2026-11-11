import { describe, expect, it } from 'vitest'
import {
  type Candidate,
  LEFT_OUT_LOSSY_FIRST_HOP,
  LEFT_OUT_LOSSY_PATH,
  LEFT_OUT_POLICY,
  LEFT_OUT_UNACKED,
  newSelectorPath,
  preferBiasMicros,
  selectionInput,
  selectionParams,
  selectPaths,
  switchingThresholdMicros,
  transportBias,
} from '../src/modules/mpSelection'
import vectors from './vectors/select_paths.json'

interface Vectors {
  transport_bias: { kind: string, remote: string, rules?: any[], expect: [string, number] }[]
  prefer_bias: { rtt_micros: number, weight: number, expect: number }[]
  switching_threshold: { rtt_micros: number, params?: any, expect: number }[]
  select: {
    name: string
    kmax: number
    current: number[]
    pinned: number[]
    paths: { id: number, tier: 'primary' | 'backup', rtt_micros: number, bias_micros: number }[]
    params?: any
    expect: number[]
  }[]
}
const v = vectors as unknown as Vectors

const isV6 = (remote: string) => remote.startsWith('[')

describe('path selection port: vectors shared with the core', () => {
  it('transport_bias', () => {
    for (const c of v.transport_bias) {
      const params = selectionParams({ kind_rules: c.rules ?? [] })
      expect(transportBias(c.kind, isV6(c.remote), params), JSON.stringify(c)).toEqual(c.expect)
    }
  })

  it('prefer_bias', () => {
    for (const c of v.prefer_bias) expect(preferBiasMicros(c.rtt_micros, c.weight), JSON.stringify(c)).toBe(c.expect)
  })

  it('switching_threshold', () => {
    for (const c of v.switching_threshold) {
      const params = selectionParams(c.params)
      expect(switchingThresholdMicros(c.rtt_micros, params), JSON.stringify(c)).toBe(c.expect)
    }
  })

  it('select', () => {
    expect(v.select.length).toBeGreaterThan(30)
    for (const c of v.select) {
      const params = selectionParams(c.params)
      const paths = c.paths.map(p => newSelectorPath(
        { key: String(p.id), carrierId: p.id, tier: p.tier, biasMicros: p.bias_micros },
        p.rtt_micros,
        params,
      ))
      const chosen = selectPaths(paths, c.current.map(String), c.kmax, new Set(c.pinned.map(String)), params)
      expect(chosen.map(Number), c.name).toEqual(c.expect)
    }
  })
})

describe('selectionInput', () => {
  const params = selectionParams()
  const cand = (key: number, over: Partial<Candidate> = {}): Candidate => ({
    key: String(key),
    carrierId: key,
    localAddr: `127.0.0.1:${35000 + key}`,
    remoteAddr: `127.0.0.1:${36000 + key}`,
    carrierKind: 'udp-direct',
    remoteIsV6: false,
    propagationRttMicros: 20_000,
    recentLoss: null,
    firstHopLoss: null,
    unacked: false,
    policy: null,
    ...over,
  })
  const keys = (candidates: Candidate[], p = params) => selectionInput(candidates, p).paths.map(x => x.key)

  it('keeps a lossy path out while a clean one is selectable', () => {
    const input = selectionInput([cand(1, { recentLoss: 0.4 }), cand(2)], params)
    expect(input.paths.map(p => p.key)).toEqual(['2'])
    expect(input.leftOut.get('1')).toBe(LEFT_OUT_LOSSY_PATH)
  })

  it('an excluded or paused clean path does not keep a lossy one out', () => {
    const lossy = cand(1, { recentLoss: 0.4 })
    for (const action of ['exclude', 'pause'] as const) {
      const input = selectionInput([lossy, cand(2, { policy: { action, prefer_weight: 0 } })], params)
      expect(input.paths.map(p => p.key)).toEqual(['1'])
      expect(input.leftOut.get('2')).toBe(LEFT_OUT_POLICY)
    }
  })

  it('the loss threshold is a parameter', () => {
    const eighteen = [cand(1, { recentLoss: 0.18 }), cand(2)]
    expect(keys(eighteen)).toEqual(['2'])
    expect(keys(eighteen, selectionParams({ lossy_percent: 20 }))).toEqual(['1', '2'])
    expect(keys([cand(1, { recentLoss: 0.4 }), cand(2)], selectionParams({ lossy_percent: 20 }))).toEqual(['2'])
  })

  it('an unacked path and an unreachable first hop give way to a path that is not', () => {
    const unacked = selectionInput([cand(1, { unacked: true }), cand(2, { recentLoss: 0.4 })], params)
    expect(unacked.paths.map(p => p.key)).toEqual(['2'])
    expect(unacked.leftOut.get('1')).toBe(LEFT_OUT_UNACKED)
    const hop = selectionInput([cand(1, { firstHopLoss: 1 }), cand(2)], params)
    expect(hop.paths.map(p => p.key)).toEqual(['2'])
    expect(hop.leftOut.get('1')).toBe(LEFT_OUT_LOSSY_FIRST_HOP)
    // nothing better left: the only path keeps carrying data
    expect(keys([cand(1, { unacked: true })])).toEqual(['1'])
  })

  it('a pinned path stays in whatever its class', () => {
    const input = selectionInput([cand(1, { recentLoss: 0.4, policy: { action: 'pin', prefer_weight: 0 } }), cand(2)], params)
    expect(input.pinned.has('1')).toBe(true)
    expect(input.paths.map(p => p.key).sort()).toEqual(['1', '2'])
  })

  it('prefer becomes an RTT advantage and the tier table decides the tier', () => {
    const input = selectionInput([
      cand(1, { policy: { action: 'prefer', prefer_weight: 2 } }),
      cand(2, { carrierKind: 'relay-next-hop', remoteIsV6: true }),
    ], params)
    const [direct, relay] = input.paths
    expect(direct.biasMicros).toBe(-10_000)
    expect(relay.tier).toBe('backup')
    expect(relay.biasMicros).toBe(0)
  })

  it('an unmeasured path ranks as the configured stand-in', () => {
    const input = selectionInput([cand(1, { propagationRttMicros: 0 })], selectionParams({ unmeasured_rtt_ms: 50 }))
    expect(input.paths[0].rttMicros).toBe(50_000)
  })
})
