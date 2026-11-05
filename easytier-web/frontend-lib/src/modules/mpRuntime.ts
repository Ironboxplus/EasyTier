// Turns successive `NetworkInstanceRunningInfo.mp_runtime` samples into rates
// and rolling histories for the MP status view. Counters from the core are
// monotonic; rates are differenced against the core's own `sample_time_ms`
// (never the browser clock), so polling jitter does not distort them.

import type {
  MpEgressResourceStatus,
  MpPathStatus,
  MpPeerStatus,
  MpRuntimeInfo,
} from '../types/mpConfig'

/** 5 minutes at the 1 s polling interval. */
export const MP_HISTORY_POINTS = 300

export function toNum(v: unknown): number | undefined {
  if (v === undefined || v === null || v === '') return undefined
  const n = typeof v === 'number' ? v : Number(v)
  return Number.isFinite(n) ? n : undefined
}

export function formatBps(bps: number | undefined): string {
  if (bps === undefined) return '-'
  const units = ['bps', 'kbps', 'Mbps', 'Gbps', 'Tbps']
  let v = bps
  let u = 0
  while (Math.abs(v) >= 1000 && u < units.length - 1) {
    v /= 1000
    u++
  }
  return `${v.toFixed(u === 0 ? 0 : v < 10 ? 2 : 1)} ${units[u]}`
}

export function formatBytes(bytes: number | undefined): string {
  if (bytes === undefined) return '-'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let v = bytes
  let u = 0
  while (Math.abs(v) >= 1024 && u < units.length - 1) {
    v /= 1024
    u++
  }
  return `${v.toFixed(u === 0 ? 0 : 1)} ${units[u]}`
}

export function formatUs(us: number | undefined): string {
  if (us === undefined) return '-'
  return us >= 1000 ? `${(us / 1000).toFixed(us >= 100_000 ? 0 : 1)} ms` : `${Math.round(us)} µs`
}

export function pathKey(peerId: number | string, path: MpPathStatus): string {
  const id = path.path
  return `${peerId}|${id?.carrier_id ?? ''}|${id?.local_addr ?? ''}|${id?.remote_addr ?? ''}`
}

/** Per-second rate of a monotonic counter; undefined on first sample or reset. */
export function counterRate(prev: number | undefined, cur: number | undefined, dtMs: number): number | undefined {
  if (prev === undefined || cur === undefined || dtMs <= 0 || cur < prev) return undefined
  return ((cur - prev) * 1000) / dtMs
}

export interface EgressPoint {
  /** Wire send rate (bits/s) from the CAKE queue's sent bytes, else achieved_bps. */
  sendBps?: number
  estimateBps?: number
  ceilingBps?: number
  queueDelayMs?: number
  /** Bytes waiting in the CAKE queue. */
  backlogBytes?: number
  /** Average time a packet waited in the CAKE queue. */
  cakeDelayMs?: number
  /** Packets the CAKE queue dropped per second (AQM and over-memory). */
  dropsPerSec?: number
}

export interface PathRates {
  sendBps?: number
  recvBps?: number
  lossBps?: number
}

/** Per-class data-plane rates differenced from MpClassStatus counters. */
export interface ClassRates {
  txBps?: number
  rxBps?: number
}

/** Stable key of one data-plane class of one peer session (MP-managed and standalone differ). */
export function classKey(peer: MpPeerStatus, cls: string): string {
  return `${peer.peer_id}|${peer.standalone ? 's' : 'm'}|${cls}`
}

export interface EgressView {
  status: MpEgressResourceStatus
  current: EgressPoint
  history: EgressPoint[]
}

/** One physical NIC: its one send queue and the resources sampled on it, as one card. */
export interface NicView {
  key: string
  device: string
  scopes: EgressView[]
  current: EgressPoint
  history: EgressPoint[]
}

function sumDefined(values: Array<number | undefined>): number | undefined {
  const defined = values.filter((v): v is number => v !== undefined)
  return defined.length ? defined.reduce((a, b) => a + b, 0) : undefined
}

function minDefined(values: Array<number | undefined>): number | undefined {
  const defined = values.filter((v): v is number => v !== undefined)
  return defined.length ? Math.min(...defined) : undefined
}

function maxDefined(values: Array<number | undefined>): number | undefined {
  const defined = values.filter((v): v is number => v !== undefined)
  return defined.length ? Math.max(...defined) : undefined
}

function mergePoints(points: EgressPoint[]): EgressPoint {
  return {
    // The scopes of one NIC split its paths, so their send rates add up; they
    // share one physical link, so their capacity estimates do not.
    sendBps: sumDefined(points.map(p => p.sendBps)),
    estimateBps: maxDefined(points.map(p => p.estimateBps)),
    ceilingBps: minDefined(points.map(p => p.ceilingBps)),
    queueDelayMs: maxDefined(points.map(p => p.queueDelayMs)),
    backlogBytes: sumDefined(points.map(p => p.backlogBytes)),
    cakeDelayMs: maxDefined(points.map(p => p.cakeDelayMs)),
    dropsPerSec: sumDefined(points.map(p => p.dropsPerSec)),
  }
}

/** Groups send scopes by NIC; scopes without an identified NIC stay on their own. */
export function groupEgressByNic(egress: EgressView[]): NicView[] {
  const groups = new Map<string, EgressView[]>()
  for (const e of egress) {
    const key = e.status.egress_device || e.status.resource
    const list = groups.get(key) ?? []
    list.push(e)
    groups.set(key, list)
  }
  return [...groups.entries()].map(([key, scopes]) => {
    // histories are newest-last and may differ in length; align them at the end
    const len = Math.max(...scopes.map(s => s.history.length))
    const history = Array.from({ length: len }, (_, i) => mergePoints(
      scopes.map(s => s.history[s.history.length - len + i]).filter((p): p is EgressPoint => p !== undefined),
    ))
    return {
      key,
      device: key,
      scopes,
      current: mergePoints(scopes.map(s => s.current)),
      history,
    }
  })
}

/** One network card in the NIC → path chart: what it sends now and the bandwidth Autorate gives it. */
export interface NicFlow {
  /** Device name; empty when the path's card is not known. */
  id: string
  sendBps: number
  /** Autorate budget of the card (within the user's bounds); undefined until it has one. */
  budgetBps?: number
}

/** One path in the NIC → path chart, with its actual send rate. */
export interface PathFlow {
  id: string
  nic: string
  sendBps: number
  path: MpPathStatus
}

/** The card a path leaves by; a relay path's resource id is no card name. */
export function pathNic(path: MpPathStatus): string {
  if (path.egress_device) return path.egress_device
  const resource = path.local_resource ?? ''
  return resource.startsWith('relay-next-hop:') ? '' : resource
}

/**
 * Actual send rate of each live path of a peer, grouped under the network card
 * it leaves by, each card with its Autorate budget (the largest of its send
 * scopes, as the core shares that budget among the paths on the card).
 */
export function nicPathFlows(view: MpRuntimeView, peer: MpPeerStatus): { nics: NicFlow[], paths: PathFlow[] } {
  const nicViews = groupEgressByNic(view.egress)
  const nics = new Map<string, NicFlow>()
  const paths: PathFlow[] = []
  for (const path of peer.paths ?? []) {
    if ((path.lifecycle_state ?? '') === 'dead') continue
    const nic = pathNic(path)
    const id = pathKey(peer.peer_id, path)
    const sendBps = view.pathRates.get(id)?.sendBps ?? 0
    paths.push({ id, nic, sendBps, path })
    let entry = nics.get(nic)
    if (!entry) {
      const budgets = (nicViews.find(n => n.device === nic)?.scopes ?? [])
        .map(s => toNum(s.status.capacity_bps))
        .filter((v): v is number => v !== undefined && v > 0)
      entry = { id: nic, sendBps: 0, budgetBps: budgets.length ? Math.max(...budgets) : undefined }
      nics.set(nic, entry)
    }
    entry.sendBps += sendBps
  }
  return { nics: [...nics.values()], paths }
}

export interface MpRuntimeView {
  sampleTimeMs?: number
  labels: string[]
  peers: MpPeerStatus[]
  egress: EgressView[]
  pathRates: Map<string, PathRates>
  classRates: Map<string, ClassRates>
  totalSendBps?: number
  totalRecvBps?: number
}

interface CounterSnapshot {
  timeMs: number
  values: Map<string, number>
}

/** The history kept under `key`, created empty on first use. */
function historyOf<T>(histories: Map<string, T[]>, key: string): T[] {
  let history = histories.get(key)
  if (!history) {
    history = []
    histories.set(key, history)
  }
  return history
}

function pushBounded<T>(arr: T[], item: T, max: number) {
  arr.push(item)
  if (arr.length > max) arr.splice(0, arr.length - max)
}

/**
 * Rolling state across polls. Feed each `mp_runtime` into `ingest`; the view it
 * returns is self-contained for rendering. Entities that disappear are dropped.
 */
export class MpRuntimeHistory {
  private prev?: CounterSnapshot
  private labels: string[] = []
  private egressHistory = new Map<string, EgressPoint[]>()

  constructor(private readonly maxPoints = MP_HISTORY_POINTS) {}

  reset() {
    this.prev = undefined
    this.labels = []
    this.egressHistory.clear()
  }

  ingest(info: MpRuntimeInfo | null | undefined, wallClock: Date = new Date()): MpRuntimeView {
    const peers = info?.peers ?? []
    const egress = info?.egress ?? []
    const timeMs = toNum(info?.sample_time_ms)

    const counters = new Map<string, number>()
    const setCounter = (key: string, v: unknown) => {
      const n = toNum(v)
      if (n !== undefined) counters.set(key, n)
    }

    let dtMs = 0
    let prevValues = new Map<string, number>()
    if (timeMs !== undefined && this.prev && timeMs > this.prev.timeMs) {
      dtMs = timeMs - this.prev.timeMs
      prevValues = this.prev.values
    }
    // A repeated or older sample (same poll answered twice, core restart) must
    // not append a point or produce a rate.
    const fresh = timeMs !== undefined && (!this.prev || timeMs > this.prev.timeMs)
    const rate = (key: string) => counterRate(prevValues.get(key), counters.get(key), dtMs)
    /** Rate of a byte counter in bits/s. */
    const bitRate = (key: string) => {
      const bytesPerSec = rate(key)
      return bytesPerSec === undefined ? undefined : bytesPerSec * 8
    }

    const pathRates = new Map<string, PathRates>()
    let totalSend: number | undefined
    let totalRecv: number | undefined
    for (const peer of peers) {
      for (const path of peer.paths ?? []) {
        const key = pathKey(peer.peer_id, path)
        setCounter(`p:${key}:s`, path.sent_bytes)
        setCounter(`p:${key}:r`, path.recv_bytes)
        setCounter(`p:${key}:l`, path.lost_bytes)
        const rates: PathRates = {
          sendBps: bitRate(`p:${key}:s`),
          recvBps: bitRate(`p:${key}:r`),
          lossBps: bitRate(`p:${key}:l`),
        }
        pathRates.set(key, rates)
        if (rates.sendBps !== undefined) totalSend = (totalSend ?? 0) + rates.sendBps
        if (rates.recvBps !== undefined) totalRecv = (totalRecv ?? 0) + rates.recvBps
      }
    }

    const classRates = new Map<string, ClassRates>()
    for (const peer of peers) {
      for (const cls of peer.data_plane?.classes ?? []) {
        const key = classKey(peer, cls.class)
        setCounter(`c:${key}:tx`, cls.tx_bytes)
        setCounter(`c:${key}:rx`, cls.rx_bytes)
        classRates.set(key, {
          txBps: bitRate(`c:${key}:tx`),
          rxBps: bitRate(`c:${key}:rx`),
        })
      }
    }

    const liveEgress = new Set<string>()
    const egressViews: EgressView[] = egress.map((e) => {
      const key = e.resource
      liveEgress.add(key)
      setCounter(`e:${key}:a`, e.cake?.sent_bytes)
      const cakeDrops = (toNum(e.cake?.dropped_packets) ?? 0) + (toNum(e.cake?.overlimit_drops) ?? 0)
      if (e.cake) counters.set(`e:${key}:d`, cakeDrops)
      const avgDelayUs = toNum(e.cake?.avg_delay_us)
      const current: EgressPoint = {
        sendBps: bitRate(`e:${key}:a`) ?? toNum(e.achieved_bps),
        // Until a measurement moves it, the estimate is only its start value.
        estimateBps: e.autorate_measured ? toNum(e.autorate_estimate_bps) : undefined,
        ceilingBps: toNum(e.ceiling_bps),
        queueDelayMs: (() => {
          const us = toNum(e.queue_delay_micros)
          return us === undefined ? undefined : us / 1000
        })(),
        backlogBytes: toNum(e.cake?.backlog_bytes),
        cakeDelayMs: avgDelayUs === undefined ? undefined : avgDelayUs / 1000,
        dropsPerSec: rate(`e:${key}:d`),
      }
      const history = historyOf(this.egressHistory, key)
      if (fresh) pushBounded(history, current, this.maxPoints)
      return { status: e, current, history }
    })
    for (const key of [...this.egressHistory.keys()]) {
      if (!liveEgress.has(key)) this.egressHistory.delete(key)
    }

    if (fresh) {
      pushBounded(this.labels, wallClock.toLocaleTimeString(undefined, { hour12: false }), this.maxPoints)
      this.prev = { timeMs: timeMs!, values: counters }
    }

    return {
      sampleTimeMs: timeMs,
      labels: [...this.labels],
      peers,
      egress: egressViews,
      pathRates,
      classRates,
      totalSendBps: totalSend,
      totalRecvBps: totalRecv,
    }
  }
}
