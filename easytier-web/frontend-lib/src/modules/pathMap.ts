// Model of the path map: the paths of one peer as rows between this machine and
// the peer. A row is one direct path; its upper lane is what we send on it (we
// choose the path), its lower lane what the peer sends back on it (the peer
// chooses). On each side the rows are grouped under the exit they use: the
// network card here, the address there. Relays are a separate group, folded
// by default.

import { pathKey, pathNic, type PathRates } from './mpRuntime'
import type { PathState, RunwayPath, RunwayView } from './pathRunway'

/** Below this a lane counts as idle: probes and keepalives alone stay under it. */
export const ACTIVE_BPS = 16_000

export type AddrScope = 'lan' | 'wan' | 'v6'

export interface MapRow {
  path: RunwayPath
  /** Network card here; empty when unknown. */
  nic: string
  /** Address the path leaves by, as the far end sees it when known. */
  localHost: string
  remoteHost: string
  /** What we send on it, bits/s. */
  sendBps: number
  /** What the peer sends back on it, bits/s. */
  recvBps: number
}

/** One exit drawn as a box spanning the rows `from`..`to` (inclusive). */
export interface MapPort {
  key: string
  from: number
  to: number
  label: string
  sub: string
}

export interface PathMapModel {
  rows: MapRow[]
  relays: MapRow[]
  localPorts: MapPort[]
  remotePorts: MapPort[]
}

const STATE_RANK: Record<PathState, number> = {
  sending: 0, held: 1, standby: 2, lossy: 3, silent: 4, paused: 5, excluded: 6,
}

export function hostOf(addr: string | undefined): string {
  if (!addr) return ''
  if (addr.startsWith('[')) return addr.slice(1, addr.indexOf(']'))
  return (addr.match(/:/g)?.length ?? 0) === 1 ? addr.slice(0, addr.indexOf(':')) : addr
}

/** Private, link-local and unique-local addresses are the LAN; any other IPv6 is shown as IPv6. */
export function addrScope(host: string): AddrScope {
  if (host.includes(':')) return /^(fe[89ab]|f[cd])/i.test(host) ? 'lan' : 'v6'
  const [a, b] = host.split('.').map(Number)
  if (a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254)) return 'lan'
  return 'wan'
}

const isRelay = (p: RunwayPath) => p.kind.carrierKind === 'relay-next-hop'

/** Rows of `items` regrouped so that equal keys sit together, groups in order of first appearance. */
function groupStable<T>(items: T[], key: (t: T) => string): T[] {
  const groups = new Map<string, T[]>()
  for (const item of items) {
    const k = key(item)
    const list = groups.get(k)
    if (list) list.push(item)
    else groups.set(k, [item])
  }
  return [...groups.values()].flat()
}

/** Runs of consecutive rows with the same key, one port each. */
function portsOf(rows: MapRow[], key: (r: MapRow) => string, label: (r: MapRow) => string, sub: (r: MapRow) => string): MapPort[] {
  const ports: MapPort[] = []
  rows.forEach((r, i) => {
    const last = ports[ports.length - 1]
    if (last && last.key === key(r)) last.to = i
    else ports.push({ key: key(r), from: i, to: i, label: label(r), sub: sub(r) })
  })
  return ports
}

export function pathMap(
  view: RunwayView,
  peerId: number | string,
  rates: Map<string, PathRates>,
  scopeName: (scope: AddrScope) => string,
): PathMapModel {
  const all = [...view.lanes.primary, ...view.lanes.backup, ...view.out]
    .sort((a, b) => STATE_RANK[a.state] - STATE_RANK[b.state] || a.biasedMs - b.biasedMs)
  const toRow = (p: RunwayPath): MapRow => {
    const r = rates.get(pathKey(peerId, p.status)) ?? {}
    return {
      path: p,
      nic: pathNic(p.status),
      localHost: hostOf(p.status.observed_public_addr) || hostOf(p.status.path?.local_addr),
      remoteHost: hostOf(p.status.path?.remote_addr),
      sendBps: Math.max(0, r.sendBps ?? 0),
      recvBps: Math.max(0, r.recvBps ?? 0),
    }
  }
  // Best path first; then each card's paths together, and under a card each far address together.
  const direct = groupStable(all.filter(p => !isRelay(p)).map(toRow), r => r.nic)
  const rows: MapRow[] = []
  for (const nic of new Set(direct.map(r => r.nic))) rows.push(...groupStable(direct.filter(r => r.nic === nic), r => r.remoteHost))
  return {
    rows,
    relays: all.filter(isRelay).map(toRow),
    localPorts: portsOf(rows, r => r.nic, r => r.nic || '-', r => r.localHost),
    remotePorts: portsOf(rows, r => r.remoteHost, r => scopeName(addrScope(r.remoteHost)), r => r.remoteHost),
  }
}

/** Lane width in px for a rate: log-scaled so 50 Mbit/s does not drown 1 Mbit/s. */
export function laneWidth(bps: number): number {
  const mbps = bps / 1e6
  return Math.max(3, Math.min(9, 3 + Math.log2(1 + mbps) * 1.6))
}

/** A rate as the short number on a lane, in Mbit/s. */
export function laneRate(bps: number): string {
  const mbps = bps / 1e6
  if (mbps < 0.1) return '<0.1'
  return mbps < 10 ? mbps.toFixed(1) : Math.round(mbps).toString()
}

export const fmtMs = (ms: number) => (ms < 10 ? ms.toFixed(1) : Math.round(ms).toString())
export const fmtLoss = (pct: number) => (pct >= 10 ? Math.round(pct).toString() : pct.toFixed(1))
