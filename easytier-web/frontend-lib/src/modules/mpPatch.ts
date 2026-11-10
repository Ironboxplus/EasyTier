// Decides how an edit of a running instance's config reaches it: through
// `patch_network_config` (hot, no restart) or through `run_network` (restart).
// The core's field-effect table (`generated/mp_field_effects.json`, written
// from `common/config.rs` FIELD_EFFECTS) says per field which one applies; a
// hot field is turned into the matching part of `InstanceConfigPatch`, a list
// field into ADD / REMOVE entries of the items that differ.

import { IPv4, IPv6 } from 'ip-num/IPNumber'
import type { InstanceConfigPatch, PatchAction } from './api'
import { fieldEffect, normalizeMpConfig, type MpConfig } from '../types/mpConfig'
import { toBackendNetworkConfig, type NetworkConfig } from '../types/network'

type Json = Record<string, unknown>

export interface ConfigChangePlan {
  /** What the core applies without a restart. */
  patch: InstanceConfigPatch
  /** Changed fields that only take effect when the instance starts again. */
  restartFields: string[]
  /** Every changed field of the backend config. */
  changed: string[]
}

// ---- value conversion (canonical proto3 JSON, snake_case) -------------------

function ipv4Addr(text: string): Json {
  return { addr: Number(IPv4.fromString(text.trim()).getValue()) }
}

function ipv6Addr(text: string): Json {
  const v = IPv6.fromString(text.trim()).getValue()
  const part = (shift: bigint) => Number((v >> shift) & 0xffff_ffffn)
  return { part1: part(96n), part2: part(64n), part3: part(32n), part4: part(0n) }
}

function inet4(text: string, fallbackLength = 32): Json {
  const [address, length] = text.trim().split('/')
  return { address: ipv4Addr(address), network_length: length === undefined ? fallbackLength : Number(length) }
}

function inet6(text: string): Json {
  const [address, length] = text.trim().split('/')
  return { address: ipv6Addr(address), network_length: length === undefined ? 128 : Number(length) }
}

function ipAddr(text: string): Json {
  return text.includes(':') ? { ipv6: ipv6Addr(text) } : { ipv4: ipv4Addr(text) }
}

function socketAddr(ip: string, port: number): Json {
  return { ...ipAddr(ip), port }
}

const sameJson = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b)
const asList = (value: unknown): unknown[] => (Array.isArray(value) ? value : [])

/** ADD for what `after` has and `before` lacks, REMOVE for the reverse, in list order. */
function listDiff<T>(before: T[], after: T[], key: (item: T) => string): { action: PatchAction, item: T }[] {
  const beforeKeys = new Set(before.map(key))
  const afterKeys = new Set(after.map(key))
  return [
    ...before.filter(item => !afterKeys.has(key(item))).map(item => ({ action: 'REMOVE' as const, item })),
    ...after.filter(item => !beforeKeys.has(key(item))).map(item => ({ action: 'ADD' as const, item })),
  ]
}

const textKey = (item: unknown) => String(item)
const strings = (value: unknown) => asList(value).map(String).filter(item => item.trim() !== '')

interface Change {
  key: string
  before: unknown
  after: unknown
}

type Builder = (c: Change, patch: InstanceConfigPatch, ctx: { before: Json, after: Json }) => void
// A builder throws when the value cannot be expressed as a patch (the change
// then goes through `run_network`, which validates and reports it).

const boolPatch = (field: 'ipv6_public_addr_provider' | 'ipv6_public_addr_auto' | 'disable_relay_data'): Builder =>
  (c, patch) => { patch[field] = Boolean(c.after) }

const urlPatch = (field: 'connectors' | 'mapped_listeners'): Builder => (c, patch) => {
  patch[field] = listDiff(strings(c.before), strings(c.after), textKey)
    .map(({ action, item }) => ({ action, url: { url: item } }))
}

/** acl, tcp_whitelist and udp_whitelist share one `AclPatch`. */
const aclPatch = (c: Change, patch: InstanceConfigPatch) => {
  const acl = (patch.acl ??= {})
  if (c.key === 'acl') acl.acl = c.after as Json
  else {
    const field = c.key === 'tcp_whitelist' ? 'tcp_whitelist' : 'udp_whitelist'
    acl[field] = listDiff(strings(c.before), strings(c.after), textKey).map(({ action, item }) => ({ action, value: item }))
  }
}

function effectiveRoutes(config: Json): string[] {
  return config.enable_manual_routes ? strings(config.routes) : []
}

function portForwardJson(raw: Json, action: PatchAction): Json {
  return {
    action,
    cfg: {
      bind_addr: socketAddr(String(raw.bind_ip), Number(raw.bind_port)),
      dst_addr: socketAddr(String(raw.dst_ip), Number(raw.dst_port)),
      socket_type: String(raw.proto).toLowerCase() === 'udp' ? 'UDP' : 'TCP',
    },
  }
}

const portForwardKey = (raw: unknown) => {
  const r = raw as Json
  return [r.proto, r.bind_ip, r.bind_port, r.dst_ip, r.dst_port].join('|')
}

/** How each hot field of the config becomes part of the patch. */
const HOT_BUILDERS: Record<string, Builder> = {
  hostname: (c, patch) => {
    if (!String(c.after ?? '').trim()) throw new Error('cannot clear the hostname')
    patch.hostname = String(c.after)
  },
  virtual_ipv4: (_c, patch, { after }) => ipv4Patch(patch, after),
  network_length: (_c, patch, { after }) => ipv4Patch(patch, after),
  ipv6: (c, patch) => {
    if (!String(c.after ?? '').trim()) throw new Error('cannot clear the IPv6 address')
    patch.ipv6 = inet6(String(c.after))
  },
  port_forwards: (c, patch) => {
    patch.port_forwards = listDiff(asList(c.before) as Json[], asList(c.after) as Json[], portForwardKey)
      .map(({ action, item }) => portForwardJson(item, action))
  },
  acl: aclPatch,
  tcp_whitelist: aclPatch,
  udp_whitelist: aclPatch,
  proxy_cidrs: (c, patch) => {
    const split = (item: string) => item.split('->').map(part => part.trim())
    patch.proxy_networks = listDiff(strings(c.before), strings(c.after), textKey).map(({ action, item }) => {
      const [cidr, mapped] = split(item)
      return { action, cidr: inet4(cidr), ...(mapped ? { mapped_cidr: inet4(mapped) } : {}) }
    })
  },
  enable_manual_routes: (_c, patch, ctx) => routesPatch(patch, ctx),
  routes: (_c, patch, ctx) => routesPatch(patch, ctx),
  exit_nodes: (c, patch) => {
    patch.exit_nodes = listDiff(strings(c.before), strings(c.after), textKey)
      .map(({ action, item }) => ({ action, node: ipAddr(item) }))
  },
  mapped_listeners: urlPatch('mapped_listeners'),
  peer_urls: urlPatch('connectors'),
  ipv6_public_addr_provider: boolPatch('ipv6_public_addr_provider'),
  ipv6_public_addr_auto: boolPatch('ipv6_public_addr_auto'),
  ipv6_public_addr_prefix: (c, patch) => {
    if (!String(c.after ?? '').trim()) throw new Error('cannot clear the public IPv6 prefix')
    patch.ipv6_public_addr_prefix = String(c.after)
  },
  disable_relay_data: boolPatch('disable_relay_data'),
  networking_method: () => {},
  public_server_url: () => {},
  tcp_hole_punch_mode: (c, patch) => { patch.tcp_hole_punch_mode = String(c.after) },
  egress_wire_limit_bps: (c, patch) => {
    patch.egress_wire_limit_bps = c.after === undefined || c.after === null ? '0' : String(c.after)
  },
  mp: (c, patch) => { patch.mp = normalizeMpConfig(c.after) as MpConfig },
}

function ipv4Patch(patch: InstanceConfigPatch, after: Json) {
  // With DHCP on the core ignores a static address; the field has no effect.
  if (after.dhcp) return
  const address = String(after.virtual_ipv4 ?? '').trim()
  if (!address) throw new Error('cannot clear the IPv4 address')
  patch.ipv4 = inet4(`${address}/${Number(after.network_length ?? 24)}`)
}

function routesPatch(patch: InstanceConfigPatch, { before, after }: { before: Json, after: Json }) {
  patch.routes = listDiff(effectiveRoutes(before), effectiveRoutes(after), textKey)
    .map(({ action, item }) => ({ action, cidr: inet4(item) }))
}

/**
 * What changing `before` into `after` needs: the patch for every hot field,
 * and the changed fields that have to wait for a restart. An empty patch and
 * no restart fields mean nothing changed.
 */
export function planConfigChange(before: NetworkConfig, after: NetworkConfig): ConfigChangePlan {
  const a = toBackendNetworkConfig(before) as unknown as Json
  const b = toBackendNetworkConfig(after) as unknown as Json
  const plan: ConfigChangePlan = { patch: {}, restartFields: [], changed: [] }
  for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
    if (key === 'instance_id' || key === 'advanced_settings') continue
    if (sameJson(a[key], b[key])) continue
    plan.changed.push(key)
    const effect = key === 'mp' ? 'hot' : fieldEffect(key)
    const build = HOT_BUILDERS[key]
    if (effect === undefined || effect === 'restart' || !build) {
      plan.restartFields.push(key)
      continue
    }
    try {
      build({ key, before: a[key], after: b[key] }, plan.patch, { before: a, after: b })
    }
    catch {
      plan.restartFields.push(key)
    }
  }
  // Fields that share one patch entry may add an empty list; the core ignores them.
  return plan
}

/**
 * Patch that turns `before` into `after`, or null when some changed field
 * needs a restart. An empty patch object means nothing changed.
 */
export function buildHotPatch(before: NetworkConfig, after: NetworkConfig): InstanceConfigPatch | null {
  const plan = planConfigChange(before, after)
  return plan.restartFields.length ? null : plan.patch
}

/** Patch replacing only the MpConfig (path actions, reconnect). */
export function mpPatch(mp: MpConfig): InstanceConfigPatch {
  return { mp: normalizeMpConfig(mp) }
}
