// Decides whether a config edit on a running instance can be hot-applied
// through `patch_network_config` instead of `run_network` (which restarts the
// instance). Only the fields the core's InstanceConfigPatch carries qualify.

import type { InstanceConfigPatch } from './api'
import { normalizeMpConfig, type MpConfig } from '../types/mpConfig'
import { toBackendNetworkConfig, type NetworkConfig } from '../types/network'

const HOT_PATCH_FIELDS = new Set(['mp', 'tcp_hole_punch_mode', 'egress_wire_limit_bps'])

/**
 * Patch that turns `before` into `after`, or null when some changed field
 * needs a restart. An empty patch object means nothing changed.
 */
export function buildHotPatch(before: NetworkConfig, after: NetworkConfig): InstanceConfigPatch | null {
  const a = toBackendNetworkConfig(before) as unknown as Record<string, unknown>
  const b = toBackendNetworkConfig(after) as unknown as Record<string, unknown>
  const patch: InstanceConfigPatch = {}
  for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
    if (key === 'instance_id') continue
    if (JSON.stringify(a[key]) === JSON.stringify(b[key])) continue
    if (!HOT_PATCH_FIELDS.has(key)) return null
    if (key === 'mp') patch.mp = b.mp as MpConfig
    else if (key === 'tcp_hole_punch_mode') patch.tcp_hole_punch_mode = String(b.tcp_hole_punch_mode)
    else patch.egress_wire_limit_bps = b.egress_wire_limit_bps === undefined ? '0' : String(b.egress_wire_limit_bps)
  }
  return patch
}

/** Patch replacing only the MpConfig (path actions, reconnect). */
export function mpPatch(mp: MpConfig): InstanceConfigPatch {
  return { mp: normalizeMpConfig(mp) }
}
