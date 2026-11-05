// Pluggable MP plugin registry (packet schedulers and congestion controllers).
//
// The only source is `generated/mp_plugins.json`, exported from the Rust
// registry in `easytier/src/tunnel/mp_plugin.rs` by the `mp_plugin_schema_snapshot`
// test (the test fails whenever the snapshot drifts). Its shape is the
// `api.config.MpSchedulerPluginSchema` message, so the same parser also accepts
// the live `ConfigRpc.GetConfig` response. The GUI renders every plugin's
// parameter panel from `tunables`; adding a plugin needs no GUI change.

import pluginSnapshot from '../generated/mp_plugins.json'

export type TunableKind =
  | { type: 'slider', min: number, max: number, step: number }
  | { type: 'toggle' }
  | { type: 'number', min?: number, max?: number }
  | { type: 'enum', options: string[] }

export interface Tunable {
  key: string
  label: string
  kind: TunableKind
  /** `null` means the value is required (no default). */
  default: unknown
  help: string
}

export type MpPluginKind = 'scheduler' | 'congestion_control'

export type MpAlgorithm = 'min-rtt' | 'round-robin' | 'redundant' | 'sqm-weighted'

export interface MpSchedulerPlugin {
  name: string
  kind: MpPluginKind
  description: string
  tunables: Tunable[]
}

export interface ResolvedMpConfig {
  algorithm: MpAlgorithm
  /** slider λ ∈ [0,1] (0 = lowest latency, 1 = max bandwidth) */
  lambda: number
}

export const LATENCY_BANDWIDTH_KEY = 'latency_bandwidth'

/** `MpTunableSchema` as serialized by the core (proto field names). */
interface TunableSchemaJson {
  key: string
  label: string
  kind: string
  min?: number | null
  max?: number | null
  step?: number | null
  options?: string[]
  default_json?: string
  help?: string
}

interface PluginSchemaJson {
  name: string
  kind?: string
  description?: string
  tunables?: TunableSchemaJson[]
}

function parseDefault(raw: string | undefined): unknown {
  if (raw === undefined || raw === '') return null
  try {
    return JSON.parse(raw)
  }
  catch {
    return null
  }
}

function toTunable(t: TunableSchemaJson): Tunable {
  const opt = (v: number | null | undefined) => (v == null ? undefined : v)
  let kind: TunableKind
  switch (t.kind) {
    case 'slider':
      kind = { type: 'slider', min: t.min ?? 0, max: t.max ?? 1, step: t.step ?? 0.01 }
      break
    case 'toggle':
      kind = { type: 'toggle' }
      break
    case 'enum':
      kind = { type: 'enum', options: t.options ?? [] }
      break
    default: {
      const number: { type: 'number', min?: number, max?: number } = { type: 'number' }
      if (opt(t.min) !== undefined) number.min = t.min!
      if (opt(t.max) !== undefined) number.max = t.max!
      kind = number
    }
  }
  return { key: t.key, label: t.label, kind, default: parseDefault(t.default_json), help: t.help ?? '' }
}

/** Parse `MpSchedulerPluginSchema[]` (snapshot or live GetConfig) into plugins. */
export function parsePluginSchemas(raw: unknown): MpSchedulerPlugin[] {
  if (!Array.isArray(raw)) return []
  return (raw as PluginSchemaJson[]).filter(p => p && typeof p.name === 'string').map(p => ({
    name: p.name,
    // Schemas from cores that predate `kind` only carried schedulers.
    kind: p.kind === 'congestion_control' ? 'congestion_control' : 'scheduler',
    description: p.description ?? '',
    tunables: (p.tunables ?? []).map(toTunable),
  }))
}

const REGISTRY: MpSchedulerPlugin[] = parsePluginSchemas(pluginSnapshot)

export function listPlugins(kind: MpPluginKind): MpSchedulerPlugin[] {
  return REGISTRY.filter(p => p.kind === kind)
}

export function getPlugin(kind: MpPluginKind, name: string): MpSchedulerPlugin | undefined {
  return REGISTRY.find(p => p.kind === kind && p.name === name)
}

/** All registered scheduler plugins (for a dropdown). */
export function listSchedulers(): MpSchedulerPlugin[] {
  return listPlugins('scheduler')
}

export function getScheduler(name: string): MpSchedulerPlugin | undefined {
  return getPlugin('scheduler', name)
}

export function listCongestionControls(): MpSchedulerPlugin[] {
  return listPlugins('congestion_control')
}

function clamp(v: number, min: number, max: number): number {
  return Math.min(Math.max(v, min), max)
}

/** Default params object for a plugin (each tunable with a default at that default). */
export function defaultParams(name: string, kind: MpPluginKind = 'scheduler'): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  getPlugin(kind, name)?.tunables.forEach((t) => {
    if (t.default !== null) out[t.key] = t.default
  })
  return out
}

/** Keys of required tunables (no default) that are missing or not usable. */
export function missingRequiredParams(
  kind: MpPluginKind,
  name: string,
  params: Record<string, unknown>,
): string[] {
  const plugin = getPlugin(kind, name)
  if (!plugin) return []
  return plugin.tunables
    .filter(t => t.default === null)
    .filter((t) => {
      const v = params?.[t.key]
      if (t.kind.type === 'number' || t.kind.type === 'slider')
        return typeof v !== 'number' || !Number.isFinite(v) || v <= 0
      return v === undefined || v === null || v === ''
    })
    .map(t => t.key)
}

/**
 * Validate/normalize params and resolve to a concrete scheduler config. Total:
 * out-of-range/missing/bad params fall back to defaults (mirrors the Rust
 * `resolve`), so the caller always gets a usable config.
 */
export function resolveScheduler(name: string, params: Record<string, unknown>): ResolvedMpConfig | undefined {
  const plugin = getScheduler(name)
  if (!plugin)
    return undefined
  let lambda = 0.5
  if (name === 'sqm-weighted') {
    const raw = params?.[LATENCY_BANDWIDTH_KEY]
    lambda = clamp(typeof raw === 'number' && Number.isFinite(raw) ? raw : 0.5, 0, 1)
  }
  return { algorithm: name as MpAlgorithm, lambda }
}
