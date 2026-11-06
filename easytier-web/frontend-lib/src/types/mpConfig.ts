// Frontend mirror of `common.MpConfig` + runtime `stats mp` / `mp_runtime` shapes.
// These match core/proto (MP_SQM_PLAN.md §9); GUI must not invent fields the backend does not export.

import fieldEffectSnapshot from '../generated/mp_field_effects.json'
import { listCongestionControls, listSchedulers } from './mpScheduler'

export type TcpHolePunchMode = 'auto' | 'faketcp' | 'tcp'

export const MP_PROVIDERS = [
  'udp-direct',
  'udp-punch',
  'faketcp-punch',
  'relay-next-hop',
  'manual',
] as const

export type MpProvider = (typeof MP_PROVIDERS)[number]

export interface MpResourceGroupConfig {
  name: string
  egress_devices: string[]
  capacity_bps: number
  remote_endpoints: string[]
}

export const MP_POLICY_ACTIONS = ['pin', 'exclude', 'pause', 'prefer'] as const
export type MpPolicyAction = (typeof MP_POLICY_ACTIONS)[number]

/** common.proto MpPathPolicy. Empty match fields are wildcards. */
export interface MpPathPolicy {
  match_egress_device: string
  match_carrier_kind: string
  match_remote_endpoint: string
  action: MpPolicyAction
  prefer_weight: number
  enabled: boolean
  note: string
}

/** common.proto MpEgressLimit: per-NIC override of the global egress limit. */
export interface MpEgressLimit {
  egress_device: string
  limit_bps: number
}

/** common.proto MpPunchRateLimit: per-NIC override of punch_pps (0 = unlimited). */
export interface MpPunchRateLimit {
  egress_device: string
  pps: number
}

/** common.proto MpSqmConfig. */
export interface MpSqmConfig {
  enabled: boolean
  target_ms: number
  interval_ms: number
  autorate_min_bps: number
  autorate_max_bps: number
  /** Public ICMP-timestamp reflectors for Autorate (IPv4); empty = the built-in six. */
  reflectors: string[]
  /** Do not probe public reflectors: Autorate uses the MP peer's delay only. */
  reflectors_disabled: boolean
}

// ---- Data plane (MP_SQM_PLAN.md S2.9–S2.11, §9 MpDataPlaneConfig) ----

/** How one traffic class is carried inside the mpquic session. */
export const MP_DATAPLANE_MODES = ['datagram', 'reliable_stream'] as const
export type MpDataPlaneMode = (typeof MP_DATAPLANE_MODES)[number]

/** Built-in traffic classes; user rules add named classes on top. */
export const MP_DATAPLANE_CLASSES = ['et_control', 'tcp', 'udp', 'icmp', 'proxy', 'other'] as const

export const MP_OVERSIZE_POLICIES = ['icmp_ptb', 'fragment'] as const
export type MpOversizePolicy = (typeof MP_OVERSIZE_POLICIES)[number]

export const MP_RULE_PROTOCOLS = ['any', 'tcp', 'udp', 'icmp'] as const

/** common.proto MpClassPolicy. */
export interface MpClassPolicy {
  class: string
  mode: MpDataPlaneMode
}

/** common.proto MpClassRule: first enabled match wins and puts the packet in class `name`. */
export interface MpClassRule {
  name: string
  protocol: string
  port_range: string
  dst_cidr: string
  enabled: boolean
}

/** common.proto MpDataPlaneConfig. Absent/disabled = the historical single reliable stream. */
export interface MpDataPlaneConfig {
  enabled: boolean
  oversize: MpOversizePolicy
  class_policies: MpClassPolicy[]
  class_rules: MpClassRule[]
  reliable_stream_max: number
  reliable_stream_idle_ms: number
}

export function DEFAULT_MP_DATAPLANE_CONFIG(): MpDataPlaneConfig {
  return {
    enabled: false,
    oversize: 'icmp_ptb',
    class_policies: [],
    class_rules: [],
    reliable_stream_max: 64,
    reliable_stream_idle_ms: 30_000,
  }
}

/** Defaults for a freshly added class policy row. */
export function DEFAULT_MP_CLASS_POLICY(cls: string, mode: MpDataPlaneMode = 'datagram'): MpClassPolicy {
  return { class: cls, mode }
}

/** Engine-default CC; stored as the historical empty string in MpConfig. */
export const ENGINE_DEFAULT_CC = 'engine-default'

/** Full backend MpConfig surface (common.proto MpConfig). */
export interface MpConfig {
  enabled: boolean
  packet_scheduler: string
  scheduler_params_json: string
  /** How many paths carry data at once; the other established paths stand by. */
  kmax: number
  control_interval_ms: number
  establishment_timeout_ms: number
  providers: string[]
  egress_devices: string[]
  resource_groups: MpResourceGroupConfig[]
  manual_paths: string[]
  disable_overlay_weighted_routing: boolean
  /** Empty = engine default (BBR). */
  congestion_control: string
  congestion_control_params_json: string
  path_policies: MpPathPolicy[]
  egress_limits: MpEgressLimit[]
  sqm: MpSqmConfig
  /** Incrementing it rebuilds MP sessions so reconnect-only fields apply. */
  session_generation: number
  /** Native hole punches per peer, to reach several WANs of a multi-WAN router (1-8). */
  punch_attempts: number
  data_plane: MpDataPlaneConfig
  /** Hole-punch packets each NIC may send per second; 0 = unlimited. */
  punch_pps: number
  punch_rate_limits: MpPunchRateLimit[]
}

export function DEFAULT_MP_SQM_CONFIG(): MpSqmConfig {
  return {
    enabled: false,
    target_ms: 5,
    interval_ms: 100,
    autorate_min_bps: 0,
    autorate_max_bps: 0,
    reflectors: [],
    reflectors_disabled: false,
  }
}

export function DEFAULT_MP_CONFIG(): MpConfig {
  return {
    enabled: false,
    packet_scheduler: 'sqm-weighted',
    scheduler_params_json: '{}',
    kmax: 1,
    control_interval_ms: 500,
    establishment_timeout_ms: 10_000,
    providers: ['udp-direct', 'udp-punch', 'faketcp-punch', 'relay-next-hop'],
    egress_devices: [],
    resource_groups: [],
    manual_paths: [],
    disable_overlay_weighted_routing: true,
    congestion_control: '',
    congestion_control_params_json: '{}',
    path_policies: [],
    egress_limits: [],
    sqm: DEFAULT_MP_SQM_CONFIG(),
    session_generation: 0,
    punch_attempts: 1,
    data_plane: DEFAULT_MP_DATAPLANE_CONFIG(),
    punch_pps: 0,
    punch_rate_limits: [],
  }
}

function asFiniteNumber(value: unknown, fallback: number): number {
  const n = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(n) ? n : fallback
}

function asUint(value: unknown, fallback = 0): number {
  return Math.max(0, Math.floor(asFiniteNumber(value, fallback)))
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.map((v) => String(v).trim()).filter((v) => v.length > 0)
}

function parseParams(json: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(json)
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed))
      return { ...parsed as Record<string, unknown> }
  }
  catch {}
  return {}
}

function asJsonObjectString(value: unknown): string {
  const text = String(value ?? '{}')
  try {
    const parsed = JSON.parse(text)
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? text : '{}'
  }
  catch {
    return '{}'
  }
}

function asResourceGroups(value: unknown): MpResourceGroupConfig[] {
  if (!Array.isArray(value)) return []
  return value.flatMap((raw): MpResourceGroupConfig[] => {
    if (!raw || typeof raw !== 'object') return []
    const group = raw as Record<string, unknown>
    const name = String(group.name ?? '').trim()
    if (!name) return []
    return [{
      name,
      egress_devices: asStringArray(group.egress_devices),
      capacity_bps: asUint(group.capacity_bps),
      remote_endpoints: asStringArray(group.remote_endpoints),
    }]
  })
}

function asPathPolicies(value: unknown): MpPathPolicy[] {
  if (!Array.isArray(value)) return []
  const actions = new Set<string>(MP_POLICY_ACTIONS)
  return value.flatMap((raw): MpPathPolicy[] => {
    if (!raw || typeof raw !== 'object') return []
    const p = raw as Record<string, unknown>
    const action = String(p.action ?? '')
    if (!actions.has(action)) return []
    return [{
      match_egress_device: String(p.match_egress_device ?? '').trim(),
      match_carrier_kind: String(p.match_carrier_kind ?? '').trim(),
      match_remote_endpoint: String(p.match_remote_endpoint ?? '').trim(),
      action: action as MpPolicyAction,
      prefer_weight: action === 'prefer' ? Math.max(0, asFiniteNumber(p.prefer_weight, 1)) : 0,
      enabled: p.enabled === undefined ? true : Boolean(p.enabled),
      note: String(p.note ?? ''),
    }]
  })
}

function asEgressLimits(value: unknown): MpEgressLimit[] {
  if (!Array.isArray(value)) return []
  const seen = new Set<string>()
  return value.flatMap((raw): MpEgressLimit[] => {
    if (!raw || typeof raw !== 'object') return []
    const l = raw as Record<string, unknown>
    const egress_device = String(l.egress_device ?? '').trim()
    const limit_bps = asUint(l.limit_bps)
    if (!egress_device || limit_bps <= 0 || seen.has(egress_device)) return []
    seen.add(egress_device)
    return [{ egress_device, limit_bps }]
  })
}

function asPunchRateLimits(value: unknown): MpPunchRateLimit[] {
  if (!Array.isArray(value)) return []
  const seen = new Set<string>()
  return value.flatMap((raw): MpPunchRateLimit[] => {
    if (!raw || typeof raw !== 'object') return []
    const l = raw as Record<string, unknown>
    const egress_device = String(l.egress_device ?? '').trim()
    if (!egress_device || seen.has(egress_device)) return []
    seen.add(egress_device)
    return [{ egress_device, pps: asUint(l.pps) }]
  })
}

function asSqmConfig(value: unknown): MpSqmConfig {
  const base = DEFAULT_MP_SQM_CONFIG()
  if (!value || typeof value !== 'object') return base
  const s = value as Record<string, unknown>
  const autorate_min_bps = asUint(s.autorate_min_bps)
  const autorate_max_bps = asUint(s.autorate_max_bps)
  return {
    enabled: Boolean(s.enabled ?? base.enabled),
    target_ms: Math.max(1, asUint(s.target_ms, base.target_ms)),
    interval_ms: Math.max(1, asUint(s.interval_ms, base.interval_ms)),
    autorate_min_bps,
    autorate_max_bps: autorate_max_bps > 0 ? Math.max(autorate_min_bps, autorate_max_bps) : 0,
    reflectors: asStringArray(s.reflectors),
    reflectors_disabled: Boolean(s.reflectors_disabled ?? base.reflectors_disabled),
  }
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n))
}

function asClassPolicies(value: unknown): MpClassPolicy[] {
  if (!Array.isArray(value)) return []
  const modes = new Set<string>(MP_DATAPLANE_MODES)
  const seen = new Set<string>()
  return value.flatMap((raw): MpClassPolicy[] => {
    if (!raw || typeof raw !== 'object') return []
    const p = raw as Record<string, unknown>
    const cls = String(p.class ?? '').trim()
    const mode = String(p.mode ?? 'datagram')
    if (!cls || !modes.has(mode) || seen.has(cls)) return []
    seen.add(cls)
    return [DEFAULT_MP_CLASS_POLICY(cls, mode as MpDataPlaneMode)]
  })
}

const PORT_RANGE = /^(\d{1,5})(?:-(\d{1,5}))?$/

/** "" (any port), "22" or "27015-27030"; returns null when malformed. */
export function normalizePortRange(raw: string): string | null {
  const text = raw.trim()
  if (!text) return ''
  const m = PORT_RANGE.exec(text)
  if (!m) return null
  const lo = Number(m[1])
  const hi = m[2] === undefined ? lo : Number(m[2])
  if (lo < 1 || hi > 65535 || lo > hi) return null
  return lo === hi ? String(lo) : `${lo}-${hi}`
}

function asClassRules(value: unknown): MpClassRule[] {
  if (!Array.isArray(value)) return []
  const protocols = new Set<string>(MP_RULE_PROTOCOLS)
  const builtins = new Set<string>(MP_DATAPLANE_CLASSES)
  return value.flatMap((raw): MpClassRule[] => {
    if (!raw || typeof raw !== 'object') return []
    const r = raw as Record<string, unknown>
    const name = String(r.name ?? '').trim()
    const port_range = normalizePortRange(String(r.port_range ?? ''))
    if (!name || builtins.has(name) || port_range === null) return []
    const protocol = String(r.protocol ?? 'any')
    return [{
      name,
      protocol: protocols.has(protocol) ? protocol : 'any',
      port_range,
      dst_cidr: String(r.dst_cidr ?? '').trim(),
      enabled: r.enabled === undefined ? true : Boolean(r.enabled),
    }]
  })
}

function asDataPlaneConfig(value: unknown): MpDataPlaneConfig {
  const base = DEFAULT_MP_DATAPLANE_CONFIG()
  if (!value || typeof value !== 'object') return base
  const d = value as Record<string, unknown>
  const oversize = String(d.oversize ?? base.oversize)
  return {
    enabled: Boolean(d.enabled ?? base.enabled),
    oversize: (MP_OVERSIZE_POLICIES as readonly string[]).includes(oversize) ? oversize as MpOversizePolicy : base.oversize,
    class_policies: asClassPolicies(d.class_policies),
    class_rules: asClassRules(d.class_rules),
    reliable_stream_max: clamp(asUint(d.reliable_stream_max, base.reliable_stream_max), 1, 1024),
    reliable_stream_idle_ms: clamp(asUint(d.reliable_stream_idle_ms, base.reliable_stream_idle_ms), 1_000, 600_000),
  }
}

/** Normalize partial/legacy mp blobs into a complete MpConfig. */
export function normalizeMpConfig(raw: unknown): MpConfig {
  const base = DEFAULT_MP_CONFIG()
  if (!raw || typeof raw !== 'object') return base
  const input = raw as Record<string, unknown>

  const packet_scheduler = String(input.packet_scheduler ?? base.packet_scheduler)
  const knownSchedulers = new Set(listSchedulers().map((p) => p.name))
  const scheduler = knownSchedulers.has(packet_scheduler)
    ? packet_scheduler
    : base.packet_scheduler

  const providers = asStringArray(input.providers)
  const allowed = new Set<string>(MP_PROVIDERS)

  const ccRaw = String(input.congestion_control ?? '')
  const knownCc = new Set(listCongestionControls().map((p) => p.name))
  // engine-default is stored as '' so old cores keep reading the historical value.
  const congestion_control = ccRaw === ENGINE_DEFAULT_CC || !knownCc.has(ccRaw) ? '' : ccRaw

  const control_interval_ms = Math.max(1, Math.floor(asFiniteNumber(input.control_interval_ms, base.control_interval_ms)))

  return {
    enabled: Boolean(input.enabled ?? base.enabled),
    packet_scheduler: scheduler,
    scheduler_params_json: asJsonObjectString(input.scheduler_params_json ?? base.scheduler_params_json),
    kmax: Math.max(1, Math.floor(asFiniteNumber(input.kmax, base.kmax))),
    control_interval_ms,
    establishment_timeout_ms: Math.min(
      120_000,
      Math.max(1_000, Math.floor(asFiniteNumber(input.establishment_timeout_ms, base.establishment_timeout_ms))),
    ),
    providers: (providers.length ? providers : base.providers).filter((p) => allowed.has(p)),
    egress_devices: asStringArray(input.egress_devices),
    resource_groups: asResourceGroups(input.resource_groups),
    manual_paths: asStringArray(input.manual_paths),
    disable_overlay_weighted_routing: input.disable_overlay_weighted_routing === undefined
      ? base.disable_overlay_weighted_routing
      : Boolean(input.disable_overlay_weighted_routing),
    congestion_control,
    congestion_control_params_json: asJsonObjectString(input.congestion_control_params_json),
    path_policies: asPathPolicies(input.path_policies),
    egress_limits: asEgressLimits(input.egress_limits),
    sqm: asSqmConfig(input.sqm),
    session_generation: asUint(input.session_generation),
    // The core treats 0 (proto default) as 1 and caps at 8.
    punch_attempts: clamp(asUint(input.punch_attempts, base.punch_attempts) || 1, 1, 8),
    data_plane: asDataPlaneConfig(input.data_plane),
    punch_pps: asUint(input.punch_pps),
    punch_rate_limits: asPunchRateLimits(input.punch_rate_limits),
  }
}

export function normalizeTcpHolePunchMode(raw: unknown): TcpHolePunchMode {
  const value = String(raw ?? 'auto')
  if (value === 'faketcp' || value === 'tcp' || value === 'auto') return value
  return 'auto'
}

/** Map scheduler panel model ↔ MpConfig packet_scheduler + params (the latency/bandwidth slider is one of the params). */
export function mpConfigToSchedulerModel(mp: MpConfig): { scheduler: string, params: Record<string, unknown> } {
  return { scheduler: mp.packet_scheduler, params: parseParams(mp.scheduler_params_json) }
}

export function applySchedulerModelToMpConfig(
  mp: MpConfig,
  model: { scheduler: string, params: Record<string, unknown> },
): MpConfig {
  return normalizeMpConfig({
    ...mp,
    packet_scheduler: model.scheduler,
    scheduler_params_json: JSON.stringify(model.params ?? {}),
  })
}

/** A congestion control choice as edited by MpSchedulerPanel: plugin name + its params. */
export type CongestionModel = { scheduler: string, params: Record<string, unknown> }

/** Map the CC panel model ↔ MpConfig congestion_control + params JSON. */
export function mpConfigToCongestionModel(mp: MpConfig): CongestionModel {
  return {
    scheduler: mp.congestion_control || ENGINE_DEFAULT_CC,
    params: parseParams(mp.congestion_control_params_json),
  }
}

export function applyCongestionModelToMpConfig(
  mp: MpConfig,
  model: { scheduler: string, params: Record<string, unknown> },
): MpConfig {
  return normalizeMpConfig({
    ...mp,
    congestion_control: model.scheduler === ENGINE_DEFAULT_CC ? '' : model.scheduler,
    congestion_control_params_json: JSON.stringify(model.params ?? {}),
  })
}

// ---- Path policies ----

export type MpPolicyMatch = Pick<MpPathPolicy, 'match_egress_device' | 'match_carrier_kind' | 'match_remote_endpoint'>

function sameMatch(a: MpPolicyMatch, b: MpPolicyMatch): boolean {
  return a.match_egress_device === b.match_egress_device
    && a.match_carrier_kind === b.match_carrier_kind
    && a.match_remote_endpoint === b.match_remote_endpoint
}

/** Exact selector for one runtime path (egress NIC + carrier + remote endpoint). */
export function policyMatchForPath(path: MpPathStatus): MpPolicyMatch {
  return {
    match_egress_device: path.egress_device ?? '',
    match_carrier_kind: path.carrier_kind ?? '',
    match_remote_endpoint: path.path?.remote_addr ?? '',
  }
}

/** Insert or replace the policy whose match selector is identical. */
export function upsertPathPolicy(mp: MpConfig, policy: MpPathPolicy): MpConfig {
  const others = mp.path_policies.filter((p) => !sameMatch(p, policy))
  return normalizeMpConfig({ ...mp, path_policies: [...others, policy] })
}

export function removePathPolicy(mp: MpConfig, match: MpPolicyMatch): MpConfig {
  return normalizeMpConfig({ ...mp, path_policies: mp.path_policies.filter((p) => !sameMatch(p, match)) })
}

// ---- Data plane presets and class policy/rule editing ----

/** Scenario presets are shortcuts that write class_policies; they never touch other fields. */
export const MP_DATAPLANE_PRESETS = {
  'default': [] as Array<[string, MpDataPlaneMode]>,
  'rfc': [['tcp', 'datagram'], ['proxy', 'datagram']] as Array<[string, MpDataPlaneMode]>,
} as const

export type MpDataPlanePresetName = keyof typeof MP_DATAPLANE_PRESETS
export type MpDataPlanePreset = MpDataPlanePresetName | 'custom'

function presetPolicies(name: MpDataPlanePresetName): MpClassPolicy[] {
  return MP_DATAPLANE_PRESETS[name].map(([cls, mode]) => DEFAULT_MP_CLASS_POLICY(cls, mode))
}

/** Which preset the current class_policies equal exactly, else 'custom'. */
export function detectDataPlanePreset(dp: MpDataPlaneConfig): MpDataPlanePreset {
  const current = JSON.stringify([...dp.class_policies].sort((a, b) => a.class.localeCompare(b.class)))
  for (const name of Object.keys(MP_DATAPLANE_PRESETS) as MpDataPlanePresetName[]) {
    const expected = JSON.stringify(presetPolicies(name).sort((a, b) => a.class.localeCompare(b.class)))
    if (current === expected) return name
  }
  return 'custom'
}

export function applyDataPlanePreset(mp: MpConfig, name: MpDataPlanePresetName): MpConfig {
  return normalizeMpConfig({ ...mp, data_plane: { ...mp.data_plane, class_policies: presetPolicies(name) } })
}

/** Built-in classes followed by enabled-or-not user rule names, deduplicated, in rule order. */
export function dataPlaneClassNames(dp: MpDataPlaneConfig): string[] {
  const out: string[] = [...MP_DATAPLANE_CLASSES]
  for (const r of dp.class_rules) {
    if (!out.includes(r.name)) out.push(r.name)
  }
  return out
}

/** Mode of a class without a policy row, as the core applies it (`mp_dataplane::default_mode`):
 *  TCP and the quic/kcp proxy (which carries TCP) get reliable streams, everything else is a datagram.
 *  Proxy-as-datagram was tried and reverted: it measured slower than the stream (_phase3/s3_regression.md). */
export function defaultClassMode(cls: string): MpDataPlaneMode {
  return cls === 'tcp' || cls === 'proxy' ? 'reliable_stream' : 'datagram'
}

/** Effective mode of a class: its policy row, or its default. */
export function classMode(dp: MpDataPlaneConfig, cls: string): MpDataPlaneMode {
  return dp.class_policies.find((p) => p.class === cls)?.mode ?? defaultClassMode(cls)
}

export function upsertClassPolicy(mp: MpConfig, policy: MpClassPolicy): MpConfig {
  const others = mp.data_plane.class_policies.filter((p) => p.class !== policy.class)
  return normalizeMpConfig({ ...mp, data_plane: { ...mp.data_plane, class_policies: [...others, policy] } })
}

export function removeClassPolicy(mp: MpConfig, cls: string): MpConfig {
  return normalizeMpConfig({
    ...mp,
    data_plane: { ...mp.data_plane, class_policies: mp.data_plane.class_policies.filter((p) => p.class !== cls) },
  })
}

/** Replace or append the rule named `rule.name`; a rename passes the previous name. */
export function upsertClassRule(mp: MpConfig, rule: MpClassRule, previousName = rule.name): MpConfig {
  const rules = [...mp.data_plane.class_rules]
  const idx = rules.findIndex((r) => r.name === previousName)
  if (idx >= 0) rules[idx] = rule
  else rules.push(rule)
  // a renamed rule keeps its class policy
  const class_policies = previousName === rule.name
    ? mp.data_plane.class_policies
    : mp.data_plane.class_policies.map((p) => (p.class === previousName ? { ...p, class: rule.name } : p))
  return normalizeMpConfig({ ...mp, data_plane: { ...mp.data_plane, class_rules: rules, class_policies } })
}

/** Removing a rule also drops the class policy that only it could match. */
export function removeClassRule(mp: MpConfig, name: string): MpConfig {
  return normalizeMpConfig({
    ...mp,
    data_plane: {
      ...mp.data_plane,
      class_rules: mp.data_plane.class_rules.filter((r) => r.name !== name),
      class_policies: mp.data_plane.class_policies.filter((p) => p.class !== name),
    },
  })
}

/** Move rule `name` one step earlier (-1) or later (+1); rule order is match priority. */
export function moveClassRule(mp: MpConfig, name: string, delta: -1 | 1): MpConfig {
  const rules = [...mp.data_plane.class_rules]
  const i = rules.findIndex((r) => r.name === name)
  const j = i + delta
  if (i < 0 || j < 0 || j >= rules.length) return mp
  ;[rules[i], rules[j]] = [rules[j], rules[i]]
  return normalizeMpConfig({ ...mp, data_plane: { ...mp.data_plane, class_rules: rules } })
}

// ---- Field effect modes (generated from the core's S2.6 table) ----

export type MpFieldEffect = 'hot' | 'new_path' | 'reconnect' | 'restart'

const FIELD_EFFECTS = fieldEffectSnapshot as Record<string, MpFieldEffect>

/** How a config field takes effect on a running instance; undefined if unknown. */
export function fieldEffect(field: string): MpFieldEffect | undefined {
  return FIELD_EFFECTS[field]
}

/** MpConfig fields that differ between two configs, as `mp.<key>` / `mp.sqm.<key>` / `mp.data_plane.<key>` paths. */
export function changedMpFields(before: MpConfig, after: MpConfig): string[] {
  const out: string[] = []
  for (const key of Object.keys(after) as (keyof MpConfig)[]) {
    if (key === 'sqm' || key === 'data_plane') {
      const b = (before[key] ?? {}) as unknown as Record<string, unknown>
      const a = after[key] as unknown as Record<string, unknown>
      for (const k of Object.keys(a)) {
        if (JSON.stringify(b[k]) !== JSON.stringify(a[k])) out.push(`mp.${key}.${k}`)
      }
      continue
    }
    if (JSON.stringify(before[key]) !== JSON.stringify(after[key])) out.push(`mp.${key}`)
  }
  return out
}

// ---- Runtime shapes (api_instance MpPeerStatus/MpEgressResourceStatus, api_manage MpRuntimeInfo) ----

export interface MpPathIdentity {
  carrier_id: number | string
  local_addr: string
  remote_addr: string
}

export interface MpPathStatus {
  path?: MpPathIdentity
  carrier_kind?: string
  lifecycle_state?: string
  local_resource?: string
  local_resource_kind?: string
  remote_resource?: string
  remote_resource_kind?: string
  btlbw_bps?: number | string
  delivery_rate_bps?: number | string
  srtt_micros?: number | string
  loss_rate?: number
  app_limited?: boolean
  sample_age_micros?: number | string
  congestion_control_state?: string
  target_rate_bps?: number | string
  validation_state?: string
  bandwidth_model_valid?: boolean
  min_rtt_micros?: number | string
  sent_bytes?: number | string
  recv_bytes?: number | string
  lost_bytes?: number | string
  first_hop_peer_id?: number | string
  egress_first_hop_peer_id?: number | string
  route_generation?: number | string
  cwnd_bytes?: number | string
  pacing_rate_bps?: number | string
  bytes_in_flight?: number | string
  brutal_ack_rate?: number | null
  /** Action of the matched user policy (pin|exclude|pause|prefer) or empty. */
  user_policy?: string
  egress_device?: string
  /** Our public endpoint as the peer sees it on this path (the path's WAN). */
  observed_public_addr?: string
  /** Smallest round trip time of the last 300 s, the delay the selection ranks by. */
  windowed_min_rtt_micros?: number | string
  recent_loss?: number | null
  /** EasyTier ping loss of a relay path's physical first hop. */
  first_hop_loss?: number | null
  backed_off?: boolean
  /** not-established | policy | lossy-path | lossy-first-hop | unacked, or empty. */
  not_selected_reason?: string
}

export interface MpFakeTcpUpgradeStatus {
  failures?: number | string
  consecutive_failures?: number
  last_error?: string
  plain_tcp_fallback?: boolean
}

export interface MpPeerStatus {
  peer_id: number | string
  candidate_count?: number
  eligible_count?: number
  paths?: MpPathStatus[]
  active_paths?: MpPathIdentity[]
  effective_engine?: string
  effective_congestion_control?: string
  path_mode?: string
  scheduler_state?: string
  unsupported_reason?: string | null
  desired_congestion_control?: string
  reconnect_required?: boolean
  standalone?: boolean
  effective_recovery?: string
  brutal_tx_bps?: number | string | null
  peer_advertised_rx_bps?: number | string | null
  data_plane?: MpDataPlaneStatus
  faketcp_upgrade?: MpFakeTcpUpgradeStatus
}

/** api_instance MpClassStatus: counters are monotonic; the GUI differences them. */
export interface MpClassStatus {
  class: string
  mode?: string
  tx_packets?: number | string
  tx_bytes?: number | string
  rx_packets?: number | string
  rx_bytes?: number | string
  open_streams?: number
  streams_recycled?: number | string
}

/** api_instance MpDataPlaneStatus, one per peer. */
export interface MpDataPlaneStatus {
  /** datagram | stream_fallback | disabled */
  negotiated?: string
  fallback_reason?: string
  max_datagram_bytes?: number
  recommended_mtu?: number
  classes?: MpClassStatus[]
  oversize_dropped?: number | string
  oversize_ptb?: number | string
  frag_sent?: number | string
  frag_reassembled?: number | string
  frag_timeout?: number | string
  dgram_queue_dropped?: number | string
  circuit_breaker_trips?: number
  /** Inner frames the reliable-stream queues dropped on purpose (queueing time) / for being over their limit. */
  stream_aqm_drops?: number | string
  stream_overlimit_drops?: number | string
}

export interface MpEgressResourceStatus {
  resource: string
  resource_kind?: string
  capacity_bps?: number | string
  achieved_bps?: number | string
  queue_delay_micros?: number | string
  path_count?: number
  egress_device?: string
  ceiling_bps?: number | string | null
  /** none | static | per_device | autorate */
  ceiling_source?: string
  autorate_estimate_bps?: number | string | null
  /** False (omitted) while the estimate is still its start value. */
  autorate_measured?: boolean
  /** nic-counter | path-sent-bytes: where achieved_bps was read from. */
  achieved_source?: string
  /** The CAKE queue of this egress; absent until a packet used it. */
  cake?: MpCakeStatus | null
  fallback_scope?: boolean
}

/** api_instance MpCakeStatus: the one send queue of an egress, with the names of `tc -s qdisc show`. */
export interface MpCakeStatus {
  bandwidth_bps?: number | string
  target_us?: number
  interval_us?: number
  qlen_packets?: number
  backlog_bytes?: number | string
  memory_used?: number
  memory_peak?: number
  memory_limit?: number
  sent_packets?: number | string
  sent_bytes?: number | string
  dropped_packets?: number | string
  overlimit_drops?: number | string
  peak_delay_us?: number
  avg_delay_us?: number
  base_delay_us?: number
  sparse_flows?: number
  bulk_flows?: number
  unresponsive_flows?: number
  way_collisions?: number
  stream_aqm_drops?: number | string
  stream_overlimit_drops?: number | string
}

/** api_manage MpRuntimeInfo carried in NetworkInstanceRunningInfo.mp_runtime. */
export interface MpRuntimeInfo {
  peers?: MpPeerStatus[]
  egress?: MpEgressResourceStatus[]
  /** Monotonic core clock; counters are differenced against it. */
  sample_time_ms?: number | string
}

export interface MpStatsSnapshot {
  mp_peers: MpPeerStatus[]
  mp_egress_resources: MpEgressResourceStatus[]
}

/** Every GUI control key that must map to a real backend MpConfig / flags field. */
export const MP_GUI_BACKEND_FIELDS = [
  'mp.enabled',
  'mp.packet_scheduler',
  'mp.scheduler_params_json',
  'mp.kmax',
  'mp.control_interval_ms',
  'mp.establishment_timeout_ms',
  'mp.providers',
  'mp.egress_devices',
  'mp.resource_groups',
  'mp.manual_paths',
  'mp.disable_overlay_weighted_routing',
  'mp.congestion_control',
  'mp.congestion_control_params_json',
  'mp.path_policies',
  'mp.egress_limits',
  'mp.sqm',
  'mp.session_generation',
  'mp.punch_attempts',
  'mp.data_plane',
  'mp.punch_pps',
  'mp.punch_rate_limits',
  'tcp_hole_punch_mode',
  'egress_wire_limit_bps',
  'enable_quic_proxy',
  'enable_kcp_proxy',
  'disable_quic_input',
  'disable_kcp_input',
  'mtu',
] as const

export const MP_RUNTIME_BACKEND_FIELDS = [
  'mp_peers',
  'mp_egress_resources',
  'mp_runtime.peers',
  'mp_runtime.egress',
  'mp_runtime.sample_time_ms',
  'paths.carrier_kind',
  'paths.lifecycle_state',
  'paths.btlbw_bps',
  'paths.delivery_rate_bps',
  'paths.srtt_micros',
  'paths.sent_bytes',
  'paths.recv_bytes',
  'paths.target_rate_bps',
  'paths.cwnd_bytes',
  'paths.pacing_rate_bps',
  'paths.bytes_in_flight',
  'paths.user_policy',
  'paths.egress_device',
  'egress.ceiling_bps',
  'egress.autorate_estimate_bps',
  'egress.cake',
  'peers.active_paths',
  'peers.data_plane',
  'data_plane.classes',
  'data_plane.recommended_mtu',
] as const
