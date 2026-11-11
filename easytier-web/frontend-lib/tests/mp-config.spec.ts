import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import MpConfigPanel from '../src/components/MpConfigPanel.vue'
import { buildHotPatch } from '../src/modules/mpPatch'
import {
  applyCongestionModelToMpConfig,
  applySchedulerModelToMpConfig,
  changedMpFields,
  DEFAULT_MP_CONFIG,
  fieldEffect,
  MP_GUI_BACKEND_FIELDS,
  MP_RUNTIME_BACKEND_FIELDS,
  mpConfigToCongestionModel,
  mpConfigToSchedulerModel,
  normalizeMpConfig,
  normalizeTcpHolePunchMode,
  policyMatchForPath,
  removePathPolicy,
  upsertPathPolicy,
  type MpConfig,
} from '../src/types/mpConfig'
import {
  DEFAULT_NETWORK_CONFIG,
  normalizeNetworkConfig,
  toBackendNetworkConfig,
} from '../src/types/network'
import fieldEffects from '../src/generated/mp_field_effects.json'
import { mpGlobal } from './primevueStubs'

const NETWORK_LEVEL_FIELDS = new Set([
  'tcp_hole_punch_mode',
  'egress_wire_limit_bps',
  'enable_quic_proxy',
  'enable_kcp_proxy',
  'disable_quic_input',
  'disable_kcp_input',
  'mtu',
])

describe('MpConfig normalization and backend contract', () => {
  it('defaults match core gen_default_mp_config surface', () => {
    const d = DEFAULT_MP_CONFIG()
    expect(d.enabled).toBe(false)
    expect(d.packet_scheduler).toBe('sqm-weighted')
    expect(d.kmax).toBe(1)
    // The optimizer and its five tunables are gone from the config (phase 4).
    for (const retired of ['optimizer', 'lambda', 'churn_penalty', 'path_penalty', 'switch_margin', 'confirm_rounds', 'max_sample_age_ms']) {
      expect(d, retired).not.toHaveProperty(retired)
    }
    expect(d.providers).toEqual([
      'udp-direct',
      'udp-punch',
      'faketcp-punch',
      'relay-next-hop',
    ])
    expect(d.disable_overlay_weighted_routing).toBe(true)
    // New fields default to "off / old behaviour" (no breaking change).
    expect(d.congestion_control).toBe('')
    expect(d.congestion_control_params_json).toBe('{}')
    expect(d.path_policies).toEqual([])
    expect(d.egress_limits).toEqual([])
    expect(d.sqm).toEqual({
      enabled: false,
      target_ms: 5,
      interval_ms: 100,
      autorate_min_bps: 0,
      autorate_max_bps: 0,
      reflectors: [],
      reflectors_disabled: false,
    })
    expect(d.session_generation).toBe(0)
    expect(d.punch_attempts).toBe(1)
  })

  it('normalizes punch_attempts like the core (0 means 1, capped at 8)', () => {
    expect(normalizeMpConfig({}).punch_attempts).toBe(1)
    expect(normalizeMpConfig({ punch_attempts: 0 }).punch_attempts).toBe(1)
    expect(normalizeMpConfig({ punch_attempts: 3 }).punch_attempts).toBe(3)
    expect(normalizeMpConfig({ punch_attempts: 20 }).punch_attempts).toBe(8)
  })

  it('clamps invalid values and drops unknown providers', () => {
    const n = normalizeMpConfig({
      enabled: true,
      kmax: 0,
      establishment_timeout_ms: 50,
      providers: ['udp-direct', 'bogus', 'manual'],
    })
    expect(n.kmax).toBeGreaterThanOrEqual(1)
    expect(n.establishment_timeout_ms).toBeGreaterThanOrEqual(1000)
    expect(n.providers).toEqual(['udp-direct', 'manual'])
  })

  it('drops the retired optimizer fields of an old config on read', () => {
    const n = normalizeMpConfig({
      enabled: true,
      kmax: 3,
      optimizer: 'min-latency',
      lambda: 0.8,
      churn_penalty: 0.05,
      path_penalty: 0.01,
      switch_margin: 0.1,
      confirm_rounds: 3,
      max_sample_age_ms: 5000,
    })
    expect(n.kmax).toBe(3)
    for (const retired of ['optimizer', 'lambda', 'churn_penalty', 'path_penalty', 'switch_margin', 'confirm_rounds', 'max_sample_age_ms']) {
      expect(n, retired).not.toHaveProperty(retired)
    }
  })

  it('legacy blobs without the new fields normalize to defaults', () => {
    const n = normalizeMpConfig({ enabled: true, kmax: 3 })
    expect(n.path_policies).toEqual([])
    expect(n.egress_limits).toEqual([])
    expect(n.sqm.enabled).toBe(false)
    expect(n.congestion_control).toBe('')
  })

  it('normalizes congestion control names', () => {
    expect(normalizeMpConfig({ congestion_control: 'brutal' }).congestion_control).toBe('brutal')
    expect(normalizeMpConfig({ congestion_control: 'cubic' }).congestion_control).toBe('cubic')
    // engine-default is stored as the historical empty string
    expect(normalizeMpConfig({ congestion_control: 'engine-default' }).congestion_control).toBe('')
    expect(normalizeMpConfig({ congestion_control: 'nope' }).congestion_control).toBe('')
    expect(normalizeMpConfig({ congestion_control_params_json: '[1]' }).congestion_control_params_json).toBe('{}')
    expect(normalizeMpConfig({ congestion_control_params_json: 'x' }).congestion_control_params_json).toBe('{}')
  })

  it('normalizes path policies', () => {
    const n = normalizeMpConfig({
      path_policies: [
        { match_egress_device: ' eth0 ', action: 'prefer' },
        { match_carrier_kind: 'udp', action: 'pause', prefer_weight: 9, enabled: false },
        { action: 'teleport' },
        null,
      ],
    })
    expect(n.path_policies).toEqual([
      { match_egress_device: 'eth0', match_carrier_kind: '', match_remote_endpoint: '', action: 'prefer', prefer_weight: 1, enabled: true, note: '' },
      { match_egress_device: '', match_carrier_kind: 'udp', match_remote_endpoint: '', action: 'pause', prefer_weight: 0, enabled: false, note: '' },
    ])
  })

  it('normalizes per-NIC limits and SQM settings', () => {
    const n = normalizeMpConfig({
      egress_limits: [
        { egress_device: 'eth0', limit_bps: 800_000 },
        { egress_device: 'eth0', limit_bps: 1 },
        { egress_device: 'wlan0', limit_bps: 0 },
        { egress_device: '', limit_bps: 5 },
        { egress_device: 'wwan0', limit_bps: '2000000' },
      ],
      sqm: { enabled: true, target_ms: 0, interval_ms: 50, autorate_min_bps: 5_000_000, autorate_max_bps: 1_000_000 },
    })
    expect(n.egress_limits).toEqual([
      { egress_device: 'eth0', limit_bps: 800_000 },
      { egress_device: 'wwan0', limit_bps: 2_000_000 },
    ])
    expect(n.sqm.enabled).toBe(true)
    expect(n.sqm.target_ms).toBe(1)
    expect(n.sqm.interval_ms).toBe(50)
    // max is raised to min rather than producing an empty range
    expect(n.sqm.autorate_max_bps).toBe(5_000_000)
  })

  it('normalizes the punch rate caps', () => {
    const n = normalizeMpConfig({
      punch_pps: '200',
      punch_rate_limits: [
        { egress_device: 'eth0', pps: 50 },
        { egress_device: 'eth0', pps: 9 },
        { egress_device: 'wlan0', pps: 0 },
        { egress_device: '', pps: 5 },
      ],
    })
    expect(n.punch_pps).toBe(200)
    // 0 on one NIC means no cap there, so the row is kept
    expect(n.punch_rate_limits).toEqual([
      { egress_device: 'eth0', pps: 50 },
      { egress_device: 'wlan0', pps: 0 },
    ])
    expect(normalizeMpConfig({}).punch_pps).toBe(0)
  })

  it('scheduler model round-trips its parameters through scheduler_params_json', () => {
    const base = DEFAULT_MP_CONFIG()
    const next = applySchedulerModelToMpConfig(base, {
      scheduler: 'sqm-weighted',
      params: { latency_bandwidth: 0.8 },
    })
    expect(next.packet_scheduler).toBe('sqm-weighted')
    expect(JSON.parse(next.scheduler_params_json).latency_bandwidth).toBe(0.8)
    const model = mpConfigToSchedulerModel(next)
    expect(model.params.latency_bandwidth).toBe(0.8)
  })

  it('congestion model round-trips Brutal parameters', () => {
    const base = DEFAULT_MP_CONFIG()
    expect(mpConfigToCongestionModel(base).scheduler).toBe('engine-default')
    const next = applyCongestionModelToMpConfig(base, {
      scheduler: 'brutal',
      params: { up_mbps: 50, down_mbps: 200, disable_loss_compensation: true },
    })
    expect(next.congestion_control).toBe('brutal')
    expect(JSON.parse(next.congestion_control_params_json)).toEqual({ up_mbps: 50, down_mbps: 200, disable_loss_compensation: true })
    expect(mpConfigToCongestionModel(next)).toEqual({
      scheduler: 'brutal',
      params: { up_mbps: 50, down_mbps: 200, disable_loss_compensation: true },
    })
    expect(applyCongestionModelToMpConfig(next, { scheduler: 'engine-default', params: {} }).congestion_control).toBe('')
  })

  it('upserts and removes path policies by exact match', () => {
    const path = {
      path: { carrier_id: 3, local_addr: '192.168.1.2:5000', remote_addr: '1.2.3.4:11010' },
      carrier_kind: 'udp',
      egress_device: 'eth0',
    }
    const match = policyMatchForPath(path)
    expect(match).toEqual({ match_egress_device: 'eth0', match_carrier_kind: 'udp', match_remote_endpoint: '1.2.3.4:11010' })

    let mp = upsertPathPolicy(DEFAULT_MP_CONFIG(), { ...match, action: 'pause', prefer_weight: 0, enabled: true, note: '' })
    mp = upsertPathPolicy(mp, { ...match, action: 'exclude', prefer_weight: 0, enabled: true, note: '' })
    mp = upsertPathPolicy(mp, { ...match, match_egress_device: 'wlan0', action: 'pin', prefer_weight: 0, enabled: true, note: '' })
    expect(mp.path_policies.map(p => [p.match_egress_device, p.action])).toEqual([['eth0', 'exclude'], ['wlan0', 'pin']])

    mp = removePathPolicy(mp, match)
    expect(mp.path_policies.map(p => p.match_egress_device)).toEqual(['wlan0'])
  })

  it('reports changed MP fields with their effect mode', () => {
    const before = DEFAULT_MP_CONFIG()
    const after: MpConfig = { ...before, kmax: 4, congestion_control: 'cubic', sqm: { ...before.sqm, target_ms: 10 } }
    const changed = changedMpFields(before, after)
    expect(changed.sort()).toEqual(['mp.congestion_control', 'mp.kmax', 'mp.sqm.target_ms'])
    expect(fieldEffect('mp.kmax')).toBe('hot')
    expect(fieldEffect('mp.congestion_control')).toBe('reconnect')
    expect(fieldEffect('mp.nonexistent')).toBeUndefined()
  })

  it('field effect table covers every GUI-editable field', () => {
    const table = fieldEffects as Record<string, string>
    for (const v of Object.values(table)) expect(['hot', 'new_path', 'reconnect', 'restart']).toContain(v)
    for (const field of MP_GUI_BACKEND_FIELDS) {
      if (field === 'mp.sqm' || field === 'mp.data_plane' || field === 'mp.selection') {
        const nested = DEFAULT_MP_CONFIG()[field.slice(3) as 'sqm' | 'data_plane' | 'selection']
        for (const k of Object.keys(nested)) expect(table[`${field}.${k}`], `${field}.${k}`).toBeDefined()
        continue
      }
      expect(table[field], field).toBeDefined()
    }
  })

  it('every GUI control maps to a real backend field name', () => {
    for (const field of MP_GUI_BACKEND_FIELDS) {
      expect(field.startsWith('mp.') || NETWORK_LEVEL_FIELDS.has(field), field).toBe(true)
    }
    // Network-level fields must exist on NetworkConfig itself.
    const networkKeys = new Set(Object.keys(DEFAULT_NETWORK_CONFIG()))
    for (const field of NETWORK_LEVEL_FIELDS) expect(networkKeys.has(field), field).toBe(true)
    const configKeys = new Set(Object.keys(DEFAULT_MP_CONFIG()))
    for (const field of MP_GUI_BACKEND_FIELDS.filter(f => f.startsWith('mp.'))) {
      expect(configKeys.has(field.slice(3)), field).toBe(true)
    }
    for (const field of MP_RUNTIME_BACKEND_FIELDS) {
      expect(field.length).toBeGreaterThan(0)
    }
    expect(MP_RUNTIME_BACKEND_FIELDS).toContain('paths.btlbw_bps')
    expect(MP_RUNTIME_BACKEND_FIELDS).toContain('egress.cake')
    expect(MP_RUNTIME_BACKEND_FIELDS).not.toContain('mp_runtime.sqm_queues')
  })

  it('NetworkConfig normalize/toBackend preserve full MpConfig and the egress limit', () => {
    const cfg = DEFAULT_NETWORK_CONFIG()
    cfg.mp = normalizeMpConfig({
      enabled: true,
      kmax: 4,
      providers: ['udp-direct', 'relay-next-hop'],
      congestion_control: 'brutal',
      congestion_control_params_json: '{"up_mbps":20}',
      path_policies: [{ match_egress_device: 'eth0', action: 'pin' }],
      egress_limits: [{ egress_device: 'eth0', limit_bps: 800_000 }],
      sqm: { enabled: true },
      session_generation: 3,
    })
    cfg.tcp_hole_punch_mode = 'faketcp'
    cfg.egress_wire_limit_bps = 800_000
    const normalized = normalizeNetworkConfig(cfg)
    expect(normalized.mp?.enabled).toBe(true)
    expect(normalized.mp?.kmax).toBe(4)
    expect(normalized.mp?.path_policies[0].action).toBe('pin')
    expect(normalized.tcp_hole_punch_mode).toBe('faketcp')
    expect(normalized.egress_wire_limit_bps).toBe(800_000)

    const backend = toBackendNetworkConfig(normalized) as any
    expect(backend.mp.enabled).toBe(true)
    expect(backend.mp.kmax).toBe(4)
    expect(backend.mp).not.toHaveProperty('lambda')
    expect(backend.mp).not.toHaveProperty('optimizer')
    expect(backend.mp.providers).toEqual(['udp-direct', 'relay-next-hop'])
    expect(backend.mp.congestion_control).toBe('brutal')
    expect(backend.mp.egress_limits).toEqual([{ egress_device: 'eth0', limit_bps: 800_000 }])
    expect(backend.mp.sqm.enabled).toBe(true)
    expect(backend.mp.session_generation).toBe(3)
    expect(backend.tcp_hole_punch_mode).toBe('faketcp')
    expect(backend.egress_wire_limit_bps).toBe('800000')

    // unlimited is omitted, like instance_recv_bps_limit
    const unlimited = toBackendNetworkConfig({ ...normalized, egress_wire_limit_bps: null }) as any
    expect('egress_wire_limit_bps' in unlimited).toBe(false)
    // legacy string form round-trips
    expect(normalizeNetworkConfig({ ...cfg, egress_wire_limit_bps: '9007199254740993' }).egress_wire_limit_bps).toBe('9007199254740993')
  })

  it('normalizes tcp hole mode', () => {
    expect(normalizeTcpHolePunchMode('auto')).toBe('auto')
    expect(normalizeTcpHolePunchMode('faketcp')).toBe('faketcp')
    expect(normalizeTcpHolePunchMode('tcp')).toBe('tcp')
    expect(normalizeTcpHolePunchMode('weird')).toBe('auto')
  })
})

describe('hot patch builder', () => {
  const base = () => {
    const c = DEFAULT_NETWORK_CONFIG()
    c.instance_id = '00000000-0000-0000-0000-000000000001'
    c.hostname = 'host-a'
    return normalizeNetworkConfig(c)
  }

  it('returns an empty patch when nothing changed', () => {
    expect(buildHotPatch(base(), base())).toEqual({})
  })

  it('patches MP / hole mode / egress limit changes', () => {
    const before = base()
    const after = base()
    after.mp = { ...after.mp!, kmax: 5 }
    after.tcp_hole_punch_mode = 'faketcp'
    after.egress_wire_limit_bps = 1_000_000
    const patch = buildHotPatch(before, after)!
    expect(patch.mp?.kmax).toBe(5)
    expect(patch.tcp_hole_punch_mode).toBe('faketcp')
    expect(patch.egress_wire_limit_bps).toBe('1000000')
  })

  it('clearing the egress limit sends "0"', () => {
    const before = base()
    before.egress_wire_limit_bps = 1_000_000
    const after = base()
    expect(buildHotPatch(before, after)).toEqual({ egress_wire_limit_bps: '0' })
  })

  it('refuses when a restart-only field changed', () => {
    const before = base()
    const after = base()
    after.mp = { ...after.mp!, kmax: 5 }
    after.network_name = 'other-net'
    expect(buildHotPatch(before, after)).toBeNull()
  })
})

describe('MpConfigPanel', () => {
  function mountPanel(mp: MpConfig = DEFAULT_MP_CONFIG(), egressWireLimitBps: number | null = null) {
    return mount(MpConfigPanel, {
      props: { modelValue: mp, tcpHolePunchMode: 'auto', egressWireLimitBps },
      global: mpGlobal(),
    })
  }

  function lastMp(wrapper: ReturnType<typeof mountPanel>): MpConfig {
    const events = wrapper.emitted('update:modelValue')!
    return events[events.length - 1][0] as MpConfig
  }

  it('renders the basic layer and keeps advanced controls mounted but hidden', async () => {
    const wrapper = mountPanel()
    for (const id of ['mp-enabled', 'mp-sqm-enabled', 'mp-egress-wire-limit', 'mp-scheduler-select', 'mp-cc-select']) {
      expect(wrapper.find(`[data-testid="${id}"]`).exists(), id).toBe(true)
    }
    const advancedHidden = () => (wrapper.find('[data-testid="mp-advanced"]').attributes('style') ?? '').includes('display: none')
    expect(advancedHidden()).toBe(true)
    expect(wrapper.find('[data-testid="mp-kmax"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="mp-provider-relay-next-hop"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="mp-tcp-hole-mode"]').exists()).toBe(true)
    await wrapper.find('[data-testid="mp-advanced-toggle"]').trigger('click')
    expect(advancedHidden()).toBe(false)
  })

  it('edits the per-peer punch count', async () => {
    const wrapper = mountPanel()
    await wrapper.find('[data-testid="mp-punch-attempts"]').setValue('4')
    expect(lastMp(wrapper).punch_attempts).toBe(4)
  })

  it('lists every registered congestion controller including Brutal', () => {
    const wrapper = mountPanel()
    const options = wrapper.find('[data-testid="mp-cc-select"]').findAll('option').map(o => o.attributes('value'))
    expect(options).toEqual(expect.arrayContaining(['engine-default', 'bbr', 'bbr3', 'cubic', 'copa', 'brutal']))
  })

  it('selecting Brutal renders its schema with the 50 Mbps default upload rate', async () => {
    const wrapper = mountPanel()
    await wrapper.find('[data-testid="mp-cc-select"]').setValue('brutal')
    const selected = lastMp(wrapper)
    expect(selected.congestion_control).toBe('brutal')
    expect(JSON.parse(selected.congestion_control_params_json)).toEqual({ up_mbps: 50, down_mbps: 0, disable_loss_compensation: false })

    await wrapper.setProps({ modelValue: selected })
    expect(wrapper.find('[data-testid="mp-cc-missing"]').exists()).toBe(false)

    await wrapper.find('[data-testid="mp-tunable-up_mbps"]').setValue('80')
    const withUp = lastMp(wrapper)
    expect(JSON.parse(withUp.congestion_control_params_json).up_mbps).toBe(80)
  })

  it('converts the global limit between Mbps and bits/s', async () => {
    const wrapper = mountPanel(DEFAULT_MP_CONFIG(), 2_500_000)
    const input = wrapper.find('[data-testid="mp-egress-wire-limit"]')
    expect((input.element as HTMLInputElement).value).toBe('2.5')
    await input.setValue('0.8')
    expect(wrapper.emitted('update:egressWireLimitBps')!.at(-1)).toEqual([800_000])
    await input.setValue('')
    expect(wrapper.emitted('update:egressWireLimitBps')!.at(-1)).toEqual([null])
  })

  it('has no optimizer controls, only the number of paths in use', () => {
    const wrapper = mountPanel()
    expect(wrapper.find('[data-testid="mp-kmax"]').exists()).toBe(true)
    for (const id of ['mp-preset', 'mp-optimizer', 'mp-lambda', 'mp-churn-penalty', 'mp-path-penalty', 'mp-switch-margin', 'mp-confirm-rounds']) {
      expect(wrapper.find(`[data-testid="${id}"]`).exists(), id).toBe(false)
    }
  })

  it('toggles SQM and edits its details', async () => {
    const wrapper = mountPanel()
    await wrapper.find('[data-testid="mp-sqm-enabled"]').setValue(true)
    expect(lastMp(wrapper).sqm.enabled).toBe(true)
    await wrapper.find('[data-testid="mp-sqm-autorate-max"]').setValue('100')
    expect(lastMp(wrapper).sqm.autorate_max_bps).toBe(100_000_000)
    // Shaping to the Autorate estimate is always on: no switch for it.
    expect(wrapper.find('[data-testid="mp-sqm-enforce"]').exists()).toBe(false)
  })

  it('adds, edits and removes path policies', async () => {
    const wrapper = mountPanel()
    await wrapper.find('[data-testid="mp-policy-add"]').trigger('click')
    let mp = lastMp(wrapper)
    expect(mp.path_policies).toHaveLength(1)
    expect(mp.path_policies[0].action).toBe('prefer')
    expect(mp.path_policies[0].prefer_weight).toBe(2)

    await wrapper.setProps({ modelValue: mp })
    const row = wrapper.find('[data-testid="mp-policy-row"]')
    await row.findAll('input')[0].setValue('eth0')
    mp = lastMp(wrapper)
    expect(mp.path_policies[0].match_egress_device).toBe('eth0')

    await wrapper.setProps({ modelValue: mp })
    await wrapper.find('[data-testid="mp-policy-row"] select').setValue('pause')
    mp = lastMp(wrapper)
    expect(mp.path_policies[0].action).toBe('pause')
    expect(mp.path_policies[0].prefer_weight).toBe(0)

    await wrapper.setProps({ modelValue: mp })
    await wrapper.find('[data-testid="mp-policy-remove"]').trigger('click')
    expect(lastMp(wrapper).path_policies).toEqual([])
  })

  it('adds per-NIC limits in Mbps', async () => {
    const wrapper = mountPanel()
    await wrapper.find('[data-testid="mp-limit-device"]').setValue('eth0')
    await wrapper.find('[data-testid="mp-limit-mbps"]').setValue('0.8')
    await wrapper.find('[data-testid="mp-limit-add"]').trigger('click')
    const mp = lastMp(wrapper)
    expect(mp.egress_limits).toEqual([{ egress_device: 'eth0', limit_bps: 800_000 }])
    await wrapper.setProps({ modelValue: mp })
    expect(wrapper.findAll('[data-testid="mp-egress-limit-row"]')).toHaveLength(1)
  })

  it('sets the punch rate globally and per NIC', async () => {
    const wrapper = mountPanel()
    await wrapper.find('[data-testid="mp-punch-pps"]').setValue('300')
    let mp = lastMp(wrapper)
    expect(mp.punch_pps).toBe(300)
    await wrapper.setProps({ modelValue: mp })
    await wrapper.find('[data-testid="mp-punch-rate-device"]').setValue('eth1')
    await wrapper.find('[data-testid="mp-punch-rate-add"]').trigger('click')
    mp = lastMp(wrapper)
    // a new NIC row starts from the global cap
    expect(mp.punch_rate_limits).toEqual([{ egress_device: 'eth1', pps: 300 }])
    await wrapper.setProps({ modelValue: mp })
    await wrapper.find('[data-testid="mp-punch-rate-row"] input').setValue('40')
    expect(lastMp(wrapper).punch_rate_limits).toEqual([{ egress_device: 'eth1', pps: 40 }])
  })

  it('edits resource groups as a table', async () => {
    const wrapper = mountPanel()
    await wrapper.find('[data-testid="mp-group-name"]').setValue('lte')
    await wrapper.find('[data-testid="mp-group-add"]').trigger('click')
    let mp = lastMp(wrapper)
    expect(mp.resource_groups.map(g => g.name)).toEqual(['lte'])
    await wrapper.setProps({ modelValue: mp })
    const inputs = wrapper.find('[data-testid="mp-group-row"]').findAll('input')
    await inputs[0].setValue('wwan0, wwan1')
    mp = lastMp(wrapper)
    expect(mp.resource_groups[0].egress_devices).toEqual(['wwan0', 'wwan1'])
    await wrapper.setProps({ modelValue: mp })
    await wrapper.find('[data-testid="mp-group-row"]').findAll('input')[1].setValue('20')
    expect(lastMp(wrapper).resource_groups[0].capacity_bps).toBe(20_000_000)
  })

  it('keeps multi-line manual paths', async () => {
    const wrapper = mountPanel()
    await wrapper.find('[data-testid="mp-manual-paths"]').setValue('mp+udp://a:1\n\nmp+udp://b:2\n')
    expect(lastMp(wrapper).manual_paths).toEqual(['mp+udp://a:1', 'mp+udp://b:2'])
  })

  it('labels fields with their effect mode', () => {
    const wrapper = mountPanel()
    expect(wrapper.findAll('.mp-effect-hot').length).toBeGreaterThan(0)
    expect(wrapper.findAll('.mp-effect-reconnect').length).toBeGreaterThan(0)
    expect(wrapper.findAll('.mp-effect-new-path').length).toBeGreaterThan(0)
  })
})
