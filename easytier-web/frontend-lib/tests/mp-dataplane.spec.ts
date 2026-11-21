import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import MpDataPlanePanel, { type ProxyFlags } from '../src/components/MpDataPlanePanel.vue'
import MpRuntimePanel from '../src/components/MpRuntimePanel.vue'
import { classKey, MpRuntimeHistory } from '../src/modules/mpRuntime'
import {
  applyDataPlanePreset,
  changedMpFields,
  classMode,
  dataPlaneClassNames,
  DEFAULT_MP_CONFIG,
  detectDataPlanePreset,
  fieldEffect,
  moveClassRule,
  MP_OVERSIZE_POLICIES,
  normalizeMpConfig,
  normalizePortRange,
  removeClassRule,
  upsertClassPolicy,
  upsertClassRule,
  DEFAULT_MP_CLASS_POLICY,
  type MpClassRule,
  type MpConfig,
  type MpPeerStatus,
  type MpRuntimeInfo,
} from '../src/types/mpConfig'
import { mpGlobal } from './primevueStubs'

const GAME: MpClassRule = { name: 'game', protocol: 'udp', port_range: '27015-27030', dst_cidr: '', enabled: true }

function dpEnabled(): MpConfig {
  const mp = DEFAULT_MP_CONFIG()
  return { ...mp, data_plane: { ...mp.data_plane, enabled: true } }
}

describe('MpDataPlaneConfig normalization', () => {
  it('defaults are off with TCP and the proxy on reliable streams and the rest datagrams', () => {
    const dp = DEFAULT_MP_CONFIG().data_plane
    expect(dp.enabled).toBe(false)
    expect(dp.oversize).toBe('icmp_ptb')
    expect('datagram_bypass_cwnd' in dp).toBe(false)
    expect(dp.class_policies).toEqual([])
    expect(dp.class_rules).toEqual([])
    expect(dp.reliable_stream_max).toBe(64)
    expect(dp.reliable_stream_idle_ms).toBe(30_000)
    expect(detectDataPlanePreset(dp)).toBe('default')
    expect(classMode(dp, 'tcp')).toBe('reliable_stream')
    expect(classMode(dp, 'udp')).toBe('datagram')
    expect(classMode(dp, 'proxy')).toBe('reliable_stream')
    expect(classMode(dp, 'icmp')).toBe('datagram')
  })

  it('drops unknown modes, removed FEC/ARQ modes and duplicate classes', () => {
    const mp = normalizeMpConfig({
      data_plane: {
        enabled: true,
        oversize: 'bogus',
        class_policies: [
          { class: 'udp', mode: 'reliable_stream', arq_max_retries: 3 },
          { class: 'udp', mode: 'datagram' },
          { class: 'tcp', mode: 'teleport' },
          { class: 'icmp', mode: 'fec' },
          { class: 'other', mode: 'bounded_arq' },
          { class: 'proxy', mode: 'datagram' },
        ],
      },
    })
    const dp = mp.data_plane
    expect(dp.oversize).toBe('icmp_ptb')
    expect(dp.class_policies).toEqual([
      { class: 'udp', mode: 'reliable_stream' },
      { class: 'proxy', mode: 'datagram' },
    ])
  })

  it('validates port ranges and rejects rules shadowing built-in classes', () => {
    expect(normalizePortRange('')).toBe('')
    expect(normalizePortRange(' 22 ')).toBe('22')
    expect(normalizePortRange('27015-27030')).toBe('27015-27030')
    expect(normalizePortRange('30-20')).toBeNull()
    expect(normalizePortRange('70000')).toBeNull()
    expect(normalizePortRange('ssh')).toBeNull()
    const mp = normalizeMpConfig({
      data_plane: { class_rules: [GAME, { ...GAME, name: 'tcp' }, { ...GAME, name: 'bad', port_range: 'x' }] },
    })
    expect(mp.data_plane.class_rules.map(r => r.name)).toEqual(['game'])
  })
})

describe('data plane presets and rule helpers', () => {
  it('applies and detects presets, custom when edited', () => {
    const rfc = applyDataPlanePreset(dpEnabled(), 'rfc')
    expect(detectDataPlanePreset(rfc.data_plane)).toBe('rfc')
    expect(rfc.data_plane.class_policies).toEqual([
      { class: 'tcp', mode: 'datagram' },
      { class: 'proxy', mode: 'datagram' },
    ])
    expect(classMode(rfc.data_plane, 'tcp')).toBe('datagram')
    expect(classMode(rfc.data_plane, 'proxy')).toBe('datagram')
    expect(detectDataPlanePreset(applyDataPlanePreset(rfc, 'default').data_plane)).toBe('default')
    const edited = upsertClassPolicy(rfc, { ...DEFAULT_MP_CLASS_POLICY('icmp', 'reliable_stream') })
    expect(detectDataPlanePreset(edited.data_plane)).toBe('custom')
  })

  it('renames, reorders and removes rules together with their policies', () => {
    let mp = upsertClassRule(dpEnabled(), GAME)
    mp = upsertClassRule(mp, { ...GAME, name: 'voip', port_range: '5060' })
    mp = upsertClassPolicy(mp, DEFAULT_MP_CLASS_POLICY('game', 'reliable_stream'))
    expect(dataPlaneClassNames(mp.data_plane)).toEqual(expect.arrayContaining(['tcp', 'udp', 'game', 'voip']))

    mp = upsertClassRule(mp, { ...GAME, name: 'games' }, 'game')
    expect(mp.data_plane.class_policies.map(p => p.class)).toEqual(['games'])

    mp = moveClassRule(mp, 'voip', -1)
    expect(mp.data_plane.class_rules.map(r => r.name)).toEqual(['voip', 'games'])
    expect(moveClassRule(mp, 'voip', -1).data_plane.class_rules.map(r => r.name)).toEqual(['voip', 'games'])

    mp = removeClassRule(mp, 'games')
    expect(mp.data_plane.class_rules.map(r => r.name)).toEqual(['voip'])
    expect(mp.data_plane.class_policies).toEqual([])
  })

  it('reports nested data_plane changes with their effect', () => {
    const before = DEFAULT_MP_CONFIG()
    const after = applyDataPlanePreset({ ...before, data_plane: { ...before.data_plane, enabled: true } }, 'rfc')
    expect(changedMpFields(before, after).sort()).toEqual(['mp.data_plane.class_policies', 'mp.data_plane.enabled'])
    expect(fieldEffect('mp.data_plane.enabled')).toBe('reconnect')
    expect(fieldEffect('mp.data_plane.class_policies')).toBe('hot')
    expect(fieldEffect('mtu')).toBe('restart')
    expect(fieldEffect('enable_quic_proxy')).toBe('restart')
  })
})

describe('MpDataPlanePanel', () => {
  const NO_PROXY: ProxyFlags = { enable_quic_proxy: false, disable_quic_input: false, enable_kcp_proxy: false, disable_kcp_input: false }

  function mountDp(mp: MpConfig, advanced = true) {
    return mount(MpDataPlanePanel, {
      props: { modelValue: mp, advanced, proxyFlags: NO_PROXY },
      global: mpGlobal(),
    })
  }

  function lastMp(wrapper: ReturnType<typeof mountDp>): MpConfig {
    const events = wrapper.emitted('update:modelValue')!
    return events[events.length - 1][0] as MpConfig
  }

  it('enables the data plane and applies a preset', async () => {
    const wrapper = mountDp(DEFAULT_MP_CONFIG())
    await wrapper.find('[data-testid="mp-dp-enabled"]').setValue(true)
    expect(lastMp(wrapper).data_plane.enabled).toBe(true)

    await wrapper.setProps({ modelValue: dpEnabled() })
    await wrapper.find('[data-testid="mp-dp-preset"]').setValue('rfc')
    expect(detectDataPlanePreset(lastMp(wrapper).data_plane)).toBe('rfc')
  })

  it('hides advanced controls until both advanced and enabled', async () => {
    const wrapper = mountDp(dpEnabled(), false)
    expect(wrapper.find('[data-testid="mp-dp-classes"]').exists()).toBe(false)
    await wrapper.setProps({ advanced: true })
    expect(wrapper.find('[data-testid="mp-dp-classes"]').exists()).toBe(true)
    await wrapper.setProps({ modelValue: DEFAULT_MP_CONFIG() })
    expect(wrapper.find('[data-testid="mp-dp-classes"]').exists()).toBe(false)
  })

  it('switching a class to datagram removes its policy row; other modes store one', async () => {
    const wrapper = mountDp(dpEnabled())
    await wrapper.find('[data-testid="mp-dp-mode-udp"]').setValue('reliable_stream')
    const withStream = lastMp(wrapper)
    expect(withStream.data_plane.class_policies).toEqual([{ class: 'udp', mode: 'reliable_stream' }])

    await wrapper.setProps({ modelValue: withStream })
    const options = wrapper.find('[data-testid="mp-dp-mode-udp"]').findAll('option').map(o => o.element.value)
    expect(options).toEqual(['datagram', 'reliable_stream'])
    await wrapper.find('[data-testid="mp-dp-mode-udp"]').setValue('datagram')
    expect(lastMp(wrapper).data_plane.class_policies).toEqual([])
  })

  it('TCP defaults to reliable_stream: only datagram needs a row', async () => {
    const wrapper = mountDp(dpEnabled())
    await wrapper.find('[data-testid="mp-dp-mode-tcp"]').setValue('datagram')
    const withDatagram = lastMp(wrapper)
    expect(withDatagram.data_plane.class_policies).toEqual([{ class: 'tcp', mode: 'datagram' }])

    await wrapper.setProps({ modelValue: withDatagram })
    await wrapper.find('[data-testid="mp-dp-mode-tcp"]').setValue('reliable_stream')
    expect(lastMp(wrapper).data_plane.class_policies).toEqual([])
  })

  it('adds a rule, rejecting bad names and ports', async () => {
    const wrapper = mountDp(dpEnabled())
    await wrapper.find('[data-testid="mp-dp-rule-name"]').setValue('tcp')
    await wrapper.find('[data-testid="mp-dp-rule-add"]').trigger('click')
    expect(wrapper.find('[data-testid="mp-dp-rule-error"]').text()).toBe('mp_dp.rule_name_invalid')

    await wrapper.find('[data-testid="mp-dp-rule-name"]').setValue('game')
    await wrapper.find('[data-testid="mp-dp-rule-ports"]').setValue('99999')
    await wrapper.find('[data-testid="mp-dp-rule-add"]').trigger('click')
    expect(wrapper.find('[data-testid="mp-dp-rule-error"]').text()).toBe('mp_dp.rule_port_invalid')

    await wrapper.find('[data-testid="mp-dp-rule-ports"]').setValue('27015-27030')
    await wrapper.find('[data-testid="mp-dp-rule-add"]').trigger('click')
    expect(lastMp(wrapper).data_plane.class_rules).toEqual([
      expect.objectContaining({ name: 'game', port_range: '27015-27030' }),
    ])
  })

  it('offers no oversize policy that sends a packet on a reliable stream', () => {
    expect(MP_OVERSIZE_POLICIES).toEqual(['icmp_ptb', 'fragment'])
    // A config saved before the option was removed reads as the default.
    expect(normalizeMpConfig({ data_plane: { enabled: true, oversize: 'stream' } }).data_plane.oversize).toBe('icmp_ptb')
    const wrapper = mountDp(dpEnabled())
    expect(wrapper.find('[data-testid="mp-dp-bypass"]').exists()).toBe(false)
  })

  it('emits proxy flag edits separately from the MP config', async () => {
    const wrapper = mountDp(dpEnabled())
    await wrapper.find('[data-testid="mp-dp-enable_kcp_proxy"]').setValue(true)
    expect(wrapper.emitted('update:proxyFlags')![0][0]).toEqual({ ...NO_PROXY, enable_kcp_proxy: true })
    expect(wrapper.emitted('update:modelValue')).toBeUndefined()
  })
})

function dpSample(t: number, txBytes: number, extra: Partial<MpPeerStatus> = {}): MpRuntimeInfo {
  return {
    sample_time_ms: t,
    peers: [{
      peer_id: 7,
      paths: [],
      data_plane: {
        negotiated: 'datagram',
        max_datagram_bytes: 1452,
        recommended_mtu: 1360,
        oversize_dropped: 3,
        circuit_breaker_trips: 1,
        classes: [
          { class: 'udp', mode: 'datagram', tx_bytes: txBytes, rx_bytes: txBytes / 2 },
          { class: 'game', mode: 'reliable_stream', tx_bytes: 0, open_streams: 3, streams_recycled: 7 },
        ],
      },
      ...extra,
    }],
  }
}

describe('data plane runtime', () => {
  it('differences class counters into bit rates', () => {
    const h = new MpRuntimeHistory()
    h.ingest(dpSample(1000, 0))
    const view = h.ingest(dpSample(3000, 250_000))
    const peer = view.peers[0]
    const r = view.classRates.get(classKey(peer, 'udp'))!
    expect(r.txBps).toBe(1_000_000)
    expect(r.rxBps).toBe(500_000)
    // standalone and MP-managed sessions of one peer never share a key
    expect(classKey({ ...peer, standalone: true }, 'udp')).not.toBe(classKey(peer, 'udp'))
  })

  function mountRt(runtime: MpRuntimeInfo, props: Record<string, unknown> = {}) {
    return mount(MpRuntimePanel, {
      props: { runtime, mpConfig: { ...dpEnabled(), enabled: true }, initialStep: 'classify', ...props },
      global: mpGlobal(),
    })
  }

  it('renders negotiation, counters and per-class rows', async () => {
    const wrapper = mountRt(dpSample(1000, 0))
    await wrapper.setProps({ runtime: dpSample(2000, 125_000) })
    expect(wrapper.find('[data-testid="mp-dp-negotiated"]').text()).toBe('mp_dp.rt.negotiated.datagram')
    expect(wrapper.find('[data-testid="mp-dp-breaker"]').text()).toBe('1')
    const rows = wrapper.findAll('[data-testid="mp-dp-class-row"]')
    expect(rows).toHaveLength(2)
    expect(rows[0].find('[data-testid="mp-dp-class-tx"]').text()).toContain('1.00 Mbps')
    expect(rows[1].text()).toContain('3')
    expect(rows[1].text()).toContain('↻7')
  })

  it('shows the fallback reason when datagrams were not negotiated', () => {
    const s = dpSample(1000, 0)
    s.peers![0].data_plane = { ...s.peers![0].data_plane, negotiated: 'stream_fallback', fallback_reason: 'peer lacks datagram cap' }
    const wrapper = mountRt(s)
    expect(wrapper.find('[data-testid="mp-dp-negotiated"]').attributes('data-severity')).toBe('warn')
    expect(wrapper.find('[data-testid="mp-dp-fallback-reason"]').text()).toContain('peer lacks datagram cap')
  })

  it('explains a session built without the data plane in plain words', () => {
    const s = dpSample(1000, 0)
    s.peers![0].data_plane = {
      ...s.peers![0].data_plane,
      negotiated: 'disabled',
      fallback_reason: 'session built without the data plane; reconnect to enable',
    }
    const text = mountRt(s).find('[data-testid="mp-dp-fallback-reason"]').text()
    expect(text).not.toContain('session built')
    expect(text).toBe('mp_dp.rt.reason.not_built')
  })

  it('offers the recommended MTU only when the saved one is larger', async () => {
    const wrapper = mountRt(dpSample(1000, 0), { currentMtu: 1380 })
    await wrapper.find('[data-testid="mp-dp-apply-mtu"]').trigger('click')
    expect(wrapper.emitted('apply-mtu')).toEqual([[1360]])
    await wrapper.setProps({ currentMtu: 1360 })
    expect(wrapper.find('[data-testid="mp-dp-apply-mtu"]').exists()).toBe(false)
    // a smaller MTU already fits one datagram: nothing to change
    await wrapper.setProps({ currentMtu: 1300 })
    expect(wrapper.find('[data-testid="mp-dp-apply-mtu"]').exists()).toBe(false)
  })

  it('omits the section for peers without data plane status', () => {
    const wrapper = mountRt({ sample_time_ms: 1, peers: [{ peer_id: 1, paths: [] }] })
    expect(wrapper.find('[data-testid="mp-runtime-dataplane"]').exists()).toBe(false)
  })
})
