import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import MpEgressPanel from '../src/components/MpEgressPanel.vue'
import MpFlowSankey from '../src/components/MpFlowSankey.vue'
import MpRuntimePanel from '../src/components/MpRuntimePanel.vue'
import NetworkChart from '../src/components/NetworkChart.vue'
import {
  counterRate,
  formatBps,
  formatBytes,
  formatUs,
  MpRuntimeHistory,
  nicPathFlows,
  pathKey,
} from '../src/modules/mpRuntime'
import { DEFAULT_MP_CONFIG, type MpRuntimeInfo } from '../src/types/mpConfig'
import { mpGlobal } from './primevueStubs'

const PATH_A = { carrier_id: 1, local_addr: '192.168.1.2:5000', remote_addr: '1.2.3.4:11010' }
const PATH_B = { carrier_id: 2, local_addr: '10.0.0.2:5001', remote_addr: '1.2.3.4:11010' }

function sample(t: number, sentA: number, applied: number, drops: number, extra: Partial<MpRuntimeInfo> = {}): MpRuntimeInfo {
  return {
    sample_time_ms: t,
    peers: [{
      peer_id: 42,
      active_paths: [PATH_A],
      paths: [
        {
          path: PATH_A,
          carrier_kind: 'udp',
          egress_device: 'eth0',
          lifecycle_state: 'available',
          validation_state: 'Validated',
          sent_bytes: sentA,
          recv_bytes: sentA / 2,
          srtt_micros: 25_000,
          cwnd_bytes: 64 * 1024,
          pacing_rate_bps: 10_000_000,
          target_rate_bps: 8_000_000,
          user_policy: '',
        },
        {
          path: PATH_B,
          carrier_kind: 'faketcp',
          egress_device: 'wwan0',
          lifecycle_state: 'standby',
          sent_bytes: 0,
          target_rate_bps: 0,
          user_policy: 'pause',
        },
      ],
      effective_congestion_control: 'bbr',
      effective_recovery: 'tquic-rfc9002',
    }],
    egress: [{
      resource: 'egress:eth0',
      egress_device: 'eth0',
      capacity_bps: 9_000_000,
      achieved_bps: 1,
      ceiling_bps: 800_000,
      ceiling_source: 'static',
      autorate_estimate_bps: 9_000_000,
      autorate_measured: true,
      queue_delay_micros: 4_000,
      path_count: 1,
      cake: {
        bandwidth_bps: 9_000_000,
        target_us: 5_000,
        interval_us: 100_000,
        qlen_packets: 2,
        backlog_bytes: 3000,
        memory_used: 3000,
        memory_peak: 20_000,
        memory_limit: 112_500,
        sent_packets: applied / 1000,
        sent_bytes: applied,
        dropped_packets: drops,
        overlimit_drops: 1,
        peak_delay_us: 9_000,
        avg_delay_us: 2_500,
        base_delay_us: 400,
        sparse_flows: 2,
        bulk_flows: 1,
        unresponsive_flows: 0,
        stream_aqm_drops: 7,
        stream_overlimit_drops: 3,
      },
    }],
    ...extra,
  }
}

describe('runtime formatting', () => {
  it('formats bits, bytes and microseconds', () => {
    expect(formatBps(undefined)).toBe('-')
    expect(formatBps(800_000)).toBe('800.0 kbps')
    expect(formatBps(8_000_000)).toBe('8.00 Mbps')
    expect(formatBytes(2048)).toBe('2.0 KiB')
    expect(formatUs(250)).toBe('250 µs')
    expect(formatUs(4_000)).toBe('4.0 ms')
  })

  it('counterRate ignores first sample, resets and non-advancing clocks', () => {
    expect(counterRate(undefined, 10, 1000)).toBeUndefined()
    expect(counterRate(100, 50, 1000)).toBeUndefined()
    expect(counterRate(100, 200, 0)).toBeUndefined()
    expect(counterRate(100, 600, 500)).toBe(1000)
  })
})

describe('MpRuntimeHistory', () => {
  it('differences counters against the core sample clock', () => {
    const h = new MpRuntimeHistory()
    const first = h.ingest(sample(10_000, 0, 0, 0))
    expect(first.pathRates.get(pathKey(42, { path: PATH_A }))?.sendBps).toBeUndefined()
    // no applied-bytes rate yet → falls back to the instantaneous achieved_bps
    expect(first.egress[0].current.sendBps).toBe(1)

    // 2 s later on the core clock (poll jitter must not matter)
    const second = h.ingest(sample(12_000, 250_000, 200_000, 4))
    expect(second.pathRates.get(pathKey(42, { path: PATH_A }))?.sendBps).toBe(1_000_000)
    expect(second.pathRates.get(pathKey(42, { path: PATH_A }))?.recvBps).toBe(500_000)
    expect(second.totalSendBps).toBe(1_000_000)
    expect(second.egress[0].current.sendBps).toBe(800_000)
    expect(second.egress[0].current.estimateBps).toBe(9_000_000)
    expect(second.egress[0].current.ceilingBps).toBe(800_000)
    expect(second.egress[0].current.queueDelayMs).toBe(4)
    // 4 queue drops over the 2 s, the over-memory one did not grow
    expect(second.egress[0].current.dropsPerSec).toBe(2)
    expect(second.egress[0].current.cakeDelayMs).toBe(2.5)
    expect(second.egress[0].current.backlogBytes).toBe(3000)
    expect(second.labels).toHaveLength(2)
    expect(second.egress[0].history).toHaveLength(2)
  })

  it('does not append or rate a repeated sample', () => {
    const h = new MpRuntimeHistory()
    h.ingest(sample(10_000, 0, 0, 0))
    h.ingest(sample(11_000, 125_000, 125_000, 0))
    const repeat = h.ingest(sample(11_000, 125_000, 125_000, 0))
    expect(repeat.labels).toHaveLength(2)
    expect(repeat.pathRates.get(pathKey(42, { path: PATH_A }))?.sendBps).toBeUndefined()
  })

  it('treats a counter reset (core restart) as no rate', () => {
    const h = new MpRuntimeHistory()
    h.ingest(sample(10_000, 500_000, 500_000, 9))
    const after = h.ingest(sample(11_000, 1_000, 1_000, 0))
    expect(after.pathRates.get(pathKey(42, { path: PATH_A }))?.sendBps).toBeUndefined()
    expect(after.egress[0].current.dropsPerSec).toBeUndefined()
  })

  it('bounds history and drops vanished egress entries', () => {
    const h = new MpRuntimeHistory(3)
    for (let i = 0; i < 5; i++) h.ingest(sample(1000 * (i + 1), i * 1000, i * 1000, 0))
    const v = h.ingest(sample(10_000, 9000, 9000, 0))
    expect(v.labels).toHaveLength(3)
    expect(v.egress[0].history).toHaveLength(3)
    const gone = h.ingest(sample(11_000, 9000, 9000, 0, { egress: [] }))
    expect(gone.egress).toHaveLength(0)
    const back = h.ingest(sample(12_000, 9000, 9000, 0))
    expect(back.egress[0].history).toHaveLength(1)
  })

  it('handles a missing mp_runtime (old core)', () => {
    const v = new MpRuntimeHistory().ingest(undefined)
    expect(v.peers).toEqual([])
    expect(v.egress).toEqual([])
    expect(v.labels).toEqual([])
  })
})

describe('nicPathFlows', () => {
  /** P4-A: the chart is fed the actual send rate per path, grouped by NIC, with the NIC's Autorate budget. */
  it('groups the actual send rate of each live path under its NIC with the NIC budget', () => {
    const h = new MpRuntimeHistory()
    h.ingest(sample(10_000, 0, 0, 0))
    const view = h.ingest(sample(12_000, 250_000, 200_000, 4))
    const flows = nicPathFlows(view, view.peers[0])
    expect(flows.nics).toEqual([
      { id: 'eth0', sendBps: 1_000_000, budgetBps: 9_000_000 },
      { id: 'wwan0', sendBps: 0, budgetBps: undefined },
    ])
    expect(flows.paths.map(p => [p.nic, p.sendBps])).toEqual([['eth0', 1_000_000], ['wwan0', 0]])
  })

  it('leaves a dead path out, groups a relay path under no NIC and sums the paths of one NIC', () => {
    const extra = () => [
      { path: { carrier_id: 3, local_addr: '[fd4d:5000::1]:1', remote_addr: '[fd4d:5000::2]:1' }, carrier_kind: 'relay-next-hop', local_resource: 'relay-next-hop:7:1', lifecycle_state: 'available' },
      { path: { carrier_id: 4, local_addr: '192.168.1.2:5002', remote_addr: '5.6.7.8:11010' }, carrier_kind: 'udp', egress_device: 'eth0', lifecycle_state: 'dead' },
      { path: { carrier_id: 5, local_addr: '192.168.1.2:5003', remote_addr: '9.9.9.9:11010' }, carrier_kind: 'udp', egress_device: 'eth0', lifecycle_state: 'standby' },
    ]
    const h = new MpRuntimeHistory()
    const first = sample(10_000, 0, 0, 0)
    first.peers![0].paths!.push(...extra())
    h.ingest(first)
    const second = sample(12_000, 250_000, 200_000, 4)
    second.peers![0].paths!.push(...extra())
    const view = h.ingest(second)
    const flows = nicPathFlows(view, view.peers[0])
    expect(flows.nics.map(n => n.id)).toEqual(['eth0', 'wwan0', ''])
    expect(flows.paths).toHaveLength(4)
    expect(flows.paths.some(p => p.path.path?.carrier_id === 4)).toBe(false)
    expect(flows.nics[0].sendBps).toBe(1_000_000)
  })
})

describe('MpRuntimePanel', () => {
  function mountPanel(runtime: MpRuntimeInfo | null, props: Record<string, unknown> = {}, stubs: Record<string, unknown> = {}) {
    return mount(MpRuntimePanel, {
      props: { runtime, mpConfig: { ...DEFAULT_MP_CONFIG(), enabled: true }, ...props },
      global: mpGlobal(stubs),
    })
  }

  it('renders the session overview, pipeline and path rows', async () => {
    const wrapper = mountPanel(sample(10_000, 0, 0, 0))
    await wrapper.setProps({ runtime: sample(12_000, 250_000, 200_000, 4) })
    expect(wrapper.find('[data-testid="mp-runtime-path-count"]').text()).toBe('1 / 2')
    expect(wrapper.find('[data-testid="mp-runtime-total-send"]').text()).toContain('1.00 Mbps')
    // NIC-level state lives in MpEgressPanel, not in the per-session panel
    expect(wrapper.find('[data-testid="mp-runtime-egress-card"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="mp-egress-cake"]').exists()).toBe(false)
    expect(wrapper.findAll('[data-testid="mp-runtime-peer"]')).toHaveLength(1)
    const rows = wrapper.findAll('[data-testid="mp-runtime-path-row"]')
    expect(rows).toHaveLength(2)
    expect(rows[0].find('[data-testid="mp-path-rates"]').text()).toContain('1.00 Mbps')
    // target 0 is shown as paused, and the matched user policy is labelled
    expect(rows[1].text()).toContain('mp_rt.paused')
    expect(rows[1].find('[data-testid="mp-path-policy"]').text()).toBe('mp_policy.pause')
    expect(rows[0].find('[data-testid="mp-path-policy"]').exists()).toBe(false)
    // how many paths carry data, and the chart of NIC → path send rates beside it
    expect(wrapper.find('[data-testid="mp-runtime-selection"]').text()).toBe('mp_rt.selection')
    for (const gone of ['mp-runtime-decision', 'mp-utility', 'mp-max-flow', 'mp-graph-edge']) {
      expect(wrapper.find(`[data-testid="${gone}"]`).exists(), gone).toBe(false)
    }
    const sankey = wrapper.findComponent(MpFlowSankey)
    expect(sankey.exists()).toBe(true)
    expect(sankey.props('nics')).toEqual([
      { id: 'eth0', sendBps: 1_000_000, budgetBps: 9_000_000 },
      { id: 'wwan0', sendBps: 0, budgetBps: undefined },
    ])
    expect(sankey.props('paths')).toHaveLength(2)
  })

  it('switches the congestion control with its parameters', async () => {
    const wrapper = mountPanel(sample(10_000, 0, 0, 0), { initialStep: 'cc' }, { MpSchedulerPanel: false })
    expect(wrapper.find('[data-testid="mp-runtime-cc-apply"]').attributes('disabled')).toBeDefined()
    await wrapper.find('[data-testid="mp-runtime-cc-select"]').setValue('brutal')
    await wrapper.find('[data-testid="mp-tunable-up_mbps"]').setValue('80')
    const apply = wrapper.find('[data-testid="mp-runtime-cc-apply"]')
    expect(apply.attributes('disabled')).toBeUndefined()
    await apply.trigger('click')
    expect(wrapper.emitted('set-congestion-control')).toEqual([[
      { scheduler: 'brutal', params: { up_mbps: 80, down_mbps: 0, disable_loss_compensation: false } },
    ]])
  })

  it('offers no congestion control switch for a standalone session', () => {
    const rt = sample(10_000, 0, 0, 0)
    rt.peers![0].standalone = true
    const wrapper = mountPanel(rt, { initialStep: 'cc' })
    expect(wrapper.find('[data-testid="mp-runtime-cc-select"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('mp_rt.cc.standalone_note')
  })

  it('emits policy edits for path actions', async () => {
    const wrapper = mountPanel(sample(10_000, 0, 0, 0))
    const rows = wrapper.findAll('[data-testid="mp-runtime-path-row"]')
    await rows[0].find('[data-testid="mp-path-pin"]').trigger('click')
    await rows[0].find('[data-testid="mp-path-exclude"]').trigger('click')
    expect(rows[0].find('[data-testid="mp-path-clear"]').exists()).toBe(false)
    await rows[1].find('[data-testid="mp-path-clear"]').trigger('click')
    expect(wrapper.emitted('set-policy')).toEqual([
      [{ match_egress_device: 'eth0', match_carrier_kind: 'udp', match_remote_endpoint: '1.2.3.4:11010' }, 'pin'],
      [{ match_egress_device: 'eth0', match_carrier_kind: 'udp', match_remote_endpoint: '1.2.3.4:11010' }, 'exclude'],
      [{ match_egress_device: 'wwan0', match_carrier_kind: 'faketcp', match_remote_endpoint: '1.2.3.4:11010' }, null],
    ])
  })

  it('disables actions while a patch is in flight', () => {
    const wrapper = mountPanel(sample(10_000, 0, 0, 0), { busy: true })
    expect(wrapper.find('[data-testid="mp-path-pin"]').attributes('disabled')).toBeDefined()
  })

  it('shows the reconnect banner and emits reconnect', async () => {
    const rt = sample(10_000, 0, 0, 0)
    rt.peers![0].reconnect_required = true
    rt.peers![0].desired_congestion_control = 'brutal'
    const wrapper = mountPanel(rt, { initialStep: 'cc' })
    expect(wrapper.find('[data-testid="mp-runtime-reconnect"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('→ brutal')
    await wrapper.find('[data-testid="mp-runtime-reconnect-btn"]').trigger('click')
    expect(wrapper.emitted('reconnect')).toHaveLength(1)
  })

  it("shows the Brutal rate as the Autorate allocation under the peer's download", async () => {
    const rt = sample(10_000, 0, 0, 0)
    Object.assign(rt.peers![0], {
      effective_congestion_control: 'brutal',
      brutal_tx_bps: 50_000_000,
      peer_advertised_rx_bps: 20_000_000,
    })
    rt.peers![0].paths![0].brutal_ack_rate = 0.85
    const wrapper = mountPanel(rt, { initialStep: 'cc' })
    const brutal = wrapper.find('[data-testid="mp-runtime-brutal"]').text()
    expect(brutal).toContain('50.0 Mbps')
    expect(brutal).toContain('20.0 Mbps')
    // The only active path was allocated 8 Mbit/s (the paused one does not
    // count): that is the effective rate, the last figure of the equation.
    expect(brutal).toMatch(/=\D*8\.00 Mbps\s*$/)

    // Allocation above the peer's receive limit: the limit wins.
    rt.peers![0].paths![0].target_rate_bps = 90_000_000
    const capped = mountPanel(rt, { initialStep: 'cc' }).find('[data-testid="mp-runtime-brutal"]').text()
    expect(capped).toContain('90.0 Mbps')
    expect(capped).toMatch(/=\D*20\.0 Mbps\s*$/)
    // No receive limit: the allocation is the rate, above the starting rate.
    rt.peers![0].peer_advertised_rx_bps = undefined
    const above = mountPanel(rt, { initialStep: 'cc' }).find('[data-testid="mp-runtime-brutal"]').text()
    expect(above).toMatch(/=\D*90\.0 Mbps\s*$/)
    // the step bar switches the detail to the paths
    await wrapper.find('[data-testid="mp-step-paths"]').trigger('click')
    await new Promise(r => setTimeout(r, 400))
    expect(wrapper.find('[data-testid="mp-runtime-path-row"]').text()).toContain('0.85')
  })

  it('distinguishes an idle QUIC rate from a nonzero target and names standby chart paths', async () => {
    const runtime = (time: number) => {
      const rt = sample(time, 0, 0, 0)
      Object.assign(rt.peers![0], { effective_congestion_control: 'brutal', brutal_tx_bps: 10_000_000 })
      rt.peers![0].paths![0].target_rate_bps = 10_000_000
      return rt
    }
    const wrapper = mountPanel(runtime(10_000), { initialStep: 'cc' })
    await wrapper.setProps({ runtime: runtime(11_000) })
    expect(wrapper.find('[data-testid="mp-runtime-overview"]').text()).toContain('QUIC')
    expect(wrapper.find('[data-testid="mp-runtime-total-send"]').text()).toContain('0 bps')
    expect(wrapper.find('[data-testid="mp-runtime-brutal"]').text()).toContain('10.0 Mbps')
    expect(wrapper.find('[data-testid="mp-runtime-target-note"]').exists()).toBe(true)
    await wrapper.find('[data-testid="mp-step-paths"]').trigger('click')
    await new Promise(r => setTimeout(r, 400))
    const chart = wrapper.findComponent(MpFlowSankey)
    const standby = chart.props('paths').find((path: any) => path.path.lifecycle_state === 'standby')
    expect(chart.props('pathName')(standby)).toContain('standby')
  })

  it('gives every pipeline step its name as a title, so a phone can hide the label and keep the name', () => {
    const wrapper = mountPanel(sample(10_000, 0, 0, 0))
    for (const [id, key] of [['classify', 'classify'], ['cc', 'cc'], ['paths', 'paths'], ['egress', 'egress']]) {
      const step = wrapper.find(`[data-testid="mp-step-${id}"]`)
      expect(step.attributes('title')).toBe(`mp_rt.pipe.${key}`)
      expect(step.find('.mp-step-label').exists()).toBe(true)
    }
  })

  it('shows FakeTCP upgrade failures and the plain TCP fallback only when there are failures', () => {
    expect(mountPanel(sample(10_000, 0, 0, 0)).find('[data-testid="mp-runtime-faketcp-upgrade"]').exists()).toBe(false)
    const rt = sample(10_000, 0, 0, 0)
    rt.peers![0].faketcp_upgrade = { failures: '3', consecutive_failures: 2, last_error: 'handshake timed out', plain_tcp_fallback: true }
    const tag = mountPanel(rt).find('[data-testid="mp-runtime-faketcp-upgrade"]')
    expect(tag.text()).toContain('mp_rt.faketcp_upgrade_failures')
    expect(tag.text()).toContain('mp_rt.faketcp_plain_tcp_fallback')
    expect(tag.attributes('title')).toBe('handshake timed out')
  })

  it('does not claim MP/limit state when the saved config is unavailable', () => {
    // CLI/TOML-started instances have no config readable through the client.
    const wrapper = mount(MpRuntimePanel, {
      props: { runtime: sample(10_000, 0, 0, 0), mpConfig: null },
      global: mpGlobal(),
    })
    // a non-standalone MP-managed peer proves MP is on
    expect(wrapper.find('[data-testid="mp-runtime-mp-state"]').text()).toContain('mp_rt.mp_on')

    const standaloneOnly = sample(10_000, 0, 0, 0, { egress: [] })
    standaloneOnly.peers![0].standalone = true
    const w2 = mount(MpRuntimePanel, { props: { runtime: standaloneOnly, mpConfig: null }, global: mpGlobal() })
    expect(w2.find('[data-testid="mp-runtime-mp-state"]').text()).toContain('mp_rt.mp_unknown')
  })

  it('renders MP-managed and standalone sessions of the same peer separately', () => {
    const rt = sample(10_000, 0, 0, 0)
    rt.peers!.push({ ...rt.peers![0], standalone: true, paths: [{ path: { carrier_id: 9, local_addr: '0.0.0.0:1', remote_addr: '127.0.0.1:16190' }, carrier_kind: 'udp-direct' }] })
    const wrapper = mountPanel(rt)
    expect(wrapper.findAll('[data-testid="mp-runtime-peer"]')).toHaveLength(2)
    expect(wrapper.findAll('[data-testid="mp-runtime-path-row"]')).toHaveLength(3)
  })

  it('labels each path with its peer-observed public address', () => {
    const s = sample(10_000, 0, 0, 0)
    s.peers![0].paths![0].observed_public_addr = '203.0.113.7:40000'
    const rows = mountPanel(s).findAll('[data-testid="mp-runtime-path-row"]')
    expect(rows[0].find('[data-testid="mp-path-wan"]').text()).toBe('WAN 203.0.113.7:40000')
    expect(rows[1].find('[data-testid="mp-path-wan"]').exists()).toBe(false)
  })

  it('says why a path is passed over and whether its probes keep timing out', () => {
    const s = sample(10_000, 0, 0, 0)
    Object.assign(s.peers![0].paths![1], {
      windowed_min_rtt_micros: 47_000,
      first_hop_loss: 1,
      backed_off: true,
      not_selected_reason: 'lossy-first-hop',
    })
    const rows = mountPanel(s).findAll('[data-testid="mp-runtime-path-row"]')
    expect(rows[1].find('[data-testid="mp-path-not-selected"]').text()).toContain('lossy-first-hop')
    expect(rows[1].find('[data-testid="mp-path-backed-off"]').exists()).toBe(true)
    expect(rows[0].find('[data-testid="mp-path-not-selected"]').exists()).toBe(false)
    expect(rows[0].find('[data-testid="mp-path-backed-off"]').exists()).toBe(false)
  })

  it('names a relay path by its first relay node, not its virtual addresses', () => {
    const s = sample(10_000, 0, 0, 0)
    s.peers![0].paths![1] = {
      ...s.peers![0].paths![1],
      carrier_kind: 'relay-next-hop',
      first_hop_peer_id: 7,
      egress_device: '',
      local_resource: 'relay-next-hop:7:42',
      observed_public_addr: '[fd4d::1]:44443',
      path: { carrier_id: 5, local_addr: '[fd4d::1]:44443', remote_addr: '[fd4d::2]:44443' },
    }
    const rows = mountPanel(s, { peerNames: { 7: 'tencent' } }).findAll('[data-testid="mp-runtime-path-row"]')
    expect(rows[1].find('[data-testid="mp-path-route"]').text()).toBe('tencent')
    expect(rows[1].text()).not.toContain('fd4d')
    expect(rows[1].text()).not.toContain('relay-next-hop:7')
    expect(rows[1].find('[data-testid="mp-path-wan"]').exists()).toBe(false)
    // A direct path shows its peer's address.
    expect(rows[0].find('[data-testid="mp-path-route"]').text()).toBe(s.peers![0].paths![0].path!.remote_addr)
  })

  it('shows 0% loss when proto3 JSON omitted a zero loss_rate', () => {
    const wrapper = mountPanel(sample(10_000, 0, 0, 0))
    expect(wrapper.find('[data-testid="mp-runtime-path-row"]').text()).toContain('0.0%')
  })

  it('renders an empty state without runtime data', () => {
    const wrapper = mountPanel(null)
    expect(wrapper.text()).toContain('mp_runtime_empty')
  })
})

describe('MpEgressPanel', () => {
  function mountEgress(runtime: MpRuntimeInfo | null, props: Record<string, unknown> = {}) {
    return mount(MpEgressPanel, {
      props: { runtime, mpConfig: { ...DEFAULT_MP_CONFIG(), enabled: true }, ...props },
      global: mpGlobal(),
    })
  }

  it('shows each NIC with its one CAKE send queue', async () => {
    const wrapper = mountEgress(sample(10_000, 0, 0, 0))
    await wrapper.setProps({ runtime: sample(12_000, 250_000, 200_000, 4) })
    const cards = wrapper.findAll('[data-testid="mp-runtime-egress-card"]')
    expect(cards).toHaveLength(1)
    // the wire rate is differenced from the queue's sent bytes
    expect(cards[0].find('[data-testid="mp-egress-send"]').text()).toBe('800.0 kbps')
    const cake = cards[0].findAll('[data-testid="mp-egress-cake"]')
    expect(cake).toHaveLength(1)
    expect(cake[0].find('[data-testid="mp-cake-rate"]').text()).toBe('9.00 Mbps')
    expect(cake[0].find('[data-testid="mp-cake-backlog"]').text()).toBe('2.9 KiB')
    expect(cake[0].find('[data-testid="mp-cake-flows"]').text()).toBe('2 / 1 / 0')
    // queue drops, the over-memory ones and the reliable-stream queues' drops are separate figures
    const drops = cake[0].find('[data-testid="mp-cake-drops"]').text()
    expect(drops).toContain('4')
    expect(drops).toContain('7')
    expect(drops).toContain('3')
    // the per-peer queues are gone
    expect(wrapper.find('[data-testid="mp-runtime-sqm-queue"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="mp-runtime-limit"]').text()).toBe('mp_rt.unlimited')
  })

  it('shows an estimate no measurement has moved as not measured', () => {
    const s = sample(10_000, 0, 0, 0)
    const nic = s.egress![0]
    s.egress = [{ ...nic, autorate_estimate_bps: 50_000_000, autorate_measured: false }]
    const card = mountEgress(s).find('[data-testid="mp-runtime-egress-card"]')
    expect(card.find('[data-testid="mp-egress-estimate-unmeasured"]').text()).toBe('mp_rt.autorate_unmeasured')

    s.egress[0].autorate_measured = true
    s.egress[0].autorate_estimate_bps = 30_000_000
    const measured = mountEgress(s).find('[data-testid="mp-runtime-egress-card"]')
    expect(measured.find('[data-testid="mp-egress-estimate-unmeasured"]').exists()).toBe(false)
    expect(measured.text()).toContain('30.0 Mbps')
  })

  it('shows no send queue section while the egress has no queue yet', () => {
    const s = sample(10_000, 0, 0, 0)
    delete s.egress![0].cake
    const wrapper = mountEgress(s)
    expect(wrapper.find('[data-testid="mp-runtime-egress-card"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="mp-egress-cake"]').exists()).toBe(false)
  })

  it('feeds the NIC chart with send, estimate, ceiling and queue-delay series', async () => {
    const wrapper = mountEgress(sample(10_000, 0, 0, 0))
    await wrapper.setProps({ runtime: sample(11_000, 125_000, 100_000, 0) })
    const chart = wrapper.findAllComponents(NetworkChart)[0]
    const series = chart.props('series') as Array<{ label: string, data: Array<number | null>, axis?: string }>
    expect(series.map(s => s.label)).toEqual(['mp_rt.send_rate', 'mp_rt.autorate_estimate', 'mp_rt.ceiling', 'mp_rt.queue_delay'])
    expect(series[0].data.at(-1)).toBe(800_000)
    expect(series[3].axis).toBe('y1')
    expect(chart.props('labels')).toHaveLength(2)
    // the send queue has its own chart: what waits, and for how long
    const queue = wrapper.findAllComponents(NetworkChart)[1].props('series') as Array<{ label: string, data: Array<number | null>, axis?: string }>
    expect(queue.map(s => s.label)).toEqual(['mp_rt.cake_backlog', 'mp_rt.cake_delay_avg'])
    expect(queue[0].data.at(-1)).toBe(3000)
    expect(queue[1].data.at(-1)).toBe(2.5)
    expect(queue[1].axis).toBe('y1')
  })

  it('takes the limit from the runtime ceiling when the saved config is unavailable', () => {
    const wrapper = mountEgress(sample(10_000, 0, 0, 0), { mpConfig: null })
    expect(wrapper.find('[data-testid="mp-runtime-limit"]').text()).toContain('800.0 kbps')
    expect(wrapper.find('[data-testid="mp-egress-sqm-state"]').text()).toBe('mp_rt.sqm_on')
    const none = mountEgress(sample(10_000, 0, 0, 0, { egress: [] }), { mpConfig: null })
    expect(none.find('[data-testid="mp-runtime-limit"]').text()).toContain('mp_rt.unknown')
  })
})

describe('NetworkChart series mode', () => {
  it('shows the latest value of every series in the legend', () => {
    const wrapper = mount(NetworkChart, {
      props: {
        labels: ['a', 'b'],
        series: [
          { label: 'send', color: 'red', data: [1_000_000, 2_000_000] },
          { label: 'delay', color: 'blue', data: [3, 4.25], unit: 'ms', axis: 'y1' },
          { label: 'backlog', color: 'green', data: [null, 2048], unit: 'bytes' },
        ],
      },
      global: mpGlobal({ NetworkChart: false }),
    })
    const legend = wrapper.find('[data-testid="chart-legend"]').text()
    expect(legend).toContain('send: 2 Mbps')
    expect(legend).toContain('delay: 4.3 ms')
    expect(legend).toContain('backlog: 2 KB')
  })
})
