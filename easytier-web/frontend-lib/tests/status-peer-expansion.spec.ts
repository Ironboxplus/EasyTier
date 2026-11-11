// Status.vue lists the peers with PeerList: every row
// is clickable and expands (accordion-style) to that peer's MP info, reusing
// MpRuntimePanel filtered by peer_id instead of a separate standalone MP card.
import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import Status from '../src/components/Status.vue'
import { DEFAULT_MP_CONFIG } from '../src/types/mpConfig'
import { mpGlobal } from './primevueStubs'

function networkInst(overrides: Record<string, unknown> = {}) {
  return {
    instance_id: 'inst-1',
    running: true,
    error_msg: '',
    detail: {
      dev_name: 'tun0',
      my_node_info: {
        peer_id: 100,
        hostname: 'self-host',
        version: '1.0.0',
      },
      events: [],
      routes: [],
      peers: [],
      // peer 42 has an active MP session (mp_runtime below); peer 7 does not.
      peer_route_pairs: [
        { route: { peer_id: 42, ipv4_addr: '10.0.0.2', hostname: 'peer-a', version: '1.0.0' }, peer: { peer_id: 42, conns: [] } },
        { route: { peer_id: 7, ipv4_addr: '10.0.0.3', hostname: 'peer-b', version: '1.0.0' }, peer: { peer_id: 7, conns: [] } },
      ],
      running: true,
      mp_runtime: {
        sample_time_ms: 1000,
        peers: [{
          peer_id: 42,
          paths: [{
            path: { carrier_id: 1, local_addr: '192.168.1.2:5000', remote_addr: '1.2.3.4:11010' },
            carrier_kind: 'udp',
            egress_device: 'eth0',
            lifecycle_state: 'available',
          }],
          active_paths: [],
          effective_congestion_control: 'bbr',
        }],
        egress: [],
      },
      ...overrides,
    },
  }
}

function mountStatus(inst = networkInst()) {
  return mount(Status, {
    props: { curNetworkInst: inst as any, mpConfig: { ...DEFAULT_MP_CONFIG(), enabled: true } },
    global: mpGlobal(),
  })
}

describe('Status peer row expansion', () => {
  it('renders the upstream peer rows collapsed, with no MP panel until a row is clicked', () => {
    const wrapper = mountStatus()
    expect(wrapper.find('[data-testid="mp-runtime-panel"]').exists()).toBe(false)
    // self + peer 42 + peer 7
    expect(wrapper.findAll('[data-testid="peer-row"]')).toHaveLength(3)
  })

  it('expands a peer with an MP session to its own filtered MpRuntimePanel', async () => {
    const wrapper = mountStatus()
    const rows = wrapper.findAll('[data-testid="peer-row"]')
    await rows[1].trigger('click') // peer 42

    const expansion = wrapper.find('[data-testid="peer-mp-expansion-42"]')
    expect(expansion.exists()).toBe(true)
    expect(expansion.find('[data-testid="mp-runtime-panel"]').exists()).toBe(true)
    expect(expansion.find('[data-testid="mp-runtime-path-row"]').exists()).toBe(true)
    expect(expansion.text()).toContain('eth0')
    // scoped to peer 42: no "not active" note for a peer that does have a session
    expect(expansion.find('[data-testid="mp-runtime-peer-inactive"]').exists()).toBe(false)
  })

  it('expands a peer without an MP session to a short "not active" note, one row open at a time', async () => {
    const wrapper = mountStatus()
    const rows = wrapper.findAll('[data-testid="peer-row"]')
    await rows[1].trigger('click') // open peer 42
    expect(wrapper.find('[data-testid="peer-mp-expansion-42"]').exists()).toBe(true)

    await rows[2].trigger('click') // open peer 7 -> accordion closes peer 42
    expect(wrapper.find('[data-testid="peer-mp-expansion-42"]').exists()).toBe(false)

    const expansion7 = wrapper.find('[data-testid="peer-mp-expansion-7"]')
    expect(expansion7.exists()).toBe(true)
    expect(expansion7.find('[data-testid="mp-runtime-peer-inactive"]').exists()).toBe(true)
    expect(expansion7.text()).toContain('mp_rt.peer_not_active')
  })

  it('collapses when the expanded row is clicked again', async () => {
    const wrapper = mountStatus()
    const rows = wrapper.findAll('[data-testid="peer-row"]')
    await rows[1].trigger('click')
    expect(wrapper.find('[data-testid="peer-mp-expansion-42"]').exists()).toBe(true)
    await rows[1].trigger('click')
    expect(wrapper.find('[data-testid="peer-mp-expansion-42"]').exists()).toBe(false)
  })

  it('never shows a standalone MP card outside the peer rows (no duplicated global MP view)', async () => {
    const wrapper = mountStatus()
    expect(wrapper.find('[data-testid="status-mp-card"]').exists()).toBe(false)
    const rows = wrapper.findAll('[data-testid="peer-row"]')
    await rows[1].trigger('click')
    // exactly one MpRuntimePanel is mounted (the expanded row's), not a global one plus a per-row one
    expect(wrapper.findAll('[data-testid="mp-runtime-panel"]')).toHaveLength(1)
  })
})
