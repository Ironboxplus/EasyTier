// The path map: one row per direct path between this machine and the peer, the
// upper lane what we send, the lower lane what the peer sends back; the exits
// on both sides grouped; relays folded. The controls emit `edit` / `set-policy`.
import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import PathMap from '../src/components/runway/PathMap.vue'
import { pathKey, type PathRates } from '../src/modules/mpRuntime'
import { addrScope, hostOf, laneRate, laneWidth, pathMap } from '../src/modules/pathMap'
import { reportedView } from '../src/modules/pathRunway'
import { DEFAULT_MP_CONFIG, DEFAULT_MP_SELECTION_CONFIG, normalizeMpConfig, type MpPathStatus, type MpPeerStatus } from '../src/types/mpConfig'
import { mpGlobal } from './primevueStubs'

vi.mock('@vueuse/core', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vueuse/core')>()),
  useElementSize: () => ({ width: { value: 900 }, height: { value: 300 } }),
}))

function path(id: number, kind: string, nic: string, remote: string, rttMicros: number, extra: Partial<MpPathStatus> = {}): MpPathStatus {
  return {
    path: { carrier_id: id, local_addr: `192.0.2.${id}:5000`, remote_addr: remote },
    carrier_kind: kind,
    egress_device: nic,
    lifecycle_state: 'available',
    windowed_min_rtt_micros: rttMicros,
    tier: kind === 'relay-next-hop' ? 'backup' : 'primary',
    rtt_bias_micros: 0,
    ranked_rtt_micros: rttMicros,
    ...extra,
  }
}

// Two cards here; the peer has a public address and a LAN address. Path 3 is the best and sends.
function peer(selected: number[] = [3]): MpPeerStatus {
  const flag = (id: number) => (selected.includes(id) ? { selected: true } : {})
  return {
    peer_id: 42,
    active_tier: 'primary',
    switch_threshold_micros: 5000,
    paths: [
      path(1, 'udp-punch', 'wlan0', '203.0.113.9:4000', 18_000, { observed_public_addr: '198.51.100.7:1234', ...flag(1) }),
      path(2, 'udp-direct', 'eth0', '192.168.1.9:11010', 20_000, { loss_rate: 0.12, recent_loss: 0.12, not_selected_reason: 'lossy-path' }),
      path(3, 'udp-punch', 'eth0', '203.0.113.9:4001', 15_000, flag(3)),
      path(4, 'relay-next-hop', '', '198.18.0.9:11010', 97_000, { first_hop_peer_id: 7, local_resource: 'relay-next-hop:7', ...flag(4) }),
      path(5, 'udp-punch', 'wlan0', '203.0.113.9:4002', 22_000, flag(5)),
    ],
    active_paths: [],
  }
}

const rates = (r: Record<number, PathRates>) => {
  const p = peer()
  return new Map(Object.entries(r).map(([id, v]) => [pathKey(42, p.paths!.find(x => x.path!.carrier_id === Number(id))!), v]))
}
const scopeName = (s: string) => s

describe('path map model', () => {
  it('groups the rows under the card they leave by, the best card first, relays apart', () => {
    const m = pathMap(reportedView(peer()), 42, new Map(), scopeName)
    expect(m.rows.map(r => r.path.status.path!.carrier_id)).toEqual([3, 2, 1, 5])
    expect(m.relays.map(r => r.path.status.path!.carrier_id)).toEqual([4])
    expect(m.localPorts.map(p => [p.label, p.from, p.to])).toEqual([['eth0', 0, 1], ['wlan0', 2, 3]])
    // the address the far end sees is shown under the card when the core knows it
    expect(m.localPorts[1].sub).toBe('198.51.100.7')
  })

  it('names each far address by its scope, one port per run of rows', () => {
    const m = pathMap(reportedView(peer()), 42, new Map(), scopeName)
    expect(m.remotePorts.map(p => [p.label, p.sub, p.from, p.to])).toEqual([
      ['wan', '203.0.113.9', 0, 0], ['lan', '192.168.1.9', 1, 1], ['wan', '203.0.113.9', 2, 3],
    ])
  })

  it('carries each path\'s two rates', () => {
    const m = pathMap(reportedView(peer()), 42, rates({ 3: { sendBps: 4_100_000, recvBps: 900_000 } }), scopeName)
    expect(m.rows[0]).toMatchObject({ sendBps: 4_100_000, recvBps: 900_000 })
    expect(m.rows[1]).toMatchObject({ sendBps: 0, recvBps: 0 })
  })

  it('tells LAN, public and IPv6 addresses apart', () => {
    expect(['10.1.2.3', '172.20.0.1', '192.168.6.2', 'fe80::1', 'fd00::2'].map(addrScope)).toEqual(['lan', 'lan', 'lan', 'lan', 'lan'])
    expect(addrScope('221.2.164.42')).toBe('wan')
    expect(addrScope('172.32.0.1')).toBe('wan')
    expect(addrScope('2001:db8::1')).toBe('v6')
    expect(hostOf('[2001:db8::1]:11010')).toBe('2001:db8::1')
    expect(hostOf('1.2.3.4:5')).toBe('1.2.3.4')
  })

  it('draws a lane 3 to 9 px wide, growing with the log of the rate', () => {
    expect(laneWidth(0)).toBe(3)
    expect(laneWidth(1e6)).toBeGreaterThan(laneWidth(1e5))
    expect(laneWidth(1e10)).toBe(9)
    expect([laneRate(50_000), laneRate(4_120_000), laneRate(48_600_000)]).toEqual(['<0.1', '4.1', '49'])
  })
})

// ---- the component ----------------------------------------------------------------

function mountMap(extra: Record<string, unknown> = {}) {
  const mpConfig = normalizeMpConfig({ ...DEFAULT_MP_CONFIG(), enabled: true, kmax: 2 })
  const wrapper = mount(PathMap, {
    props: { peer: peer([3, 5]), mpConfig, peerName: 'DESKTOP', rates: rates({ 3: { sendBps: 4_100_000, recvBps: 900_000 }, 1: { recvBps: 500_000 } }), ...extra },
    global: mpGlobal(),
    attachTo: document.body,
  })
  return { wrapper, mpConfig }
}

type Edit = [string, (mp: ReturnType<typeof normalizeMpConfig>) => ReturnType<typeof normalizeMpConfig>]
const lastEdit = (wrapper: ReturnType<typeof mountMap>['wrapper']) => {
  const edits = wrapper.emitted('edit') as Edit[] | undefined
  expect(edits?.length).toBeGreaterThan(0)
  return edits![edits!.length - 1]
}
const states = (wrapper: ReturnType<typeof mountMap>['wrapper']) =>
  wrapper.findAll('[data-testid="path-map-path"][data-relay="false"]').map(n => n.attributes('data-state'))

describe('PathMap', () => {
  it('draws one row per direct path and folds the idle relays', () => {
    const { wrapper } = mountMap()
    // eth0: 3 sends, 2 loses too much; wlan0: 5 sends, 1 ranks ahead of it but not by the switch threshold
    expect(states(wrapper)).toEqual(['sending', 'lossy', 'sending', 'held'])
    expect(wrapper.findAll('[data-relay="true"]')).toHaveLength(0)
    expect(wrapper.find('[data-testid="path-map-relays"]').text()).toContain('mp_map.relays')
    expect(wrapper.findAll('[data-testid="path-map-port-local"]')).toHaveLength(2)
    wrapper.unmount()
  })

  it('sends on the chosen paths and shows the return traffic on whichever path the peer uses', () => {
    const { wrapper } = mountMap()
    const lanes = wrapper.findAll('line[data-lane]').map(n => n.attributes('data-lane'))
    // path 3: up + down; path 2: lossy, nothing back; path 5: up (chosen, no traffic yet), idle down; path 1: idle up, down
    expect(lanes).toEqual(['up', 'down', 'lossy', 'up', 'idle', 'idle', 'down'])
    expect(wrapper.findAll('[data-testid="path-map-rate-up"]').map(n => n.text())).toEqual(['4.1'])
    expect(wrapper.findAll('[data-testid="path-map-rate-down"]').map(n => n.text())).toEqual(['0.9', '0.5'])
    wrapper.unmount()
  })

  it('opens the relays on a click', async () => {
    const { wrapper } = mountMap()
    await wrapper.find('[data-testid="path-map-relays"]').trigger('click')
    expect(wrapper.findAll('[data-testid="path-map-path"][data-relay="true"]')).toHaveLength(1)
    wrapper.unmount()
  })

  it('shows a relay that carries data without being asked', () => {
    const p = peer([4])
    const { wrapper } = mountMap({ peer: p })
    expect(wrapper.findAll('[data-testid="path-map-path"][data-relay="true"]')).toHaveLength(1)
    wrapper.unmount()
  })

  it('the stepper emits a kmax edit and previews it until the core reports', async () => {
    const { wrapper, mpConfig } = mountMap()
    await wrapper.find('[data-testid="path-map-kmax-plus"]').trigger('click')
    const [, update] = lastEdit(wrapper)
    expect(update(mpConfig).kmax).toBe(3)
    expect(update(mpConfig).selection).toEqual(DEFAULT_MP_SELECTION_CONFIG())
    expect(wrapper.find('[data-testid="path-map-kmax-value"]').text()).toBe('3')
    expect(states(wrapper).filter(s => s === 'sending')).toHaveLength(3)
    await wrapper.setProps({ peer: peer([3, 5, 1]), mpConfig: normalizeMpConfig({ ...DEFAULT_MP_CONFIG(), enabled: true, kmax: 3 }) })
    expect(wrapper.find('[data-testid="path-map-kmax-value"]').text()).toBe('3')
    expect(states(wrapper)).toEqual(['sending', 'lossy', 'sending', 'sending'])
    wrapper.unmount()
  })

  it('does not go below one path, and edits nothing while a patch is in flight', async () => {
    const one = mountMap({ mpConfig: normalizeMpConfig({ ...DEFAULT_MP_CONFIG(), enabled: true, kmax: 1 }) })
    await one.wrapper.find('[data-testid="path-map-kmax-minus"]').trigger('click')
    expect(one.wrapper.emitted('edit')).toBeUndefined()
    one.wrapper.unmount()
    const busy = mountMap({ busy: true })
    await busy.wrapper.find('[data-testid="path-map-kmax-plus"]').trigger('click')
    expect(busy.wrapper.emitted('edit')).toBeUndefined()
    busy.wrapper.unmount()
  })

  it('a click on a path opens it; its controls edit the rule of its kind and its own policy', async () => {
    const { wrapper, mpConfig } = mountMap()
    await wrapper.find('[data-testid="path-map-path"]').trigger('click')
    const detail = document.body.querySelector('[data-testid="runway-detail"]')
    expect(detail).not.toBeNull()
    expect(detail!.querySelector('[data-testid="runway-detail-send"]')!.textContent).toContain('4.1')
    expect(detail!.querySelector('[data-testid="runway-detail-recv"]')!.textContent).toContain('0.9')
    ;(detail!.querySelector('[data-testid="runway-bias-plus"]') as HTMLButtonElement).click()
    const [, update] = lastEdit(wrapper)
    expect(update(mpConfig).selection.kind_rules).toEqual([{ carrier_kind: 'udp-punch', ip_family: 'v4', tier: 'primary', rtt_bias_ms: 1 }])
    wrapper.unmount()
  })

  // The web console shows the status page in a drawer that closes on Escape (a listener on the
  // document); Escape in an open popover must close the popover only.
  it('Escape closes an open path popover and goes no further', async () => {
    const { wrapper } = mountMap()
    const outer = vi.fn()
    document.addEventListener('keydown', outer)
    await wrapper.find('[data-testid="path-map-path"]').trigger('click')
    expect(document.body.querySelector('[data-testid="runway-detail"]')).not.toBeNull()
    document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    await wrapper.vm.$nextTick()
    await new Promise(r => setTimeout(r, 0))
    expect(outer).not.toHaveBeenCalled()
    expect(document.body.querySelector('[data-testid="runway-detail"]')).toBeNull()
    // with no popover open, Escape reaches the page as before
    document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    expect(outer).toHaveBeenCalledTimes(1)
    document.removeEventListener('keydown', outer)
    wrapper.unmount()
  })
})
