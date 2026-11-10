// The path runway: the model that places the paths of a peer and turns a
// dragged handle into a selection rule, and the component that wires the
// handles to `edit` events (test 9).
import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import PathRunway from '../src/components/runway/PathRunway.vue'
import {
  kindOf,
  kmaxAfterDrag,
  previewView,
  reportedView,
  runwayAxis,
  withKindRule,
  withLossyPercent,
  withSwitchThreshold,
  withUnmeasuredMs,
} from '../src/modules/pathRunway'
import { DEFAULT_MP_CONFIG, DEFAULT_MP_SELECTION_CONFIG, normalizeMpConfig, type MpPathStatus, type MpPeerStatus } from '../src/types/mpConfig'
import { mpGlobal } from './primevueStubs'

vi.mock('@vueuse/core', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vueuse/core')>()),
  useElementSize: () => ({ width: { value: 600 }, height: { value: 100 } }),
}))

const WIDTH = 600

function path(id: number, kind: string, remote: string, rttMicros: number, extra: Partial<MpPathStatus> = {}): MpPathStatus {
  return {
    path: { carrier_id: id, local_addr: `192.0.2.${id}:5000`, remote_addr: remote },
    carrier_kind: kind,
    egress_device: 'eth0',
    lifecycle_state: 'available',
    windowed_min_rtt_micros: rttMicros,
    ...extra,
  }
}

// Built-in rules: direct IPv6 is 3 ms ahead, a relay is the backup.
function peer(selected: number[] = [3, 2]): MpPeerStatus {
  const flag = (id: number) => (selected.includes(id) ? { selected: true } : {})
  return {
    peer_id: 42,
    active_tier: 'primary',
    switch_threshold_micros: 5000,
    paths: [
      path(1, 'udp-direct', '198.18.0.2:11010', 12_400, { tier: 'primary', rtt_bias_micros: 0, ranked_rtt_micros: 12_400, ...flag(1) }),
      path(2, 'udp-direct', '[2001:db8::2]:11010', 13_100, { tier: 'primary', rtt_bias_micros: -3000, ranked_rtt_micros: 13_100, ...flag(2) }),
      path(3, 'udp-direct', '198.18.0.3:11010', 9_200, { tier: 'primary', rtt_bias_micros: 0, ranked_rtt_micros: 9_200, ...flag(3) }),
      path(4, 'relay-next-hop', '198.18.0.9:11010', 40_000, { tier: 'backup', rtt_bias_micros: 0, ranked_rtt_micros: 40_000, first_hop_peer_id: 7 }),
      path(5, 'udp-punch', '203.0.113.5:4000', 30_000, { tier: 'primary', rtt_bias_micros: 0, ranked_rtt_micros: 30_000, loss_rate: 0.18, recent_loss: 0.18, not_selected_reason: 'lossy-path' }),
    ],
    active_paths: [],
  }
}

const idsOf = (paths: { status: MpPathStatus }[]) => paths.map(p => Number(p.status.path!.carrier_id))

describe('runway model: what is shown', () => {
  it('shows the core report: sending first, lanes by tier, lossy ones outside', () => {
    const view = reportedView(peer())
    expect(idsOf(view.lanes.primary)).toEqual([3, 2, 1])
    expect(view.lanes.primary.map(p => p.state)).toEqual(['sending', 'sending', 'standby'])
    expect(idsOf(view.lanes.backup)).toEqual([4])
    expect(idsOf(view.out)).toEqual([5])
    expect(view.out[0].state).toBe('lossy')
    expect(view.activeTier).toBe('primary')
    expect(view.sending).toBe(2)
  })

  it('the shield spans the switch threshold in front of the slowest sending path', () => {
    const view = reportedView(peer())
    // path 2 ranks at 13.1 - 3 = 10.1 ms
    expect(view.shield?.toMs).toBeCloseTo(10.1, 6)
    expect(view.shield?.fromMs).toBeCloseTo(5.1, 6)
  })

  it('a path that ranks ahead of a sending one but is not fast enough is held back', () => {
    const view = reportedView(peer([1, 3]))
    expect(view.lanes.primary.find(p => p.status.path!.carrier_id === 2)?.state).toBe('held')
  })

  it('a preview under the saved rules sends on what the core chose', () => {
    const view = previewView(peer(), DEFAULT_MP_SELECTION_CONFIG(), 2)
    expect(view.lanes.primary.filter(p => p.state === 'sending').map(p => Number(p.status.path!.carrier_id))).toEqual([3, 2])
    expect(idsOf(view.out)).toEqual([5])
  })

  it('a preview with kmax 1 sends on one path', () => {
    const view = previewView(peer(), DEFAULT_MP_SELECTION_CONFIG(), 1)
    expect(view.sending).toBe(1)
  })

  it('a preview with the relay promoted over the direct paths sends on the relay', () => {
    const selection = withKindRule(DEFAULT_MP_SELECTION_CONFIG(), kindOf(peer().paths![3]), { biasMs: -50 })
    const view = previewView(peer(), selection, 1)
    expect(view.lanes.backup.find(p => p.state === 'sending')).toBeUndefined()
    const moved = withKindRule(selection, kindOf(peer().paths![3]), { tier: 'primary' })
    const promoted = previewView(peer(), moved, 1)
    expect(idsOf(promoted.lanes.primary.filter(p => p.state === 'sending'))).toEqual([4])
  })

  it('a higher loss threshold lets the lossy path back in', () => {
    const view = previewView(peer(), withLossyPercent(DEFAULT_MP_SELECTION_CONFIG(), 20), 5)
    expect(view.out).toEqual([])
  })

  it('the stand-in for an unmeasured path moves it on the axis', () => {
    const p = peer()
    p.paths!.push(path(6, 'udp-direct', '198.18.0.6:11010', 0))
    const at = (ms: number) => previewView(p, withUnmeasuredMs(DEFAULT_MP_SELECTION_CONFIG(), ms), 1)
      .lanes.primary.find(x => x.status.path!.carrier_id === 6)!
    expect(at(333).biasedMs).toBe(333)
    expect(at(80).biasedMs).toBe(80)
    expect(at(80).measuredMs).toBeNull()
  })
})

describe('runway model: handles to rules', () => {
  const v6 = kindOf(peer().paths![1])
  const v4 = kindOf(peer().paths![0])

  it('names the kind by carrier and, for a direct path, the IP family', () => {
    expect(v6).toMatchObject({ carrierKind: 'udp-direct', family: 'v6' })
    expect(v4).toMatchObject({ carrierKind: 'udp-direct', family: 'v4' })
    expect(kindOf(peer().paths![3])).toMatchObject({ carrierKind: 'relay-next-hop', family: '' })
  })

  it('a rule equal to the built-in one is not stored', () => {
    expect(withKindRule(DEFAULT_MP_SELECTION_CONFIG(), v6, { biasMs: -3 }).kind_rules).toEqual([])
    expect(withKindRule(DEFAULT_MP_SELECTION_CONFIG(), v4, { tier: 'primary', biasMs: 0 }).kind_rules).toEqual([])
  })

  it('a changed bias or tier is one rule of its kind, replaced on the next change', () => {
    const one = withKindRule(DEFAULT_MP_SELECTION_CONFIG(), v6, { biasMs: 0 })
    expect(one.kind_rules).toEqual([{ carrier_kind: 'udp-direct', ip_family: 'v6', tier: 'primary', rtt_bias_ms: 0 }])
    const two = withKindRule(one, v6, { tier: 'backup' })
    expect(two.kind_rules).toEqual([{ carrier_kind: 'udp-direct', ip_family: 'v6', tier: 'backup', rtt_bias_ms: 0 }])
  })

  it('keeps the other half of a rule when only one of tier and bias changes', () => {
    const one = withKindRule(DEFAULT_MP_SELECTION_CONFIG(), v4, { biasMs: 7 })
    expect(one.kind_rules[0]).toMatchObject({ tier: 'primary', rtt_bias_ms: 7 })
    expect(withKindRule(one, v4, { tier: 'backup' }).kind_rules[0]).toMatchObject({ tier: 'backup', rtt_bias_ms: 7 })
  })

  it('limits the bias to what the core accepts', () => {
    expect(withKindRule(DEFAULT_MP_SELECTION_CONFIG(), v4, { biasMs: 5000 }).kind_rules[0].rtt_bias_ms).toBe(1000)
    expect(withKindRule(DEFAULT_MP_SELECTION_CONFIG(), v4, { biasMs: -5000 }).kind_rules[0].rtt_bias_ms).toBe(-1000)
  })

  it('the switch threshold handle sets the minimum, or the percentage when that is what governs', () => {
    // 10.1 ms ranked, 5 ms minimum: the minimum governs
    const minimum = withSwitchThreshold(DEFAULT_MP_SELECTION_CONFIG(), { fromMs: 5.1, toMs: 10.1, worstRttMs: 13.1 }, 2.1)
    expect(minimum.switch_min_ms).toBe(8)
    expect(minimum.switch_percent).toBe(0)
    // the shield is wider than the 5 ms minimum: the percentage governs
    const percentage = withSwitchThreshold(DEFAULT_MP_SELECTION_CONFIG(), { fromMs: 40, toMs: 50, worstRttMs: 50 }, 30)
    expect(percentage.switch_percent).toBe(40)
    expect(percentage.switch_min_ms).toBe(0)
  })

  it('never writes a zero, which the core reads as the default', () => {
    expect(withSwitchThreshold(DEFAULT_MP_SELECTION_CONFIG(), { fromMs: 5.1, toMs: 10.1, worstRttMs: 13.1 }, 10.1).switch_min_ms).toBe(1)
    expect(withLossyPercent(DEFAULT_MP_SELECTION_CONFIG(), 0).lossy_percent).toBe(1)
    expect(withUnmeasuredMs(DEFAULT_MP_SELECTION_CONFIG(), 0).unmeasured_rtt_ms).toBe(1)
  })

  it('the cut moves by whole rows and stays between one path and the lane size', () => {
    expect(kmaxAfterDrag(2, 1, 3)).toBe(3)
    expect(kmaxAfterDrag(2, 5, 3)).toBe(3)
    expect(kmaxAfterDrag(2, -5, 3)).toBe(1)
    expect(kmaxAfterDrag(1, 1, 0)).toBe(1)
  })

  it('the axis is logarithmic and invertible', () => {
    const axis = runwayAxis(WIDTH)
    for (const ms of [0, 1, 9.2, 100, 333]) expect(axis.ms(axis.x(ms))).toBeCloseTo(ms, 6)
    expect(axis.x(1)).toBeLessThan(axis.x(10))
    expect(axis.x(10) - axis.x(1)).toBeLessThan(axis.x(100) - axis.x(10))
    expect(axis.x(1000)).toBe(axis.x(600))
  })
})

// ---- the component ----------------------------------------------------------------

function mountRunway(selected?: number[]) {
  const mpConfig = normalizeMpConfig({ ...DEFAULT_MP_CONFIG(), enabled: true, kmax: 2 })
  const wrapper = mount(PathRunway, {
    props: { peer: peer(selected), mpConfig, peerName: 'peer-a', peerAddress: '10.0.0.2' },
    global: mpGlobal(),
    attachTo: document.body,
  })
  return { wrapper, mpConfig }
}

type Edit = [string, (mp: ReturnType<typeof normalizeMpConfig>) => ReturnType<typeof normalizeMpConfig>]
const lastEdit = (wrapper: ReturnType<typeof mountRunway>['wrapper']) => {
  const edits = wrapper.emitted('edit') as Edit[] | undefined
  expect(edits?.length).toBeGreaterThan(0)
  return edits![edits!.length - 1]
}

describe('PathRunway', () => {
  it('shows every sending path on the primary lane and the relay on the backup lane', () => {
    const { wrapper } = mountRunway()
    const primary = wrapper.find('[data-testid="runway-lane-primary"]')
    const backup = wrapper.find('[data-testid="runway-lane-backup"]')
    expect(primary.findAll('[data-testid="runway-path"]').map(n => n.attributes('data-state'))).toEqual(['sending', 'sending', 'standby'])
    expect(backup.findAll('[data-testid="runway-path"]')).toHaveLength(1)
    expect(wrapper.findAll('[data-testid="runway-out-item"]')).toHaveLength(1)
    wrapper.unmount()
  })

  it('dragging the cut down one row emits a kmax edit; the update sets kmax', async () => {
    const { wrapper, mpConfig } = mountRunway()
    const handle = wrapper.find('[data-testid="runway-kmax"]')
    expect(handle.text()).toContain('2')
    await handle.trigger('pointerdown', { clientX: 0, clientY: 100, button: 0 })
    await handle.trigger('pointermove', { clientX: 0, clientY: 140 })
    expect(handle.text()).toContain('3')
    await handle.trigger('pointerup', { clientX: 0, clientY: 140 })
    const [, update] = lastEdit(wrapper)
    expect(update(mpConfig).kmax).toBe(3)
    expect(update(mpConfig).selection).toEqual(DEFAULT_MP_SELECTION_CONFIG())
    wrapper.unmount()
  })

  it('a cut released where it started edits nothing', async () => {
    const { wrapper } = mountRunway()
    const handle = wrapper.find('[data-testid="runway-kmax"]')
    await handle.trigger('pointerdown', { clientX: 0, clientY: 100, button: 0 })
    await handle.trigger('pointerup', { clientX: 0, clientY: 100 })
    expect(wrapper.emitted('edit')).toBeUndefined()
    wrapper.unmount()
  })

  it('dragging the shield wider emits the switch threshold', async () => {
    const { wrapper, mpConfig } = mountRunway()
    const axis = runwayAxis(WIDTH)
    const handle = wrapper.find('[data-testid="runway-shield"]')
    const from = axis.x(5.1)
    await handle.trigger('pointerdown', { clientX: from, clientY: 0, button: 0 })
    await handle.trigger('pointermove', { clientX: axis.x(2.1), clientY: 0 })
    await handle.trigger('pointerup', { clientX: axis.x(2.1), clientY: 0 })
    const [, update] = lastEdit(wrapper)
    expect(update(mpConfig).selection.switch_min_ms).toBe(8)
    expect(update(mpConfig).kmax).toBe(2)
    wrapper.unmount()
  })

  it('dragging a dot sideways writes a rule for its kind', async () => {
    const { wrapper, mpConfig } = mountRunway()
    const axis = runwayAxis(WIDTH)
    // the IPv6 path sits at 13.1 - 3 = 10.1 ms; drag it to its real RTT
    const dots = wrapper.find('[data-testid="runway-lane-primary"]').findAll('[data-testid="runway-dot"]')
    const v6Dot = dots[1]
    await v6Dot.trigger('pointerdown', { clientX: axis.x(10.1), clientY: 0, button: 0 })
    await v6Dot.trigger('pointermove', { clientX: axis.x(13.1), clientY: 0 })
    await v6Dot.trigger('pointerup', { clientX: axis.x(13.1), clientY: 0 })
    const [, update] = lastEdit(wrapper)
    expect(update(mpConfig).selection.kind_rules).toEqual([
      { carrier_kind: 'udp-direct', ip_family: 'v6', tier: 'primary', rtt_bias_ms: 0 },
    ])
    wrapper.unmount()
  })

  // A dot dragged into the other lane is redrawn by another element: the one that took the pointer
  // never sees the release, so the release is heard on the window.
  it('a dot released away from its own element still ends the drag', async () => {
    const { wrapper, mpConfig } = mountRunway()
    const axis = runwayAxis(WIDTH)
    const v6Dot = wrapper.find('[data-testid="runway-lane-primary"]').findAll('[data-testid="runway-dot"]')[1]
    await v6Dot.trigger('pointerdown', { clientX: axis.x(10.1), clientY: 0, button: 0 })
    window.dispatchEvent(new MouseEvent('pointermove', { clientX: axis.x(13.1), clientY: 0 }))
    window.dispatchEvent(new MouseEvent('pointerup', { clientX: axis.x(13.1), clientY: 0 }))
    await wrapper.vm.$nextTick()
    const [, update] = lastEdit(wrapper)
    expect(update(mpConfig).selection.kind_rules).toEqual([
      { carrier_kind: 'udp-direct', ip_family: 'v6', tier: 'primary', rtt_bias_ms: 0 },
    ])
    wrapper.unmount()
  })

  it('a click on a dot opens its detail instead of editing', async () => {
    const { wrapper } = mountRunway()
    const dot = wrapper.find('[data-testid="runway-dot"]')
    await dot.trigger('pointerdown', { clientX: 10, clientY: 0, button: 0 })
    await dot.trigger('pointerup', { clientX: 10, clientY: 0 })
    expect(wrapper.emitted('edit')).toBeUndefined()
    expect(document.body.querySelector('[data-testid="runway-detail"]')).not.toBeNull()
    wrapper.unmount()
  })

  it('the loss handle emits the loss threshold', async () => {
    const { wrapper, mpConfig } = mountRunway()
    const handle = wrapper.find('[data-testid="runway-loss"]')
    await handle.trigger('pointerdown', { clientX: 0, clientY: 0, button: 0 })
    // the meter has no layout in the test DOM: width 0 is treated as 1 px, so any move clamps to the maximum
    await handle.trigger('pointermove', { clientX: 1000, clientY: 0 })
    await handle.trigger('pointerup', { clientX: 1000, clientY: 0 })
    const [, update] = lastEdit(wrapper)
    expect(update(mpConfig).selection.lossy_percent).toBe(40)
    wrapper.unmount()
  })

  it('shows the core report again once the next report arrives after a release', async () => {
    const { wrapper } = mountRunway()
    const handle = wrapper.find('[data-testid="runway-kmax"]')
    await handle.trigger('pointerdown', { clientX: 0, clientY: 100, button: 0 })
    await handle.trigger('pointermove', { clientX: 0, clientY: 140 })
    await handle.trigger('pointerup', { clientX: 0, clientY: 140 })
    expect(wrapper.find('[data-testid="runway-kmax"]').text()).toContain('3')
    await wrapper.setProps({ peer: peer([3, 2, 1]), mpConfig: normalizeMpConfig({ ...DEFAULT_MP_CONFIG(), enabled: true, kmax: 3 }) })
    expect(wrapper.find('[data-testid="runway-kmax"]').text()).toContain('3')
    expect(wrapper.findAll('[data-testid="runway-lane-primary"] [data-testid="runway-path"]').map(n => n.attributes('data-state')))
      .toEqual(['sending', 'sending', 'sending'])
    wrapper.unmount()
  })

  it('does not start an edit while a patch is in flight', async () => {
    const mpConfig = normalizeMpConfig({ ...DEFAULT_MP_CONFIG(), enabled: true, kmax: 2 })
    const wrapper = mount(PathRunway, { props: { peer: peer(), mpConfig, peerName: 'peer-a', busy: true }, global: mpGlobal() })
    const handle = wrapper.find('[data-testid="runway-kmax"]')
    await handle.trigger('pointerdown', { clientX: 0, clientY: 100, button: 0 })
    await handle.trigger('pointermove', { clientX: 0, clientY: 140 })
    await handle.trigger('pointerup', { clientX: 0, clientY: 140 })
    expect(wrapper.emitted('edit')).toBeUndefined()
    wrapper.unmount()
  })
})
