// The peer list draws each peer as one line with its latency as a dot on the
// logarithmic axis of the path runway, and keeps what does not fit a narrow
// screen in the opened row. No table, so nothing can scroll sideways.
import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import PeerList, { type PeerRow } from '../src/components/PeerList.vue'
import { runwayAxis } from '../src/modules/pathRunway'
import { mpGlobal } from './primevueStubs'

const row = (key: string, extra: Partial<PeerRow> = {}): PeerRow => ({
  key,
  name: `host-${key}`,
  kind: 'direct',
  server: false,
  avoidRelay: false,
  latencyMs: 24,
  latencyText: '24ms',
  tx: '1.0 KiB',
  rx: '2.0 KiB',
  loss: '0%',
  lossPercent: 0,
  ...extra,
})

function mountList(rows: PeerRow[], expandedKey: string | null = null) {
  return mount(PeerList, {
    props: { rows, expandedKey },
    slots: { expansion: '<template #expansion="scope"><div data-testid="slot-body">{{ scope.row.key }}</div></template>' },
    global: mpGlobal(),
  })
}

describe('PeerList', () => {
  it('has one line per peer and no table', () => {
    const wrapper = mountList([row('1'), row('2'), row('3', { kind: 'relay' })])
    expect(wrapper.findAll('[data-testid="peer-row"]')).toHaveLength(3)
    expect(wrapper.find('table').exists()).toBe(false)
    expect(wrapper.text()).toContain('host-1')
    expect(wrapper.text()).toContain('24ms')
  })

  it('puts the latency dot where the runway axis puts that latency', () => {
    const axis = runwayAxis(100, 2, 3)
    const wrapper = mountList([row('1', { latencyMs: 5 }), row('2', { latencyMs: 120 })])
    const lefts = wrapper.findAll('[data-testid="peer-latency-dot"]')
      .map(dot => Number.parseFloat(/left:\s*([\d.]+)%/.exec(dot.attributes('style') ?? '')?.[1] ?? 'NaN'))
    expect(lefts[0]).toBeCloseTo(axis.x(5), 2)
    expect(lefts[1]).toBeCloseTo(axis.x(120), 2)
    expect(lefts[0]).toBeLessThan(lefts[1])
  })

  it('draws no dot for a peer without a measurement', () => {
    const wrapper = mountList([row('1', { latencyMs: null, latencyText: '' })])
    expect(wrapper.find('[data-testid="peer-latency-dot"]').exists()).toBe(false)
  })

  it('shows traffic and loss in the row text', () => {
    const wrapper = mountList([row('1', { loss: '14%', lossPercent: 14 })])
    expect(wrapper.find('[data-testid="peer-traffic"]').text()).toContain('14%')
    expect(wrapper.find('[data-testid="peer-traffic"]').text()).toContain('1.0 KiB')
  })

  it('emits the key when a row is clicked or activated from the keyboard', async () => {
    const wrapper = mountList([row('1'), row('2')])
    const rows = wrapper.findAll('[data-testid="peer-row"]')
    await rows[1].trigger('click')
    await rows[0].trigger('keydown.enter')
    expect(wrapper.emitted('toggle')).toEqual([['2'], ['1']])
  })

  it('renders the opened row\'s expansion under it, for that row only', () => {
    const wrapper = mountList([row('1'), row('2')], '2')
    const expansions = wrapper.findAll('[data-testid="peer-row-expansion"]')
    expect(expansions).toHaveLength(1)
    expect(expansions[0].text()).toBe('2')
    expect(wrapper.findAll('[data-testid="peer-row"]')[1].attributes('aria-expanded')).toBe('true')
  })
})
