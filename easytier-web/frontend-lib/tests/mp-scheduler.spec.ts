import { mount } from '@vue/test-utils'
import { mpGlobal } from './primevueStubs'
import { describe, expect, it } from 'vitest'
import MpSchedulerPanel from '../src/components/MpSchedulerPanel.vue'
import {
  defaultParams,
  getScheduler,
  LATENCY_BANDWIDTH_KEY,
  listSchedulers,
  resolveScheduler,
} from '../src/types/mpScheduler'

// Mirrors the Rust unit tests in easytier/src/tunnel/mp_plugin.rs so the two
// registries stay in lockstep (MP_SQM_PLAN.md §5).
describe('mp scheduler registry (ts mirror)', () => {
  it('registers the four built-ins', () => {
    const names = listSchedulers().map(p => p.name).sort()
    expect(names).toEqual(['min-rtt', 'redundant', 'round-robin', 'sqm-weighted'])
    expect(getScheduler('nonexistent')).toBeUndefined()
  })

  it('exposes the latency<->bandwidth slider only on sqm-weighted', () => {
    const sqm = getScheduler('sqm-weighted')!
    expect(sqm.tunables).toHaveLength(1)
    expect(sqm.tunables[0].key).toBe(LATENCY_BANDWIDTH_KEY)
    expect(sqm.tunables[0].kind).toEqual({ type: 'slider', min: 0, max: 1, step: 0.01 })
    for (const name of ['min-rtt', 'round-robin', 'redundant'])
      expect(getScheduler(name)!.tunables).toHaveLength(0)
  })

  it('resolves names to algorithms and clamps the slider', () => {
    expect(resolveScheduler('min-rtt', {})?.algorithm).toBe('min-rtt')
    expect(resolveScheduler('bogus', {})).toBeUndefined()
    expect(resolveScheduler('sqm-weighted', { [LATENCY_BANDWIDTH_KEY]: 0.8 })?.lambda).toBe(0.8)
    expect(resolveScheduler('sqm-weighted', {})?.lambda).toBe(0.5)
    expect(resolveScheduler('sqm-weighted', { [LATENCY_BANDWIDTH_KEY]: 5 })?.lambda).toBe(1)
    expect(resolveScheduler('sqm-weighted', { [LATENCY_BANDWIDTH_KEY]: -1 })?.lambda).toBe(0)
    expect(resolveScheduler('sqm-weighted', { [LATENCY_BANDWIDTH_KEY]: 'x' as unknown as number })?.lambda).toBe(0.5)
  })

  it('defaultParams seeds each tunable at its default', () => {
    expect(defaultParams('sqm-weighted')).toEqual({ [LATENCY_BANDWIDTH_KEY]: 0.5 })
    expect(defaultParams('min-rtt')).toEqual({})
  })
})

describe('MpSchedulerPanel auto-renders tunables', () => {
  // PrimeVue controls are stubbed (as elsewhere in this suite) so the mount does
  // not need the PrimeVue plugin context; we assert on the panel's own markup.
  const stubs = { Select: true, Slider: true, ToggleButton: true, ToggleSwitch: true, InputNumber: true }

  it('renders one tunable row for sqm-weighted and none for min-rtt', async () => {
    const wrapper = mount(MpSchedulerPanel, {
      props: {
        modelValue: { scheduler: 'sqm-weighted', params: { [LATENCY_BANDWIDTH_KEY]: 0.5 } },
      },
      global: { ...mpGlobal(), stubs },
    })
    expect(wrapper.findAll('[data-testid="mp-tunable"]')).toHaveLength(1)

    await wrapper.setProps({ modelValue: { scheduler: 'min-rtt', params: {} } })
    expect(wrapper.findAll('[data-testid="mp-tunable"]')).toHaveLength(0)
  })
})
