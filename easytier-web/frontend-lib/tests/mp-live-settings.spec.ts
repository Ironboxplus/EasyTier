// The MP settings card of the status page: every field applies by itself when its edit is done, as
// its own change (flags-level fields apart from the MpConfig ones); there is no Apply button.
import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import MpLiveSettings, { type LiveChange } from '../src/components/MpLiveSettings.vue'
import { DEFAULT_MP_CONFIG, normalizeMpConfig } from '../src/types/mpConfig'
import { mpGlobal } from './primevueStubs'

function mountCard(extra: Record<string, unknown> = {}) {
  return mount(MpLiveSettings, {
    props: { mpConfig: normalizeMpConfig({ ...DEFAULT_MP_CONFIG(), enabled: true }), egressWireLimitBps: 50_000_000, tcpHolePunchMode: 'auto', ...extra },
    global: mpGlobal(),
  })
}

const applied = (wrapper: ReturnType<typeof mountCard>) => (wrapper.emitted('apply') ?? []) as [string, LiveChange][]
const before = () => normalizeMpConfig({ ...DEFAULT_MP_CONFIG(), enabled: true })

describe('MpLiveSettings', () => {
  it('has no Apply or Discard button and no explanatory sentence', () => {
    const wrapper = mountCard()
    expect(wrapper.find('[data-testid="mp-live-apply"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="mp-live-discard"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('Edited here')
  })

  it('applies nothing while a number is being typed and nothing when it ends unchanged', async () => {
    const wrapper = mountCard()
    const input = wrapper.find('[data-testid="mp-live-egress-limit"]')
    await input.setValue(20)
    expect(applied(wrapper)).toHaveLength(0)
    await input.setValue(50)
    await input.trigger('blur')
    expect(applied(wrapper)).toHaveLength(0)
  })

  it('sends a changed send rate limit as a flags change only, when the field loses focus', async () => {
    const wrapper = mountCard()
    const input = wrapper.find('[data-testid="mp-live-egress-limit"]')
    await input.setValue(20)
    await input.trigger('blur')
    const [[, change]] = applied(wrapper)
    expect(change.flags).toEqual({ egress_wire_limit_bps: 20_000_000 })
    expect(change.mp).toBeUndefined()
  })

  it('applies a number on Enter too', async () => {
    const wrapper = mountCard()
    const input = wrapper.find('[data-testid="mp-live-punch-attempts"]')
    await input.setValue(3)
    await input.trigger('keydown.enter')
    expect(applied(wrapper)).toHaveLength(1)
  })

  it('sends one MpConfig field per change and leaves the others as they were', async () => {
    const wrapper = mountCard()
    const target = wrapper.find('[data-testid="mp-live-sqm-target"]')
    await target.setValue(12)
    await target.trigger('blur')
    const [[, change]] = applied(wrapper)
    expect(change.flags).toBeUndefined()
    const after = change.mp!(before())
    expect(after.sqm.target_ms).toBe(12)
    expect(after.punch_attempts).toBe(before().punch_attempts)
    expect(after.data_plane.enabled).toBe(before().data_plane.enabled)
  })

  it('a checkbox applies at once and a reconnect-effect field then offers the reconnect', async () => {
    const wrapper = mountCard()
    expect(wrapper.find('[data-testid="mp-live-reconnect"]').exists()).toBe(false)
    await wrapper.find('[data-testid="mp-live-data-plane"]').setValue(!before().data_plane.enabled)
    const [[, change]] = applied(wrapper)
    expect(change.mp!(before()).data_plane.enabled).toBe(!before().data_plane.enabled)
    const button = wrapper.find('[data-testid="mp-live-reconnect"]')
    expect(button.exists()).toBe(true)
    await button.trigger('click')
    expect(wrapper.emitted('reconnect')).toHaveLength(1)
    expect(wrapper.find('[data-testid="mp-live-reconnect"]').exists()).toBe(false)
  })

  it('a hot field does not offer the reconnect', async () => {
    const wrapper = mountCard()
    const input = wrapper.find('[data-testid="mp-live-punch-pps"]')
    await input.setValue(500)
    await input.trigger('blur')
    expect(applied(wrapper)).toHaveLength(1)
    expect(wrapper.find('[data-testid="mp-live-reconnect"]').exists()).toBe(false)
  })
})
