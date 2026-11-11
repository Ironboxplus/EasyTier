// The MP settings card of the status page: edits become one change, with the
// flags-level fields apart from the MpConfig ones.
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

describe('MpLiveSettings', () => {
  it('has nothing to apply until a field changes', () => {
    const wrapper = mountCard()
    expect(wrapper.find('[data-testid="mp-live-apply"]').attributes('disabled')).toBeDefined()
  })

  it('sends a changed send rate limit as a flags change only', async () => {
    const wrapper = mountCard()
    await wrapper.find('[data-testid="mp-live-egress-limit"]').setValue(20)
    await wrapper.find('[data-testid="mp-live-apply"]').trigger('click')
    const [[, change]] = applied(wrapper)
    expect(change.flags).toEqual({ egress_wire_limit_bps: 20_000_000 })
    expect(change.mp).toBeUndefined()
  })

  it('sends MpConfig fields as one update and leaves the others as they were', async () => {
    const wrapper = mountCard()
    await wrapper.find('[data-testid="mp-live-sqm-target"]').setValue(12)
    await wrapper.find('[data-testid="mp-live-punch-attempts"]').setValue(3)
    await wrapper.find('[data-testid="mp-live-apply"]').trigger('click')
    const [[, change]] = applied(wrapper)
    expect(change.flags).toBeUndefined()
    const before = normalizeMpConfig({ ...DEFAULT_MP_CONFIG(), enabled: true })
    const after = change.mp!(before)
    expect(after.sqm.target_ms).toBe(12)
    expect(after.punch_attempts).toBe(3)
    expect(after.kmax).toBe(before.kmax)
    expect(after.data_plane.enabled).toBe(before.data_plane.enabled)
  })

  it('discard puts the saved values back', async () => {
    const wrapper = mountCard()
    await wrapper.find('[data-testid="mp-live-punch-pps"]').setValue(500)
    await wrapper.find('[data-testid="mp-live-discard"]').trigger('click')
    expect(wrapper.find('[data-testid="mp-live-apply"]').attributes('disabled')).toBeDefined()
  })
})
