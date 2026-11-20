// OWD_AUTORATE_PLAN.md 1.5: the peer list shows a peer's loss rate as the mean
// over its connections, like the latency column, not the sum.
import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import Status from '../src/components/Status.vue'
import { DEFAULT_MP_CONFIG } from '../src/types/mpConfig'
import { mpGlobal } from './primevueStubs'

function networkInst(conns: Array<Record<string, unknown>>) {
  return {
    instance_id: 'inst-1',
    running: true,
    error_msg: '',
    detail: {
      dev_name: 'tun0',
      my_node_info: { peer_id: 100, hostname: 'self-host', version: '1.0.0' },
      events: [],
      routes: [],
      peers: [],
      peer_route_pairs: [
        { route: { peer_id: 42, ipv4_addr: '10.0.0.2', hostname: 'peer-a', version: '1.0.0' }, peer: { peer_id: 42, conns } },
      ],
      running: true,
    },
  }
}

describe('Status loss rate column', () => {
  it('loss rate is the mean over connections', () => {
    const wrapper = mount(Status, {
      props: {
        curNetworkInst: networkInst([{ loss_rate: 0.09 }, { loss_rate: 0.19 }]) as any,
        mpConfig: { ...DEFAULT_MP_CONFIG(), enabled: true },
      },
      global: mpGlobal(),
    })
    const row = wrapper.findAll('[data-testid="peer-row"]')[1]
    expect(row.text()).toContain('14%')
    expect(row.text()).not.toContain('28%')
  })
})
