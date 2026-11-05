import { mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createI18n } from 'vue-i18n'
import { SankeyChart } from 'echarts/charts'
import { SVGRenderer } from 'echarts/renderers'
import MpFlowSankey from '../src/components/MpFlowSankey.vue'
import type { PathFlow } from '../src/modules/mpRuntime'

const chart = vi.hoisted(() => ({ setOption: vi.fn(), resize: vi.fn(), dispose: vi.fn() }))
vi.mock('echarts/core', () => ({ use: vi.fn(), init: () => chart }))

function path(id: string, sendBps: number): PathFlow {
  return {
    id, nic: 'eth0', sendBps,
    path: { path: { carrier_id: 1, local_addr: '', remote_addr: '' }, lifecycle_state: 'standby' },
  }
}

function mountChart(paths: PathFlow[]) {
  return mount(MpFlowSankey, {
    props: {
      nics: [{ id: 'eth0', sendBps: paths.reduce((sum, p) => sum + p.sendBps, 0) }],
      paths, nicName: (id: string) => id, pathName: (p: PathFlow) => p.id,
    },
    global: { plugins: [createI18n({
      legacy: false, locale: 'en', messages: { en: { mp_rt: { sankey: { idle: 'No outgoing traffic to display' } } } },
    })] },
  })
}

function series() {
  return chart.setOption.mock.calls.at(-1)![0].series[0]
}

describe('NIC/path chart uses measured traffic', () => {
  beforeEach(() => vi.clearAllMocks())

  it('keeps a small real standby rate proportional and never invents traffic on an idle path', () => {
    const wrapper = mountChart([path('busy', 1000), path('keepalive', 0.1), path('idle', 0)])
    expect(series().links.map((l: any) => [l.target, l.value])).toEqual([
      ['path:busy', 1000], ['path:keepalive', 0.1],
    ])
    expect(series().data.some((n: any) => n.name === 'path:idle')).toBe(false)
    expect(wrapper.find('[role="status"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('clears the chart when all paths become idle and resumes when measured traffic returns', async () => {
    const wrapper = mountChart([path('active', 500)])
    await wrapper.setProps({ paths: [path('active', 0)] })
    expect(series().links).toEqual([])
    expect(series().data).toEqual([])
    expect(wrapper.get('[role="status"]').text()).toBe('No outgoing traffic to display')
    await wrapper.setProps({ paths: [path('active', 12)] })
    expect(series().links[0].value).toBe(12)
    expect(wrapper.find('[role="status"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('renders finite ECharts geometry with the measured width ratio, including the idle transition', async () => {
    const echarts = await vi.importActual<typeof import('echarts/core')>('echarts/core')
    echarts.use([SankeyChart, SVGRenderer])
    const renderer = echarts.init(null, undefined, { renderer: 'svg', ssr: true, width: 800, height: 300 })
    const wrapper = mountChart([path('busy', 1000), path('keepalive', 0.1), path('idle', 0)])
    try {
      renderer.setOption(chart.setOption.mock.calls.at(-1)![0], true)
      const edges = (renderer as any).getModel().getSeriesByIndex(0).getGraph().edges
      expect(edges).toHaveLength(2)
      expect(edges[0].getLayout().dy / edges[1].getLayout().dy).toBeCloseTo(10_000)
      expect(renderer.renderToSVGString()).not.toMatch(/NaN|Infinity/)
      await wrapper.setProps({ paths: [path('busy', 0)] })
      renderer.setOption(chart.setOption.mock.calls.at(-1)![0], true)
      expect(renderer.renderToSVGString()).not.toMatch(/NaN|Infinity/)
    } finally {
      renderer.dispose()
      wrapper.unmount()
    }
  })
})
