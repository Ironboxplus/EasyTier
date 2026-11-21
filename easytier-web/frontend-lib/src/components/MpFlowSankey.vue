<script setup lang="ts">
// Actual send rate by network card and path: each local egress card on the left
// (labelled with what it sends now / the bandwidth Autorate gives it), the paths
// through it on the right. Link width is the path's actual send rate, so a card
// whose send rate reaches its budget is one whose bandwidth is the limit.
import { useElementSize } from '@vueuse/core'
import { SankeyChart } from 'echarts/charts'
import { TooltipComponent } from 'echarts/components'
import { init, use, type ECharts } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { formatBps, type NicFlow, type PathFlow } from '../modules/mpRuntime'

use([SankeyChart, TooltipComponent, CanvasRenderer])

const props = defineProps<{
  nics: NicFlow[]
  paths: PathFlow[]
  /** Display name of a card (the card's device name, or a word for an unknown one). */
  nicName: (nic: string) => string
  pathName: (path: PathFlow) => string
}>()

const box = ref<HTMLElement | null>(null)
const { t } = useI18n()
const { width } = useElementSize(box)
let chart: ECharts | undefined

const nicId = (nic: string) => `nic:${nic}`

// Zero-rate paths remain in the runtime table. A flow chart must not give them
// invented traffic, and an all-zero Sankey has no finite layout scale.
const flowingPaths = computed(() => props.paths.filter(p => p.sendBps > 0))
const model = computed(() => ({
  nodes: [
    ...props.nics.filter(n => flowingPaths.value.some(p => p.nic === n.id)).map(n => ({
      id: nicId(n.id),
      column: 0,
      name: props.nicName(n.id),
      send: n.sendBps,
      budget: n.budgetBps,
    })),
    ...flowingPaths.value.map(p => ({
      id: `path:${p.id}`,
      column: 1,
      name: props.pathName(p),
      send: p.sendBps,
      budget: undefined as number | undefined,
    })),
  ],
  links: flowingPaths.value.map(p => ({ source: nicId(p.nic), target: `path:${p.id}`, flow: p.sendBps })),
}))

const height = computed(() => Math.max(150, props.paths.length * 52 + 24))

function cssVar(name: string, fallback: string): string {
  const v = box.value ? getComputedStyle(box.value).getPropertyValue(name).trim() : ''
  return v || fallback
}

function rateText(send: number, budget?: number): string {
  return budget === undefined ? formatBps(send) : `${formatBps(send)} / ${formatBps(budget)}`
}

function render() {
  if (!chart) return
  const text = cssVar('--p-text-color', '#e5e7eb')
  const muted = cssVar('--p-text-muted-color', '#94a3b8')
  const colors = [cssVar('--p-primary-color', '#10b981'), '#38bdf8']
  chart.setOption({
    tooltip: {
      trigger: 'item',
      formatter: (p: any) => p.dataType === 'edge'
        ? `${p.data.sourceName} → ${p.data.targetName}<br/>${formatBps(p.data.flow)}`
        : `${p.data.label.name}<br/>${rateText(p.data.send, p.data.budget)}`,
    },
    series: [{
      type: 'sankey',
      left: 4,
      right: 4,
      top: 8,
      bottom: 8,
      nodeWidth: 10,
      nodeGap: 26,
      draggable: false,
      layoutIterations: 0,
      emphasis: { focus: 'adjacency' },
      data: model.value.nodes.map(n => ({
        name: n.id,
        depth: n.column,
        send: n.send,
        budget: n.budget,
        label: {
          name: n.name,
          position: 'right',
          color: text,
          formatter: () => `{name|${n.name}}\n{rate|${rateText(n.send, n.budget)}}`,
          rich: { name: { color: text, fontSize: 12, lineHeight: 16 }, rate: { color: muted, fontSize: 11, lineHeight: 14 } },
        },
        itemStyle: { color: colors[n.column], borderWidth: 0 },
      })),
      links: model.value.links.map(l => ({
        ...l,
        sourceName: model.value.nodes.find(n => n.id === l.source)?.name,
        targetName: model.value.nodes.find(n => n.id === l.target)?.name,
        value: l.flow,
      })),
      lineStyle: { color: 'gradient', opacity: 0.35, curveness: 0.5 },
    }],
  }, true)
}

onMounted(() => {
  if (!box.value) return
  chart = init(box.value, undefined, { renderer: 'canvas' })
  render()
})
onBeforeUnmount(() => chart?.dispose())
watch(model, render, { deep: true })
watch([width, height], () => chart?.resize())
</script>

<template>
  <div class="relative w-full" :style="{ height: `${height}px` }">
    <div ref="box" class="h-full w-full" data-testid="mp-flow-sankey" />
    <div v-if="!flowingPaths.length" class="absolute inset-0 flex items-center justify-center text-muted-color text-sm" role="status">
      {{ t('mp_rt.sankey.idle') }}
    </div>
  </div>
</template>
