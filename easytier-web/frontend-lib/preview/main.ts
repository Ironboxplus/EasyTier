// Local layout preview of the MP panels with captured runtime data (not shipped).
import { createApp, defineComponent, h, ref } from 'vue'
import EasyTierLib from '../src/easytier-frontend-lib'
import MpEgressPanel from '../src/components/MpEgressPanel.vue'
import MpRuntimePanel from '../src/components/MpRuntimePanel.vue'
import MpConfigPanel from '../src/components/MpConfigPanel.vue'
import { DEFAULT_MP_CONFIG } from '../src/types/mpConfig'
import sample from './sample.json'

document.documentElement.classList.add('dark')
const width = Number(new URLSearchParams(location.search).get('w') ?? 920)
const step = (new URLSearchParams(location.search).get('step') ?? 'paths') as any

function snapshot(tick: number) {
  const s = JSON.parse(JSON.stringify(sample)) as any
  const grow = (v: any, k: number) => String(Number(v ?? 0) + tick * k)
  for (const p of s.mp_peers) {
    for (const path of p.paths ?? []) { path.sent_bytes = grow(path.sent_bytes, 400_000); path.recv_bytes = grow(path.recv_bytes, 900_000) }
    for (const c of p.data_plane?.classes ?? []) { c.tx_bytes = grow(c.tx_bytes, 120_000); c.rx_bytes = grow(c.rx_bytes, 300_000) }
  }
  for (const e of s.mp_egress_resources) e.cake.sent_bytes = grow(e.cake.sent_bytes, 420_000)
  return { sample_time_ms: 1000 * (tick + 1), peers: s.mp_peers, egress: s.mp_egress_resources }
}

const App = defineComponent(() => {
  const rt = ref(snapshot(0))
  let tick = 0
  setInterval(() => { rt.value = snapshot(++tick) }, 1000)
  const cc = new URLSearchParams(location.search).get('cc') ?? ''
  const mp = { ...DEFAULT_MP_CONFIG(), enabled: true, congestion_control: cc, congestion_control_params_json: cc === 'brutal' ? '{"up_mbps":80,"down_mbps":0,"disable_loss_compensation":false}' : '{}', sqm: { ...DEFAULT_MP_CONFIG().sqm, enabled: true } }
  const view = new URLSearchParams(location.search).get('view')
  const cfg = ref({ ...mp, punch_pps: 200, punch_rate_limits: [{ egress_device: 'eth1', pps: 50 }] })
  if (view === 'config') {
    return () => h('div', { style: { width: `${width}px` } }, [
      h(MpConfigPanel, { modelValue: cfg.value, 'onUpdate:modelValue': (v: any) => { cfg.value = v }, tcpHolePunchMode: 'auto', egressWireLimitBps: null }),
    ])
  }
  return () => h('div', { style: { width: `${width}px` }, class: 'flex flex-col gap-4' }, [
    h(MpEgressPanel, { runtime: rt.value, mpConfig: mp }),
    h(MpRuntimePanel, { runtime: rt.value, mpConfig: mp, peerId: rt.value.peers[0]?.peer_id, currentMtu: 1380, initialStep: step }),
  ])
})

import { loadLanguageAsync } from '../src/modules/i18n'
loadLanguageAsync(new URLSearchParams(location.search).get('lang') ?? 'cn').then(() => createApp(App).use(EasyTierLib).mount('#app'))
