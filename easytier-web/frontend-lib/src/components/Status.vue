<script setup lang="ts">
import { useTimeAgo } from '@vueuse/core'
import { IPv4 } from 'ip-num/IPNumber'
import { NetworkInstance, type TunnelInfo, type NodeInfo, type PeerRoutePair } from '../types/network'
import { useI18n } from 'vue-i18n';
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { AnimatePresence, motion } from 'motion-v'
import { ipv4InetToString, ipv4ToString, ipv6ToString, UuidToStr } from '../modules/utils';
import { Badge, Chip, Button, Dialog, ScrollPanel, Timeline, Divider, Card, } from 'primevue';
import NetworkChart from './NetworkChart.vue'
import PeerList, { type PeerRow } from './PeerList.vue'
import MpEgressPanel from './MpEgressPanel.vue'
import MpLiveSettings, { type LiveChange } from './MpLiveSettings.vue'
import MpRuntimePanel from './MpRuntimePanel.vue'
import type { CongestionModel, MpConfig, MpPolicyAction, MpPolicyMatch } from '../types/mpConfig'

const props = defineProps<{
  curNetworkInst: NetworkInstance | null,
  /** Config of the running instance (MP switches, policies) for the MP card. */
  mpConfig?: MpConfig | null,
  egressWireLimitBps?: number | string | null,
  mpBusy?: boolean,
  /** Saved MTU of the running instance, for the data plane's MTU recommendation. */
  mtu?: number | null,
  /** Saved hole punch mode of the running instance. */
  tcpHolePunchMode?: string | null,
}>()

const emit = defineEmits<{
  'mp-set-policy': [match: MpPolicyMatch, action: MpPolicyAction | null]
  'mp-reconnect': []
  'mp-edit': [label: string, update: (mp: MpConfig) => MpConfig]
  'mp-live-apply': [label: string, change: LiveChange]
  'mp-apply-mtu': [mtu: number]
  'mp-set-congestion-control': [model: CongestionModel]
}>()

const mpRuntime = computed(() => props.curNetworkInst?.detail?.mp_runtime ?? null)
/** NIC-level MP state (send limits, autorate, the CAKE send queue) is shown once, outside the peer table. */
const showEgressPanel = computed(() => !!props.mpConfig?.enabled || !!mpRuntime.value?.egress?.length)

const { t } = useI18n()

const peerRouteInfos = computed(() => {
  if (props.curNetworkInst) {
    const my_node_info = props.curNetworkInst.detail?.my_node_info
    return [{
      route: {
        // carried through so the self row can also be expanded to its MP session
        peer_id: my_node_info?.peer_id,
        ipv4_addr: my_node_info?.virtual_ipv4,
        hostname: my_node_info?.hostname,
        version: my_node_info?.version,
        stun_info: my_node_info?.stun_info
      },
    }, ...(props.curNetworkInst.detail?.peer_route_pairs || [])]
  }

  return []
})

/** Host names by peer id, for the MP panels. */
const peerNames = computed<Record<string, string>>(() => Object.fromEntries(
  peerRouteInfos.value
    .filter(info => info.route?.peer_id !== undefined && info.route?.hostname)
    .map(info => [String(info.route.peer_id), info.route.hostname as string]),
))

// ---- peer row expansion: one peer's MP session shown at a time, reusing MpRuntimePanel ----
const reveal = { initial: { opacity: 0, height: 0 }, animate: { opacity: 1, height: 'auto' }, exit: { opacity: 0, height: 0 } }
const expandedPeerKey = ref<string | null>(null)

function peerRowKey(info: PeerRoutePair): string {
  return String(info.route?.peer_id ?? '')
}

function peerIdForKey(key: string): number | string | undefined {
  return peerRouteInfos.value.find(info => peerRowKey(info) === key)?.route?.peer_id
}

function onPeerToggle(key: string) {
  expandedPeerKey.value = expandedPeerKey.value === key ? null : key
}

const peerRows = computed<PeerRow[]>(() => peerRouteInfos.value.map((info: any) => {
  const route = info.route
  const cost = route.cost
  const lat = latencyValue(info)
  return {
    key: peerRowKey(info),
    name: route.hostname ?? '',
    kind: cost ? (cost === 1 ? 'direct' : 'relay') : 'self',
    server: !!cost && !!route.feature_flag?.is_public_server,
    avoidRelay: !!cost && !!route.feature_flag?.avoid_relay_data,
    latencyMs: lat,
    latencyText: latencyMs(info),
    tx: txBytes(info),
    rx: rxBytes(info),
    loss: lossRate(info),
    lossPercent: lossPercentValue(info),
  }
}))

/** What does not fit on a narrow row, shown once the row is opened. */
function peerDetails(key: string): { label: string, value: string }[] {
  const info = peerRouteInfos.value.find(i => peerRowKey(i) === key)
  if (!info)
    return []
  return [
    { label: t('virtual_ipv4'), value: ipFormat(info as PeerRoutePair) },
    { label: t('route_cost'), value: String(routeCost(info)) },
    { label: t('tunnel_proto'), value: tunnelProto(info as PeerRoutePair) },
    { label: t('nat_type'), value: natType(info as PeerRoutePair) },
    { label: t('status.version'), value: version(info as PeerRoutePair) },
  ].filter(item => item.value !== '' && item.value !== undefined)
}
function routeCost(info: any) {
  if (info.route) {
    const cost = info.route.cost
    return cost ? cost === 1 ? 'p2p' : `relay(${cost})` : t('status.local')
  }

  return '?'
}

function resolveObjPath(path: string, obj = globalThis, separator = '.') {
  const properties = Array.isArray(path) ? path : path.split(separator)
  return properties.reduce((prev, curr) => prev?.[curr], obj)
}

function statsCommon(info: any, field: string): number | undefined {
  if (!info.peer)
    return undefined

  const conns = info.peer.conns
  return conns.reduce((acc: number, conn: any) => {
    return acc + Number(resolveObjPath(field, conn) ?? 0) // uint64 arrives as a JSON string
  }, 0)
}

function humanFileSize(bytes: number, si = false, dp = 1) {
  const thresh = si ? 1000 : 1024

  if (Math.abs(bytes) < thresh)
    return `${bytes} B`

  const units = si
    ? ['kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    : ['KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB']
  let u = -1
  const r = 10 ** dp

  do {
    bytes /= thresh
    ++u
  } while (Math.round(Math.abs(bytes) * r) / r >= thresh && u < units.length - 1)

  return `${bytes.toFixed(dp)} ${units[u]}`
}

/** Mean latency over the connections in milliseconds, null without a measurement. */
function latencyValue(info: PeerRoutePair): number | null {
  const sum = statsCommon(info, 'stats.latency_us')
  if (sum === undefined || !info.peer!.conns.length)
    return null
  return sum / 1000 / info.peer!.conns.length
}

/** Mean loss over the connections in percent. */
function lossPercentValue(info: PeerRoutePair): number {
  const sum = statsCommon(info, 'loss_rate')
  if (sum === undefined)
    return 0
  return sum / Math.max(info.peer!.conns.length, 1) * 100
}

function latencyMs(info: PeerRoutePair) {
  let lat_us_sum = statsCommon(info, 'stats.latency_us')
  if (lat_us_sum === undefined)
    return ''
  lat_us_sum = lat_us_sum / 1000 / info.peer!.conns.length
  return `${lat_us_sum % 1 > 0 ? Math.round(lat_us_sum) + 1 : Math.round(lat_us_sum)}ms`
}

function txBytes(info: PeerRoutePair) {
  const tx = statsCommon(info, 'stats.tx_bytes')
  return tx ? humanFileSize(tx) : ''
}

function rxBytes(info: PeerRoutePair) {
  const rx = statsCommon(info, 'stats.rx_bytes')
  return rx ? humanFileSize(rx) : ''
}

function lossRate(info: PeerRoutePair) {
  // OWD_AUTORATE_PLAN.md 1.5: the mean over the connections, like `latencyMs`.
  const lossSum = statsCommon(info, 'loss_rate')
  if (lossSum === undefined)
    return ''
  const mean = lossSum / Math.max(info.peer!.conns.length, 1)
  return `${Math.round(mean * 100)}%`
}

function version(info: PeerRoutePair) {
  return info.route.version === '' ? 'unknown' : info.route.version
}

function ipFormat(info: PeerRoutePair) {
  const ip = info.route.ipv4_addr
  if (typeof ip === 'string')
    return ip
  return ip ? `${IPv4.fromNumber(ip.address.addr)}/${ip.network_length}` : ''
}

function oneTunnelProto(tunnel?: TunnelInfo): string {
  if (!tunnel)
    return ''

  const local_addr = tunnel.local_addr
  let isIPv6 = false;
  if (local_addr?.url) {
    try {
      const urlObj = new URL(local_addr.url, 'http://dummy');
      // IPv6 addresses in URLs are enclosed in brackets and contain ':'
      isIPv6 = /^\[.*:.*\]$/.test(urlObj.hostname);
    } catch (e) {
      // fallback to original check if URL parsing fails
      isIPv6 = local_addr.url.indexOf('[') >= 0;
    }
  }
  if (isIPv6)
    return `${tunnel.tunnel_type}6`
  else
    return tunnel.tunnel_type
}

function tunnelProto(info: PeerRoutePair) {
  const conns = info.peer?.conns ?? []
  const all = [...new Set(conns.map(c => oneTunnelProto(c.tunnel)))]
  // With several connections to one peer, say which one carries the data.
  const defaultId = info.peer?.default_conn_id
  const data = defaultId && conns.length > 1 ? conns.find(c => c.conn_id === UuidToStr(defaultId)) : undefined
  if (!data)
    return all.join(',')
  const dataProto = oneTunnelProto(data.tunnel)
  const others = [...new Set(conns.filter(c => c !== data).map(c => oneTunnelProto(c.tunnel)))]
  return others.length
    ? `${dataProto}（${t('status.conn_data')}）· ${others.join(',')}（${t('status.conn_standby')}）`
    : dataProto
}

const myNodeInfo = computed(() => {
  if (!props.curNetworkInst)
    return {} as NodeInfo

  return props.curNetworkInst.detail?.my_node_info
})

interface Chip {
  label: string
  icon: string
}

// udp nat type
enum NatType {
  // has NAT; but own a single public IP, port is not changed
  Unknown = 0,
  OpenInternet = 1,
  NoPAT = 2,
  FullCone = 3,
  Restricted = 4,
  PortRestricted = 5,
  Symmetric = 6,
  SymUdpFirewall = 7,
  SymmetricEasyInc = 8,
  SymmetricEasyDec = 9,
};

const udpNatTypeStrMap = {
  [NatType.Unknown]: 'Unknown',
  [NatType.OpenInternet]: 'Open Internet',
  [NatType.NoPAT]: 'No PAT',
  [NatType.FullCone]: 'Full Cone',
  [NatType.Restricted]: 'Restricted',
  [NatType.PortRestricted]: 'Port Restricted',
  [NatType.Symmetric]: 'Symmetric',
  [NatType.SymUdpFirewall]: 'Symmetric UDP Firewall',
  [NatType.SymmetricEasyInc]: 'Symmetric Easy Inc',
  [NatType.SymmetricEasyDec]: 'Symmetric Easy Dec',
}

const myNodeInfoChips = computed(() => {
  if (!props.curNetworkInst)
    return []

  const chips: Array<Chip> = []
  const my_node_info = props.curNetworkInst.detail?.my_node_info
  if (!my_node_info)
    return chips

  // peer id
  chips.push({
    label: `Peer ID: ${my_node_info.peer_id}`,
    icon: '',
  } as Chip)

  // TUN Device Name
  const dev_name = props.curNetworkInst.detail?.dev_name
  if (dev_name) {
    chips.push({
      label: `TUN Device Name: ${dev_name}`,
      icon: '',
    } as Chip)
  }

  // virtual ipv4
  chips.push({
    label: `Virtual IPv4: ${ipv4InetToString(my_node_info.virtual_ipv4)}`,
    icon: '',
  } as Chip)

  // local ipv4s
  const local_ipv4s = my_node_info.ips?.interface_ipv4s
  for (const [idx, ip] of (local_ipv4s ?? []).entries()) {
    chips.push({
      label: `Local IPv4 ${idx}: ${ipv4ToString(ip)}`,
      icon: '',
    } as Chip)
  }

  // local ipv6s
  const local_ipv6s = my_node_info.ips?.interface_ipv6s
  for (const [idx, ip] of (local_ipv6s ?? []).entries()) {
    chips.push({
      label: `Local IPv6 ${idx}: ${ipv6ToString(ip)}`,
      icon: '',
    } as Chip)
  }

  // public ip
  const public_ip = my_node_info.ips?.public_ipv4
  if (public_ip) {
    chips.push({
      label: `Public IP: ${IPv4.fromNumber(public_ip.addr)}`,
      icon: '',
    } as Chip)
  }

  const public_ipv6 = my_node_info.ips?.public_ipv6
  if (public_ipv6) {
    chips.push({
      label: `Public IPv6: ${ipv6ToString(public_ipv6)}`,
      icon: '',
    } as Chip)
  }

  // listeners:
  const listeners = my_node_info.listeners
  for (const [idx, listener] of (listeners ?? []).entries()) {
    chips.push({
      label: `Listener ${idx}: ${listener.url}`,
      icon: '',
    } as Chip)
  }

  const udpNatType: NatType = my_node_info.stun_info?.udp_nat_type
  if (udpNatType !== undefined) {
    chips.push({
      label: `UDP NAT Type: ${udpNatTypeStrMap[udpNatType]}`,
      icon: '',
    } as Chip)
  }

  return chips
})

function globalSumCommon(field: string) {
  let sum = 0
  if (!peerRouteInfos.value)
    return sum

  for (const info of peerRouteInfos.value) {
    const tx = statsCommon(info, field)
    if (tx)
      sum += tx
  }
  return sum
}

function txGlobalSum() {
  return globalSumCommon('stats.tx_bytes')
}

function rxGlobalSum() {
  return globalSumCommon('stats.rx_bytes')
}

function natType(info: PeerRoutePair): string {
  const udpNatType = info.route?.stun_info?.udp_nat_type;
  if (udpNatType !== undefined)
    return udpNatTypeStrMap[udpNatType as NatType]

  return ''
}

const peerCount = computed(() => {
  if (!peerRouteInfos.value)
    return 0

  return peerRouteInfos.value.length
})

// calculate tx/rx rate every 2 seconds
let rateIntervalId = 0
const rateInterval = 2000
let prevTxSum = 0
let prevRxSum = 0
const txRate = ref('0')
const rxRate = ref('0')

// 控制节点详细信息chips的显示/隐藏
const showNodeDetails = ref(false)

onMounted(() => {
  rateIntervalId = window.setInterval(() => {
    const curTxSum = txGlobalSum()
    txRate.value = humanFileSize((curTxSum - prevTxSum) / (rateInterval / 1000))
    prevTxSum = curTxSum

    const curRxSum = rxGlobalSum()
    rxRate.value = humanFileSize((curRxSum - prevRxSum) / (rateInterval / 1000))
    prevRxSum = curRxSum
  }, rateInterval)
})

onUnmounted(() => {
  clearInterval(rateIntervalId)
})

const dialogVisible = ref(false)
const dialogContent = ref<any>('')
const dialogHeader = ref('event_log')

function showVpnPortalConfig() {
  const my_node_info = myNodeInfo.value
  if (!my_node_info)
    return

  const url = 'https://www.wireguardconfig.com/qrcode'
  dialogContent.value = `${my_node_info.vpn_portal_cfg}\n\n # can generate QR code: ${url}`
  dialogHeader.value = 'vpn_portal_config'
  dialogVisible.value = true
}

function showEventLogs() {
  const detail = props.curNetworkInst?.detail
  if (!detail)
    return

  dialogContent.value = detail.events.map((event: string) => JSON.parse(event))
  dialogHeader.value = 'event_log'
  dialogVisible.value = true
}
</script>

<template>
  <div class="frontend-lib">
    <Dialog v-model:visible="dialogVisible" modal :header="t(dialogHeader)" class="w-full h-auto max-h-full"
      :baseZIndex="2000">
      <ScrollPanel v-if="dialogHeader === 'vpn_portal_config'">
        <pre>{{ dialogContent }}</pre>
      </ScrollPanel>
      <Timeline v-else :value="dialogContent">
        <template #opposite="slotProps">
          <small class="text-surface-500 dark:text-surface-400">{{ useTimeAgo(Date.parse(slotProps.item.time))
          }}</small>
        </template>
        <template #content="slotProps">
          <HumanEvent :event="slotProps.item.event" />
        </template>
      </Timeline>
    </Dialog>

    <Card v-if="curNetworkInst?.error_msg">
      <template #title>
        Run Network Error
      </template>
      <template #content>
        <div class="flex flex-col gap-y-5">
          <div class="text-red-500">
            {{ curNetworkInst.error_msg }}
          </div>
        </div>
      </template>
    </Card>

    <template v-else>
      <Card>
        <template #title>
          {{ t('my_node_info') }}
        </template>
        <template #content>
          <div class="flex w-full flex-col gap-y-5">
            <div class="gap-4">
              <!-- 网络流量图表 -->
              <div class="w-full">
                <NetworkChart :upload-rate="txRate" :download-rate="rxRate" />
              </div>
            </div>

            <!-- 展开/收起节点详细信息的divider按钮 -->
            <div class="w-full">
              <Button @click="showNodeDetails = !showNodeDetails"
                :icon="showNodeDetails ? 'pi pi-chevron-up' : 'pi pi-chevron-down'"
                :label="showNodeDetails ? t('hide_node_details') : t('show_node_details')" severity="secondary" outlined
                class="w-full justify-center" size="small" />
            </div>

            <!-- 节点详细信息chips，根据showNodeDetails状态显示/隐藏 -->
            <div v-show="showNodeDetails" class="flex flex-row items-center flex-wrap w-full max-h-40 overflow-scroll">
              <Chip v-for="(chip, i) in myNodeInfoChips" :key="i" :label="chip.label" :icon="chip.icon"
                class="mr-2 mt-2 text-sm" />
            </div>

            <div v-if="myNodeInfo" class="m-0 flex flex-row justify-center gap-x-5 text-sm">
              <Button severity="info" :label="t('show_vpn_portal_config')" @click="showVpnPortalConfig" />
              <Button severity="info" :label="t('show_event_log')" @click="showEventLogs" />
            </div>
          </div>
        </template>
      </Card>

      <Divider />

      <template v-if="showEgressPanel">
        <MpEgressPanel :runtime="mpRuntime" :mp-config="mpConfig" :egress-wire-limit-bps="egressWireLimitBps" />
        <MpLiveSettings v-if="mpConfig" :mp-config="mpConfig" :egress-wire-limit-bps="egressWireLimitBps"
          :tcp-hole-punch-mode="tcpHolePunchMode" :busy="mpBusy" class="mt-3"
          @apply="(label, change) => emit('mp-live-apply', label, change)" />
        <Divider />
      </template>

      <Card>
        <template #title>
          <div class="flex items-center gap-3">
            <div class="flex items-center gap-2">
              <span>{{ t('peer_info') }}</span>
            </div>
            <div class="flex items-center gap-1">
              <Badge :value="peerCount" severity="info"
                class="text-lg font-semibold px-2 py-1 rounded-full bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200" />
            </div>
          </div>
        </template>
        <template #content>
          <div>
            <PeerList :rows="peerRows" :expanded-key="expandedPeerKey" @toggle="onPeerToggle">
              <template #expansion="{ row }">
                <div class="box-border" :data-testid="`peer-mp-expansion-${row.key}`">
                  <dl class="mb-2 flex flex-wrap gap-x-5 gap-y-1 text-sm" data-testid="peer-details">
                    <div v-for="item in peerDetails(row.key)" :key="item.label" class="flex gap-1.5">
                      <dt class="text-zinc-500">{{ item.label }}</dt>
                      <dd class="m-0 break-all">{{ item.value }}</dd>
                    </div>
                  </dl>
                  <AnimatePresence>
                    <motion.div key="peer-mp" v-bind="reveal" class="overflow-hidden">
                      <MpRuntimePanel :runtime="mpRuntime" :peer-id="peerIdForKey(row.key)" :mp-config="mpConfig"
                        :busy="mpBusy" :current-mtu="mtu" :peer-names="peerNames"
                        @set-policy="(m, a) => emit('mp-set-policy', m, a)" @reconnect="emit('mp-reconnect')"
                        @apply-mtu="(v) => emit('mp-apply-mtu', v)"
                        @edit-mp="(label, update) => emit('mp-edit', label, update)"
                        @set-congestion-control="(m) => emit('mp-set-congestion-control', m)" />
                    </motion.div>
                  </AnimatePresence>
                </div>
              </template>
            </PeerList>
          </div>
        </template>
      </Card>
    </template>
  </div>
</template>

<style lang="postcss" scoped>
.p-timeline :deep(.p-timeline-event-opposite) {
  @apply flex-none;
}
</style>
