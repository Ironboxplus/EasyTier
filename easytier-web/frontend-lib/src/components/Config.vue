<script setup lang="ts">
import { AutoComplete, Button, Checkbox, Dialog, Divider, InputNumber, InputText, Panel, Password, Select, SelectButton, ToggleButton } from 'primevue'
import InputGroup from 'primevue/inputgroup'
import InputGroupAddon from 'primevue/inputgroupaddon'
import {
  addRow,
  CompressionAlgoPb,
  DEFAULT_NETWORK_CONFIG,
  NetworkConfig,
  normalizeNetworkConfig,
  removeRow
} from '../types/network'
import { computed, ref, onMounted, onUnmounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import AclManager from './acl/AclManager.vue'
import UrlListInput from './UrlListInput.vue'
import MpConfigPanel from './MpConfigPanel.vue'
import MpEffectBadge from './MpEffectBadge.vue'
import { DEFAULT_MP_CONFIG, normalizeMpConfig, normalizeTcpHolePunchMode } from '../types/mpConfig'

const props = defineProps<{
  configInvalid?: boolean
  hostname?: string
}>()

defineEmits(['runNetwork'])

const curNetwork = defineModel('curNetwork', {
  type: Object as () => NetworkConfig,
  default: DEFAULT_NETWORK_CONFIG,
})

const { t } = useI18n()

const protos: { [proto: string]: number } = {
  tcp: 11010,
  udp: 11010,
  wg: 11011,
  ws: 11011,
  wss: 11012,
  quic: 11012,
  faketcp: 11013,
  http: 80,
  https: 443,
  txt: 0,
  srv: 0,
}

const inetSuggestions = ref([''])

function searchInetSuggestions(e: { query: string }) {
  if (e.query.search('/') >= 0) {
    inetSuggestions.value = [e.query]
  } else {
    const ret = []
    for (let i = 0; i < 32; i++) {
      ret.push(`${e.query}/${i}`)
    }
    inetSuggestions.value = ret
  }
}

const exitNodesSuggestions = ref([''])

function searchExitNodesSuggestions(e: { query: string }) {
  const ret = []
  ret.push(e.query)
  exitNodesSuggestions.value = ret
}

const whitelistSuggestions = ref([''])

function searchWhitelistSuggestions(e: { query: string }) {
  const ret = []
  ret.push(e.query)
  whitelistSuggestions.value = ret
}

interface BoolFlag {
  field: keyof NetworkConfig
  help: string
}

const bool_flags: BoolFlag[] = [
  { field: 'latency_first', help: 'latency_first_help' },
  { field: 'use_smoltcp', help: 'use_smoltcp_help' },
  { field: 'disable_ipv6', help: 'disable_ipv6_help' },
  { field: 'ipv6_public_addr_auto', help: 'ipv6_public_addr_auto_help' },
  { field: 'enable_kcp_proxy', help: 'enable_kcp_proxy_help' },
  { field: 'disable_kcp_input', help: 'disable_kcp_input_help' },
  { field: 'enable_quic_proxy', help: 'enable_quic_proxy_help' },
  { field: 'disable_quic_input', help: 'disable_quic_input_help' },
  { field: 'disable_p2p', help: 'disable_p2p_help' },
  { field: 'p2p_only', help: 'p2p_only_help' },
  { field: 'lazy_p2p', help: 'lazy_p2p_help' },
  { field: 'bind_device', help: 'bind_device_help' },
  { field: 'no_tun', help: 'no_tun_help' },
  { field: 'enable_exit_node', help: 'enable_exit_node_help' },
  { field: 'relay_all_peer_rpc', help: 'relay_all_peer_rpc_help' },
  { field: 'need_p2p', help: 'need_p2p_help' },
  { field: 'multi_thread', help: 'multi_thread_help' },
  { field: 'proxy_forward_by_system', help: 'proxy_forward_by_system_help' },
  { field: 'disable_encryption', help: 'disable_encryption_help' },
  { field: 'disable_tcp_hole_punching', help: 'disable_tcp_hole_punching_help' },
  { field: 'disable_udp_hole_punching', help: 'disable_udp_hole_punching_help' },
  { field: 'enable_udp_broadcast_relay', help: 'enable_udp_broadcast_relay_help' },
  { field: 'disable_upnp', help: 'disable_upnp_help' },
  { field: 'disable_sym_hole_punching', help: 'disable_sym_hole_punching_help' },
  { field: 'enable_magic_dns', help: 'enable_magic_dns_help' },
  { field: 'enable_private_mode', help: 'enable_private_mode_help' },
]

const portForwardProtocolOptions = ref(["tcp", "udp"]);
const defaultProtocolOptions = ['tcp', 'udp', 'ws', 'wss', 'quic', 'wg'];
const encryptionAlgorithmOptions = ['aes-gcm', 'aes-gcm-256', 'chacha20', 'xor', 'openssl-aes128-gcm', 'openssl-aes256-gcm', 'openssl-chacha20']
const compressionOptions = [
  { label: 'None', value: CompressionAlgoPb.None },
  { label: 'Zstd', value: CompressionAlgoPb.Zstd },
]
const secureModeEnabled = computed({
  get: () => curNetwork.value.secure_mode?.enabled === true,
  set: (value: boolean) => {
    curNetwork.value.secure_mode = value ? { enabled: true } : undefined
  },
})

const editingPortForward = ref(false);
const editingPortForwardIndex = ref(-1);
const editingPortForwardData = ref();

function openPortForwardEditor(index: number) {
  editingPortForwardIndex.value = index;
  // deep copy
  editingPortForwardData.value = JSON.parse(JSON.stringify(curNetwork.value.port_forwards[index]));
  editingPortForward.value = true;
}

function addPortForward() {
  addRow(curNetwork.value.port_forwards)
  if (isCompact.value) {
    openPortForwardEditor(curNetwork.value.port_forwards.length - 1)
  }
}

function savePortForward() {
  curNetwork.value.port_forwards[editingPortForwardIndex.value] = editingPortForwardData.value;
  editingPortForward.value = false;
}

const portForwardContainer = ref<HTMLElement | null>(null);
const isCompact = ref(false);

const UINT64_MAX = (1n << 64n) - 1n

onMounted(() => {
  if (portForwardContainer.value) {
    let resizeObserver = new ResizeObserver(entries => {
      for (const entry of entries) {
        isCompact.value = entry.contentRect.width < 540;
      }
    });
    resizeObserver.observe(portForwardContainer.value);

    onUnmounted(() => {
      if (resizeObserver && portForwardContainer.value) {
        resizeObserver.unobserve(portForwardContainer.value);
      }
    });
  }
});

function syncNormalizedNetwork(network: NetworkConfig | undefined): void {
  if (!network) {
    return
  }

  Object.assign(network, normalizeNetworkConfig(network))
}

watch(() => curNetwork.value, syncNormalizedNetwork, { immediate: true, deep: false })

function parseInstanceRecvBpsLimitInput(value: string): number | string | null | undefined {
  const trimmed = value.trim()
  if (trimmed.length === 0) {
    return null
  }
  if (!/^\d+$/.test(trimmed)) {
    return undefined
  }

  const limit = BigInt(trimmed)
  if (limit === 0n) {
    return null
  }
  if (limit > UINT64_MAX) {
    return undefined
  }

  return limit <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(limit) : limit.toString()
}

const instanceRecvBpsLimitInput = computed<string>({
  get: () => {
    const limit = curNetwork.value.instance_recv_bps_limit
    return limit == null ? '' : String(limit)
  },
  set: (value) => {
    const limit = parseInstanceRecvBpsLimitInput(value)
    if (limit !== undefined) {
      curNetwork.value.instance_recv_bps_limit = limit
    }
  },
})
</script>

<template>
  <div class="frontend-lib">
    <div class="flex flex-col h-full">
      <div class="flex flex-col">
        <div class="w-full self-center ">
          <Panel :header="t('basic_settings')">
            <div class="flex flex-col gap-y-2">
              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <div class="flex items-center" for="virtual_ip">
                    <label class="mr-2"> {{ t('virtual_ipv4') }} </label>
                    <Checkbox v-model="curNetwork.dhcp" input-id="virtual_ip_auto" :binary="true" />

                    <label for="virtual_ip_auto" class="ml-2">
                      {{ t('virtual_ipv4_dhcp') }}
                    </label>
                  </div>
                  <InputGroup>
                    <InputText id="virtual_ip" v-model="curNetwork.virtual_ipv4" :disabled="curNetwork.dhcp"
                      aria-describedby="virtual_ipv4-help" />
                    <InputGroupAddon>
                      <span>/</span>
                    </InputGroupAddon>
                    <InputNumber v-model="curNetwork.network_length" :disabled="curNetwork.dhcp"
                      inputId="horizontal-buttons" showButtons :step="1" mode="decimal" :min="1" :max="32" fluid
                      class="max-w-20" />
                  </InputGroup>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label for="network_name">{{ t('network_name') }}</label>
                  <InputText id="network_name" v-model="curNetwork.network_name" aria-describedby="network_name-help" />
                </div>
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label for="network_secret">{{ t('network_secret') }}</label>
                  <Password id="network_secret" v-model="curNetwork.network_secret"
                    aria-describedby="network_secret-help" toggleMask :feedback="false" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <div class="flex items-center">
                    <label for="initial_nodes">{{ t('initial_nodes') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('initial_nodes_help')"></span>
                  </div>
                  <div class="items-center flex flex-col p-fluid gap-y-2">
                    <UrlListInput id="initial_nodes" v-model="curNetwork.peer_urls" :protos="protos"
                      defaultUrl="tcp://:11010" :add-label="t('add_initial_node')"
                      :placeholder="t('initial_node_placeholder')" />
                  </div>
                </div>
              </div>
            </div>
          </Panel>

          <Divider />

          <Panel :header="t('advanced_settings')" toggleable collapsed>
            <div class="flex flex-col gap-y-2">

              <div class="flex flex-row gap-x-9 flex-wrap w-full">
                <div class="flex flex-col gap-2 grow min-w-0 basis-full">
                  <label>{{ t('mp_settings') }}</label>
                  <MpConfigPanel
                    :model-value="curNetwork.mp ?? DEFAULT_MP_CONFIG()"
                    :tcp-hole-punch-mode="curNetwork.tcp_hole_punch_mode ?? 'auto'"
                    :egress-wire-limit-bps="curNetwork.egress_wire_limit_bps ?? null"
                    :proxy-flags="curNetwork"
                    @update:proxy-flags="(v) => Object.assign(curNetwork, v)"
                    @update:model-value="(v) => { curNetwork.mp = normalizeMpConfig(v) }"
                    @update:egress-wire-limit-bps="(v) => { curNetwork.egress_wire_limit_bps = v }"
                    @update:tcp-hole-punch-mode="(v) => { curNetwork.tcp_hole_punch_mode = normalizeTcpHolePunchMode(v) }"
                  />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label> {{ t('flags_switch') }} </label>
                  <div class="flex flex-row flex-wrap">

                    <div class="basis-[20rem] flex items-center" v-for="flag in bool_flags">
                      <Checkbox v-model="curNetwork[flag.field]" :input-id="flag.field" :binary="true" />
                      <label :for="flag.field" class="ml-2"> {{ t(flag.field) }} </label>
                      <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t(flag.help)"></span>
                    </div>

                  </div>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label for="hostname">{{ t('hostname') }}</label>
                  <InputText id="hostname" v-model="curNetwork.hostname" aria-describedby="hostname-help" :format="true"
                    :placeholder="t('hostname_placeholder', [props.hostname])" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap w-full">
                <div class="flex flex-col gap-2 grow p-fluid min-w-0">
                  <label for="username">{{ t('proxy_cidrs') }}</label>
                  <AutoComplete id="subnet-proxy" v-model="curNetwork.proxy_cidrs"
                    :placeholder="t('chips_placeholder', ['10.0.0.0/24'])" class="w-full" multiple fluid
                    :suggestions="inetSuggestions" @complete="searchInetSuggestions" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap ">
                <div class="flex flex-col gap-2 grow min-w-0">
                  <label for="username">VPN Portal</label>
                  <ToggleButton v-model="curNetwork.enable_vpn_portal" on-icon="pi pi-check" off-icon="pi pi-times"
                    :on-label="t('off_text')" :off-label="t('on_text')" class="w-48" />
                  <div v-if="curNetwork.enable_vpn_portal" class="items-center flex flex-row gap-x-4">
                    <div class="flex flex-row gap-x-9 flex-wrap w-full">
                      <div class="flex flex-col gap-2 basis-8/12 grow min-w-0">
                        <InputGroup>
                          <InputText v-model="curNetwork.vpn_portal_client_network_addr"
                            :placeholder="t('vpn_portal_client_network')" />
                          <InputGroupAddon>
                            <span>/{{ curNetwork.vpn_portal_client_network_len }}</span>
                          </InputGroupAddon>
                        </InputGroup>
                      </div>
                      <div class="flex flex-col gap-2 basis-3/12 grow min-w-0">
                        <InputNumber v-model="curNetwork.vpn_portal_listen_port" :allow-empty="false" :format="false"
                          :min="0" :max="65535" fluid />
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 grow p-fluid min-w-0">
                  <label for="listener_urls">{{ t('listener_urls') }}</label>
                  <UrlListInput v-model="curNetwork.listener_urls" :protos="protos" :add-label="t('add_listener_url')"
                    placeholder="0.0.0.0" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label for="dev_name">{{ t('dev_name') }}</label>
                  <InputText id="dev_name" v-model="curNetwork.dev_name" aria-describedby="dev_name-help" :format="true"
                    :placeholder="t('dev_name_placeholder')" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <div class="flex">
                    <label for="mtu">{{ t('mtu') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('mtu_help')"></span>
                  </div>
                  <InputNumber id="mtu" v-model="curNetwork.mtu" aria-describedby="mtu-help" :format="false"
                    :placeholder="t('mtu_placeholder')" :min="400" :max="1380" fluid />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <div class="flex">
                    <label for="instance_recv_bps_limit">{{ t('instance_recv_bps_limit') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center"
                      v-tooltip="t('instance_recv_bps_limit_help')"></span>
                  </div>
                  <InputText id="instance_recv_bps_limit" v-model="instanceRecvBpsLimitInput"
                    aria-describedby="instance_recv_bps_limit-help" inputmode="numeric" pattern="[0-9]*"
                    :placeholder="t('instance_recv_bps_limit_placeholder')" fluid />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <div class="flex">
                    <label for="relay_network_whitelist">{{ t('relay_network_whitelist') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center"
                      v-tooltip="t('relay_network_whitelist_help')"></span>
                  </div>
                  <ToggleButton v-model="curNetwork.enable_relay_network_whitelist" on-icon="pi pi-check"
                    off-icon="pi pi-times" :on-label="t('off_text')" :off-label="t('on_text')" class="w-48" />
                  <div v-if="curNetwork.enable_relay_network_whitelist" class="items-center flex flex-row gap-x-4">
                    <div class="min-w-64 w-full">
                      <AutoComplete id="relay_network_whitelist" v-model="curNetwork.relay_network_whitelist"
                        :placeholder="t('relay_network_whitelist')" class="w-full" multiple fluid
                        :suggestions="whitelistSuggestions" @complete="searchWhitelistSuggestions" />
                    </div>
                  </div>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap ">
                <div class="flex flex-col gap-2 grow min-w-0">
                  <div class="flex">
                    <label for="routes">{{ t('manual_routes') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('manual_routes_help')"></span>
                  </div>
                  <ToggleButton v-model="curNetwork.enable_manual_routes" on-icon="pi pi-check" off-icon="pi pi-times"
                    :on-label="t('off_text')" :off-label="t('on_text')" class="w-48" />
                  <div v-if="curNetwork.enable_manual_routes" class="items-center flex flex-row gap-x-4">
                    <div class="min-w-64 w-full">
                      <AutoComplete id="routes" v-model="curNetwork.routes"
                        :placeholder="t('chips_placeholder', ['192.168.0.0/16'])" class="w-full" multiple fluid
                        :suggestions="inetSuggestions" @complete="searchInetSuggestions" />
                    </div>
                  </div>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap ">
                <div class="flex flex-col gap-2 grow min-w-0">
                  <div class="flex">
                    <label for="socks5_port">{{ t('socks5') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('socks5_help')"></span>
                  </div>
                  <ToggleButton v-model="curNetwork.enable_socks5" on-icon="pi pi-check" off-icon="pi pi-times"
                    :on-label="t('off_text')" :off-label="t('on_text')" class="w-48" />
                  <div v-if="curNetwork.enable_socks5" class="items-center flex flex-row gap-x-4">
                    <div class="min-w-64 w-full">
                      <InputNumber id="socks5_port" v-model="curNetwork.socks5_port" aria-describedby="rpc_port-help"
                        :format="false" :allow-empty="false" :min="0" :max="65535" class="w-full" />
                    </div>
                  </div>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap w-full">
                <div class="flex flex-col gap-2 grow p-fluid min-w-0">
                  <div class="flex">
                    <label for="exit_nodes">{{ t('exit_nodes') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('exit_nodes_help')"></span>
                  </div>
                  <AutoComplete id="exit_nodes" v-model="curNetwork.exit_nodes"
                    :placeholder="t('chips_placeholder', ['192.168.8.8'])" class="w-full" multiple fluid
                    :suggestions="exitNodesSuggestions" @complete="searchExitNodesSuggestions" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap w-full">
                <div class="flex flex-col gap-2 grow p-fluid min-w-0">
                  <div class="flex">
                    <label for="mapped_listeners">{{ t('mapped_listeners') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('mapped_listeners_help')"></span>
                  </div>
                  <UrlListInput v-model="curNetwork.mapped_listeners" :protos="protos"
                    :add-label="t('add_mapped_listener')" />
                </div>
              </div>

            </div>
          </Panel>

          <Divider />

          <!-- Encryption, compression, identity and the public IPv6 address. Each says when an edit takes effect. -->
          <Panel :header="t('security_settings.title')" toggleable collapsed>
            <div class="flex flex-col gap-y-3" data-testid="security-settings">
              <div class="flex flex-row gap-x-9 flex-wrap">
                <label class="flex items-center gap-2"><Checkbox v-model="secureModeEnabled" binary input-id="secure_mode" />{{ t('security_settings.secure_mode') }}<MpEffectBadge field="secure_mode" /></label>
                <label class="flex items-center gap-2"><Checkbox v-model="curNetwork.ipv6_public_addr_provider" binary />{{ t('security_settings.ipv6_provider') }}<MpEffectBadge field="ipv6_public_addr_provider" /></label>
                <label class="flex items-center gap-2"><Checkbox v-model="curNetwork.disable_relay_data" binary />{{ t('security_settings.disable_relay_data') }}<MpEffectBadge field="disable_relay_data" /></label>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label class="flex items-center gap-2" for="encryption_algorithm">{{ t('security_settings.encryption_algorithm') }}<MpEffectBadge field="encryption_algorithm" /></label>
                  <Select id="encryption_algorithm" v-model="curNetwork.encryption_algorithm" :options="encryptionAlgorithmOptions" show-clear
                    :placeholder="t('security_settings.default')" />
                </div>
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label class="flex items-center gap-2" for="data_compress_algo">{{ t('security_settings.compression') }}<MpEffectBadge field="data_compress_algo" /></label>
                  <Select id="data_compress_algo" v-model="curNetwork.data_compress_algo" :options="compressionOptions"
                    option-label="label" option-value="value" show-clear :placeholder="t('security_settings.default')" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label class="flex items-center gap-2" for="credential_file">{{ t('security_settings.credential_file') }}<MpEffectBadge field="credential_file" /></label>
                  <InputText id="credential_file" v-model="curNetwork.credential_file" />
                </div>
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label class="flex items-center gap-2" for="ipv6_public_addr_prefix">{{ t('security_settings.ipv6_prefix') }}<MpEffectBadge field="ipv6_public_addr_prefix" /></label>
                  <InputText id="ipv6_public_addr_prefix" v-model="curNetwork.ipv6_public_addr_prefix" placeholder="2001:db8::/64" />
                </div>
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label class="flex items-center gap-2" for="socket_mark">{{ t('security_settings.socket_mark') }}<MpEffectBadge field="socket_mark" /></label>
                  <InputNumber id="socket_mark" v-model="curNetwork.socket_mark" :min="0" :format="false" fluid />
                </div>
              </div>
            </div>
          </Panel>

          <Divider />

          <!-- Core switches that used to live only in the TOML file. Each says when an edit takes effect. -->
          <Panel :header="t('core_switches.title')" toggleable collapsed>
            <div class="flex flex-col gap-y-3" data-testid="core-switches">
              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label class="flex items-center gap-2" for="default_protocol">{{ t('core_switches.default_protocol') }}<MpEffectBadge field="default_protocol" /></label>
                  <Select id="default_protocol" v-model="curNetwork.default_protocol" :options="defaultProtocolOptions" show-clear
                    :placeholder="t('core_switches.default_protocol_auto')" />
                </div>
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label class="flex items-center gap-2" for="multi_thread_count">{{ t('core_switches.multi_thread_count') }}<MpEffectBadge field="multi_thread_count" /></label>
                  <InputNumber id="multi_thread_count" v-model="curNetwork.multi_thread_count" :min="1" :max="256" :format="false"
                    :placeholder="t('core_switches.multi_thread_count_placeholder')" fluid />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <label class="flex items-center gap-2"><Checkbox v-model="curNetwork.disable_relay_kcp" binary />{{ t('core_switches.disable_relay_kcp') }}<MpEffectBadge field="disable_relay_kcp" /></label>
                <label class="flex items-center gap-2"><Checkbox v-model="curNetwork.disable_relay_quic" binary />{{ t('core_switches.disable_relay_quic') }}<MpEffectBadge field="disable_relay_quic" /></label>
                <label class="flex items-center gap-2"><Checkbox v-model="curNetwork.enable_relay_foreign_network_kcp" binary />{{ t('core_switches.relay_foreign_kcp') }}<MpEffectBadge field="enable_relay_foreign_network_kcp" /></label>
                <label class="flex items-center gap-2"><Checkbox v-model="curNetwork.enable_relay_foreign_network_quic" binary />{{ t('core_switches.relay_foreign_quic') }}<MpEffectBadge field="enable_relay_foreign_network_quic" /></label>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label class="flex items-center gap-2" for="foreign_relay_bps_limit">{{ t('core_switches.foreign_relay_limit') }}<MpEffectBadge field="foreign_relay_bps_limit" /></label>
                  <InputNumber id="foreign_relay_bps_limit" v-model="curNetwork.foreign_relay_bps_limit as number | null" :min="0" :format="false"
                    suffix=" bps" :placeholder="t('core_switches.unlimited')" fluid />
                </div>
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label class="flex items-center gap-2" for="tld_dns_zone">{{ t('core_switches.tld_dns_zone') }}<MpEffectBadge field="tld_dns_zone" /></label>
                  <InputText id="tld_dns_zone" v-model="curNetwork.tld_dns_zone" placeholder="et.net." />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label class="flex items-center gap-2" for="ipv6_addr">{{ t('core_switches.ipv6') }}<MpEffectBadge field="ipv6" /></label>
                  <InputText id="ipv6_addr" v-model="curNetwork.ipv6" placeholder="fd00::2/64" />
                </div>
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label class="flex items-center gap-2" for="netns">{{ t('core_switches.netns') }}<MpEffectBadge field="netns" /></label>
                  <InputText id="netns" v-model="curNetwork.netns" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label class="flex items-center gap-2" for="tcp_whitelist">{{ t('core_switches.tcp_whitelist') }}<MpEffectBadge field="tcp_whitelist" /></label>
                  <AutoComplete id="tcp_whitelist" v-model="curNetwork.tcp_whitelist" :placeholder="t('chips_placeholder', ['80,8000-8100'])" multiple fluid
                    :suggestions="whitelistSuggestions" @complete="searchWhitelistSuggestions" />
                </div>
                <div class="flex flex-col gap-2 basis-5/12 grow min-w-0">
                  <label class="flex items-center gap-2" for="udp_whitelist">{{ t('core_switches.udp_whitelist') }}<MpEffectBadge field="udp_whitelist" /></label>
                  <AutoComplete id="udp_whitelist" v-model="curNetwork.udp_whitelist" :placeholder="t('chips_placeholder', ['53'])" multiple fluid
                    :suggestions="whitelistSuggestions" @complete="searchWhitelistSuggestions" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-3/12 grow min-w-0">
                  <label class="flex items-center gap-2" for="stun_servers">{{ t('core_switches.stun_servers') }}<MpEffectBadge field="stun_servers" /></label>
                  <AutoComplete id="stun_servers" v-model="curNetwork.stun_servers" :placeholder="t('chips_placeholder', ['stun.example.org:3478'])" multiple fluid
                    :suggestions="whitelistSuggestions" @complete="searchWhitelistSuggestions" />
                </div>
                <div class="flex flex-col gap-2 basis-3/12 grow min-w-0">
                  <label class="flex items-center gap-2" for="tcp_stun_servers">{{ t('core_switches.tcp_stun_servers') }}<MpEffectBadge field="tcp_stun_servers" /></label>
                  <AutoComplete id="tcp_stun_servers" v-model="curNetwork.tcp_stun_servers" :placeholder="t('chips_placeholder', ['stun.example.org:3478'])" multiple fluid
                    :suggestions="whitelistSuggestions" @complete="searchWhitelistSuggestions" />
                </div>
                <div class="flex flex-col gap-2 basis-3/12 grow min-w-0">
                  <label class="flex items-center gap-2" for="stun_servers_v6">{{ t('core_switches.stun_servers_v6') }}<MpEffectBadge field="stun_servers_v6" /></label>
                  <AutoComplete id="stun_servers_v6" v-model="curNetwork.stun_servers_v6" :placeholder="t('chips_placeholder', ['stun6.example.org:3478'])" multiple fluid
                    :suggestions="whitelistSuggestions" @complete="searchWhitelistSuggestions" />
                </div>
              </div>
            </div>
          </Panel>

          <Divider />

          <Panel :header="t('port_forwards')" toggleable collapsed>
            <div ref="portForwardContainer" class="flex flex-col gap-y-2">
              <div class="flex flex-row gap-x-9 flex-wrap w-full">
                <div class="flex flex-col gap-2 grow p-fluid min-w-0">
                  <div class="flex">
                    <label for="port_forwards">{{ t('port_forwards_help') }}</label>
                  </div>
                  <div v-for="(row, index) in curNetwork.port_forwards" :key="index" class="form-row">
                    <!-- Wide screen view -->
                    <div v-if="!isCompact" class="flex gap-2 items-end">
                      <SelectButton v-model="row.proto" :options="portForwardProtocolOptions" :allow-empty="false" />
                      <div style="flex-grow: 4;">
                        <InputGroup>
                          <InputText v-model="row.bind_ip" :placeholder="t('port_forwards_bind_addr')" />
                          <InputGroupAddon>
                            <span style="font-weight: bold">:</span>
                          </InputGroupAddon>
                          <InputNumber v-model="row.bind_port" :format="false" inputId="horizontal-buttons" :step="1"
                            mode="decimal" :min="1" :max="65535" fluid class="max-w-20" />
                        </InputGroup>
                      </div>
                      <div style="flex-grow: 4;">
                        <InputGroup>
                          <InputText v-model="row.dst_ip" :placeholder="t('port_forwards_dst_addr')" />
                          <InputGroupAddon>
                            <span style="font-weight: bold">:</span>
                          </InputGroupAddon>
                          <InputNumber v-model="row.dst_port" :format="false" inputId="horizontal-buttons" :step="1"
                            mode="decimal" :min="1" :max="65535" fluid class="max-w-20" />
                        </InputGroup>
                      </div>
                      <div style="flex-grow: 1;">
                        <Button v-if="curNetwork.port_forwards.length > 0" icon="pi pi-trash" severity="danger" text
                          rounded @click="removeRow(index, curNetwork.port_forwards)" />
                      </div>
                    </div>
                    <!-- Small screen view -->
                    <div v-else class="flex justify-between items-center p-2 border-b">
                      <span>{{ row.proto }}://{{ row.bind_ip }}:{{ row.bind_port }}/{{ row.dst_ip }}:{{
                        row.dst_port }}</span>
                      <div class="flex gap-2">
                        <Button icon="pi pi-pencil" class="p-button-sm" @click="openPortForwardEditor(index)" />
                        <Button icon="pi pi-trash" class="p-button-sm p-button-danger"
                          @click="removeRow(index, curNetwork.port_forwards)" />
                      </div>
                    </div>
                  </div>

                  <div class="flex justify-content-end mt-4">
                    <Button icon="pi pi-plus" :label="t('port_forwards_add_btn')" severity="success"
                      @click="addPortForward" />
                  </div>

                  <Dialog v-model:visible="editingPortForward" modal :header="t('edit_port_forward')"
                    :style="{ width: '90vw', maxWidth: '600px' }">
                    <div v-if="editingPortForwardData" class="flex flex-col gap-4">
                      <SelectButton v-model="editingPortForwardData.proto" :options="portForwardProtocolOptions"
                        :allow-empty="false" />
                      <InputGroup>
                        <InputText v-model="editingPortForwardData.bind_ip"
                          :placeholder="t('port_forwards_bind_addr')" />
                        <InputGroupAddon>
                          <span style="font-weight: bold">:</span>
                        </InputGroupAddon>
                        <InputNumber v-model="editingPortForwardData.bind_port" :format="false" :step="1" mode="decimal"
                          :min="1" :max="65535" class="max-w-20" />
                      </InputGroup>
                      <InputGroup>
                        <InputText v-model="editingPortForwardData.dst_ip" :placeholder="t('port_forwards_dst_addr')" />
                        <InputGroupAddon>
                          <span style="font-weight: bold">:</span>
                        </InputGroupAddon>
                        <InputNumber v-model="editingPortForwardData.dst_port" :format="false" :step="1" mode="decimal"
                          :min="1" :max="65535" class="max-w-20" />
                      </InputGroup>
                    </div>
                    <template #footer>
                      <Button :label="t('web.common.cancel')" icon="pi pi-times" @click="editingPortForward = false"
                        text />
                      <Button :label="t('web.common.save')" icon="pi pi-save" @click="savePortForward" />
                    </template>
                  </Dialog>
                </div>
              </div>
            </div>
          </Panel>

          <Divider />

          <Panel :header="t('acl.title')" toggleable collapsed>
            <div v-if="curNetwork.acl" class="flex flex-col gap-y-2">
              <AclManager v-model="curNetwork.acl" />
            </div>
            <div v-else class="flex justify-center p-4">
              <Button :label="t('acl.enabled')"
                @click="curNetwork.acl = { acl_v1: { chains: [], group: { declares: [], members: [] } } }" />
            </div>
          </Panel>

          <div class="flex pt-6 justify-center">
            <Button :label="t('run_network')" icon="pi pi-arrow-right" icon-pos="right" :disabled="configInvalid"
              @click="$emit('runNetwork', curNetwork)" />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
