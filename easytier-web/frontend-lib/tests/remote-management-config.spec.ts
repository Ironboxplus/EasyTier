import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import { defineComponent, h, nextTick } from 'vue'
import RemoteManagement from '../src/components/RemoteManagement.vue'
import {
  DEFAULT_NETWORK_CONFIG,
  type NetworkConfig,
} from '../src/types/network'

const BOOLEAN_CONFIG_FIELDS = [
  'dhcp',
  'enable_vpn_portal',
  'advanced_settings',
  'latency_first',
  'use_smoltcp',
  'disable_ipv6',
  'enable_kcp_proxy',
  'disable_kcp_input',
  'disable_p2p',
  'bind_device',
  'no_tun',
  'enable_exit_node',
  'relay_all_peer_rpc',
  'multi_thread',
  'enable_relay_network_whitelist',
  'enable_manual_routes',
  'proxy_forward_by_system',
  'disable_encryption',
  'enable_socks5',
  'disable_udp_hole_punching',
  'enable_magic_dns',
  'enable_private_mode',
  'enable_quic_proxy',
  'disable_quic_input',
  'disable_sym_hole_punching',
  'p2p_only',
  'lazy_p2p',
  'need_p2p',
  'disable_upnp',
  'ipv6_public_addr_provider',
  'ipv6_public_addr_auto',
  'disable_relay_data',
  'enable_udp_broadcast_relay',
  'disable_tcp_hole_punching',
] as const satisfies readonly (keyof NetworkConfig)[]

vi.mock('vue-i18n', () => ({
  useI18n: () => ({
    t: (key: string) => key,
  }),
}))

vi.mock('primevue', async () => {
  const { defineComponent, h } = await import('vue')

  const PassThrough = defineComponent({
    name: 'PassThrough',
    props: {
      label: String,
      value: String,
    },
    setup(props, { slots }) {
      return () => h('div', {
        'data-label': props.label,
        'data-value': props.value,
        'data-stub': 'pass-through',
      }, slots.default?.())
    },
  })

  const ButtonStub = defineComponent({
    name: 'Button',
    props: {
      label: String,
      icon: String,
      disabled: Boolean,
    },
    emits: ['click'],
    setup(props, { slots, emit }) {
      return () => h('button', {
        type: 'button',
        disabled: props.disabled,
        'data-label': props.label ?? props.icon,
        onClick: (event: MouseEvent) => emit('click', event),
      }, slots.default?.() ?? props.label ?? props.icon)
    },
  })

  const SelectStub = defineComponent({
    name: 'Select',
    props: {
      modelValue: Object,
      options: Array,
    },
    emits: ['update:modelValue'],
    setup(props, { slots }) {
      return () => h('div', { 'data-stub': 'select' }, [
        slots.value?.({ value: props.modelValue, placeholder: '' }),
      ])
    },
  })

  const MenuStub = defineComponent({
    name: 'Menu',
    setup(_, { expose }) {
      expose({ toggle: vi.fn() })
      return () => h('div', { 'data-stub': 'menu' })
    },
  })

  return {
    Button: ButtonStub,
    ConfirmPopup: PassThrough,
    Divider: PassThrough,
    IftaLabel: PassThrough,
    Menu: MenuStub,
    Message: PassThrough,
    Select: SelectStub,
    Tag: PassThrough,
    useConfirm: () => ({ require: vi.fn() }),
    useToast: () => ({ add: vi.fn() }),
  }
})

const INSTANCE_ID = '00000000-0000-0000-0000-000000000001'
const INSTANCE_UUID = {
  part1: 0,
  part2: 0,
  part3: 0,
  part4: 1,
}

function makeFlagConfig(): NetworkConfig {
  const config = {
    ...DEFAULT_NETWORK_CONFIG(),
    instance_id: INSTANCE_ID,
    network_name: 'mesh-save',
  }

  BOOLEAN_CONFIG_FIELDS.forEach((field, index) => {
    config[field] = index % 2 === 0
  })

  return config
}

function cloneConfig(config: NetworkConfig): NetworkConfig {
  return JSON.parse(JSON.stringify(config)) as NetworkConfig
}

function snapshotBooleanConfigFields(config: NetworkConfig): Record<string, unknown> {
  return Object.fromEntries(
    BOOLEAN_CONFIG_FIELDS.map((field) => [field, config[field]]),
  )
}

async function settleRemoteManagement() {
  for (let i = 0; i < 3; i++) {
    await new Promise((resolve) => setTimeout(resolve, 0))
    await flushPromises()
    await nextTick()
  }
}

describe('RemoteManagement config save', () => {
  it('saves the current network config without dropping boolean fields', async () => {
    const config = makeFlagConfig()
    const expectedFlags = snapshotBooleanConfigFields(config)
    const api = {
      delete_network: vi.fn(),
      generate_config: vi.fn(),
      get_network_config: vi.fn(async () => cloneConfig(config)),
      get_network_info: vi.fn(),
      get_network_metas: vi.fn(async (instanceIds: string[]) => ({
        metas: Object.fromEntries(instanceIds.map((id) => [id, {
          config_permission: 0xffffffff,
          inst_id: INSTANCE_UUID,
          instance_name: 'mesh-save',
          network_name: 'mesh-save',
          source: 2,
        }])),
      })),
      list_network_instance_ids: vi.fn(async () => ({
        disabled_inst_ids: [INSTANCE_UUID],
        running_inst_ids: [],
      })),
      parse_config: vi.fn(),
      run_network: vi.fn(),
      save_config: vi.fn(async () => undefined),
      update_network_instance_state: vi.fn(),
      validate_config: vi.fn(),
    }

    const wrapper = mount(RemoteManagement, {
      props: {
        api,
        instanceId: INSTANCE_ID,
      },
      global: {
        stubs: {
          Config: true,
          ConfigEditDialog: true,
          Status: true,
        },
      },
    })

    try {
      await settleRemoteManagement()

      const saveButton = wrapper.find('button[data-label="web.device_management.save_config"]')
      expect(saveButton.exists()).toBe(true)
      expect(saveButton.attributes('disabled')).toBeUndefined()

      await saveButton.trigger('click')
      await flushPromises()

      expect(api.save_config).toHaveBeenCalledOnce()
      const savedConfig = api.save_config.mock.calls[0][0] as NetworkConfig

      for (const field of BOOLEAN_CONFIG_FIELDS) {
        expect(savedConfig[field], `${field} should be saved`).toBe(expectedFlags[field])
      }
    } finally {
      wrapper.unmount()
    }
  })
})

describe('RemoteManagement MP hot patch', () => {
  function runningApi(config: NetworkConfig, withPatch = true) {
    const api: Record<string, any> = {
      delete_network: vi.fn(),
      generate_config: vi.fn(),
      get_network_config: vi.fn(async () => cloneConfig(config)),
      get_network_info: vi.fn(async () => ({ running: true, error_msg: '', mp_runtime: { peers: [], egress: [], sample_time_ms: 1 } })),
      get_network_metas: vi.fn(async (instanceIds: string[]) => ({
        metas: Object.fromEntries(instanceIds.map((id) => [id, { config_permission: 0, network_name: 'mesh-mp' }])),
      })),
      list_network_instance_ids: vi.fn(async () => ({ disabled_inst_ids: [], running_inst_ids: [INSTANCE_UUID] })),
      parse_config: vi.fn(),
      run_network: vi.fn(async () => undefined),
      save_config: vi.fn(async () => undefined),
      update_network_instance_state: vi.fn(),
      validate_config: vi.fn(),
    }
    if (withPatch) api.patch_network_config = vi.fn(async () => undefined)
    return api
  }

  function mpConfig(): NetworkConfig {
    const config = { ...DEFAULT_NETWORK_CONFIG(), instance_id: INSTANCE_ID, network_name: 'mesh-mp', hostname: 'host-a' }
    config.mp = { ...config.mp!, enabled: true }
    return config
  }

  const StatusStub = defineComponent({
    name: 'Status',
    props: { curNetworkInst: Object, mpConfig: Object, egressWireLimitBps: [Number, String], mpBusy: Boolean, mtu: Number },
    emits: ['mp-set-policy', 'mp-reconnect', 'mp-apply-mtu'],
    setup() {
      return () => h('div', { 'data-stub': 'status' })
    },
  })

  function mountRunning(api: Record<string, any>) {
    return mount(RemoteManagement, {
      props: { api: api as any, instanceId: INSTANCE_ID },
      global: { stubs: { Config: true, ConfigEditDialog: true, Status: StatusStub } },
    })
  }

  const MATCH = { match_egress_device: 'eth0', match_carrier_kind: 'udp', match_remote_endpoint: '1.2.3.4:11010' }

  it('passes mp_runtime and the running MpConfig to Status', async () => {
    const api = runningApi(mpConfig())
    const wrapper = mountRunning(api)
    try {
      await settleRemoteManagement()
      const status = wrapper.findComponent({ name: 'Status' })
      expect(status.exists()).toBe(true)
      expect((status.props('curNetworkInst') as any).detail.mp_runtime.sample_time_ms).toBe(1)
      expect((status.props('mpConfig') as any).enabled).toBe(true)
    } finally {
      wrapper.unmount()
    }
  })

  it('hot-patches a path policy from the status view without restarting', async () => {
    const api = runningApi(mpConfig())
    const wrapper = mountRunning(api)
    try {
      await settleRemoteManagement()
      wrapper.findComponent({ name: 'Status' }).vm.$emit('mp-set-policy', MATCH, 'pause')
      await settleRemoteManagement()
      expect(api.run_network).not.toHaveBeenCalled()
      expect(api.patch_network_config).toHaveBeenCalledOnce()
      const [instId, patch] = api.patch_network_config.mock.calls[0]
      expect(instId).toBe(INSTANCE_ID)
      expect(Object.keys(patch)).toEqual(['mp'])
      expect(patch.mp.enabled).toBe(true)
      expect(patch.mp.path_policies).toEqual([{ ...MATCH, action: 'pause', prefer_weight: 0, enabled: true, note: '' }])
    } finally {
      wrapper.unmount()
    }
  })

  it('reconnect increments session_generation', async () => {
    const config = mpConfig()
    config.mp = { ...config.mp!, session_generation: 4 }
    const api = runningApi(config)
    const wrapper = mountRunning(api)
    try {
      await settleRemoteManagement()
      wrapper.findComponent({ name: 'Status' }).vm.$emit('mp-reconnect')
      await settleRemoteManagement()
      expect(api.patch_network_config.mock.calls[0][1].mp.session_generation).toBe(5)
    } finally {
      wrapper.unmount()
    }
  })

  it('saves the recommended MTU without restarting or hot-patching', async () => {
    const config = mpConfig()
    config.mtu = 1380
    const api = runningApi(config)
    const wrapper = mountRunning(api)
    try {
      await settleRemoteManagement()
      const status = wrapper.findComponent({ name: 'Status' })
      expect(status.props('mtu')).toBe(1380)
      status.vm.$emit('mp-apply-mtu', 1360)
      await settleRemoteManagement()
      expect(api.run_network).not.toHaveBeenCalled()
      expect(api.patch_network_config).not.toHaveBeenCalled()
      expect(api.save_config).toHaveBeenCalledOnce()
      expect(api.save_config.mock.calls[0][0]).toMatchObject({ instance_id: INSTANCE_ID, mtu: 1360 })
    } finally {
      wrapper.unmount()
    }
  })

  it('falls back to run_network when the client cannot patch', async () => {
    const api = runningApi(mpConfig(), false)
    const wrapper = mountRunning(api)
    try {
      await settleRemoteManagement()
      wrapper.findComponent({ name: 'Status' }).vm.$emit('mp-set-policy', MATCH, 'exclude')
      await settleRemoteManagement()
      expect(api.run_network).toHaveBeenCalledOnce()
      expect(api.run_network.mock.calls[0][0].mp.path_policies[0].action).toBe('exclude')
    } finally {
      wrapper.unmount()
    }
  })

  async function editAndRun(api: Record<string, any>, edit: (c: NetworkConfig) => void) {
    const wrapper = mountRunning(api)
    await settleRemoteManagement()
    const model = wrapper.findComponent({ name: 'Menu' }).vm.$attrs.model as Array<{ icon: string, command: () => unknown }>
    await model.find(item => item.icon === 'pi pi-pencil')!.command()
    await settleRemoteManagement()
    const config = cloneConfig(mpConfig())
    edit(config)
    wrapper.findComponent({ name: 'Config' }).vm.$emit('run-network', config)
    await settleRemoteManagement()
    return wrapper
  }

  it('applies an MP-only edit of a running network through patch_network_config', async () => {
    const api = runningApi(mpConfig())
    const wrapper = await editAndRun(api, (c) => {
      c.mp = { ...c.mp!, kmax: 6 }
      c.egress_wire_limit_bps = 800_000
    })
    try {
      expect(api.run_network).not.toHaveBeenCalled()
      const patch = api.patch_network_config.mock.calls[0][1]
      expect(patch.mp.kmax).toBe(6)
      expect(patch.egress_wire_limit_bps).toBe('800000')
    } finally {
      wrapper.unmount()
    }
  })

  it('applies a hostname change without restarting', async () => {
    const api = runningApi(mpConfig())
    const wrapper = await editAndRun(api, (c) => {
      c.hostname = 'host-b'
    })
    try {
      expect(api.run_network).not.toHaveBeenCalled()
      expect(api.patch_network_config.mock.calls[0][1]).toEqual({ hostname: 'host-b' })
    } finally {
      wrapper.unmount()
    }
  })

  it('restarts through run_network when a non-patchable field changed', async () => {
    const api = runningApi(mpConfig())
    const wrapper = await editAndRun(api, (c) => {
      c.mp = { ...c.mp!, kmax: 6 }
      c.dev_name = 'et1'
    })
    try {
      expect(api.patch_network_config).not.toHaveBeenCalled()
      expect(api.run_network).toHaveBeenCalledOnce()
    } finally {
      wrapper.unmount()
    }
  })
})
