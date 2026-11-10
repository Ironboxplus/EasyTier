import { describe, expect, it } from 'vitest'
import fieldEffects from '../src/generated/mp_field_effects.json'
import { buildHotPatch, planConfigChange } from '../src/modules/mpPatch'
import { DEFAULT_NETWORK_CONFIG, normalizeNetworkConfig, type NetworkConfig } from '../src/types/network'

const ip4 = (a: number, b: number, c: number, d: number) => ((a << 24) >>> 0) + (b << 16) + (c << 8) + d

function base(): NetworkConfig {
  const config = DEFAULT_NETWORK_CONFIG()
  config.instance_id = '00000000-0000-0000-0000-000000000001'
  config.hostname = 'host-a'
  config.dhcp = false
  config.virtual_ipv4 = '10.0.0.1'
  config.network_length = 24
  return normalizeNetworkConfig(config)
}

function edited(edit: (config: NetworkConfig) => void): NetworkConfig {
  const config = base()
  edit(config)
  return config
}

const hotFields = new Set<string>()
// Hot in the table, but the form only shows them: `peer_urls` carries what they mean.
const NO_PATCH_PART = new Set(['networking_method', 'public_server_url'])

/** One hot field: the patch is exactly `expected`, and nothing needs a restart. */
function hot(field: string, edit: (config: NetworkConfig) => void, expected: Record<string, unknown>, from?: (config: NetworkConfig) => void) {
  it(`patches ${field}`, () => {
    hotFields.add(field)
    const before = from ? edited(from) : base()
    const after = edited((c) => { from?.(c); edit(c) })
    const plan = planConfigChange(before, after)
    expect(plan.restartFields).toEqual([])
    expect(plan.changed).toContain(field)
    expect(buildHotPatch(before, after)).toEqual(expected)
  })
}

describe('buildHotPatch: every hot field', () => {
  hot('hostname', (c) => { c.hostname = 'host-b' }, { hostname: 'host-b' })
  hot('virtual_ipv4', (c) => { c.virtual_ipv4 = '10.0.0.2' }, {
    ipv4: { address: { addr: ip4(10, 0, 0, 2) }, network_length: 24 },
  })
  hot('network_length', (c) => { c.network_length = 16 }, {
    ipv4: { address: { addr: ip4(10, 0, 0, 1) }, network_length: 16 },
  })
  hot('ipv6', (c) => { c.ipv6 = 'fd00::2/64' }, {
    ipv6: { address: { part1: 0xfd000000, part2: 0, part3: 0, part4: 2 }, network_length: 64 },
  })
  hot('port_forwards', (c) => {
    c.port_forwards = [{ proto: 'tcp', bind_ip: '0.0.0.0', bind_port: 8080, dst_ip: '10.0.0.2', dst_port: 80 }]
  }, {
    port_forwards: [{
      action: 'ADD',
      cfg: {
        bind_addr: { ipv4: { addr: 0 }, port: 8080 },
        dst_addr: { ipv4: { addr: ip4(10, 0, 0, 2) }, port: 80 },
        socket_type: 'TCP',
      },
    }],
  })
  hot('proxy_cidrs', (c) => { c.proxy_cidrs = ['10.1.0.0/24', '10.5.0.0/24->10.9.0.0/24'] }, {
    proxy_networks: [
      { action: 'ADD', cidr: { address: { addr: ip4(10, 1, 0, 0) }, network_length: 24 } },
      {
        action: 'ADD',
        cidr: { address: { addr: ip4(10, 5, 0, 0) }, network_length: 24 },
        mapped_cidr: { address: { addr: ip4(10, 9, 0, 0) }, network_length: 24 },
      },
    ],
  })
  hot('routes', (c) => { c.routes = ['10.2.0.0/16'] }, {
    routes: [{ action: 'ADD', cidr: { address: { addr: ip4(10, 2, 0, 0) }, network_length: 16 } }],
  }, (c) => { c.enable_manual_routes = true })
  hot('enable_manual_routes', (c) => { c.enable_manual_routes = false }, {
    routes: [{ action: 'REMOVE', cidr: { address: { addr: ip4(10, 2, 0, 0) }, network_length: 16 } }],
  }, (c) => { c.enable_manual_routes = true; c.routes = ['10.2.0.0/16'] })
  hot('exit_nodes', (c) => { c.exit_nodes = ['10.0.0.9'] }, {
    exit_nodes: [{ action: 'ADD', node: { ipv4: { addr: ip4(10, 0, 0, 9) } } }],
  })
  hot('mapped_listeners', (c) => { c.mapped_listeners = ['tcp://203.0.113.5:11010'] }, {
    mapped_listeners: [{ action: 'ADD', url: { url: 'tcp://203.0.113.5:11010' } }],
  })
  hot('peer_urls', (c) => { c.peer_urls = ['tcp://198.51.100.7:11010'] }, {
    connectors: [{ action: 'ADD', url: { url: 'tcp://198.51.100.7:11010' } }],
  })
  hot('tcp_whitelist', (c) => { c.tcp_whitelist = ['80', '8000-8100'] }, {
    acl: { tcp_whitelist: [{ action: 'ADD', value: '80' }, { action: 'ADD', value: '8000-8100' }] },
  })
  hot('udp_whitelist', (c) => { c.udp_whitelist = ['53'] }, {
    acl: { udp_whitelist: [{ action: 'ADD', value: '53' }] },
  })
  hot('ipv6_public_addr_provider', (c) => { c.ipv6_public_addr_provider = true }, { ipv6_public_addr_provider: true })
  hot('ipv6_public_addr_auto', (c) => { c.ipv6_public_addr_auto = true }, { ipv6_public_addr_auto: true })
  hot('ipv6_public_addr_prefix', (c) => { c.ipv6_public_addr_prefix = '2001:db8::/64' }, { ipv6_public_addr_prefix: '2001:db8::/64' })
  hot('disable_relay_data', (c) => { c.disable_relay_data = true }, { disable_relay_data: true })
  hot('tcp_hole_punch_mode', (c) => { c.tcp_hole_punch_mode = 'faketcp' }, { tcp_hole_punch_mode: 'faketcp' })
  hot('egress_wire_limit_bps', (c) => { c.egress_wire_limit_bps = 2_000_000 }, { egress_wire_limit_bps: '2000000' })

  it('replaces the whole ACL', () => {
    hotFields.add('acl')
    const before = base()
    const after = edited((c) => {
      c.acl = { acl_v1: { group: { declares: [], members: [] }, chains: [{ name: 'in', chain_type: 1, description: '', enabled: true, rules: [], default_action: 1 } as any] } }
    })
    const patch = buildHotPatch(before, after)!
    expect(Object.keys(patch)).toEqual(['acl'])
    expect(Object.keys(patch.acl!)).toEqual(['acl'])
    expect((patch.acl!.acl as any).acl_v1.chains).toHaveLength(1)
  })

  it('has a patch builder for every hot field of the table', () => {
    const hotInTable = Object.entries(fieldEffects as Record<string, string>)
      .filter(([field, effect]) => effect === 'hot' && !field.startsWith('mp.') && !NO_PATCH_PART.has(field))
      .map(([field]) => field)
    for (const field of hotInTable) expect(hotFields, field).toContain(field)
  })
})

it('networking_method and public_server_url add nothing to the patch', () => {
  const plan = planConfigChange(base(), edited((c) => { c.public_server_url = 'tcp://203.0.113.9:11010' }))
  expect(plan.restartFields).toEqual([])
  expect(plan.patch).toEqual({})
})

describe('buildHotPatch: lists and values', () => {
  it('removes and adds only the items that differ', () => {
    const from = (c: NetworkConfig) => { c.peer_urls = ['tcp://198.51.100.7:11010', 'udp://198.51.100.8:11010'] }
    const before = edited(from)
    const after = edited((c) => { c.peer_urls = ['udp://198.51.100.8:11010', 'wg://198.51.100.9:11011'] })
    expect(buildHotPatch(before, after)).toEqual({
      connectors: [
        { action: 'REMOVE', url: { url: 'tcp://198.51.100.7:11010' } },
        { action: 'ADD', url: { url: 'wg://198.51.100.9:11011' } },
      ],
    })
  })

  it('removes a port forward and an exit node', () => {
    const from = (c: NetworkConfig) => {
      c.port_forwards = [{ proto: 'udp', bind_ip: '127.0.0.1', bind_port: 53, dst_ip: '10.0.0.3', dst_port: 53 }]
      c.exit_nodes = ['10.0.0.9']
    }
    const patch = buildHotPatch(edited(from), edited((c) => { from(c); c.port_forwards = []; c.exit_nodes = [] }))!
    expect(patch.port_forwards).toEqual([{
      action: 'REMOVE',
      cfg: {
        bind_addr: { ipv4: { addr: ip4(127, 0, 0, 1) }, port: 53 },
        dst_addr: { ipv4: { addr: ip4(10, 0, 0, 3) }, port: 53 },
        socket_type: 'UDP',
      },
    }])
    expect(patch.exit_nodes).toEqual([{ action: 'REMOVE', node: { ipv4: { addr: ip4(10, 0, 0, 9) } } }])
  })

  it('a static address changed while DHCP is on has no effect', () => {
    const before = edited((c) => { c.dhcp = true })
    const after = edited((c) => { c.dhcp = true; c.virtual_ipv4 = '10.0.0.7' })
    expect(buildHotPatch(before, after)).toEqual({})
  })

  it('a value that cannot be patched goes to the restart list', () => {
    const cleared = planConfigChange(base(), edited((c) => { c.hostname = '' }))
    expect(cleared.restartFields).toEqual(['hostname'])
    const bad = planConfigChange(base(), edited((c) => { c.exit_nodes = ['not-an-address'] }))
    expect(bad.restartFields).toEqual(['exit_nodes'])
  })

  it('combines hot fields in one patch', () => {
    const patch = buildHotPatch(base(), edited((c) => {
      c.hostname = 'host-b'
      c.disable_relay_data = true
      c.tcp_whitelist = ['22']
      c.udp_whitelist = ['53']
    }))!
    expect(patch).toEqual({
      hostname: 'host-b',
      disable_relay_data: true,
      acl: {
        tcp_whitelist: [{ action: 'ADD', value: '22' }],
        udp_whitelist: [{ action: 'ADD', value: '53' }],
      },
    })
  })
})

describe('buildHotPatch: fields that need a restart', () => {
  const restartCases: [string, (c: NetworkConfig) => void][] = [
    ['network_name', (c) => { c.network_name = 'other' }],
    ['network_secret', (c) => { c.network_secret = 'secret' }],
    ['dhcp', (c) => { c.dhcp = true }],
    ['listener_urls', (c) => { c.listener_urls = ['tcp://0.0.0.0:12000'] }],
    ['dev_name', (c) => { c.dev_name = 'et1' }],
    ['enable_kcp_proxy', (c) => { c.enable_kcp_proxy = true }],
    ['mtu', (c) => { c.mtu = 1300 }],
    ['tld_dns_zone', (c) => { c.tld_dns_zone = 'corp.example.' }],
    ['default_protocol', (c) => { c.default_protocol = 'udp' }],
    ['multi_thread_count', (c) => { c.multi_thread_count = 4 }],
    ['stun_servers', (c) => { c.stun_servers = ['stun.example.org:3478'] }],
    ['netns', (c) => { c.netns = 'et-ns' }],
    ['encryption_algorithm', (c) => { c.encryption_algorithm = 'chacha20' }],
  ]
  for (const [field, edit] of restartCases) {
    it(`${field} waits for a restart`, () => {
      expect((fieldEffects as Record<string, string>)[field], field).toBe('restart')
      const after = edited(edit)
      expect(buildHotPatch(base(), after)).toBeNull()
      expect(planConfigChange(base(), after).restartFields).toContain(field)
    })
  }

  it('a restart field next to a hot one: the hot part is still planned', () => {
    const plan = planConfigChange(base(), edited((c) => { c.hostname = 'host-b'; c.dev_name = 'et1' }))
    expect(plan.patch).toEqual({ hostname: 'host-b' })
    expect(plan.restartFields).toEqual(['dev_name'])
  })

  it('nothing changed: an empty patch', () => {
    expect(buildHotPatch(base(), base())).toEqual({})
  })
})
