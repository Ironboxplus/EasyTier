import { UUID } from './utils';
import { NetworkConfig, NetworkInstanceRunningInfo } from '../types/network';
import type { MpConfig } from '../types/mpConfig';

export interface ValidateConfigResponse {
    toml_config: string;
}

export interface ListNetworkInstanceIdResponse {
    running_inst_ids: Array<UUID>,
    disabled_inst_ids: Array<UUID>,
}

export interface GenerateConfigResponse {
    toml_config?: string;
    error?: string;
}

export interface ParseConfigResponse {
    config?: NetworkConfig;
    error?: string;
}

export interface CollectNetworkInfoResponse {
    info: {
        map: Record<string, NetworkInstanceRunningInfo | undefined>;
    }
}

export namespace ConfigFilePermission {
    export type Flags = number;
    export const READ_ONLY: Flags = 1 << 0;
    export const NO_DELETE: Flags = 1 << 1;
    export function hasPermission(perm: Flags, flag: Flags): boolean {
        return (perm & flag) === flag;
    }
    export function isRemoveSaveable(perm: Flags): boolean {
        return !hasPermission(perm, NO_DELETE);
    }
    export function isEditable(perm: Flags): boolean {
        return !hasPermission(perm, READ_ONLY);
    }
    export function isDeletable(perm: Flags): boolean {
        return !hasPermission(perm, NO_DELETE);
    }
}

export interface NetworkMeta {
    network_name: string;
    config_permission: ConfigFilePermission.Flags;
}

export interface GetNetworkMetasResponse {
    metas: Record<string, NetworkMeta>;
}

/**
 * Hot-patch subset of `api.config.InstanceConfigPatch` sent through
 * `WebClientService.PatchNetworkInstanceConfig`; applied without restarting the
 * instance and persisted by the core.
 */
export type PatchAction = 'ADD' | 'REMOVE' | 'CLEAR';
type PatchEntries = Record<string, unknown>[];

export interface InstanceConfigPatch {
    hostname?: string;
    ipv4?: Record<string, unknown>;
    ipv6?: Record<string, unknown>;
    port_forwards?: PatchEntries;
    acl?: {
        /** Replaces the whole ACL. */
        acl?: Record<string, unknown>;
        tcp_whitelist?: PatchEntries;
        udp_whitelist?: PatchEntries;
    };
    proxy_networks?: PatchEntries;
    routes?: PatchEntries;
    exit_nodes?: PatchEntries;
    mapped_listeners?: PatchEntries;
    /** The peers this instance connects to. */
    connectors?: PatchEntries;
    ipv6_public_addr_provider?: boolean;
    ipv6_public_addr_auto?: boolean;
    ipv6_public_addr_prefix?: string;
    disable_relay_data?: boolean;
    /** Replaces the whole MpConfig. */
    mp?: MpConfig;
    tcp_hole_punch_mode?: string;
    /** Global egress wire limit in bits/s as a uint64 decimal string; "0" removes it. */
    egress_wire_limit_bps?: string;
}

export interface RemoteClient {
    validate_config(config: NetworkConfig): Promise<ValidateConfigResponse>;
    run_network(config: NetworkConfig, save: boolean): Promise<undefined>;
    get_network_info(inst_id: string): Promise<NetworkInstanceRunningInfo | undefined>;
    list_network_instance_ids(): Promise<ListNetworkInstanceIdResponse>;
    delete_network(inst_id: string): Promise<undefined>;
    update_network_instance_state(inst_id: string, disabled: boolean): Promise<undefined>;
    save_config(config: NetworkConfig): Promise<undefined>;
    get_network_config(inst_id: string): Promise<NetworkConfig>;
    generate_config(config: NetworkConfig): Promise<GenerateConfigResponse>;
    parse_config(toml_config: string): Promise<ParseConfigResponse>;
    get_network_metas(instance_ids: string[]): Promise<GetNetworkMetasResponse>;
    /** Optional: clients without it fall back to run_network (instance restart). */
    patch_network_config?(inst_id: string, patch: InstanceConfigPatch): Promise<undefined>;
}