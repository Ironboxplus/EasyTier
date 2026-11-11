<script setup lang="ts">
// Popover body for one path: its numbers, its own policy, and the rule of its kind.
import { Ban, EthernetPort, Minus, Pause, Pin, Plus, Wifi } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import { ToggleGroup, ToggleGroupItem } from '../ui/toggle-group'
import type { Tier } from '../../modules/mpSelection'
import type { RunwayPath } from '../../modules/pathRunway'
import KindDisc from './KindDisc.vue'

defineProps<{
  placed: RunwayPath
  /** Where the path goes: an address or the relay's name. */
  name: string
  /** The network card it leaves by. */
  via: string
  /** The name of its kind, e.g. "UDP direct (IPv6)". */
  kindName: string
  tier: Tier
  biasMs: number
  policy: string
  busy?: boolean
}>()
const emit = defineEmits<{ policy: [action: 'pin' | 'pause' | 'exclude' | null], bias: [ms: number], tier: [tier: Tier] }>()

const { t } = useI18n()
const fmt = (ms: number) => (ms < 10 ? ms.toFixed(1) : Math.round(ms).toString())
const wireless = (via: string) => /wlan|wi-?fi|wireless|^wl/i.test(via)
</script>

<template>
  <div class="flex flex-col gap-3" data-testid="runway-detail">
    <div class="flex items-center gap-2.5">
      <KindDisc :kind="placed.kind" :state="placed.state" />
      <div class="min-w-0 flex-1">
        <div class="truncate text-sm font-semibold">{{ name }}</div>
        <div class="flex items-center gap-1 text-xs text-zinc-500">
          <component :is="wireless(via) ? Wifi : EthernetPort" class="size-3" />{{ via || '-' }}
          <span class="mx-1 size-1 rounded-full bg-zinc-300" />{{ kindName }}
        </div>
      </div>
    </div>

    <div class="grid grid-cols-3 overflow-hidden rounded-lg border border-zinc-200 bg-zinc-50/60 text-center">
      <div class="px-2 py-1.5" :title="t('mp_runway.rtt')">
        <div class="font-mono text-base tabular-nums">{{ placed.measuredMs === null ? '—' : fmt(placed.measuredMs) }}<span class="ml-0.5 text-[10px] text-zinc-500">ms</span></div>
      </div>
      <div class="border-x border-zinc-200 px-2 py-1.5" :title="t('mp_runway.loss')">
        <div class="font-mono text-base tabular-nums">{{ placed.lossPct.toFixed(1) }}<span class="ml-0.5 text-[10px] text-zinc-500">%</span></div>
      </div>
      <div class="flex items-center justify-center gap-1.5 px-2 py-1.5 text-xs" data-testid="runway-detail-state">
        {{ t(`mp_runway.state.${placed.state}`) }}
      </div>
    </div>

    <ToggleGroup type="single" variant="outline" size="sm" class="w-full" :disabled="busy"
      :model-value="policy === 'pin' || policy === 'pause' || policy === 'exclude' ? policy : undefined"
      @update:model-value="(v) => emit('policy', (v as 'pin' | 'pause' | 'exclude') || null)">
      <ToggleGroupItem value="pin" class="flex-1 gap-1" data-testid="runway-policy-pin"><Pin class="size-3.5" />{{ t('mp_runway.policy.pin') }}</ToggleGroupItem>
      <ToggleGroupItem value="pause" class="flex-1 gap-1" data-testid="runway-policy-pause"><Pause class="size-3.5" />{{ t('mp_runway.policy.pause') }}</ToggleGroupItem>
      <ToggleGroupItem value="exclude" class="flex-1 gap-1" data-testid="runway-policy-exclude"><Ban class="size-3.5" />{{ t('mp_runway.policy.exclude') }}</ToggleGroupItem>
    </ToggleGroup>

    <div class="flex flex-wrap items-center gap-2 rounded-lg bg-zinc-50 p-1.5 pl-2.5">
      <span class="text-xs text-zinc-500">{{ t('mp_runway.all_of_kind', [kindName]) }}</span>
      <ToggleGroup type="single" size="sm" class="ml-auto" :model-value="tier" :disabled="busy"
        @update:model-value="(v) => v && emit('tier', v as Tier)">
        <ToggleGroupItem value="primary" class="h-7 px-2 text-xs" data-testid="runway-tier-primary">{{ t('mp_runway.lane.primary') }}</ToggleGroupItem>
        <ToggleGroupItem value="backup" class="h-7 px-2 text-xs" data-testid="runway-tier-backup">{{ t('mp_runway.lane.backup') }}</ToggleGroupItem>
      </ToggleGroup>
      <div class="flex items-center rounded-md border border-zinc-200 bg-white" :title="t('mp_runway.bias')">
        <button type="button" class="grid size-7 place-items-center text-zinc-500 hover:text-zinc-900" :disabled="busy"
          data-testid="runway-bias-minus" @click="emit('bias', biasMs - 1)"><Minus class="size-3.5" /></button>
        <span class="w-12 text-center font-mono text-xs tabular-nums" :class="biasMs < 0 ? 'text-emerald-700' : biasMs > 0 ? 'text-rose-700' : ''">{{ biasMs > 0 ? '+' : biasMs < 0 ? '−' : '±' }}{{ Math.abs(biasMs) }}ms</span>
        <button type="button" class="grid size-7 place-items-center text-zinc-500 hover:text-zinc-900" :disabled="busy"
          data-testid="runway-bias-plus" @click="emit('bias', biasMs + 1)"><Plus class="size-3.5" /></button>
      </div>
    </div>
  </div>
</template>
