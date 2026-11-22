<script setup lang="ts">
// One line per peer: name and how it is reached, its latency as a dot on the
// same logarithmic axis the path runway uses, traffic and loss in small type.
// What does not fit a narrow screen (address, hops, NAT, version) goes into
// the opened row instead of a sideways scroll.
import { ArrowDown, ArrowUp, ChevronDown, ChevronRight, PackageX, Server, Waypoints, Zap } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import { cn } from '../lib/utils'
import { runwayAxis } from '../modules/pathRunway'

export interface PeerRow {
  key: string
  name: string
  /** `self` is this node; `direct` a peer-to-peer connection; `relay` one through other nodes. */
  kind: 'self' | 'direct' | 'relay' | 'unknown'
  server: boolean
  avoidRelay: boolean
  /** Mean latency in milliseconds, null when there is no measurement. */
  latencyMs: number | null
  latencyText: string
  tx: string
  rx: string
  loss: string
  lossPercent: number
}

defineProps<{ rows: PeerRow[], expandedKey: string | null }>()
const emit = defineEmits<{ toggle: [key: string] }>()
defineSlots<{ expansion(props: { row: PeerRow }): unknown }>()

const { t } = useI18n()

// The axis is drawn in percent of the track, so one geometry serves every width.
const axis = runwayAxis(100, 2, 3)
const ticks = [1, 10, 100]
const dotTone = (row: PeerRow) => {
  if (row.latencyMs === null) return 'bg-zinc-300'
  if (row.lossPercent >= 10) return 'bg-amber-500'
  return row.kind === 'relay' ? 'bg-violet-500' : 'bg-emerald-600'
}
</script>

<template>
  <div class="flex flex-col" data-testid="peer-list">
    <div class="relative mx-8 mb-1 h-4 text-[10px] text-zinc-400" aria-hidden="true">
      <span v-for="tick in ticks" :key="tick" class="absolute -translate-x-1/2 tabular-nums"
        :style="{ left: `${axis.x(tick)}%` }">{{ tick }} ms</span>
    </div>
    <template v-for="row in rows" :key="row.key">
      <div role="button" tabindex="0" data-testid="peer-row"
        :aria-expanded="expandedKey === row.key"
        class="cursor-pointer rounded-md px-2 py-1.5 hover:bg-zinc-100/60 focus-visible:outline focus-visible:outline-2 focus-visible:outline-zinc-400 dark:hover:bg-zinc-800/60"
        @click="emit('toggle', row.key)" @keydown.enter.prevent="emit('toggle', row.key)"
        @keydown.space.prevent="emit('toggle', row.key)">
        <div class="flex items-center gap-2">
          <component :is="expandedKey === row.key ? ChevronDown : ChevronRight" data-testid="peer-row-toggle"
            class="size-4 shrink-0 text-zinc-400" />
          <span class="min-w-0 flex-1 truncate font-medium" :title="row.name">{{ row.name }}</span>
          <span v-if="row.server" class="inline-flex shrink-0 items-center gap-1 rounded bg-sky-100 px-1.5 text-xs text-sky-800 dark:bg-sky-900 dark:text-sky-200">
            <Server class="size-3" />{{ t('status.server') }}
          </span>
          <span v-if="row.avoidRelay" class="shrink-0 rounded bg-amber-100 px-1.5 text-xs text-amber-800 dark:bg-amber-900 dark:text-amber-200">{{ t('status.relay') }}</span>
          <Zap v-if="row.kind === 'direct'" class="size-3.5 shrink-0 text-emerald-600" :aria-label="'p2p'" />
          <Waypoints v-else-if="row.kind === 'relay'" class="size-3.5 shrink-0 text-violet-600" :aria-label="'relay'" />
          <span class="w-14 shrink-0 text-right text-sm tabular-nums">{{ row.latencyText }}</span>
        </div>
        <div class="ml-6 mt-1 flex items-center gap-2">
          <div class="relative h-2 min-w-0 flex-1 rounded-full bg-zinc-100 dark:bg-zinc-800" data-testid="peer-latency-axis">
            <span v-for="tick in ticks" :key="tick" class="absolute top-0 h-full w-px bg-zinc-200 dark:bg-zinc-700"
              :style="{ left: `${axis.x(tick)}%` }" />
            <span v-if="row.latencyMs !== null"
              :class="cn('absolute top-1/2 size-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full', dotTone(row))"
              :style="{ left: `${axis.x(row.latencyMs)}%` }" data-testid="peer-latency-dot" />
          </div>
          <span class="flex shrink-0 items-center gap-2 text-xs tabular-nums text-zinc-500" data-testid="peer-traffic">
            <template v-if="row.tx || row.rx">
              <span class="inline-flex items-center gap-0.5"><ArrowUp class="size-3" />{{ row.tx || '0 B' }}</span>
              <span class="inline-flex items-center gap-0.5"><ArrowDown class="size-3" />{{ row.rx || '0 B' }}</span>
            </template>
            <span v-if="row.loss" :title="t('loss_rate')"
              :class="cn('inline-flex items-center gap-0.5 rounded px-1', row.lossPercent >= 10 ? 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200' : 'bg-zinc-100 dark:bg-zinc-800')">
              <PackageX class="size-3" />{{ row.loss }}
            </span>
          </span>
        </div>
      </div>
      <div v-if="expandedKey === row.key" data-testid="peer-row-expansion" class="px-2 pb-2">
        <slot name="expansion" :row="row" />
      </div>
    </template>
  </div>
</template>
