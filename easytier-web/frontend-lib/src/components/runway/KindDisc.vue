<script setup lang="ts">
// The round mark of one path: its carrier as the icon, its state as fill and ring.
import { ArrowLeftRight, Waypoints, Zap } from 'lucide-vue-next'
import { computed } from 'vue'
import { cn } from '../../lib/utils'
import type { PathKind, PathState } from '../../modules/pathRunway'

const props = withDefaults(defineProps<{ kind: PathKind, state: PathState, dim?: boolean, size?: 'md' | 'sm' }>(), { size: 'md' })

const icon = computed(() => {
  switch (props.kind.carrierKind) {
    case 'relay-next-hop': return Waypoints
    case 'udp-punch':
    case 'faketcp-punch': return Zap
    default: return ArrowLeftRight
  }
})
const badge = computed(() => (props.kind.carrierKind === 'faketcp-punch' ? 'T' : props.kind.family === 'v6' ? '6' : ''))
const tone = computed(() => {
  if (props.dim) return 'bg-zinc-50 text-zinc-400 border border-dashed border-zinc-300 dark:bg-zinc-800 dark:border-zinc-600'
  return {
    sending: 'bg-emerald-600 text-white shadow-[0_0_0_4px_rgb(16_185_129/0.16),0_2px_6px_rgb(5_150_105/0.35)]',
    held: 'bg-white text-violet-600 border-2 border-violet-500 shadow-[0_0_0_4px_rgb(139_92_246/0.12)] dark:bg-zinc-900 dark:text-violet-400',
    standby: 'bg-white text-zinc-500 border-2 border-zinc-300 dark:bg-zinc-900 dark:text-zinc-400 dark:border-zinc-600',
    lossy: 'bg-amber-50 text-amber-700 border-2 border-amber-500 dark:bg-amber-950 dark:text-amber-300',
    silent: 'bg-zinc-100 text-zinc-400 border-2 border-zinc-300 dark:bg-zinc-800 dark:border-zinc-600',
    paused: 'bg-zinc-100 text-zinc-400 border-2 border-zinc-300 dark:bg-zinc-800 dark:border-zinc-600',
    excluded: 'bg-zinc-100 text-zinc-300 border-2 border-zinc-200 dark:bg-zinc-800 dark:text-zinc-500 dark:border-zinc-700',
  }[props.state]
})
</script>

<template>
  <span :class="cn('relative inline-flex shrink-0 items-center justify-center rounded-full transition-colors duration-300',
                   size === 'md' ? 'size-[26px]' : 'size-5', tone)" :data-state="state" data-testid="runway-disc">
    <component :is="icon" :class="size === 'md' ? 'size-3.5' : 'size-3'" :stroke-width="2.4" />
    <span v-if="badge"
      :class="cn('absolute -right-1 -bottom-1 grid place-items-center rounded-full bg-white font-mono font-bold leading-none ring-1 ring-zinc-200 dark:bg-zinc-900 dark:ring-zinc-600',
                 size === 'md' ? 'size-3.5 text-[9px]' : 'size-3 text-[8px]', state === 'sending' ? 'text-emerald-700' : 'text-zinc-500')">{{ badge }}</span>
  </span>
</template>
