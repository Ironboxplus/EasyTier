<script setup lang="ts">
// A small labelled figure tile; the value goes in the default slot.
defineProps<{
  label: string
  /** Shown as a tooltip on the label. */
  help?: string
  tone?: 'default' | 'good' | 'warn' | 'bad'
}>()
</script>

<template>
  <div class="mp-stat flex flex-col gap-0.5 rounded-lg px-3 py-2 bg-surface-50 dark:bg-surface-800 min-w-0"
    :class="{
      'ring-1 ring-green-400/60': tone === 'good',
      'ring-1 ring-amber-400/70': tone === 'warn',
      'ring-1 ring-red-400/70': tone === 'bad',
    }">
    <span class="text-xs text-color-secondary truncate" v-tooltip.top="help">
      {{ label }}<i v-if="help" class="pi pi-question-circle ml-1 text-[0.65rem] align-middle" />
    </span>
    <span class="text-base font-semibold truncate">
      <slot />
    </span>
  </div>
</template>
