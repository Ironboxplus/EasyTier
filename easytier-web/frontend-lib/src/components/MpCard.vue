<script setup lang="ts">
// One titled card of the MP runtime view: an icon + title header with an
// optional one-line hint and right-aligned extras, then the body.
defineProps<{
  title: string
  icon?: string
  /** One-line explanation under the title. */
  hint?: string
}>()
</script>

<template>
  <section class="mp-card flex flex-col rounded-xl border border-surface-200 dark:border-surface-700
    bg-surface-0 dark:bg-surface-900 shadow-sm overflow-hidden">
    <header class="flex flex-wrap items-center gap-2 px-4 py-2.5 border-b border-surface-200 dark:border-surface-700
      bg-surface-50 dark:bg-surface-800">
      <i v-if="icon" :class="['pi', icon, 'text-primary']" />
      <h4 class="m-0 text-base font-semibold">{{ title }}</h4>
      <div class="ml-auto flex flex-wrap items-center gap-2">
        <slot name="extra" />
      </div>
      <small v-if="hint" class="basis-full text-color-secondary leading-snug">{{ hint }}</small>
    </header>
    <div class="flex flex-col gap-4 p-4">
      <slot />
    </div>
  </section>
</template>
