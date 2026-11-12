<script setup lang="ts">
import type { PopoverContentEmits, PopoverContentProps } from 'reka-ui'
import type { HTMLAttributes } from 'vue'
import { reactiveOmit } from '@vueuse/core'
import { PopoverContent, PopoverPortal, useForwardPropsEmits } from 'reka-ui'
import { cn } from '../../../lib/utils'

defineOptions({ inheritAttrs: false })

// Above PrimeVue's dialogs and drawers (zIndex.modal 1100 in the library's PrimeVue setup): the
// status page opens in a drawer, and a popover drawn under it cannot be seen or clicked.

const props = withDefaults(
  defineProps<PopoverContentProps & { class?: HTMLAttributes['class'] }>(),
  { align: 'center', sideOffset: 4 },
)
const emits = defineEmits<PopoverContentEmits>()

const delegatedProps = reactiveOmit(props, 'class')
const forwarded = useForwardPropsEmits(delegatedProps, emits)
</script>

<template>
  <PopoverPortal>
    <PopoverContent
      data-slot="popover-content"
      v-bind="{ ...$attrs, ...forwarded }"
      :class="cn('z-[1200] w-72 max-w-[calc(100vw-1rem)] rounded-md border border-zinc-200 bg-white p-4 text-zinc-900 shadow-md outline-none dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100', props.class)"
    >
      <slot />
    </PopoverContent>
  </PopoverPortal>
</template>
