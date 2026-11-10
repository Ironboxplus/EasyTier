<script setup lang="ts">
import type { PopoverContentEmits, PopoverContentProps } from 'reka-ui'
import type { HTMLAttributes } from 'vue'
import { reactiveOmit } from '@vueuse/core'
import { PopoverContent, PopoverPortal, useForwardPropsEmits } from 'reka-ui'
import { cn } from '../../../lib/utils'

defineOptions({ inheritAttrs: false })

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
      :class="cn('z-50 w-72 max-w-[calc(100vw-1rem)] rounded-md border border-zinc-200 bg-white p-4 text-zinc-900 shadow-md outline-none', props.class)"
    >
      <slot />
    </PopoverContent>
  </PopoverPortal>
</template>
