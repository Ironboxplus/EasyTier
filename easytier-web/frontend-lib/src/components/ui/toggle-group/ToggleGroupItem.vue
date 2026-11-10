<script setup lang="ts">
import type { VariantProps } from 'class-variance-authority'
import type { ToggleGroupItemProps } from 'reka-ui'
import type { HTMLAttributes } from 'vue'
import { reactiveOmit } from '@vueuse/core'
import { ToggleGroupItem, useForwardProps } from 'reka-ui'
import { inject } from 'vue'
import { cn } from '../../../lib/utils'
import { toggleVariants } from './variants'

type ToggleGroupVariants = VariantProps<typeof toggleVariants>

const props = defineProps<ToggleGroupItemProps & {
  class?: HTMLAttributes['class']
  variant?: ToggleGroupVariants['variant']
  size?: ToggleGroupVariants['size']
}>()

const context = inject<ToggleGroupVariants>('toggleGroup')

const delegatedProps = reactiveOmit(props, 'class', 'size', 'variant')
const forwardedProps = useForwardProps(delegatedProps)
</script>

<template>
  <ToggleGroupItem
    data-slot="toggle-group-item"
    v-bind="forwardedProps"
    :class="cn(
      toggleVariants({ variant: context?.variant || variant, size: context?.size || size }),
      'w-auto min-w-0 shrink-0 rounded-none px-3 first:rounded-l-md last:rounded-r-md focus:z-10 focus-visible:z-10',
      props.class)"
  >
    <slot />
  </ToggleGroupItem>
</template>
