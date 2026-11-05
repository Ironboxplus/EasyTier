<script setup lang="ts">
// A number input with a slider over its usual range. Every other attribute
// (min/max, fraction digits, placeholder, data-testid, ...) goes to the
// InputNumber, which still accepts values outside the slider range.
import { InputNumber, Slider } from 'primevue'
import { computed } from 'vue'

defineOptions({ inheritAttrs: false })

const props = withDefaults(defineProps<{
  modelValue?: number | null
  /** Slider range and step. */
  range: [number, number]
  step?: number
  unit?: string
}>(), { step: 1 })

const emit = defineEmits<{ 'update:modelValue': [value: number | null] }>()

const sliderValue = computed(() => {
  const [lo, hi] = props.range
  return Math.min(hi, Math.max(lo, props.modelValue ?? lo))
})
</script>

<template>
  <div class="mp-number-field flex items-center gap-3 min-w-[16rem]">
    <Slider class="flex-1 min-w-[6rem]" :model-value="sliderValue" :min="range[0]" :max="range[1]" :step="step"
      @update:model-value="(v: number | number[]) => emit('update:modelValue', Array.isArray(v) ? v[0] : v)" />
    <InputNumber v-bind="$attrs" class="w-28" input-class="w-full" :model-value="modelValue ?? null"
      @update:model-value="(v: number | null) => emit('update:modelValue', v)" />
    <span v-if="unit" class="text-sm text-color-secondary w-10">{{ unit }}</span>
  </div>
</template>
