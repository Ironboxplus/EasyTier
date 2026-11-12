<script setup lang="ts">
// When an edit to `field` takes effect on a running instance, from the field
// effect table (hot / new paths / reconnect / instance restart).
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { fieldEffect } from '../types/mpConfig'

const props = defineProps<{ field: string }>()
const { t } = useI18n()
const effect = computed(() => fieldEffect(props.field))
</script>

<template>
  <small v-if="effect" :class="['mp-effect', `mp-effect-${effect.replace('_', '-')}`]">{{ t(`mp_effect.${effect}`) }}</small>
</template>

<style scoped>
.mp-effect {
  /* A small block right after its label, also when the parent is a column flexbox or a grid
     (which would stretch it over the whole row). */
  display: inline-block;
  flex: none;
  align-self: flex-start;
  justify-self: start;
  width: fit-content;
  max-width: 100%;
  font-size: 0.7rem;
  padding: 0 0.35rem;
  border-radius: 0.25rem;
  white-space: nowrap;
}

.mp-effect-hot {
  color: rgb(21, 128, 61);
  background: rgba(34, 197, 94, 0.12);
}

.mp-effect-new-path {
  color: rgb(29, 78, 216);
  background: rgba(59, 130, 246, 0.12);
}

.mp-effect-reconnect {
  color: rgb(194, 65, 12);
  background: rgba(249, 115, 22, 0.12);
}

.mp-effect-restart {
  color: rgb(185, 28, 28);
  background: rgba(239, 68, 68, 0.12);
}
</style>
