// Functional DOM stand-ins for the PrimeVue controls used by the MP panels, so
// tests can drive real user input without the PrimeVue plugin context.
import { createI18n } from 'vue-i18n'
import { defineComponent, h } from 'vue'

export const ButtonStub = defineComponent({
  name: 'Button',
  props: { label: String, icon: String, disabled: Boolean },
  emits: ['click'],
  setup(props, { attrs, emit }) {
    return () => h('button', {
      ...attrs,
      type: 'button',
      disabled: props.disabled,
      'data-label': props.label ?? props.icon,
      onClick: (e: MouseEvent) => emit('click', e),
    }, props.label ?? props.icon)
  },
})

export const CheckboxStub = defineComponent({
  name: 'Checkbox',
  props: { modelValue: Boolean, inputId: String },
  emits: ['update:modelValue'],
  setup(props, { attrs, emit }) {
    return () => h('input', {
      ...attrs,
      id: props.inputId,
      type: 'checkbox',
      checked: props.modelValue,
      onChange: (e: Event) => emit('update:modelValue', (e.target as HTMLInputElement).checked),
    })
  },
})

export const InputNumberStub = defineComponent({
  name: 'InputNumber',
  props: { modelValue: { type: Number, default: null }, invalid: Boolean },
  emits: ['update:modelValue'],
  setup(props, { attrs, emit }) {
    return () => h('input', {
      ...attrs,
      type: 'number',
      value: props.modelValue ?? '',
      'data-invalid': String(props.invalid),
      onInput: (e: Event) => {
        const v = (e.target as HTMLInputElement).value
        emit('update:modelValue', v === '' ? null : Number(v))
      },
    })
  },
})

export const InputTextStub = defineComponent({
  name: 'InputText',
  props: { modelValue: String },
  emits: ['update:modelValue'],
  setup(props, { attrs, emit }) {
    return () => h('input', {
      ...attrs,
      value: props.modelValue ?? '',
      onInput: (e: Event) => emit('update:modelValue', (e.target as HTMLInputElement).value),
    })
  },
})

export const TextareaStub = defineComponent({
  name: 'Textarea',
  props: { modelValue: String },
  emits: ['update:modelValue'],
  setup(props, { attrs, emit }) {
    return () => h('textarea', {
      ...attrs,
      value: props.modelValue ?? '',
      onInput: (e: Event) => emit('update:modelValue', (e.target as HTMLTextAreaElement).value),
    })
  },
})

export const SelectStub = defineComponent({
  name: 'Select',
  props: { modelValue: [String, Number, Object], options: Array, optionValue: String, optionLabel: String },
  emits: ['update:modelValue'],
  setup(props, { attrs, emit }) {
    const value = (o: any) => (props.optionValue ? o[props.optionValue] : o)
    const label = (o: any) => (props.optionLabel ? o[props.optionLabel] : o)
    return () => h('select', {
      ...attrs,
      value: props.modelValue,
      onChange: (e: Event) => emit('update:modelValue', (e.target as HTMLSelectElement).value),
    }, (props.options ?? []).map((o: any) => h('option', { value: value(o) }, String(label(o)))))
  },
})

export const TagStub = defineComponent({
  name: 'Tag',
  props: { value: String, severity: String },
  setup(props, { attrs }) {
    return () => h('span', { ...attrs, 'data-severity': props.severity }, props.value)
  },
})

export const PassThrough = defineComponent({
  name: 'PassThrough',
  setup(_, { attrs, slots }) {
    return () => h('div', attrs, slots.default?.())
  },
})

export const CardStub = defineComponent({
  name: 'Card',
  setup(_, { attrs, slots }) {
    return () => h('div', { ...attrs, 'data-stub': 'card' }, [
      slots.title ? h('div', { 'data-stub': 'card-title' }, slots.title()) : null,
      slots.content ? h('div', { 'data-stub': 'card-content' }, slots.content()) : null,
    ])
  },
})

export const BadgeStub = defineComponent({
  name: 'Badge',
  props: { value: [String, Number] },
  setup(props, { attrs }) {
    return () => h('span', { ...attrs, 'data-stub': 'badge' }, String(props.value ?? ''))
  },
})

export const ChipStub = defineComponent({
  name: 'Chip',
  props: { label: String, icon: String },
  setup(props, { attrs }) {
    return () => h('span', { ...attrs, 'data-stub': 'chip' }, props.label)
  },
})

/** Only ever renders its slot while `visible`, like the real Dialog's internal v-if. */
export const DialogStub = defineComponent({
  name: 'Dialog',
  props: { visible: Boolean, header: String },
  emits: ['update:visible'],
  setup(props, { slots }) {
    return () => (props.visible ? h('div', { 'data-stub': 'dialog' }, slots.default?.()) : null)
  },
})

/**
 * Minimal DataTable + Column stand-in: reads the raw `Column` vnodes passed as
 * the default slot (field/header props, #body scoped slot) to build a plain
 * table, and supports the `#expansion` slot + row-click used by Status.vue's
 * peer-row expansion. Real PrimeVue Column vnodes are inert data holders here,
 * matching how the real DataTable also treats them (it never mounts Column).
 */
export const ColumnStub = defineComponent({
  name: 'Column',
  props: { field: [String, Function], header: String },
  setup() {
    return () => null
  },
})

export const DataTableStub = defineComponent({
  name: 'DataTable',
  props: { value: { type: Array, default: () => [] }, dataKey: String, expandedRows: Object },
  emits: ['row-click'],
  setup(props, { slots, emit }) {
    return () => {
      const columns = (slots.default?.() ?? []).filter((vn: any) => vn.type?.name === 'Column')
      const resolveKey = (row: any) => {
        if (!props.dataKey) return row
        return props.dataKey.split('.').reduce((o: any, k: string) => o?.[k], row)
      }
      const rows = (props.value as any[]).flatMap((row, index) => {
        const key = String(resolveKey(row))
        const cells = columns.map((col: any) => {
          const body = col.children?.body
          if (typeof body === 'function') return h('td', {}, body({ data: row, index }))
          const field = col.props?.field
          const value = typeof field === 'function' ? field(row) : field ? row[field] : ''
          return h('td', {}, value === undefined || value === null ? '' : String(value))
        })
        // keyed so inserting/removing a sibling expansion row does not reshuffle unrelated rows
        const tr = h('tr', {
          key,
          'data-testid': 'peer-row',
          onClick: () => emit('row-click', { data: row, index }),
        }, cells)
        const expanded = !!props.expandedRows?.[key]
        if (!expanded || !slots.expansion) return [tr]
        const expansionTr = h('tr', { key: `${key}-expansion`, 'data-testid': 'peer-row-expansion' }, [
          h('td', { colspan: columns.length }, slots.expansion({ data: row, index })),
        ])
        return [tr, expansionTr]
      })
      return h('table', {}, [h('tbody', {}, rows)])
    }
  },
})

export function mpGlobal(extraStubs: Record<string, unknown> = {}) {
  const i18n = createI18n({
    legacy: false,
    locale: 'en',
    messages: { en: {} },
    missing: (_locale: string, key: string) => key,
    missingWarn: false,
    fallbackWarn: false,
  })
  return {
    plugins: [i18n],
    directives: { tooltip: () => {} },
    stubs: {
      Button: ButtonStub,
      Checkbox: CheckboxStub,
      InputNumber: InputNumberStub,
      InputText: InputTextStub,
      Textarea: TextareaStub,
      Select: SelectStub,
      Tag: TagStub,
      Message: PassThrough,
      Slider: true,
      ToggleButton: true,
      ToggleSwitch: true,
      // chart.js needs a real canvas; the chart itself is covered by its own spec.
      NetworkChart: true,
      // echarts needs a real canvas too.
      MpFlowSankey: true,
      // Status.vue peer table + surrounding chrome.
      Card: CardStub,
      Badge: BadgeStub,
      Chip: ChipStub,
      Dialog: DialogStub,
      DataTable: DataTableStub,
      Column: ColumnStub,
      Divider: true,
      ScrollPanel: true,
      Timeline: true,
      // Globally registered in the real app (easytier-frontend-lib.ts); resolved by name here too.
      HumanEvent: true,
      ...extraStubs,
    },
  }
}
