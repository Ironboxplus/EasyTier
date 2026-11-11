import { cva } from 'class-variance-authority'

export const toggleVariants = cva(
  'inline-flex items-center justify-center gap-1 whitespace-nowrap rounded-md text-sm font-medium text-zinc-600 outline-none transition-colors hover:bg-zinc-100 disabled:pointer-events-none disabled:opacity-50 data-[state=on]:bg-zinc-900 data-[state=on]:text-white focus-visible:ring-2 focus-visible:ring-violet-400 [&_svg]:pointer-events-none [&_svg]:shrink-0',
  {
    variants: {
      variant: {
        default: 'bg-transparent',
        outline: 'border border-zinc-200 bg-transparent',
      },
      size: {
        default: 'h-9 min-w-9 px-2',
        sm: 'h-8 min-w-8 px-1.5',
        lg: 'h-10 min-w-10 px-2.5',
      },
    },
    defaultVariants: { variant: 'default', size: 'default' },
  },
)
