import { describe, expect, it } from 'vitest'
// The vite YAML plugin parses with js-yaml, which rejects duplicate keys and bad quoting,
// so a locale file that fails to load fails this suite.
import cn from '../src/locales/cn.yaml'
import en from '../src/locales/en.yaml'

function keyPaths(node: unknown, prefix = ''): string[] {
  if (node === null || typeof node !== 'object' || Array.isArray(node)) return [prefix]
  return Object.entries(node as Record<string, unknown>).flatMap(([k, v]) =>
    keyPaths(v, prefix ? `${prefix}.${k}` : k),
  )
}

describe('locale files', () => {
  const cnKeys = new Set(keyPaths(cn))
  const enKeys = new Set(keyPaths(en))

  it('parse to objects', () => {
    expect(typeof cn).toBe('object')
    expect(typeof en).toBe('object')
  })

  it('cn.yaml has every key en.yaml has', () => {
    expect([...enKeys].filter((k) => !cnKeys.has(k)).sort()).toEqual([])
  })

  it('en.yaml has every key cn.yaml has', () => {
    expect([...cnKeys].filter((k) => !enKeys.has(k)).sort()).toEqual([])
  })
})
