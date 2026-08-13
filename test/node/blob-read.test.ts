/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Tests for the portable `Blob` read helpers (`src/internal/blob.ts`): the
 * native `text()` / `arrayBuffer()` path taken in a browser and in Node, and
 * the `FileReader` fallback taken on React Native, whose `Blob` implements
 * neither method. Node has no global `FileReader`, so the fallback tests
 * install a stub for the duration and restore the global afterward.
 */
import { afterEach, describe, expect, it } from 'vitest'
import { blobBytes, blobText } from '../../src/internal/blob.js'
import { installFileReader, rnBlob } from '../helpers/rnBlob.js'

let restore: (() => void) | undefined

afterEach(() => {
  restore?.()
  restore = undefined
})

describe('blobText / blobBytes: React Native shape (no native methods)', () => {
  it('reads text through the FileReader fallback', async () => {
    restore = installFileReader()
    const blob = rnBlob(['{"a":1}\n{"a":2}\n'], { type: 'text/jsonl' })
    expect(blob.text).toBeUndefined()
    expect(await blobText(blob)).toBe('{"a":1}\n{"a":2}\n')
  })

  it('reads bytes through the FileReader fallback', async () => {
    restore = installFileReader()
    const bytes = new Uint8Array([137, 80, 78, 71, 0, 255])
    const blob = rnBlob([bytes], { type: 'image/png' })
    expect(blob.arrayBuffer).toBeUndefined()
    expect(await blobBytes(blob)).toEqual(bytes)
  })

  it('rejects when the reader fires onerror', async () => {
    restore = installFileReader({ fail: true })
    const blob = rnBlob(['hello'])
    await expect(blobText(blob)).rejects.toThrow('stub FileReader failure')
    await expect(blobBytes(blob)).rejects.toThrow('stub FileReader failure')
  })

  it('throws when there is no native method and no FileReader either', async () => {
    const blob = rnBlob(['hello'])
    await expect(blobText(blob)).rejects.toBeInstanceOf(TypeError)
    await expect(blobBytes(blob)).rejects.toBeInstanceOf(TypeError)
  })
})

describe('blobText / blobBytes: native shape', () => {
  it('reads a complete Blob with no FileReader global present', async () => {
    expect((globalThis as { FileReader?: unknown }).FileReader).toBeUndefined()
    const bytes = new Uint8Array([1, 2, 3, 4])
    expect(await blobText(new Blob(['plain text']))).toBe('plain text')
    expect(await blobBytes(new Blob([bytes]))).toEqual(bytes)
  })
})
