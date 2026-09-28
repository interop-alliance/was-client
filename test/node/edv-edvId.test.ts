/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for `edvIdFromBytes` (`./edv/cipher`'s formatter for a
 * deterministic EDV document id from 16 caller-supplied bytes): a known
 * vector, agreement with `assertDocId`, agreement with
 * `EdvDocumentCipher.deriveId`'s layout for an arbitrary digest, and the
 * `TypeError` refusals for a wrong-length or non-`Uint8Array` input.
 */
import { describe, it, expect } from 'vitest'
import { assertDocId, EdvDocumentCipher } from '@interop/edv-client/core'
import type { IJWE } from '@interop/data-integrity-core'
import { base58, base64urlnopad } from '@scure/base'
import { sha256 } from '@noble/hashes/sha2.js'

import { edvIdFromBytes } from '../../src/edv/index.js'

describe('edvIdFromBytes', () => {
  it('formats 16 zero bytes as the known vector', () => {
    const id = edvIdFromBytes(new Uint8Array(16))
    const expectedBuf = new Uint8Array(18)
    expectedBuf[1] = 0x10
    expect(id).toBe('z' + base58.encode(expectedBuf))
  })

  it('produces an id that passes assertDocId', () => {
    const bytes = new Uint8Array(16)
    for (let index = 0; index < bytes.length; index++) {
      bytes[index] = index
    }
    const id = edvIdFromBytes(bytes)
    expect(() => assertDocId(id)).not.toThrow()
  })

  it('matches EdvDocumentCipher.deriveId layout for the same digest', async () => {
    const ciphertext = base64urlnopad.encode(
      new TextEncoder().encode('some jwe ciphertext bytes')
    )
    const digest = sha256(base64urlnopad.decode(ciphertext))
    const derived = await EdvDocumentCipher.deriveId({
      jwe: { ciphertext } as IJWE
    })
    const viaHelper = edvIdFromBytes(digest.subarray(0, 16))
    expect(viaHelper).toBe(derived)
  })

  it('throws a TypeError for 15 bytes', () => {
    expect(() => edvIdFromBytes(new Uint8Array(15))).toThrow(TypeError)
  })

  it('throws a TypeError for 17 bytes', () => {
    expect(() => edvIdFromBytes(new Uint8Array(17))).toThrow(TypeError)
  })

  it('throws a TypeError for a non-Uint8Array', () => {
    expect(() => edvIdFromBytes([1, 2, 3] as unknown as Uint8Array)).toThrow(
      TypeError
    )
  })
})
