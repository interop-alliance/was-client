/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the encrypted-collection hardening layer (no network): the
 * AEAD-authenticated `was` protected-header binding (resource-id swap detection,
 * content-derived id verification, metadata binding, and the per-envelope epoch
 * label), the scheme-version refusal gate, and the authenticated epoch
 * configuration (`epochsMac`) lifecycle across initRecipients / addRecipient /
 * removeRecipient and its verification in resolveEpochKeys (including a
 * hand-simulated malicious `currentEpoch` rollback).
 */
import { describe, it, expect } from 'vitest'
import { base64urlnopad } from '@scure/base'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { EdvClientCore } from '@interop/edv-client'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { HttpResponse } from '@interop/http-client'

import {
  EncryptionError,
  IntegrityError,
  ValidationError
} from '../../src/index.js'
import type { CollectionEncryption, ResourceCodec } from '../../src/index.js'
import type { Collection } from '../../src/Collection.js'
import type { Space } from '../../src/Space.js'
import { createEdvEncryption, EdvCodec } from '../../src/edv/index.js'
import {
  didKeyResolver,
  epochKeyIdFor,
  mintEpoch,
  reconstructEpochKeyPair,
  wrapEpochSecret
} from '../../src/edv/epochCrypto.js'
import { computeEpochsMac } from '../../src/edv/epochMac.js'
import { resolveEpochKeys } from '../../src/edv/epochKeys.js'
import {
  addRecipient,
  initRecipients,
  removeRecipient
} from '../../src/edv/recipients.js'

/**
 * Generates a fresh real X25519 key agreement key and a matching resolver.
 *
 * @returns {Promise<{ kak: IKeyAgreementKey; keyResolver: IKeyResolver }>}
 */
async function makeKeys(): Promise<{
  kak: IKeyAgreementKey
  keyResolver: IKeyResolver
}> {
  const kak = await X25519KeyAgreementKey2020.generate({
    controller: 'did:example:alice'
  })
  const keyResolver = async ({ id }: { id?: string }) => {
    if (id !== kak.id) {
      throw new Error(`Unknown key id "${id}".`)
    }
    return {
      id: kak.id,
      type: kak.type,
      publicKeyMultibase: kak.publicKeyMultibase
    }
  }
  return { kak: kak as IKeyAgreementKey, keyResolver }
}

/**
 * Builds an EDV codec over a fresh real X25519 key, via the public provider.
 *
 * @param [options] {object}
 * @param [options.idDerivation] {string}
 * @returns {Promise<ResourceCodec>}
 */
async function makeCodec(
  options: { idDerivation?: 'random' | 'content' } = {}
): Promise<ResourceCodec> {
  const { kak, keyResolver } = await makeKeys()
  const provider = createEdvEncryption({
    resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver }),
    ...options
  })
  const codec = await provider.codecFor({
    spaceId: 's',
    collectionId: 'c',
    scheme: 'edv'
  })
  if (!codec) {
    throw new Error('expected a codec')
  }
  return codec
}

/**
 * Wraps encoded body bytes as a minimal read response the codec's `decode`
 * accepts.
 *
 * @param body {Uint8Array | Blob}
 * @returns {HttpResponse}
 */
function responseFrom(body?: Uint8Array | Blob): HttpResponse {
  const envelope = JSON.parse(new TextDecoder().decode(body as Uint8Array))
  return {
    data: envelope,
    async json() {
      return envelope
    }
  } as unknown as HttpResponse
}

/**
 * Parses the `was` binding out of an encoded envelope's JWE protected header.
 *
 * @param body {Uint8Array | Blob}
 * @returns {Record<string, unknown> | undefined}
 */
function wasHeaderOf(
  body?: Uint8Array | Blob
): Record<string, unknown> | undefined {
  const envelope = JSON.parse(new TextDecoder().decode(body as Uint8Array))
  const decoded = JSON.parse(
    new TextDecoder().decode(base64urlnopad.decode(envelope.jwe.protected))
  )
  return decoded.was
}

/**
 * A self-describing did:key X25519 reader (its `id` is `did:key:<pub>#<pub>`),
 * as the recipient ops and epoch resolver expect.
 *
 * @returns {Promise<{ kak: IKeyAgreementKey; publicKeyMultibase: string }>}
 */
async function makeReader(): Promise<{
  kak: IKeyAgreementKey
  publicKeyMultibase: string
}> {
  const kak = await X25519KeyAgreementKey2020.generate()
  const publicKeyMultibase = kak.publicKeyMultibase
  const did = `did:key:${publicKeyMultibase}`
  kak.controller = did
  kak.id = `${did}#${publicKeyMultibase}`
  return { kak: kak as IKeyAgreementKey, publicKeyMultibase }
}

describe('was binding: resource-id swap detection', () => {
  it('binds the minted id and reads it back with the expected id', async () => {
    const codec = await makeCodec()
    const encoded = await codec.encode({ data: { secret: 'a' } })
    // The envelope carries `was: { v: 1, resource: <minted id> }`.
    expect(wasHeaderOf(encoded.body)).toEqual({ v: 1, resource: encoded.id })
    // Reading it back under its own id verifies.
    await expect(
      codec.decode(responseFrom(encoded.body), encoded.id)
    ).resolves.toEqual({ secret: 'a' })
  })

  it('fails with IntegrityError when the server swaps two envelopes', async () => {
    const codec = await makeCodec()
    const first = await codec.encode({ data: { which: 'first' } })
    const second = await codec.encode({ data: { which: 'second' } })
    // A malicious server serves the SECOND envelope under the FIRST id: the
    // AEAD-bound `was.resource` no longer matches the requested id.
    await expect(
      codec.decode(responseFrom(second.body), first.id)
    ).rejects.toBeInstanceOf(IntegrityError)
  })

  it('still reads a legacy envelope that carries no `was` binding', async () => {
    // An envelope written before the binding existed (no additionalProtectedParams)
    // must still decode -- accepted unchanged for back-compat.
    const { kak, keyResolver } = await makeKeys()
    const edv = new EdvClientCore({ keyAgreementKey: kak, keyResolver })
    const recipients = edv.documentCipher.createDefaultRecipients(kak)
    const legacy = await edv.documentCipher.encrypt({
      doc: {
        id: 'z' + 'A'.repeat(21),
        content: { legacy: true },
        meta: { contentType: 'application/json' }
      },
      recipients,
      keyResolver,
      update: false
    })
    expect(wasHeaderOf(new TextEncoder().encode(JSON.stringify(legacy)))).toBe(
      undefined
    )
    const provider = createEdvEncryption({
      resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver })
    })
    const codec = (await provider.codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'edv'
    })) as ResourceCodec
    const body = new TextEncoder().encode(JSON.stringify(legacy))
    await expect(codec.decode(responseFrom(body), legacy.id)).resolves.toEqual({
      legacy: true
    })
  })
})

describe('was binding: content-derived id verification', () => {
  it('omits `resource` and verifies the honest round trip by re-deriving the id', async () => {
    const codec = await makeCodec({ idDerivation: 'content' })
    const encoded = await codec.encode({ data: { addressed: true } })
    // No `resource` on a content-derived write (the id is a function of the ciphertext).
    expect(wasHeaderOf(encoded.body)).toEqual({ v: 1 })
    await expect(
      codec.decode(responseFrom(encoded.body), encoded.id)
    ).resolves.toEqual({ addressed: true })
  })

  it('fails with IntegrityError when an envelope is copied under a different id', async () => {
    const codec = await makeCodec({ idDerivation: 'content' })
    const one = await codec.encode({ data: { n: 1 } })
    const two = await codec.encode({ data: { n: 2 } })
    // Serve envelope `one` under envelope `two`'s id: the re-derived id no longer
    // matches the requested id.
    await expect(
      codec.decode(responseFrom(one.body), two.id)
    ).rejects.toBeInstanceOf(IntegrityError)
  })
})

describe('was binding: metadata envelope', () => {
  it('binds the resource id into the metadata envelope and round-trips', async () => {
    const codec = await makeCodec()
    const { custom } = await codec.encodeMeta({
      custom: { name: 'Secret' },
      id: 'zResourceId'
    })
    await expect(codec.decodeMeta({ custom }, 'zResourceId')).resolves.toEqual({
      name: 'Secret'
    })
  })

  it('fails with IntegrityError when metadata is swapped between resources', async () => {
    const codec = await makeCodec()
    const { custom } = await codec.encodeMeta({
      custom: { name: 'For A' },
      id: 'zResourceA'
    })
    // The server serves resource A's metadata envelope for resource B.
    await expect(
      codec.decodeMeta({ custom }, 'zResourceB')
    ).rejects.toBeInstanceOf(IntegrityError)
  })
})

describe('was binding: per-envelope epoch label', () => {
  /**
   * Builds an epoch-bearing EdvCodec directly over a freshly-minted epoch key.
   * The declared write epoch (`was.epoch`) defaults to that key's real epoch, or
   * can be overridden with `relabelEpoch` to simulate a re-labeled envelope
   * whose declared epoch differs from the key that actually decrypts it.
   *
   * @param [options] {object}
   * @param [options.relabelEpoch] {string}   an epoch id to stamp instead of the
   *   real one
   * @returns {Promise<{ codec: EdvCodec; realEpoch: string; writeEpoch: string }>}
   */
  async function epochCodec(
    options: { relabelEpoch?: string } = {}
  ): Promise<{ codec: EdvCodec; realEpoch: string; writeEpoch: string }> {
    const { epochId: realEpoch, secret } = await mintEpoch()
    const writeEpoch = options.relabelEpoch ?? realEpoch
    const keyPair = reconstructEpochKeyPair({ epochId: realEpoch, secret })
    const edv = new EdvClientCore({
      keyAgreementKey: keyPair,
      keyResolver: didKeyResolver
    })
    const codec = new EdvCodec({
      edv,
      keyAgreementKey: keyPair,
      readKeys: [keyPair],
      writeEpoch,
      contentType: 'application/json',
      maxBlobBytes: 512 * 1024,
      idDerivation: 'random',
      hasEpochs: true
    })
    return { codec, realEpoch, writeEpoch }
  }

  it('stamps `was.epoch` with the write epoch and reads it back', async () => {
    const { codec, realEpoch } = await epochCodec()
    const encoded = await codec.encode({ data: { ok: true } })
    expect(wasHeaderOf(encoded.body)).toMatchObject({ v: 1, epoch: realEpoch })
    await expect(
      codec.decode(responseFrom(encoded.body), encoded.id)
    ).resolves.toEqual({ ok: true })
  })

  it('fails with IntegrityError when `was.epoch` mismatches the decrypting key', async () => {
    // The codec labels writes with a fake epoch while actually encrypting under
    // the real key's epoch, so the decrypting key's epoch differs from `was.epoch`.
    const fakeEpoch = 'did:key:z' + 'F'.repeat(21)
    const { codec, realEpoch } = await epochCodec({ relabelEpoch: fakeEpoch })
    const encoded = await codec.encode({ data: { ok: true } })
    expect(wasHeaderOf(encoded.body)).toMatchObject({ epoch: fakeEpoch })
    expect(realEpoch).not.toBe(fakeEpoch)
    await expect(
      codec.decode(responseFrom(encoded.body), encoded.id)
    ).rejects.toBeInstanceOf(IntegrityError)
  })
})

describe('scheme version gate', () => {
  it('refuses to build a codec for a marker whose version is greater than 1', async () => {
    const { kak, keyResolver } = await makeKeys()
    const provider = createEdvEncryption({
      resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver })
    })
    await expect(
      provider.codecFor({
        spaceId: 's',
        collectionId: 'c',
        scheme: 'edv',
        encryption: { scheme: 'edv', version: 2 }
      })
    ).rejects.toBeInstanceOf(EncryptionError)
  })

  it('builds a codec for a version-1 (or absent-version) marker', async () => {
    const { kak, keyResolver } = await makeKeys()
    const provider = createEdvEncryption({
      resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver })
    })
    const codec = await provider.codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'edv',
      encryption: { scheme: 'edv', version: 1 }
    })
    expect(codec).not.toBeNull()
  })
})

/**
 * A minimal in-memory Collection whose description read returns the evolving
 * marker and whose write applies it.
 *
 * @param initial {CollectionEncryption}
 * @returns {object}
 */
function mutableCollection(initial: CollectionEncryption) {
  const state = { encryption: initial }
  return {
    describeWithEtag: async () => ({
      description: {
        id: 'c',
        type: ['Collection'],
        encryption: state.encryption
      },
      etag: '"v1"'
    }),
    replaceDescription: async (desc: { encryption?: CollectionEncryption }) => {
      state.encryption = desc.encryption!
      return { description: { id: 'c', type: ['Collection'] }, etag: '"v2"' }
    },
    _state: state
  }
}

describe('epochsMac lifecycle', () => {
  it('initRecipients stamps version 1 and writes a valid epochsMac', async () => {
    const alice = await makeReader()
    const fake = mutableCollection({ scheme: 'edv' })
    const marker = await initRecipients({
      collection: fake as unknown as Collection,
      recipients: [
        { id: alice.kak.id, publicKeyMultibase: alice.publicKeyMultibase }
      ]
    })
    expect(marker.version).toBe(1)
    expect(marker.epochsMac).toMatchObject({ v: 1, alg: 'HS256' })
    expect(typeof marker.epochsMac!.mac).toBe('string')
    // Alice can resolve her keys, which verifies the MAC.
    await expect(
      resolveEpochKeys({ encryption: marker, keyAgreementKey: alice.kak })
    ).resolves.not.toBeNull()
  })

  it('addRecipient leaves the epochsMac and version untouched', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const fake = mutableCollection({ scheme: 'edv' })
    const initial = await initRecipients({
      collection: fake as unknown as Collection,
      recipients: [
        { id: alice.kak.id, publicKeyMultibase: alice.publicKeyMultibase }
      ]
    })
    const afterAdd = await addRecipient({
      collection: fake as unknown as Collection,
      recipient: { id: bob.kak.id, publicKeyMultibase: bob.publicKeyMultibase },
      owner: { keyAgreementKey: alice.kak }
    })
    expect(afterAdd.version).toBe(1)
    expect(afterAdd.epochsMac).toEqual(initial.epochsMac)
    // And Bob (a newly-added reader of currentEpoch) verifies the same MAC.
    await expect(
      resolveEpochKeys({ encryption: afterAdd, keyAgreementKey: bob.kak })
    ).resolves.not.toBeNull()
  })

  it('removeRecipient recomputes the epochsMac under the new epoch', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const fake = mutableCollection({ scheme: 'edv' })
    const initial = await initRecipients({
      collection: fake as unknown as Collection,
      recipients: [
        { id: alice.kak.id, publicKeyMultibase: alice.publicKeyMultibase },
        { id: bob.kak.id, publicKeyMultibase: bob.publicKeyMultibase }
      ]
    })
    const fakeSpace = { revoke: async () => undefined }
    const afterRemove = await removeRecipient({
      collection: fake as unknown as Collection,
      space: fakeSpace as unknown as Space,
      recipientId: bob.kak.id,
      revoke: []
    })
    // The MAC changed (new epoch secret, new currentEpoch + epoch list) but is
    // still valid: Alice, the surviving reader of the new currentEpoch, verifies it.
    expect(afterRemove.epochsMac).toBeDefined()
    expect(afterRemove.epochsMac!.mac).not.toBe(initial.epochsMac!.mac)
    await expect(
      resolveEpochKeys({ encryption: afterRemove, keyAgreementKey: alice.kak })
    ).resolves.not.toBeNull()
  })
})

describe('epochsMac verification in resolveEpochKeys', () => {
  /**
   * Builds a two-epoch marker (alice a recipient of both), with `currentEpoch`
   * set to the second and a valid `epochsMac` keyed by the second epoch's secret.
   *
   * @param alice {{ kak: IKeyAgreementKey; publicKeyMultibase: string }}
   * @returns {Promise<{ marker: CollectionEncryption; firstEpoch: string }>}
   */
  async function twoEpochMarker(alice: {
    kak: IKeyAgreementKey
    publicKeyMultibase: string
  }): Promise<{ marker: CollectionEncryption; firstEpoch: string }> {
    const first = await mintEpoch()
    const second = await mintEpoch()
    const wrapTo = (epochSecret: Uint8Array) =>
      wrapEpochSecret({
        epochSecret,
        recipient: {
          id: alice.kak.id,
          publicKeyMultibase: alice.publicKeyMultibase
        }
      })
    const marker: CollectionEncryption = {
      scheme: 'edv',
      version: 1,
      epochs: [
        { id: first.epochId, recipients: [await wrapTo(first.secret)] },
        { id: second.epochId, recipients: [await wrapTo(second.secret)] }
      ],
      currentEpoch: second.epochId
    }
    marker.epochsMac = await computeEpochsMac({
      marker,
      epochSecret: second.secret
    })
    return { marker, firstEpoch: first.epochId }
  }

  it('accepts a marker with a valid epochsMac', async () => {
    const alice = await makeReader()
    const { marker } = await twoEpochMarker(alice)
    await expect(
      resolveEpochKeys({ encryption: marker, keyAgreementKey: alice.kak })
    ).resolves.not.toBeNull()
  })

  it('rejects a currentEpoch rolled back to an older epoch (stale MAC)', async () => {
    const alice = await makeReader()
    const { marker, firstEpoch } = await twoEpochMarker(alice)
    // Simulate a malicious server: roll `currentEpoch` back to the older epoch
    // while KEEPING the MAC that was computed for the newer currentEpoch. The
    // MAC now fails to authenticate under the older epoch's secret.
    const rolledBack: CollectionEncryption = {
      ...marker,
      currentEpoch: firstEpoch
    }
    await expect(
      resolveEpochKeys({ encryption: rolledBack, keyAgreementKey: alice.kak })
    ).rejects.toBeInstanceOf(IntegrityError)
  })

  it('rejects an epochsMac with an unsupported construction (v/alg)', async () => {
    const alice = await makeReader()
    const { marker } = await twoEpochMarker(alice)
    const tampered: CollectionEncryption = {
      ...marker,
      epochsMac: { ...marker.epochsMac!, alg: 'HS512' }
    }
    await expect(
      resolveEpochKeys({ encryption: tampered, keyAgreementKey: alice.kak })
    ).rejects.toBeInstanceOf(IntegrityError)
  })

  it('accepts a legacy marker with no epochsMac', async () => {
    const alice = await makeReader()
    const { epochId, secret } = await mintEpoch()
    const marker: CollectionEncryption = {
      scheme: 'edv',
      epochs: [
        {
          id: epochId,
          recipients: [
            await wrapEpochSecret({
              epochSecret: secret,
              recipient: {
                id: alice.kak.id,
                publicKeyMultibase: alice.publicKeyMultibase
              }
            })
          ]
        }
      ],
      currentEpoch: epochId
    }
    await expect(
      resolveEpochKeys({ encryption: marker, keyAgreementKey: alice.kak })
    ).resolves.not.toBeNull()
  })
})

describe('epoch key id helper stays consistent', () => {
  it('an epoch key id splits back to the epoch did:key', async () => {
    const { epochId } = await mintEpoch()
    const kid = epochKeyIdFor(epochId)
    expect(kid.split('#')[0]).toBe(epochId)
    // A ValidationError type is exported and usable (sanity import guard).
    expect(ValidationError).toBeTypeOf('function')
  })
})
