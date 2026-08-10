/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the encrypted-collection hardening layer (no network): the
 * AEAD-authenticated `was` protected-header binding (resource-id swap detection,
 * content-derived id verification, metadata binding, and the unconditional
 * per-envelope epoch binding), the epoch-from-birth routing rule (a descriptor
 * carrying no key-epoch roster is refused fail-closed), the scheme-version
 * refusal gate, and the authenticated epoch configuration (`epochsMac`)
 * lifecycle across initRecipients / addRecipient / removeRecipient and its
 * verification in resolveEpochKeys (including a hand-simulated malicious
 * `currentEpoch` rollback).
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
 * The EDV document id the hand-crafted envelopes below are stamped with (a
 * well-formed multibase EDV id, so the cipher accepts it on decrypt).
 */
const CRAFTED_ID = 'z' + 'A'.repeat(21)

/**
 * Generates a fresh real X25519 key agreement key and a matching resolver.
 *
 * @returns {Promise<{ kak: IKeyAgreementKey; keyResolver: IKeyResolver;
 *   publicKeyMultibase: string }>}
 */
async function makeKeys(): Promise<{
  kak: IKeyAgreementKey
  keyResolver: IKeyResolver
  publicKeyMultibase: string
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
  return {
    kak: kak as IKeyAgreementKey,
    keyResolver,
    publicKeyMultibase: kak.publicKeyMultibase
  }
}

/**
 * Builds the single-epoch `edv` descriptor an encrypted collection carries from
 * birth (epoch-from-birth), with the given reader as recipient zero.
 *
 * @param reader {object}
 * @param reader.id {string}   the reader's key-agreement key id (the wrap `kid`)
 * @param reader.publicKeyMultibase {string}   the reader's public X25519 key
 * @returns {Promise<{ encryption: CollectionEncryption; epoch: string;
 *   secret: Uint8Array }>}
 */
async function makeEpochDescriptor(reader: {
  id: string
  publicKeyMultibase: string
}): Promise<{
  encryption: CollectionEncryption
  epoch: string
  secret: Uint8Array
}> {
  const { epochId, secret } = await mintEpoch()
  const encryption: CollectionEncryption = {
    scheme: 'edv',
    epochs: [
      {
        id: epochId,
        recipients: [
          await wrapEpochSecret({
            epochSecret: secret,
            recipient: {
              id: reader.id,
              publicKeyMultibase: reader.publicKeyMultibase
            }
          })
        ]
      }
    ],
    currentEpoch: epochId
  }
  return { encryption, epoch: epochId, secret }
}

/**
 * Builds an EDV codec over a fresh real X25519 reader and the single-epoch
 * descriptor that reader is recipient zero of, via the public provider. Also
 * hands back the epoch key pair itself, so a test can craft an envelope this
 * codec still routes to a read key but whose `was` binding the codec did not
 * write.
 *
 * @param [options] {object}
 * @param [options.idDerivation] {string}
 * @returns {Promise<{ codec: ResourceCodec; epoch: string;
 *   keyPair: IKeyAgreementKey }>}
 */
async function makeCodec(
  options: { idDerivation?: 'random' | 'content' } = {}
): Promise<{ codec: ResourceCodec; epoch: string; keyPair: IKeyAgreementKey }> {
  const { kak, keyResolver, publicKeyMultibase } = await makeKeys()
  const { encryption, epoch, secret } = await makeEpochDescriptor({
    id: kak.id,
    publicKeyMultibase
  })
  const provider = createEdvEncryption({
    resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver }),
    ...options
  })
  const codec = await provider.codecFor({
    spaceId: 's',
    collectionId: 'c',
    scheme: 'edv',
    encryption
  })
  if (!codec) {
    throw new Error('expected a codec')
  }
  return {
    codec,
    epoch,
    keyPair: reconstructEpochKeyPair({ epochId: epoch, secret })
  }
}

/**
 * Crafts an EDV envelope directly under an epoch key pair, bypassing the codec,
 * with a caller-chosen `was` binding -- or none at all. This is the only way to
 * produce an envelope a codec built over that epoch still routes to a read key
 * while its protected-header binding is missing or malformed.
 *
 * @param options {object}
 * @param options.keyPair {IKeyAgreementKey}   the epoch key pair to seal to
 * @param [options.was] {Record<string, unknown>}   the binding to stamp; omit it
 *   to stamp no `was` parameter at all
 * @returns {Promise<Uint8Array>}   the envelope bytes, ready for `responseFrom`
 */
async function craftEnvelope({
  keyPair,
  was
}: {
  keyPair: IKeyAgreementKey
  was?: Record<string, unknown>
}): Promise<Uint8Array> {
  const edv = new EdvClientCore({
    keyAgreementKey: keyPair,
    keyResolver: didKeyResolver
  })
  const encrypted = await edv.documentCipher.encrypt({
    doc: {
      id: CRAFTED_ID,
      content: { crafted: true },
      meta: { contentType: 'application/json' }
    },
    recipients: edv.documentCipher.createDefaultRecipients(keyPair),
    keyResolver: didKeyResolver,
    update: false,
    ...(was !== undefined && { additionalProtectedParams: { was } })
  })
  return new TextEncoder().encode(JSON.stringify(encrypted))
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
 * Parses the `was` binding out of an envelope object's JWE protected header.
 *
 * @param envelope {unknown}
 * @returns {Record<string, unknown> | undefined}
 */
function wasOf(envelope: unknown): Record<string, unknown> | undefined {
  const { jwe } = envelope as { jwe: { protected: string } }
  const decoded = JSON.parse(
    new TextDecoder().decode(base64urlnopad.decode(jwe.protected))
  )
  return decoded.was
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
  return wasOf(JSON.parse(new TextDecoder().decode(body as Uint8Array)))
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
    const { codec, epoch } = await makeCodec()
    const encoded = await codec.encode({ data: { secret: 'a' } })
    // The envelope carries `was: { v: 1, resource: <minted id>, epoch }`.
    expect(wasHeaderOf(encoded.body)).toEqual({
      v: 1,
      resource: encoded.id,
      epoch
    })
    // Reading it back under its own id verifies.
    await expect(
      codec.decode(responseFrom(encoded.body), encoded.id)
    ).resolves.toEqual({ secret: 'a' })
  })

  it('fails with IntegrityError when the server swaps two envelopes', async () => {
    const { codec } = await makeCodec()
    const first = await codec.encode({ data: { which: 'first' } })
    const second = await codec.encode({ data: { which: 'second' } })
    // A malicious server serves the SECOND envelope under the FIRST id: the
    // AEAD-bound `was.resource` no longer matches the requested id.
    await expect(
      codec.decode(responseFrom(second.body), first.id)
    ).rejects.toBeInstanceOf(IntegrityError)
  })
})

describe('was binding: malformed or absent binding', () => {
  it('refuses an envelope that carries no `was` binding at all', async () => {
    // Epoch-from-birth leaves no legacy era: an envelope sealed to the epoch key
    // but written without the binding comes from a writer this scheme does not
    // admit, so it is refused rather than accepted for back-compat.
    const { codec, keyPair } = await makeCodec()
    const body = await craftEnvelope({ keyPair })
    expect(wasHeaderOf(body)).toBe(undefined)
    await expect(
      codec.decode(responseFrom(body), CRAFTED_ID)
    ).rejects.toBeInstanceOf(EncryptionError)
    await expect(codec.decode(responseFrom(body), CRAFTED_ID)).rejects.toThrow(
      /no `was` binding/
    )
  })

  it('refuses an envelope whose `was` carries no epoch member', async () => {
    // The `was` parameter is present and its `resource` even matches, but the
    // epoch binding is missing: refused like a missing `was`, since the epoch
    // check is unconditional.
    const { codec, keyPair } = await makeCodec()
    const body = await craftEnvelope({
      keyPair,
      was: { v: 1, resource: CRAFTED_ID }
    })
    await expect(
      codec.decode(responseFrom(body), CRAFTED_ID)
    ).rejects.toBeInstanceOf(EncryptionError)
    await expect(codec.decode(responseFrom(body), CRAFTED_ID)).rejects.toThrow(
      /binds no `was.epoch`/
    )
  })

  it('fails with IntegrityError when `was.epoch` names another epoch', async () => {
    // A replay under a different epoch's label: the envelope decrypts with this
    // reader's epoch key, but the bound epoch is a different one.
    const { codec, keyPair } = await makeCodec()
    const { epochId: otherEpoch } = await mintEpoch()
    const body = await craftEnvelope({
      keyPair,
      was: { v: 1, resource: CRAFTED_ID, epoch: otherEpoch }
    })
    await expect(
      codec.decode(responseFrom(body), CRAFTED_ID)
    ).rejects.toBeInstanceOf(IntegrityError)
  })
})

describe('was binding: content-derived id verification', () => {
  it('omits `resource` and verifies the honest round trip by re-deriving the id', async () => {
    const { codec, epoch } = await makeCodec({ idDerivation: 'content' })
    const encoded = await codec.encode({ data: { addressed: true } })
    // No `resource` on a content-derived write (the id is a function of the
    // ciphertext), but the epoch is bound like every write.
    expect(wasHeaderOf(encoded.body)).toEqual({ v: 1, epoch })
    await expect(
      codec.decode(responseFrom(encoded.body), encoded.id)
    ).resolves.toEqual({ addressed: true })
  })

  it('fails with IntegrityError when an envelope is copied under a different id', async () => {
    const { codec } = await makeCodec({ idDerivation: 'content' })
    const one = await codec.encode({ data: { n: 1 } })
    const two = await codec.encode({ data: { n: 2 } })
    // Serve envelope `one` under envelope `two`'s id: the re-derived id no
    // longer matches the requested id.
    await expect(
      codec.decode(responseFrom(one.body), two.id)
    ).rejects.toBeInstanceOf(IntegrityError)
  })
})

describe('was binding: metadata envelope', () => {
  it('binds the resource id and the epoch into the metadata envelope and round-trips', async () => {
    const { codec, epoch } = await makeCodec()
    const { custom } = await codec.encodeMeta({
      custom: { name: 'Secret' },
      id: 'zResourceId'
    })
    // A metadata envelope seals to the current epoch key and binds `was.epoch`
    // like every other write, so it satisfies the unconditional decode check.
    expect(wasOf(custom)).toEqual({ v: 1, resource: 'zResourceId', epoch })
    await expect(codec.decodeMeta({ custom }, 'zResourceId')).resolves.toEqual({
      name: 'Secret'
    })
  })

  it('fails with IntegrityError when metadata is swapped between resources', async () => {
    const { codec } = await makeCodec()
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
      idDerivation: 'random'
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
    // the real key's epoch, so the decrypting key's epoch differs from
    // `was.epoch`.
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
  it('refuses to build a codec for a descriptor whose version is greater than 1', async () => {
    const { kak, keyResolver, publicKeyMultibase } = await makeKeys()
    const { encryption } = await makeEpochDescriptor({
      id: kak.id,
      publicKeyMultibase
    })
    const provider = createEdvEncryption({
      resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver })
    })
    await expect(
      provider.codecFor({
        spaceId: 's',
        collectionId: 'c',
        scheme: 'edv',
        encryption: { ...encryption, version: 2 }
      })
    ).rejects.toBeInstanceOf(EncryptionError)
  })

  it('builds a codec for a version-1 (or absent-version) descriptor', async () => {
    const { kak, keyResolver, publicKeyMultibase } = await makeKeys()
    const { encryption } = await makeEpochDescriptor({
      id: kak.id,
      publicKeyMultibase
    })
    const provider = createEdvEncryption({
      resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver })
    })
    const codec = await provider.codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'edv',
      encryption: { ...encryption, version: 1 }
    })
    expect(codec).not.toBeNull()
  })
})

describe('epoch-from-birth routing rule', () => {
  it('refuses a descriptor that carries no key epochs', async () => {
    // The one routing rule is the epoch roster. A descriptor declared encrypted
    // but carrying none is refused fail-closed rather than routed to a cipher
    // sealing straight to the reader's own key-agreement key.
    const { kak, keyResolver } = await makeKeys()
    const provider = createEdvEncryption({
      resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver })
    })
    await expect(
      provider.codecFor({
        spaceId: 's',
        collectionId: 'c',
        scheme: 'edv',
        encryption: { scheme: 'edv' }
      })
    ).rejects.toBeInstanceOf(EncryptionError)
    await expect(
      provider.codecFor({
        spaceId: 's',
        collectionId: 'c',
        scheme: 'edv',
        encryption: { scheme: 'edv' }
      })
    ).rejects.toThrow(/carries no key epochs/)
  })

  it('refuses a descriptor whose epoch roster is empty', async () => {
    const { kak, keyResolver } = await makeKeys()
    const provider = createEdvEncryption({
      resolveKeys: async () => ({ keyAgreementKey: kak, keyResolver })
    })
    await expect(
      provider.codecFor({
        spaceId: 's',
        collectionId: 'c',
        scheme: 'edv',
        encryption: { scheme: 'edv', epochs: [] }
      })
    ).rejects.toBeInstanceOf(EncryptionError)
  })
})

/**
 * A minimal in-memory Collection whose description read returns the evolving
 * descriptor and whose write applies it.
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
    const descriptor = await initRecipients({
      collection: fake as unknown as Collection,
      recipients: [
        { id: alice.kak.id, publicKeyMultibase: alice.publicKeyMultibase }
      ]
    })
    expect(descriptor.version).toBe(1)
    expect(descriptor.epochsMac).toMatchObject({ v: 1, alg: 'HS256' })
    expect(typeof descriptor.epochsMac!.mac).toBe('string')
    // Alice can resolve her keys, which verifies the MAC.
    await expect(
      resolveEpochKeys({ encryption: descriptor, keyAgreementKey: alice.kak })
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
    // still valid: Alice, the surviving reader of the new currentEpoch,
    // verifies it.
    expect(afterRemove.epochsMac).toBeDefined()
    expect(afterRemove.epochsMac!.mac).not.toBe(initial.epochsMac!.mac)
    await expect(
      resolveEpochKeys({ encryption: afterRemove, keyAgreementKey: alice.kak })
    ).resolves.not.toBeNull()
  })
})

describe('epochsMac verification in resolveEpochKeys', () => {
  /**
   * Builds a two-epoch descriptor (alice a recipient of both), with
   * `currentEpoch` set to the second and a valid `epochsMac` keyed by the
   * second epoch's secret.
   *
   * @param alice {{ kak: IKeyAgreementKey; publicKeyMultibase: string }}
   * @returns {Promise<{ descriptor: CollectionEncryption; firstEpoch: string }>}
   */
  async function twoEpochDescriptor(alice: {
    kak: IKeyAgreementKey
    publicKeyMultibase: string
  }): Promise<{ descriptor: CollectionEncryption; firstEpoch: string }> {
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
    const descriptor: CollectionEncryption = {
      scheme: 'edv',
      version: 1,
      epochs: [
        { id: first.epochId, recipients: [await wrapTo(first.secret)] },
        { id: second.epochId, recipients: [await wrapTo(second.secret)] }
      ],
      currentEpoch: second.epochId
    }
    descriptor.epochsMac = await computeEpochsMac({
      descriptor,
      epochSecret: second.secret
    })
    return { descriptor, firstEpoch: first.epochId }
  }

  it('accepts a descriptor with a valid epochsMac', async () => {
    const alice = await makeReader()
    const { descriptor } = await twoEpochDescriptor(alice)
    await expect(
      resolveEpochKeys({ encryption: descriptor, keyAgreementKey: alice.kak })
    ).resolves.not.toBeNull()
  })

  it('rejects a currentEpoch rolled back to an older epoch (stale MAC)', async () => {
    const alice = await makeReader()
    const { descriptor, firstEpoch } = await twoEpochDescriptor(alice)
    // Simulate a malicious server: roll `currentEpoch` back to the older epoch
    // while KEEPING the MAC that was computed for the newer currentEpoch. The
    // MAC now fails to authenticate under the older epoch's secret.
    const rolledBack: CollectionEncryption = {
      ...descriptor,
      currentEpoch: firstEpoch
    }
    await expect(
      resolveEpochKeys({ encryption: rolledBack, keyAgreementKey: alice.kak })
    ).rejects.toBeInstanceOf(IntegrityError)
  })

  it('rejects an epochsMac with an unsupported construction (v/alg)', async () => {
    const alice = await makeReader()
    const { descriptor } = await twoEpochDescriptor(alice)
    const tampered: CollectionEncryption = {
      ...descriptor,
      epochsMac: { ...descriptor.epochsMac!, alg: 'HS512' }
    }
    await expect(
      resolveEpochKeys({ encryption: tampered, keyAgreementKey: alice.kak })
    ).rejects.toBeInstanceOf(IntegrityError)
  })

  it('accepts a legacy descriptor with no epochsMac', async () => {
    const alice = await makeReader()
    const { epochId, secret } = await mintEpoch()
    const descriptor: CollectionEncryption = {
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
      resolveEpochKeys({ encryption: descriptor, keyAgreementKey: alice.kak })
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
