/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the blinded-index HMAC key (no network): minting it, wrapping
 * it to a reader and resolving it back off the descriptor, the fail-closed and
 * not-declared resolution paths, the provisioning-time install
 * (`ensureFirstEpoch({ blindedIndex: true })`), the roster operations that
 * carry it (`addRecipient` / `removeRecipient` / `replaceRecipient`), and the
 * codec's blinding-key resolution.
 */
import { describe, it, expect } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { SHA256HMACKey } from '@interop/data-integrity-core'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'

import { EncryptionError } from '../../src/index.js'
import type { EncryptionWithHmac } from '../../src/index.js'
import type { EncryptionDescriptorStore } from '../../src/edv/descriptorStore.js'
import { mintEpoch, wrapEpochSecret } from '../../src/edv/epochCrypto.js'
import {
  hmacKeyFromSecret,
  mintHmacKey,
  resolveHmacKey,
  HMAC_KEY_TYPE
} from '../../src/edv/hmacKey.js'
import {
  addRecipient,
  ensureFirstEpoch,
  removeRecipient,
  replaceRecipient
} from '../../src/edv/recipients.js'
import { createEdvEncryption, EdvCodec } from '../../src/edv/index.js'

/**
 * Generates a self-describing did:key X25519 reader: its `id` is
 * `did:key:<pub>#<pub>`, so the default did:key recipient resolver recovers its
 * public key from the `kid` alone.
 *
 * @returns {Promise<{ kak: IKeyAgreementKey, publicKeyMultibase: string }>}
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

/**
 * An in-memory descriptor store: `read()` resolves `null` until a descriptor
 * exists, `create` is the guarded create-if-absent write, and `replace` is the
 * compare-and-swap write.
 *
 * @param [initial] {EncryptionWithHmac}   the descriptor `read()` starts with
 * @returns {object}   the store plus its current state
 */
function memoryStore(
  initial?: EncryptionWithHmac
): EncryptionDescriptorStore & {
  state: { descriptor?: EncryptionWithHmac }
} {
  const holder = {
    state: { descriptor: initial },
    async read() {
      return holder.state.descriptor === undefined
        ? null
        : { descriptor: holder.state.descriptor, etag: '"v1"' }
    },
    async replace(descriptor: EncryptionWithHmac) {
      holder.state.descriptor = descriptor
    },
    async create(descriptor: EncryptionWithHmac) {
      holder.state.descriptor = descriptor
    }
  }
  return holder
}

/**
 * Builds an epoch-bearing descriptor whose blinded-index key is wrapped to the
 * given readers -- the shape provisioning leaves behind.
 *
 * @param readers {Array}   the readers to wrap both secrets to
 * @returns {Promise<{ encryption: EncryptionWithHmac, hmacSecret: Uint8Array,
 *   hmacId: string }>}
 */
async function makeDescriptor(
  readers: { kak: IKeyAgreementKey; publicKeyMultibase: string }[]
): Promise<{
  encryption: EncryptionWithHmac
  hmacSecret: Uint8Array
  hmacId: string
}> {
  const { epochId, secret } = await mintEpoch()
  const { id: hmacId, type, secret: hmacSecret } = await mintHmacKey()
  const wrapTo = async (epochSecret: Uint8Array) =>
    Promise.all(
      readers.map(reader =>
        wrapEpochSecret({
          epochSecret,
          recipient: {
            id: reader.kak.id,
            publicKeyMultibase: reader.publicKeyMultibase
          }
        })
      )
    )
  return {
    encryption: {
      scheme: 'edv',
      epochs: [{ id: epochId, recipients: await wrapTo(secret) }],
      currentEpoch: epochId,
      hmac: { id: hmacId, type, recipients: await wrapTo(hmacSecret) }
    },
    hmacSecret,
    hmacId
  }
}

/**
 * A key resolver over one reader's key, for the codec provider fixtures.
 *
 * @param kak {IKeyAgreementKey}
 * @returns {IKeyResolver}
 */
function resolverFor(kak: IKeyAgreementKey): IKeyResolver {
  return async ({ id }: { id?: string }) => {
    if (id !== kak.id) {
      throw new Error(`Unknown key id "${id}".`)
    }
    return { id: kak.id, type: 'X25519KeyAgreementKey2020' }
  }
}

describe('blinded-index key wrap/unwrap round-trip', () => {
  it('resolves a key whose MAC matches a directly-built SHA256HMACKey', async () => {
    const alice = await makeReader()
    const { id, type, secret } = await mintHmacKey()
    expect(secret.length).toBe(32)
    expect(type).toBe(HMAC_KEY_TYPE)
    expect(id.startsWith('urn:uuid:')).toBe(true)

    const encryption: EncryptionWithHmac = {
      scheme: 'edv',
      hmac: {
        id,
        type,
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
    }
    const resolved = await resolveHmacKey({
      encryption,
      keyAgreementKey: alice.kak
    })
    expect(resolved).not.toBeNull()
    expect(resolved!.id).toBe(id)
    expect(resolved!.type).toBe(HMAC_KEY_TYPE)

    const direct = await hmacKeyFromSecret({ id, secret })
    const data = new TextEncoder().encode('an attribute value')
    const fromDescriptor = await resolved!.sign({ data })
    const fromSecret = await direct.sign({ data })
    expect(Buffer.from(fromDescriptor).equals(Buffer.from(fromSecret))).toBe(
      true
    )
    expect(await direct.verify({ data, signature: fromDescriptor })).toBe(true)
  })

  it('resolves null when the descriptor declares no blinded index', async () => {
    const alice = await makeReader()
    const resolved = await resolveHmacKey({
      encryption: { scheme: 'edv' },
      keyAgreementKey: alice.kak
    })
    expect(resolved).toBeNull()
  })

  it('fails closed when the declared key does not unwrap for this reader', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const { encryption } = await makeDescriptor([alice])
    await expect(
      resolveHmacKey({ encryption, keyAgreementKey: bob.kak })
    ).rejects.toThrow(EncryptionError)
  })
})

describe('ensureFirstEpoch with a blinded index', () => {
  it('installs the key wrapped to every initial recipient', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const store = memoryStore()
    const { descriptor, installed } = await ensureFirstEpoch({
      store,
      recipients: [
        { id: alice.kak.id, publicKeyMultibase: alice.publicKeyMultibase },
        { id: bob.kak.id, publicKeyMultibase: bob.publicKeyMultibase }
      ],
      blindedIndex: true
    })
    expect(installed).toBe(true)
    const hmac = (descriptor as EncryptionWithHmac).hmac
    expect(hmac).toBeDefined()
    expect(hmac!.type).toBe(HMAC_KEY_TYPE)
    expect(hmac!.recipients.map(entry => entry.header.kid).sort()).toEqual(
      [alice.kak.id, bob.kak.id].sort()
    )
    // Both readers really hold the same key.
    const forAlice = await resolveHmacKey({
      encryption: descriptor,
      keyAgreementKey: alice.kak
    })
    const forBob = await resolveHmacKey({
      encryption: descriptor,
      keyAgreementKey: bob.kak
    })
    const data = new TextEncoder().encode('x')
    expect(
      Buffer.from(await forAlice!.sign({ data })).equals(
        Buffer.from(await forBob!.sign({ data }))
      )
    ).toBe(true)
  })

  it('adopts an existing blinded-index descriptor without minting a new key', async () => {
    const alice = await makeReader()
    const recipients = [
      { id: alice.kak.id, publicKeyMultibase: alice.publicKeyMultibase }
    ]
    const store = memoryStore()
    const first = await ensureFirstEpoch({
      store,
      recipients,
      blindedIndex: true
    })
    const second = await ensureFirstEpoch({
      store,
      recipients,
      blindedIndex: true
    })
    expect(second.installed).toBe(false)
    expect((second.descriptor as EncryptionWithHmac).hmac!.id).toBe(
      (first.descriptor as EncryptionWithHmac).hmac!.id
    )
  })

  it('refuses to add a blinded index to an existing hmac-less collection', async () => {
    const alice = await makeReader()
    const recipients = [
      { id: alice.kak.id, publicKeyMultibase: alice.publicKeyMultibase }
    ]
    const store = memoryStore()
    await ensureFirstEpoch({ store, recipients })
    await expect(
      ensureFirstEpoch({ store, recipients, blindedIndex: true })
    ).rejects.toThrow(EncryptionError)
  })
})

describe('roster operations carry the blinded-index key', () => {
  it('addRecipient escrows the key, idempotently', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const { encryption, hmacId } = await makeDescriptor([alice])
    const store = memoryStore(encryption)

    const added = (await addRecipient({
      store,
      recipient: { id: bob.kak.id, publicKeyMultibase: bob.publicKeyMultibase },
      owner: { keyAgreementKey: alice.kak }
    })) as EncryptionWithHmac
    expect(added.hmac!.id).toBe(hmacId)
    expect(added.hmac!.recipients.length).toBe(2)
    const forBob = await resolveHmacKey({
      encryption: added,
      keyAgreementKey: bob.kak
    })
    expect(forBob!.id).toBe(hmacId)

    const again = (await addRecipient({
      store,
      recipient: { id: bob.kak.id, publicKeyMultibase: bob.publicKeyMultibase },
      owner: { keyAgreementKey: alice.kak }
    })) as EncryptionWithHmac
    expect(again.hmac!.recipients.length).toBe(2)
  })

  it('removeRecipient drops the leaver entry but never rotates the key', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const { encryption, hmacId } = await makeDescriptor([alice, bob])
    const store = memoryStore(encryption)

    const removed = (await removeRecipient({
      store,
      recipientId: bob.kak.id,
      pull: async () => {}
    })) as EncryptionWithHmac
    expect(removed.hmac!.id).toBe(hmacId)
    expect(removed.hmac!.recipients.map(entry => entry.header.kid)).toEqual([
      alice.kak.id
    ])
    // Alice's own blinding key is unchanged by the removal.
    const stillAlice = await resolveHmacKey({
      encryption: removed,
      keyAgreementKey: alice.kak
    })
    expect(stillAlice!.id).toBe(hmacId)
  })

  it('removeRecipient tolerates an absent blinded-index entry', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const { encryption } = await makeDescriptor([alice, bob])
    // Bob never received the blinding key (an hmac roster of alice only).
    encryption.hmac!.recipients = encryption.hmac!.recipients.filter(
      entry => entry.header.kid === alice.kak.id
    )
    const store = memoryStore(encryption)
    const removed = (await removeRecipient({
      store,
      recipientId: bob.kak.id,
      pull: async () => {}
    })) as EncryptionWithHmac
    expect(removed.hmac!.recipients.length).toBe(1)
  })

  it('replaceRecipient swaps the successor in and the retiring kid out', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const carol = await makeReader()
    const { encryption, hmacId } = await makeDescriptor([alice, bob])
    const store = memoryStore(encryption)

    const replaced = (await replaceRecipient({
      store,
      retire: bob.kak.id,
      recipient: {
        id: carol.kak.id,
        publicKeyMultibase: carol.publicKeyMultibase
      },
      owner: { keyAgreementKey: alice.kak },
      pull: async () => {}
    })) as EncryptionWithHmac
    expect(replaced.hmac!.id).toBe(hmacId)
    expect(
      replaced.hmac!.recipients.map(entry => entry.header.kid).sort()
    ).toEqual([alice.kak.id, carol.kak.id].sort())
    const forCarol = await resolveHmacKey({
      encryption: replaced,
      keyAgreementKey: carol.kak
    })
    expect(forCarol!.id).toBe(hmacId)
  })
})

describe('codecFor blinding-key resolution', () => {
  it('exposes the descriptor blinding key on the codec', async () => {
    const alice = await makeReader()
    const { encryption, hmacId } = await makeDescriptor([alice])
    const provider = createEdvEncryption({
      resolveKeys: async () => ({
        keyAgreementKey: alice.kak,
        keyResolver: resolverFor(alice.kak)
      })
    })
    const codec = await provider.codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'edv',
      encryption
    })
    expect((codec as EdvCodec).blindingKey!.id).toBe(hmacId)
  })

  it('is null when the collection declares no blinded index', async () => {
    const alice = await makeReader()
    const { encryption } = await makeDescriptor([alice])
    delete encryption.hmac
    const provider = createEdvEncryption({
      resolveKeys: async () => ({
        keyAgreementKey: alice.kak,
        keyResolver: resolverFor(alice.kak)
      })
    })
    const codec = await provider.codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'edv',
      encryption
    })
    expect((codec as EdvCodec).blindingKey).toBeNull()
  })

  it('prefers an explicitly supplied blinding key over the descriptor', async () => {
    const alice = await makeReader()
    const { encryption } = await makeDescriptor([alice])
    const custodied = await SHA256HMACKey.generate({ id: 'urn:uuid:custodied' })
    const provider = createEdvEncryption({
      resolveKeys: async () => ({
        keyAgreementKey: alice.kak,
        keyResolver: resolverFor(alice.kak),
        hmac: custodied
      })
    })
    const codec = await provider.codecFor({
      spaceId: 's',
      collectionId: 'c',
      scheme: 'edv',
      encryption
    })
    expect((codec as EdvCodec).blindingKey!.id).toBe('urn:uuid:custodied')
  })

  it('fails closed when the declared blinding key does not unwrap', async () => {
    const alice = await makeReader()
    const bob = await makeReader()
    const { encryption } = await makeDescriptor([alice, bob])
    // Bob holds the epoch but not the blinding key.
    encryption.hmac!.recipients = encryption.hmac!.recipients.filter(
      entry => entry.header.kid === alice.kak.id
    )
    const provider = createEdvEncryption({
      resolveKeys: async () => ({
        keyAgreementKey: bob.kak,
        keyResolver: resolverFor(bob.kak)
      })
    })
    await expect(
      provider.codecFor({
        spaceId: 's',
        collectionId: 'c',
        scheme: 'edv',
        encryption
      })
    ).rejects.toThrow(EncryptionError)
  })
})
