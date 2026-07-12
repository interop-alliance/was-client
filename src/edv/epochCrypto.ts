/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The key-epoch cryptography for multi-recipient encrypted Collections: wrapping
 * and unwrapping a per-epoch collection key to each reader's X25519
 * key-agreement key, and minting / reconstructing the epoch key pair the EDV
 * codec encrypts resources under.
 *
 * A collection key epoch is a fresh 32-byte X25519 private key. Resources are
 * encrypted with the ordinary EDV `documentCipher`, naming the epoch's public
 * key as the sole recipient (each document gets a fresh content-encryption key
 * wrapped `ECDH-ES+A256KW` to the epoch key) -- so the read/write machinery is
 * unchanged and only key resolution is epoch-aware. The epoch's public key IS
 * its `did:key`, and the epoch id is that `did:key` string, so the standard
 * `did:key` resolver resolves the recipient named in a resource's JWE.
 *
 * The epoch key itself is shared with a reader by wrapping the 32-byte epoch
 * secret to the reader's own X25519 key-agreement key, `ECDH-ES+A256KW`, and
 * storing the result as a JWE `recipients` entry verbatim on the Collection's
 * `encryption` marker. The wrap is derive-then-wrap per recipient: an ephemeral
 * ECDH against the reader's public key, the RFC 7518 Concat KDF, then A256KW --
 * `@interop/minimal-cipher`'s own `ECDH-ES+A256KW` building blocks (via its
 * `algorithms` subpath), so the wrapped bytes are interchangeable with what its
 * `Cipher` would produce.
 *
 * The two axes stay separate here: this module governs **read** (who can
 * decrypt), which is prospective -- rotating the epoch only protects resources
 * written afterwards. **Pull** (who the server will serve ciphertext to) is the
 * zcap layer, enforced immediately at request time. Neither alone removes a
 * reader; see `removeRecipient`.
 */
import { base64urlnopad } from '@scure/base'
import { createKek, deriveKey } from '@interop/minimal-cipher/algorithms'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import {
  multibaseDecode,
  multibaseEncode,
  X25519_PRIV_HEADER,
  X25519_PUB_HEADER
} from './multibase.js'
import type { CollectionEncryptionRecipient } from '../types.js'

/**
 * The JOSE key-management algorithm for every epoch/recipient wrap.
 */
export const KEY_WRAP_ALG = 'ECDH-ES+A256KW'

/**
 * The X25519 suite tag used for the ephemeral and reconstructed key pairs.
 */
const X25519_TYPE = 'X25519KeyAgreementKey2020'

const TEXT_ENCODER = new TextEncoder()

/**
 * A reader's public key-agreement key, as needed to wrap an epoch key to it:
 * the recipient `id` (`kid`, which the reader's own key-agreement key must also
 * report) and its `publicKeyMultibase`.
 */
export interface RecipientPublicKey {
  id: string
  publicKeyMultibase: string
  type?: string
}

/**
 * Wraps a 32-byte epoch secret to one recipient's X25519 key-agreement key,
 * producing the JWE `recipients` entry stored on the marker. Generates a fresh
 * ephemeral key per call (ECDH-ES), so each wrap carries its own `epk`.
 *
 * @param options {object}
 * @param options.epochSecret {Uint8Array}       the 32-byte epoch key to wrap
 * @param options.recipient {RecipientPublicKey}   the reader's public KAK
 * @returns {Promise<CollectionEncryptionRecipient>}
 */
export async function wrapEpochSecret({
  epochSecret,
  recipient
}: {
  epochSecret: Uint8Array
  recipient: RecipientPublicKey
}): Promise<CollectionEncryptionRecipient> {
  const ephemeral = await X25519KeyAgreementKey2020.generate()
  const ephemeralPublicKey = multibaseDecode(
    X25519_PUB_HEADER,
    ephemeral.publicKeyMultibase
  )
  const secret = await ephemeral.deriveSecret({
    publicKey: { publicKeyMultibase: recipient.publicKeyMultibase }
  })
  const producerInfo = ephemeralPublicKey
  const consumerInfo = TEXT_ENCODER.encode(recipient.id)
  const keyData = await deriveKey({ secret, producerInfo, consumerInfo })
  const kek = await createKek({ keyData })
  const encryptedKey = await kek.wrapKey({ unwrappedKey: epochSecret })
  return {
    header: {
      kid: recipient.id,
      alg: KEY_WRAP_ALG,
      epk: {
        kty: 'OKP',
        crv: 'X25519',
        x: base64urlnopad.encode(ephemeralPublicKey)
      },
      apu: base64urlnopad.encode(producerInfo),
      apv: base64urlnopad.encode(consumerInfo)
    },
    encrypted_key: encryptedKey
  }
}

/**
 * Unwraps an epoch secret from a marker `recipients` entry using the reader's
 * own key-agreement key. Returns `null` when this key does not match the entry
 * (the wrong recipient, or a corrupt entry) -- never treat `null` as a key; try
 * the next candidate entry or epoch, and fail with a typed error when nothing
 * unwraps.
 *
 * @param options {object}
 * @param options.entry {CollectionEncryptionRecipient}   the marker entry
 * @param options.keyAgreementKey {IKeyAgreementKey}      the reader's own KAK
 *   (its `id` must equal `entry.header.kid` for the derivation to match)
 * @returns {Promise<Uint8Array | null>}
 */
export async function unwrapEpochSecret({
  entry,
  keyAgreementKey
}: {
  entry: CollectionEncryptionRecipient
  keyAgreementKey: IKeyAgreementKey
}): Promise<Uint8Array | null> {
  const epk = entry.header.epk as { x?: unknown } | undefined
  if (!epk || typeof epk.x !== 'string') {
    return null
  }
  const ephemeralPublicKey = base64urlnopad.decode(epk.x)
  let secret: Uint8Array
  try {
    secret = await keyAgreementKey.deriveSecret({
      publicKey: {
        type: X25519_TYPE,
        publicKeyMultibase: multibaseEncode(
          X25519_PUB_HEADER,
          ephemeralPublicKey
        )
      }
    })
  } catch {
    return null
  }
  const producerInfo = ephemeralPublicKey
  const consumerInfo = TEXT_ENCODER.encode(keyAgreementKey.id)
  const keyData = await deriveKey({ secret, producerInfo, consumerInfo })
  const kek = await createKek({ keyData })
  return kek.unwrapKey({ wrappedKey: entry.encrypted_key })
}

/**
 * Mints a fresh key epoch: a new random X25519 key pair whose `did:key` is the
 * epoch id. Returns the id, the raw 32-byte secret (to wrap to recipients), and
 * the reconstructed key pair (to encrypt resources under).
 *
 * @returns {Promise<{ epochId: string, secret: Uint8Array, keyPair: X25519KeyAgreementKey2020 }>}
 */
export async function mintEpoch(): Promise<{
  epochId: string
  secret: Uint8Array
  keyPair: IKeyAgreementKey
}> {
  const generated = await X25519KeyAgreementKey2020.generate()
  if (generated.privateKeyMultibase === undefined) {
    throw new Error('Generated epoch key is missing its private key.')
  }
  const secret = multibaseDecode(
    X25519_PRIV_HEADER,
    generated.privateKeyMultibase
  )
  const epochId = `did:key:${generated.publicKeyMultibase}`
  return {
    epochId,
    secret,
    keyPair: reconstructEpochKeyPair({ epochId, secret })
  }
}

/**
 * Reconstructs an epoch key pair from its id (a `did:key`, which carries the
 * public key) and the unwrapped 32-byte secret, ready to hand to the EDV
 * `documentCipher` as its `keyAgreementKey`.
 *
 * @param options {object}
 * @param options.epochId {string}      the epoch's `did:key`
 * @param options.secret {Uint8Array}   the unwrapped 32-byte epoch secret
 * @returns {X25519KeyAgreementKey2020}
 */
export function reconstructEpochKeyPair({
  epochId,
  secret
}: {
  epochId: string
  secret: Uint8Array
}): IKeyAgreementKey {
  const publicKeyMultibase = publicKeyMultibaseFromEpochId(epochId)
  // The concrete instance always carries a defined `id` (set here), so it
  // satisfies `IKeyAgreementKey` (whose `id` is required); the suite's type
  // declares `id` optional, hence the assertion.
  return new X25519KeyAgreementKey2020({
    controller: epochId,
    id: epochKeyIdFor(epochId),
    publicKeyMultibase,
    privateKeyMultibase: multibaseEncode(X25519_PRIV_HEADER, secret)
  }) as IKeyAgreementKey
}

/**
 * The verification-method id of an epoch key: `<did:key>#<fingerprint>`. This is
 * the `kid` the EDV `documentCipher` stamps on a resource encrypted under the
 * epoch, so a reader maps it back to the epoch via {@link epochIdFromKid}.
 *
 * @param epochId {string}   the epoch's `did:key`
 * @returns {string}
 */
export function epochKeyIdFor(epochId: string): string {
  return `${epochId}#${publicKeyMultibaseFromEpochId(epochId)}`
}

/**
 * Recovers an epoch id (a `did:key`) from a resource JWE recipient `kid`
 * (`<did:key>#<fragment>`), so the read path can pick the epoch key before
 * decrypting.
 *
 * @param kid {string}
 * @returns {string}
 */
export function epochIdFromKid(kid: string): string {
  const hash = kid.indexOf('#')
  return hash === -1 ? kid : kid.slice(0, hash)
}

/**
 * Extracts the `publicKeyMultibase` fingerprint from an epoch id (`did:key:z...`).
 *
 * @param epochId {string}
 * @returns {string}
 */
function publicKeyMultibaseFromEpochId(epochId: string): string {
  const prefix = 'did:key:'
  if (!epochId.startsWith(prefix)) {
    throw new Error(
      `Epoch id "${epochId}" is not a did:key (expected a "${prefix}z..." id).`
    )
  }
  return epochId.slice(prefix.length)
}

/**
 * A `did:key` key resolver for X25519 key-agreement keys: resolves a
 * `did:key:z...#z...` id (an epoch key, or any self-describing X25519 key) to
 * its public verification method. The public key is the fragment, so no network
 * or registry lookup is needed.
 *
 * @param options {object}
 * @param options.id {string}   the key id to resolve
 * @returns {Promise<{ id: string, type: string, publicKeyMultibase: string }>}
 */
export async function didKeyResolver({
  id
}: {
  id?: string
}): Promise<{ id: string; type: string; publicKeyMultibase: string }> {
  if (!id) {
    throw new Error('A key id is required to resolve.')
  }
  const hash = id.indexOf('#')
  const fragment = hash === -1 ? '' : id.slice(hash + 1)
  if (!fragment.startsWith('z')) {
    throw new Error(`Cannot resolve non-did:key key id "${id}".`)
  }
  // Validate the fragment is a well-formed X25519 public multibase.
  multibaseDecode(X25519_PUB_HEADER, fragment)
  return { id, type: X25519_TYPE, publicKeyMultibase: fragment }
}
