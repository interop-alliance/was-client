/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The blinded-index HMAC key of an encrypted Collection: minting it, rebuilding
 * it from its raw secret, and resolving it from the `encryption` descriptor
 * with a reader's own key-agreement key.
 *
 * A blinded index lets the server match a query without learning what it
 * matched: attribute names and values are HMAC-SHA-256 tags under a
 * per-collection key, so equal plaintext blinds to equal tokens and nothing
 * else. That is why the key never rotates -- tokens must compare across the
 * collection's whole history -- and why it is installed at provisioning or
 * never: retro-fitting a key would leave every already-written envelope
 * unindexed.
 *
 * Distribution reuses the epoch machinery verbatim: the 32-byte HMAC secret is
 * wrapped to each recipient's X25519 key-agreement key with
 * {@link wrapEpochSecret} (`ECDH-ES+A256KW`) and stored as a JWE `recipients`
 * entry on the descriptor's `hmac` member, exactly as an epoch secret is stored
 * on an epoch. There is deliberately no separate wrap primitive here: one wrap
 * shape, one review surface.
 *
 * Removing a recipient drops its wrap entry but leaves the key itself alone, so
 * a removed recipient keeps the blinding key -- an accepted, documented
 * revocation asymmetry (it can confirm guessed attribute values if the server
 * colludes).
 */
import { base64urlnopad } from '@scure/base'
import { SHA256HMACKey } from '@interop/data-integrity-core'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { EncryptionError } from '../errors.js'
import type { EncryptionWithHmac } from '../types.js'
import { unwrapEpochSecret } from './epochCrypto.js'

/**
 * The key type tag a blinded-index HMAC key is declared with on the descriptor.
 */
export const HMAC_KEY_TYPE = 'Sha256HmacKey2019'

/**
 * The minimal blinding-key contract the codec needs: an `id` (stamped on an
 * envelope's `indexed[].hmac.id`), a `type`, and HMAC sign/verify over bytes.
 * Structural rather than nominal, so a keystore that custodies the HMAC key
 * itself (or fronts a KMS) can supply its own implementation;
 * {@link SHA256HMACKey} satisfies it, and so does the `IHMAC` contract
 * `@interop/edv-client` blinds with (this narrows it: `id` and `type` are
 * required here, since both are stamped on an envelope's `indexed` entries).
 */
export interface BlindingKey {
  id: string
  type: string
  sign(options: { data: Uint8Array }): Promise<Uint8Array>
  verify(options: { data: Uint8Array; signature: Uint8Array }): Promise<boolean>
}

/**
 * Mints a fresh blinded-index HMAC key: 32 random bytes under a random
 * `urn:uuid:` id. The caller wraps the returned `secret` to each recipient with
 * {@link wrapEpochSecret} and installs `{ id, type, recipients }` on the
 * descriptor's `hmac` member.
 *
 * @returns {Promise<{ id: string, type: string, secret: Uint8Array }>}
 */
export async function mintHmacKey(): Promise<{
  id: string
  type: string
  secret: Uint8Array
}> {
  const secret = crypto.getRandomValues(new Uint8Array(32))
  return { id: `urn:uuid:${crypto.randomUUID()}`, type: HMAC_KEY_TYPE, secret }
}

/**
 * Rebuilds the concrete HMAC key from its raw secret -- what a reader does once
 * it has unwrapped the secret from its descriptor entry. The secret is imported
 * as a standard `oct` JWK, the serialization {@link SHA256HMACKey.from} accepts.
 *
 * @param options {object}
 * @param options.id {string}           the key id (`indexed[].hmac.id`)
 * @param options.secret {Uint8Array}   the raw 32-byte HMAC secret
 * @returns {Promise<SHA256HMACKey>}
 */
export async function hmacKeyFromSecret({
  id,
  secret
}: {
  id: string
  secret: Uint8Array
}): Promise<SHA256HMACKey> {
  return SHA256HMACKey.from({
    id,
    type: HMAC_KEY_TYPE,
    secretKeyJwk: {
      kty: 'oct',
      k: base64urlnopad.encode(secret),
      alg: 'HS256'
    }
  })
}

/**
 * Resolves the collection's blinding key from its `encryption` descriptor with
 * a reader's own key-agreement key. Returns `null` when the descriptor declares
 * no `hmac` member -- the collection is simply not indexable (installed at
 * provisioning or never).
 *
 * Fails closed when the descriptor DOES declare one but this key-agreement key
 * unwraps no entry: a current recipient must be able to blind, so a missing or
 * corrupt entry is an {@link EncryptionError} rather than a silent
 * "unindexable" downgrade that would write envelopes nobody can find.
 *
 * @param options {object}
 * @param options.encryption {EncryptionWithHmac}   the Collection's descriptor
 * @param options.keyAgreementKey {IKeyAgreementKey}   the reader's own KAK; its
 *   `id` must match an `hmac.recipients` entry's `kid`
 * @returns {Promise<SHA256HMACKey | null>}
 */
export async function resolveHmacKey({
  encryption,
  keyAgreementKey
}: {
  encryption: EncryptionWithHmac
  keyAgreementKey: IKeyAgreementKey
}): Promise<SHA256HMACKey | null> {
  const hmac = encryption.hmac
  if (!hmac) {
    return null
  }
  const entry = hmac.recipients?.find(
    recipient => recipient.header.kid === keyAgreementKey.id
  )
  const secret = entry
    ? await unwrapEpochSecret({ entry, keyAgreementKey })
    : null
  if (!secret) {
    throw new EncryptionError(
      'This collection declares a blinded-index key ' +
        `("${hmac.id}") that this client's key-agreement key ` +
        `("${keyAgreementKey.id}") cannot unwrap (no recipient entry names ` +
        'it, or its entry is corrupt). Re-add this reader with addRecipient, ' +
        'or supply the correct key-agreement key.'
    )
  }
  return hmacKeyFromSecret({ id: hmac.id, secret })
}
