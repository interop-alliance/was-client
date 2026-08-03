/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Derives a grantee's epoch-recipient key from the `did:key` DID a capability
 * request already names as its `controller`. An Ed25519 `did:key` has a
 * canonical X25519 twin (the Montgomery form) -- the same conversion a wallet
 * applies to its own key-agreement key. So the recipient key never travels on
 * the wire: it is derived locally from the controller DID.
 *
 * Deriving beats accepting an explicit `{ id, publicKeyMultibase }` field. An
 * explicit key would let a request pair controller DID A with recipient key B,
 * and the granting side would have to verify the binding anyway -- which for a
 * `did:key` means performing this exact derivation. Deriving makes key
 * substitution impossible by construction and keeps both axes of a share (the
 * pull zcap and the epoch roster entry) pointing at the same entity.
 *
 * The resulting recipient `id` is `did:key:z6Mk...#z6LS...` -- byte-identical
 * to what the grantee derives on its own side from the same key material, so
 * its `kid` matches the epoch roster entry that gets written, and it resolves
 * through the default `did:key` recipient resolver.
 */
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { RecipientPublicKey } from './epochCrypto.js'

const DID_KEY_PREFIX = 'did:key:'

// Multibase base58btc + multicodec ed25519-pub: every Ed25519 did:key
// identifier starts with these four characters.
const ED25519_MULTIBASE_PREFIX = 'z6Mk'

/**
 * Whether a string is an Ed25519 `did:key` DID -- the only controller shape a
 * recipient key can be derived from (an X25519 twin exists only for an Ed25519
 * key). A key id (a DID with a fragment) is not one: the derivation is defined
 * over the DID itself.
 *
 * @param did {string | undefined}
 * @returns {boolean}
 */
export function isEd25519DidKey(did: string | undefined): boolean {
  return (
    !!did &&
    did.startsWith(DID_KEY_PREFIX) &&
    did.slice(DID_KEY_PREFIX.length).startsWith(ED25519_MULTIBASE_PREFIX) &&
    !did.includes('#')
  )
}

/**
 * Derives the X25519 epoch-recipient public key for an Ed25519 `did:key`
 * controller.
 *
 * @param options {object}
 * @param options.did {string}   the grantee's Ed25519 `did:key` DID
 * @returns {RecipientPublicKey}
 */
export function x25519RecipientFromDidKey({
  did
}: {
  did: string
}): RecipientPublicKey {
  if (!isEd25519DidKey(did)) {
    throw new Error(
      `Cannot derive a recipient key: "${did}" is not an Ed25519 did:key DID.`
    )
  }
  const keyAgreementKey =
    X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
      keyPair: {
        controller: did,
        publicKeyMultibase: did.slice(DID_KEY_PREFIX.length)
      }
    })
  const { id, publicKeyMultibase, type } = keyAgreementKey
  if (typeof id !== 'string' || typeof publicKeyMultibase !== 'string') {
    throw new Error(
      'Cannot derive a recipient key: the converted key-agreement key lacks ' +
        'an id or publicKeyMultibase.'
    )
  }
  return { id, publicKeyMultibase, type }
}
