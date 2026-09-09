/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * WAS identity derivation: controller secret / seed to the agent set a did:key
 * client operates with. Every consumer must derive byte-for-byte identically,
 * so that supplying the same controller secret on any client joins the same
 * WAS account/Space.
 *
 * The derivation: secret or 32-byte seed enters `CapabilityAgent` under the
 * fixed `'bootstrap'` / `'boostrap-key'` names (the typo is load-bearing --
 * every account's data identity derives through these exact strings, so they
 * can never change without stranding existing accounts). The resulting Ed25519
 * signing key backs a did:key DID, a `ZcapClient` for signing storage
 * requests, and -- via did:key's encryption-key derivation (the Montgomery
 * form of the signing key) -- the X25519 key agreement key (KAK) the EDV
 * DocCipher encrypts and decrypts with. Everything is deterministic: a
 * returning user, on any client, decrypts the same envelopes.
 */
import { CapabilityAgent } from '@interop/capability-agent'
import { ZcapClient } from '@interop/ezcap'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { ValidationError } from '../errors.js'
import { zcapClientForSigner } from '../zcapClient.js'
import { singleKeyResolver } from './keyResolver.js'

/**
 * The load-bearing `CapabilityAgent` derivation names (see the module doc:
 * the typo in the key name can never be fixed without stranding accounts).
 */
export const BOOTSTRAP_HANDLE = 'bootstrap'
export const BOOTSTRAP_KEY_NAME = 'boostrap-key'

/**
 * The agents derived from a controller secret or seed: the signing
 * CapabilityAgent / did:key, a ZcapClient for signing storage requests, and
 * the X25519 key agreement key (KAK) + resolver used by the EDV DocCipher.
 */
export interface ProfileAgents {
  controllerDid: string
  keyAgent: CapabilityAgent
  zcapClient: ZcapClient
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}

/**
 * Derives the WAS agents from an already-derived 32-byte seed, skipping the
 * salted-hash step (`CapabilityAgent.fromSeed` semantics: a stored seed
 * stands in for the original secret).
 *
 * @param options {object}
 * @param options.seed {Uint8Array}   the 32-byte seed
 * @returns {Promise<ProfileAgents>}
 */
export async function agentsFromSeed({
  seed
}: {
  seed: Uint8Array
}): Promise<ProfileAgents> {
  if (seed.length !== 32) {
    throw new ValidationError(
      `Expected a 32-byte seed, got ${seed.length} bytes.`
    )
  }
  const keyAgent = await CapabilityAgent.fromSeed({
    seed,
    handle: BOOTSTRAP_HANDLE,
    keyName: BOOTSTRAP_KEY_NAME
  })
  return agentsFromKeyAgent({ keyAgent })
}

/**
 * Derives the WAS agents from a controller secret. The secret is always a
 * string: a passphrase, or the base64url text of 32 random bytes, not the
 * decoded bytes. `CapabilityAgent.fromSecret`'s salted hash is
 * type-sensitive, so a string and its UTF-8 bytes derive different keys.
 * Passing a string keeps every secret typeable/scannable into a login form
 * (the cross-wallet linking flow).
 *
 * @param options {object}
 * @param options.secret {string}   the controller secret (see above)
 * @returns {Promise<ProfileAgents>}
 */
export async function agentsFromSecret({
  secret
}: {
  secret: string
}): Promise<ProfileAgents> {
  const keyAgent = await CapabilityAgent.fromSecret({
    secret,
    handle: BOOTSTRAP_HANDLE,
    keyName: BOOTSTRAP_KEY_NAME
  })
  return agentsFromKeyAgent({ keyAgent })
}

/**
 * Assembles the derived agents -- signer, `ZcapClient`, key agreement key (the
 * Ed25519-to-X25519 Montgomery conversion), and single-key resolver -- from an
 * already-derived `CapabilityAgent`. The shared tail of both derivations here,
 * and exported because downstream packages derive their own `CapabilityAgent`
 * (from an app seed, under their own handle / key name) and then need this same
 * assembly: keeping it in one place means the Montgomery conversion that every
 * encrypted collection is read with has exactly one implementation.
 *
 * @param options {object}
 * @param options.keyAgent {CapabilityAgent}   the derived signing agent
 * @returns {ProfileAgents}
 */
export function agentsFromKeyAgent({
  keyAgent
}: {
  keyAgent: CapabilityAgent
}): ProfileAgents {
  const signer = keyAgent.getSigner()
  // The root key also signs delegations (sharing grants, app capability
  // grants).
  const zcapClient = zcapClientForSigner({ signer })

  const keyAgreementKey =
    X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
      keyPair: keyAgent.getVerificationKeyPair()
    })
  const keyResolver = singleKeyResolver({ keyAgreementKey })

  return {
    controllerDid: keyAgent.id,
    keyAgent,
    zcapClient,
    // `id` is always set on the KAK here (a controller was supplied at
    // derivation), so it satisfies IKeyAgreementKey's required `id`.
    keyAgreementKey: keyAgreementKey as IKeyAgreementKey,
    keyResolver
  }
}
