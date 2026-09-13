/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/was-client/edv` subpath entry: encrypted (EDV-over-WAS) storage
 * support. Kept off the core `@interop/was-client` entry so plaintext consumers
 * do not pull the `@interop/edv-client` / `@interop/minimal-cipher` crypto graph
 * unless they opt in by importing this subpath.
 *
 * Two integration levels:
 *
 * - `createEdvEncryption` -- the EDV keystore for the handle seam. Pass its
 *   result as `WasClient`'s `encryption` option; it supplies keys for the
 *   collections declared encrypted (by their `encryption` descriptor or a
 *   per-handle override), so `collection.put`/`get` transparently
 *   encrypt/decrypt.
 * - `WasTransport` -- the standalone `@interop/edv-client`
 *   transport, for driving an `EdvClient` directly against WAS.
 *
 * Every encrypted collection carries a key-epoch roster from birth:
 * `ensureFirstEpoch` installs epoch[0] at provision time (create-if-absent;
 * the crypto-free `ensureSpaceAndCollection` only ensures the container), and
 * `initRecipients` / `addRecipient` / `removeRecipient` manage the readers and
 * rotate the epoch key, so the same `createEdvEncryption` provider
 * transparently encrypts each write under the current epoch and decrypts any
 * epoch a reader still holds.
 * They mutate the descriptor through the descriptor-store seam: the Collection
 * Description by default, or any `EncryptionDescriptorStore` -- e.g.
 * `resourceDescriptorStore` for a descriptor hosted as a plain JSON Resource.
 *
 * A collection provisioned with `ensureFirstEpoch({ blindedIndex: true })` also
 * carries a blinded-index HMAC key, distributed to recipients exactly like an
 * epoch key (see `hmacKey.ts`). It is installed at provisioning or never, and
 * never rotates.
 *
 * `hasKeyEpochs` and `epochRostersEqual` are the crypto-free predicates over a
 * descriptor: whether it carries a usable roster, and whether two descriptors
 * name the same one (roster identity, recipient sets deliberately excluded).
 *
 * `x25519RecipientFromDidKey` is the one rule for turning a grantee named only
 * by its Ed25519 `did:key` controller into a `RecipientPublicKey`, so a
 * recipient key is always derived from an identifier both sides already hold
 * rather than transmitted.
 *
 * A decrypt that finds no key raises one of two classes, and a caller scanning
 * rows must tell them apart: `UnknownEpochError` when the envelope's epoch is
 * not on the descriptor the reader holds (a re-read may fix it) and
 * `KeyUnwrapError` when the epoch IS listed but this reader has no key for it
 * (never a recipient, or removed and the epoch rotated since -- re-reading
 * cannot help). Both ship from this subpath beside the cipher that raises
 * them, so a consumer classifying what a cipher threw need not reach for the
 * package root. Both assign their `name` explicitly, and a consumer whose
 * cipher arrives through an injected seam matches on that name rather than
 * `instanceof`, since the seam may resolve to a second copy of this package:
 * `isKeyUnwrapError` here, and `isUnknownEpochError` on `./sync`, are those
 * matchers.
 *
 * Which epoch a collection encrypts under, and when to ask again, is the
 * descriptor acquisition and refresh policy every consumer running an
 * encrypted collection must share (a drift between two replicas does not fail
 * loudly; it fails as a resource one of them cannot decrypt):
 *
 * - `EncryptionDescriptorSource` / `EncryptionDescriptorCache` -- the narrow
 *   seams a host implements: one signed Collection Metadata read, and a
 *   client-local get/put pre-scoped to one Space. `wasDescriptorSource` is the
 *   source over a `WasClient` handle.
 * - `acquireDescriptor` / `acquireDescriptors` -- fetch + cache with the
 *   cached fallback whenever the fetch yields no descriptor, thrown or empty
 *   (offline, a collection keeps encrypting under its current epoch; an empty
 *   description is ambiguous, since WAS masks an unauthorized read as an
 *   absent one). No descriptor anywhere means a plaintext collection, or an
 *   encrypted one whose epoch[0] install has not landed -- which a caller that
 *   has declared the collection encrypted must refuse fail-closed. A
 *   log-governed source's refusal classes rethrow instead of falling back
 *   (except a continuity rollback, which is reconcilable divergence).
 * - `DescriptorRefreshPolicy` -- the once-per-collection-per-session
 *   unknown-epoch refresh guard, plus the refresh-and-re-read-once wrapper
 *   for hosts whose reads scan rows and count unknown-epoch skips.
 * - `createRefreshingEdvDocCipher` -- `createEdvDocCipher` bound to both: a
 *   cipher that acquires its own descriptor and, on an unknown-epoch decrypt,
 *   re-reads the description, swaps itself, and retries exactly once per
 *   instance.
 */
export {
  createEdvEncryption,
  EdvCodec,
  wasTransportFactory
} from './EdvCodec.js'
export type { CodecTransportFactory, EdvKeys } from './EdvCodec.js'
export { WasTransport } from './WasTransport.js'
export { EDV_SCHEME_VERSION, JOSE_CONTENT_TYPE } from './constants.js'
export {
  ensureFirstEpoch,
  initRecipients,
  addRecipient,
  removeRecipient,
  replaceRecipient
} from './recipients.js'
export type { RecipientPublicKey } from './recipients.js'
export {
  isEd25519DidKey,
  x25519RecipientFromDidKey
} from './didKeyRecipient.js'
export {
  collectionDescriptorStore,
  resourceDescriptorStore
} from './descriptorStore.js'
export type { EncryptionDescriptorStore } from './descriptorStore.js'
export {
  EPOCH_CONFIGURATION_STATE_TYPE,
  logGovernedCollectionDescriptorStore,
  logGovernedDescriptorStore,
  readGovernedEpochConfiguration,
  toEpochConfigurationState
} from './logGovernedDescriptorStore.js'
export type { LogGovernedDescriptorStore } from './logGovernedDescriptorStore.js'
export {
  mintEpoch,
  epochKeyIdFor,
  unwrapEpochSecret,
  wrapEpochSecret
} from './epochCrypto.js'
export { hasKeyEpochs, epochRostersEqual } from './epochRoster.js'
export { resolveEpochKeys } from './epochKeys.js'
export type { ResolvedEpochKeys } from './epochKeys.js'
export {
  HMAC_KEY_TYPE,
  mintHmacKey,
  hmacKeyFromSecret,
  resolveHmacKey
} from './hmacKey.js'
export type { BlindingKey } from './hmacKey.js'
export {
  createEdvDocCipher,
  createEdvEncryptOnlyDocCipher,
  ownerRecipient,
  EncryptOnlyCipherError,
  KeyUnwrapError,
  UnknownEpochError,
  isEncryptedEnvelope
} from './docCipher.js'
export type { DocCipher, EdvDocCipher } from './docCipher.js'
export {
  acquireDescriptor,
  acquireDescriptors,
  wasDescriptorSource
} from './acquire.js'
export type {
  EncryptionDescriptorCache,
  EncryptionDescriptorSource
} from './acquire.js'
export { DescriptorRefreshPolicy } from './refresh.js'
export { createRefreshingEdvDocCipher } from './refreshingDocCipher.js'
export { isKeyUnwrapError } from '../sync/predicates.js'
