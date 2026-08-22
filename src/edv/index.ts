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
  UnknownEpochError,
  isEncryptedEnvelope
} from './docCipher.js'
export type { DocCipher, EdvDocCipher } from './docCipher.js'
