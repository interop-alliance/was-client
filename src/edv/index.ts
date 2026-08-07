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
 * Multi-recipient (key-epoch) collections layer on top: `initRecipients` /
 * `addRecipient` / `removeRecipient` manage the readers and rotate the epoch
 * key, so the same `createEdvEncryption` provider transparently encrypts each
 * write under the current epoch and decrypts any epoch a reader still holds.
 * They mutate the descriptor through the descriptor-store seam: the Collection
 * Description by default, or any `EncryptionDescriptorStore` -- e.g.
 * `resourceDescriptorStore` for a descriptor hosted as a plain JSON Resource.
 *
 * `x25519RecipientFromDidKey` is the one rule for turning a grantee named only
 * by its Ed25519 `did:key` controller into a `RecipientPublicKey`, so a
 * recipient key is always derived from an identifier both sides already hold
 * rather than transmitted.
 */
export { createEdvEncryption, EdvCodec } from './EdvCodec.js'
export type { EdvKeys } from './EdvCodec.js'
export { WasTransport } from './WasTransport.js'
export { JOSE_CONTENT_TYPE } from './constants.js'
export {
  initRecipients,
  addRecipient,
  removeRecipient,
  replaceRecipient
} from './recipients.js'
export type { OwnerKey, RecipientPublicKey } from './recipients.js'
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
export {
  computeEpochsMac,
  epochsSigPayload,
  verifyEpochsMac
} from './epochMac.js'
export type { EpochsSigner } from './epochMac.js'
export { resolveEpochKeys } from './epochKeys.js'
export type { ResolvedEpochKeys } from './epochKeys.js'
export {
  createEdvDocCipher,
  ownerRecipient,
  UnknownEpochError,
  isEncryptedEnvelope
} from './docCipher.js'
export type { DocCipher } from './docCipher.js'
