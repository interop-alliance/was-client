/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/was-client/edv` subpath entry: encrypted (EDV-over-WAS) storage
 * support. Kept off the core `@interop/was-client` entry so plaintext consumers
 * do not pull the `@interop/edv-client` / `@interop/minimal-cipher` crypto graph
 * unless they opt in by importing this subpath.
 *
 * This is the full encrypted surface, online and offline. It re-exports
 * `@interop/was-client/edv/core` -- the codec, the doc ciphers, the key
 * epochs, the recipient operations, `resourceDescriptorStore`, the log-governed
 * descriptor stores and the blinding keys, none of which need a server -- and
 * adds the modules that do talk to one, `collectionDescriptorStore` among
 * them. A consumer working offline imports `./edv/core` instead and keeps every
 * transport module out of its graph; everything this entry exported before
 * that entry existed still resolves from here.
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
 * `collectionDescriptorStore` is the `EncryptionDescriptorStore` over a live
 * `Collection` handle's Collection Description, the default the recipient
 * operations use when a caller names a collection rather than a store.
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
// The offline half, named one export at a time rather than with `export *`.
// This entry is the one every online consumer imports, so its surface is
// stated here: an export added to `core.ts` widens `./edv/core` only, and
// widening `./edv` takes an edit to this list.
export {
  EdvCodec,
  EDV_SCHEME_VERSION,
  JOSE_CONTENT_TYPE,
  ensureFirstEpoch,
  initRecipients,
  addRecipient,
  removeRecipient,
  replaceRecipient,
  isEd25519DidKey,
  x25519RecipientFromDidKey,
  resourceDescriptorStore,
  EPOCH_CONFIGURATION_STATE_TYPE,
  logGovernedCollectionDescriptorStore,
  logGovernedDescriptorStore,
  readGovernedEpochConfiguration,
  toEpochConfigurationState,
  didKeyResolver,
  mintEpoch,
  epochKeyIdFor,
  unwrapEpochSecret,
  wrapEpochSecret,
  hasKeyEpochs,
  epochRostersEqual,
  resolveEpochKeys,
  HMAC_KEY_TYPE,
  mintHmacKey,
  hmacKeyFromSecret,
  resolveHmacKey,
  createEdvDocCipher,
  createEdvEncryptOnlyDocCipher,
  ownerRecipient,
  EncryptOnlyCipherError,
  KeyUnwrapError,
  UnknownEpochError,
  isEncryptedEnvelope,
  isKeyUnwrapError
} from './core.js'
export type {
  CodecTransportFactory,
  EdvKeys,
  RecipientPublicKey,
  EncryptionDescriptorStore,
  LogGovernedDescriptorStore,
  ResolvedEpochKeys,
  BlindingKey,
  DocCipher,
  EdvDocCipher
} from './core.js'
export { createEdvEncryption } from './encryption.js'
export { wasTransportFactory } from './transportFactory.js'
export { WasTransport } from './WasTransport.js'
export { collectionDescriptorStore } from './descriptorStore.js'
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
