/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/was-client/edv/core` subpath entry:
 * `@interop/was-client/edv/cipher` plus the log-governed descriptor stores
 * (`logGovernedDescriptorStore`, `logGovernedCollectionDescriptorStore`, and
 * their read/state helpers), which read through a resource log verified by
 * `@interop/vh-resource-log`. Still transport-free -- no HTTP module and no
 * server in the graph -- but that verification does pull
 * `@interop/vh-resource-log` (and thereby `@interop/did-method-webvh`) in. A
 * consumer that wants neither the transport graph nor the resource-log graph,
 * such as `@interop/wallet-backup` opening an archive, imports `./edv/cipher`
 * instead.
 *
 * `@interop/was-client/edv` re-exports all of it and adds the online set on
 * top (`WasTransport`, `createEdvEncryption`, `wasTransportFactory`,
 * `collectionDescriptorStore`, descriptor acquisition and the refresh policy),
 * so an online consumer keeps importing that one entry and nothing moves.
 */
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
} from './cipher.js'
export type {
  CodecTransportFactory,
  EdvKeys,
  RecipientPublicKey,
  EncryptionDescriptorStore,
  ResolvedEpochKeys,
  BlindingKey,
  DocCipher,
  EdvDocCipher
} from './cipher.js'
export {
  EPOCH_CONFIGURATION_STATE_TYPE,
  logGovernedCollectionDescriptorStore,
  logGovernedDescriptorStore,
  readGovernedEpochConfiguration,
  toEpochConfigurationState
} from './logGovernedDescriptorStore.js'
export type { LogGovernedDescriptorStore } from './logGovernedDescriptorStore.js'
