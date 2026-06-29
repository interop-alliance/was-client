/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Public entry point for `@interop/was-client`: the `WasClient` and its
 * navigational handles, the typed error hierarchy, and the shared types.
 */
export { WasClient } from './WasClient.js'
export { Space } from './Space.js'
export { Collection } from './Collection.js'
export { Resource } from './Resource.js'

export {
  WasError,
  NotFoundError,
  ValidationError,
  AuthRequiredError,
  NotImplementedError,
  ConflictError,
  PreconditionFailedError,
  PayloadTooLargeError,
  QuotaExceededError,
  EncryptionError,
  WasServerError,
  mapError
} from './errors.js'

export type {
  ResourceCodec,
  EncryptionProvider,
  EncodedWrite
} from './codec.js'

export type {
  Json,
  JsonPrimitive,
  JsonObject,
  JsonArray,
  ResourceData,
  Action,
  ActionInput,
  SpaceDescription,
  CollectionDescription,
  CollectionEncryption,
  CollectionSummary,
  CollectionsList,
  SpaceSummary,
  SpaceListing,
  ResourceSummary,
  CollectionResourcesList,
  ResourceMetadata,
  ResourceMetadataCustom,
  AddResult,
  ImportStats,
  PolicyDocument,
  LinkSet,
  LinkSetEntry,
  HandleOptions,
  EncryptionOverride,
  BackendReference,
  BackendDescriptor,
  BackendRegistration,
  BackendConnectionInput,
  BackendConnectionPublic,
  StorageLimit,
  CollectionUsage,
  BackendUsage,
  SpaceQuotaReport,
  GrantOptions,
  RequestInput,
  IZcap,
  IDelegatedZcap,
  ISigner
} from './types.js'
