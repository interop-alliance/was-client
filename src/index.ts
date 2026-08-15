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

export { parseSpaceTarget } from './internal/paths.js'
export type { ParsedSpacePath } from './internal/paths.js'
export { readEtag, writeHeaders } from './internal/conditional.js'
export type { WritePrecondition } from './internal/conditional.js'

export {
  WasError,
  NotFoundError,
  ValidationError,
  AuthRequiredError,
  NotImplementedError,
  NotSupportedError,
  ConflictError,
  PreconditionFailedError,
  LogNotConfirmedError,
  PayloadTooLargeError,
  QuotaExceededError,
  EncryptionError,
  EncryptOnlyCipherError,
  KeyUnwrapError,
  IntegrityError,
  WasSyncAuthError,
  WasSyncConflictError,
  WasSyncNotFoundError,
  WasServerError,
  mapError
} from './errors.js'

export type { FeatureProbe } from './internal/features.js'

export { isChunkedWrite } from './codec.js'
export type {
  ResourceCodec,
  EncryptionProvider,
  ChunkedWrite,
  CodecRequestContext,
  CodecWrite,
  EncodedWrite,
  ResponseLike,
  BlindedQuery,
  CodecIndexing,
  IndexDeclaration,
  IndexSchema
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
  CollectionWritableFields,
  CollectionEncryption,
  CollectionEncryptionEpoch,
  CollectionEncryptionRecipient,
  CollectionEncryptionHmac,
  EncryptionWithHmac,
  CollectionSummary,
  CollectionsList,
  SpaceSummary,
  SpaceListing,
  ResourceSummary,
  CollectionResourcesList,
  ResourceMetadata,
  ResourceMetadataCustom,
  ResourceMetadataCustomInput,
  CollectionMetadata,
  AddResult,
  FindPage,
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
