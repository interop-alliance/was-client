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
  PayloadTooLargeError,
  QuotaExceededError,
  WasServerError,
  mapError
} from './errors.js'

export type {
  Json,
  JsonPrimitive,
  JsonObject,
  JsonArray,
  Action,
  ActionInput,
  SpaceDescription,
  CollectionDescription,
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
  BackendReference,
  BackendDescriptor,
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
