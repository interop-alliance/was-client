/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared type definitions for the WAS client.
 *
 * The WAS wire model (containment descriptions, listing/result shapes, backend
 * and quota shapes, the policy document, and the action vocabulary) now lives
 * in `@interop/storage-core`; this module re-exports it so the client's public
 * surface is unchanged for downstream consumers. It still declares the
 * client-local shapes: the JSON helpers, the `AddResult` of `collection.add()`,
 * the handle/delegation options, and the low-level `request()` input. ZCap and
 * signer types are re-used from `@interop/data-integrity-core`.
 */
import type { IZcap, IDelegatedZcap } from '@interop/data-integrity-core/zcap'
import type { ISigner } from '@interop/data-integrity-core'

import type { ActionInput } from '@interop/storage-core'

export type { IZcap, IDelegatedZcap, ISigner }

/**
 * Re-export the shared WAS wire model from `@interop/storage-core`. The
 * resources-in-a-collection listing is `CollectionResourcesList` (formerly
 * `ResourceListing`) and the collections-in-a-space listing is `CollectionsList`
 * (formerly `CollectionListing`).
 */
export type {
  Action,
  ActionInput,
  SpaceDescription,
  CollectionDescription,
  CollectionEncryption,
  PolicyDocument,
  LinkSet,
  LinkSetEntry,
  CollectionSummary,
  CollectionsList,
  SpaceSummary,
  SpaceListing,
  ResourceSummary,
  CollectionResourcesList,
  ResourceMetadata,
  ResourceMetadataCustom,
  ImportStats,
  BackendReference,
  BackendDescriptor,
  BackendRegistration,
  BackendConnectionInput,
  BackendConnectionPublic,
  StorageLimit,
  CollectionUsage,
  BackendUsage,
  SpaceQuotaReport
} from '@interop/storage-core'

/**
 * A JSON-serializable value, the shape stored for JSON resources and
 * descriptions.
 */
export type JsonPrimitive = string | number | boolean | null
export interface JsonObject {
  [key: string]: Json
}
export type JsonArray = Json[]
export type Json = JsonPrimitive | JsonObject | JsonArray

/**
 * The value accepted by a resource write (`put`/`add`): a JSON object or array,
 * or binary as a `Blob`/`Uint8Array`. A top-level JSON primitive
 * (`string`/`number`/`boolean`/`null`) is intentionally excluded -- the wire and
 * EDV paths only carry container JSON, so wrap a bare primitive in an object or
 * array before storing it.
 */
export type ResourceData = JsonObject | JsonArray | Blob | Uint8Array

/**
 * Return shape of `collection.add()` (server-generated resource id + location).
 */
export interface AddResult {
  id: string
  url: string
  contentType?: string
  /**
   * The created resource's strong `ETag` validator, when the backend advertises
   * the `conditional-writes` feature (absent otherwise). Pass it to a later
   * `put(id, data, { ifMatch })` for a lost-update-safe update.
   */
  etag?: string
}

/**
 * A per-handle client-side encryption override -- the escape hatch / bootstrap
 * path that takes precedence over the Collection's declared `encryption` marker
 * AND skips the marker-discovery round-trip:
 *
 * - `{ scheme }` -- treat the collection as encrypted under `scheme`, pulling
 *   keys from the client's keystore. Use right after `createCollection` (before
 *   the marker is readable), or to avoid the `describe()` round-trip.
 * - `{ scheme, keys }` -- additionally supply the key material inline (opaque to
 *   core; the encryption provider interprets it per `scheme`) instead of the
 *   keystore.
 * - `'plaintext'` -- force plaintext even if a marker / keystore would encrypt.
 *
 * The non-`'plaintext'` forms require the `WasClient` to be constructed with an
 * `encryption` provider (which turns a scheme + keys into a codec).
 */
export type EncryptionOverride =
  { scheme: string; keys?: unknown } | 'plaintext'

/**
 * Options accepted by every handle factory (`space()`, `collection()`,
 * `resource()`). A bound `capability` is attached to every request the handle
 * makes.
 */
export interface HandleOptions {
  capability?: IZcap
  /**
   * Per-handle client-side encryption override (see {@link EncryptionOverride}).
   * Omit to let the Collection's declared `encryption` marker decide.
   */
  encryption?: EncryptionOverride
}

/**
 * Options for the general delegation primitive (`was.grant()`) and the
 * `space`/`collection` sugar.
 *
 * @property to              the delegate's controller DID
 * @property actions         allowed actions (aliases or raw HTTP verbs)
 * @property [expires]       expiration; defaults to ezcap's 5-minute default
 * @property [target]        invocationTarget URL; filled by scoped grants
 * @property [capability]    parent capability to attenuate / re-delegate
 */
export interface GrantOptions {
  to: string
  actions: ActionInput[]
  expires?: string | Date
  target?: string
  capability?: IZcap
}

/**
 * Input for the low-level `was.request()` escape hatch.
 */
export interface RequestInput {
  path?: string
  url?: string
  method?: string
  action?: string
  headers?: Record<string, string>
  json?: object
  body?: Blob | Uint8Array
  capability?: IZcap
}
