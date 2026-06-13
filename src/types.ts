/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared type definitions for the WAS client: containment descriptions,
 * listing/result shapes, delegation options, and the manual-request input.
 * ZCap and signer types are re-used from `@interop/data-integrity-core` rather
 * than re-declared.
 */
import type { IZcap, IDelegatedZcap } from '@interop/data-integrity-core/zcap'
import type { ISigner } from '@interop/data-integrity-core'

export type { IZcap, IDelegatedZcap, ISigner }

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
 * A capability action -- an HTTP verb in its canonical uppercase form, as it
 * appears in the signed zcap. The WAS server matches actions case-sensitively.
 */
export type Action = 'GET' | 'PUT' | 'POST' | 'DELETE'

/**
 * The action input accepted by `grant()`: canonical uppercase or lowercase.
 * Lowercase is normalized to uppercase before the zcap is signed, so a grant of
 * `'get'` still validates on the server (which expects `'GET'`).
 */
export type ActionInput = Action | Lowercase<Action>

/**
 * A Space Description object, as returned by the server.
 */
export interface SpaceDescription {
  id: string
  type: string[]
  name?: string
  controller: string
  /** Absolute URL of the Space, if the server populates it. */
  url?: string
  /** URL of the Space's linkset (policy discovery), if the server advertises it. */
  linkset?: string
}

/**
 * A Collection Description object, as returned by the server.
 */
export interface CollectionDescription {
  id: string
  type: string[]
  name?: string
  /** Absolute URL of the Collection, if the server populates it. */
  url?: string
  /**
   * The backend the Collection is stored on. The spec default is
   * `{ id: 'default' }`; populated as the server lands the field.
   */
  backend?: BackendReference
  /** URL of the Collection's linkset (policy discovery), if advertised. */
  linkset?: string
}

/**
 * An access-control policy document attached to a Space, Collection, or
 * Resource. A `type`-discriminated, open/extensible shape: the reference server
 * recognizes `{ "type": "PublicCanRead" }` for world-readable access (see
 * `setPublic()`); other types are server-defined.
 */
export interface PolicyDocument {
  type: string
  [key: string]: unknown
}

/**
 * One member of a {@link LinkSet} (RFC9264): an `anchor` plus relation keys
 * (e.g. `https://wallet.storage/spec#policy`) mapping to arrays of link targets.
 */
export interface LinkSetEntry {
  anchor?: string
  [relation: string]: unknown
}

/**
 * Return shape of `space.linkset()` / `collection.linkset()`: an RFC9264
 * `application/linkset+json` document.
 */
export interface LinkSet {
  linkset: LinkSetEntry[]
}

/**
 * One entry in a `CollectionListing` (a collection within a space).
 */
export interface CollectionSummary {
  id: string
  name: string
  url: string
}

/**
 * Return shape of `space.collections()`.
 */
export interface CollectionListing {
  url: string
  totalItems: number
  items: CollectionSummary[]
}

/**
 * One entry in a `SpaceListing` (a space within the repository).
 */
export interface SpaceSummary {
  id: string
  name?: string
  url: string
}

/**
 * Return shape of `was.listSpaces()` (not yet implemented by the reference
 * server, which answers 501).
 */
export interface SpaceListing {
  url: string
  totalItems: number
  items: SpaceSummary[]
}

/**
 * One entry in a `ResourceListing` (a resource within a collection).
 */
export interface ResourceSummary {
  id: string
  url: string
  contentType: string
}

/**
 * Return shape of `collection.list()`.
 */
export interface ResourceListing {
  id: string
  url: string
  /**
   * The listing-level name. Once resource metadata writes exist, a resource's
   * entry `name` is fed by its metadata `custom.name` (see
   * {@link ResourceMetadataCustom}); updating one updates the other.
   */
  name?: string
  type: string[]
  totalItems: number
  items: ResourceSummary[]
}

/**
 * The user-writable properties of a resource's metadata object, nested under
 * `custom`. `name` is the same value surfaced as the listing `name` in
 * {@link ResourceListing}; `tags` are application-defined string annotations.
 */
export interface ResourceMetadataCustom {
  name?: string
  tags?: Record<string, string>
}

/**
 * Return shape of `resource.meta()`: a resource's metadata object. The
 * server-managed properties (`contentType`, `size`, and the optional
 * timestamps) sit at the top level; the user-writable properties live under
 * `custom`.
 */
export interface ResourceMetadata {
  contentType: string
  size: number
  createdAt?: string
  updatedAt?: string
  custom?: ResourceMetadataCustom
}

/**
 * Return shape of `collection.add()` (server-generated resource id + location).
 */
export interface AddResult {
  id: string
  url: string
  contentType?: string
}

/**
 * Return shape of `space.import()`.
 */
export interface ImportStats {
  collectionsCreated: number
  collectionsSkipped: number
  resourcesCreated: number
  resourcesSkipped: number
  policiesCreated: number
  policiesSkipped: number
}

/**
 * Options accepted by every handle factory (`space()`, `collection()`,
 * `resource()`). A bound `capability` is attached to every request the handle
 * makes.
 */
export interface HandleOptions {
  capability?: IZcap
}

/**
 * A reference to a storage backend, used when creating or configuring a
 * Collection.
 */
export interface BackendReference {
  id: string
}

/**
 * A Backend description object (return shape of `space.backends()` entries):
 * advertises a backend's identity and capabilities so clients can pick a
 * suitable backend for each Collection.
 */
export interface BackendDescriptor {
  id: string
  name?: string
  managedBy?: 'server' | 'external'
  storageMode?: ('document' | 'blob')[]
  persistence?: 'durable' | 'volatile'
}

/**
 * The storage limit reported for a backend in a quota report. When
 * `isUnlimited` is `true`, `capacityBytes` may be omitted.
 */
export interface StorageLimit {
  capacityBytes?: number
  isUnlimited: boolean
}

/**
 * One Collection's contribution to a backend's usage, in the optional
 * `usageByCollection` breakdown of a {@link BackendUsage} entry.
 */
export interface CollectionUsage {
  id: string
  usageBytes: number
}

/**
 * Per-backend usage entry in a {@link SpaceQuotaReport}.
 */
export interface BackendUsage {
  id: string
  name?: string
  managedBy?: 'server' | 'external'
  state: 'ok' | 'near-limit' | 'over-quota' | 'unreachable'
  usageBytes: number
  limit: StorageLimit
  /** Operational constraints such as `maxUploadBytes`. */
  constraints?: { maxUploadBytes?: number; [key: string]: unknown }
  /** Actions (uppercase HTTP verbs) currently unavailable on this backend. */
  restrictedActions: Action[]
  measuredAt: string
  /** Per-collection breakdown; present when the server includes it. */
  usageByCollection?: CollectionUsage[]
}

/**
 * Return shape of `space.quotas()`: a Space's storage report, grouped by
 * backend.
 */
export interface SpaceQuotaReport {
  respondedAt: string
  backends: BackendUsage[]
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
