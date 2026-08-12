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
import type {
  IZcap,
  IDelegatedZcap,
  IRootZcap
} from '@interop/data-integrity-core/zcap'
import type { IDID, ISigner } from '@interop/data-integrity-core'

import type { ActionInput } from '@interop/storage-core'

export type { IZcap, IDelegatedZcap, IRootZcap, IDID, ISigner }

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
  CollectionEncryptionEpoch,
  CollectionEncryptionRecipient,
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
  CollectionMetadata,
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

import type {
  BackendReference,
  CollectionEncryption
} from '@interop/storage-core'

/**
 * The Collection's blinded-index HMAC key, as it appears on the `encryption`
 * descriptor: the key `id` (the value an envelope's `indexed[].hmac.id` and a
 * blinded query's `index` name), its `type` (`'Sha256HmacKey2019'`), and the
 * 32-byte HMAC secret wrapped once per recipient -- the same JWE `recipients`
 * entry shape and `ECDH-ES+A256KW` wrap the epoch secrets use, so a recipient
 * receives the blinding key exactly the way it receives epoch keys.
 *
 * The key is installed at Collection provisioning or never, and never rotates:
 * blinded tokens must compare across the Collection's whole history. Removing a
 * recipient drops its wrap entry as housekeeping only -- the key is unchanged,
 * so a removed recipient keeps it (a documented revocation asymmetry).
 *
 * A named alias for the descriptor's own `hmac` member, so the blinding-key
 * code can refer to the shape by name.
 */
export type CollectionEncryptionHmac = NonNullable<CollectionEncryption['hmac']>

/**
 * A `CollectionEncryption` descriptor known to carry the blinded-index `hmac`
 * member. `CollectionEncryption` declares `hmac` natively, so this is now an
 * alias; the name is kept because the blinding-key code reads better naming the
 * member it works with.
 */
export type EncryptionWithHmac = CollectionEncryption

/**
 * The client-writable fields of a Collection Description -- the shape shared
 * by `Collection.configure` and `Collection.replaceDescription` and the single
 * place a new writable field is declared (the body/echo inclusion rule lives
 * in `Collection.#writableFields`).
 */
export interface CollectionWritableFields {
  name?: string
  backend?: BackendReference
  encryption?: CollectionEncryption
  /**
   * DID of the application the Collection was provisioned for, and the Web
   * origin that DID was bound to at provisioning time. Both are
   * controller-asserted attribution (the server persists them but does not
   * verify them) and both are writable at create AND update, so a wallet can
   * backfill an existing Collection on reconnect.
   */
  generator?: IDID
  generatorOrigin?: string
}

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
 * path that takes precedence over the Collection's declared `encryption`
 * descriptor AND skips the descriptor-discovery round-trip:
 *
 * - `{ scheme }` -- treat the collection as encrypted under `scheme`, pulling
 *   keys from the client's keystore. For the `edv` scheme, pass a full
 *   epoch-bearing `CollectionEncryption` descriptor as the override (a bare
 *   `{ scheme: 'edv' }` is refused fail-closed: routing needs the key-epoch
 *   roster).
 * - `{ scheme, keys }` -- additionally supply the key material inline (opaque to
 *   core; the encryption provider interprets it per `scheme`) instead of the
 *   keystore.
 * - `'plaintext'` -- force plaintext even if a descriptor / keystore would encrypt.
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
   * Omit to let the Collection's declared `encryption` descriptor decide.
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
