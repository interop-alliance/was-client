# @interop/was-client Changelog

## Unreleased - TBD

### Changed

- **The preferred EDV envelope content type is now `application/jose+json`** (the
  JWE JSON Serialization media type, RFC 7516), replacing the previous
  `application/edv+json`. This aligns with the WAS spec's Encryption Scheme
  Registry, which maps the `edv` scheme to `application/jose+json`. The exported
  constant is renamed `EDV_CONTENT_TYPE` to `JOSE_CONTENT_TYPE` (breaking) and
  now holds the new value; the zero-server-change `application/json` default is
  unchanged.

### Fixed

- **Fail-closed encryption: an unreadable collection marker no longer downgrades
  to plaintext.** When an encryption-capable client held a resource-scoped
  capability, the marker-discovery GET on the collection description was
  unauthorized; WAS masks that as a 404, which `resolveCodec` conflated with "no
  marker" and handed back the identity codec -- writing the caller's secret as
  server-visible plaintext into an encrypted collection. An unreadable
  description is now treated as ambiguous and fails closed (throws
  `EncryptionError`); pass an explicit per-handle `encryption` override
  (`'plaintext'`, or a scheme/keys override) to proceed deliberately.
- **Reserved resource ids are rejected on every operation, not just `put`.**
  `resourcePath(s, c, 'policy')` is byte-identical to the collection policy path,
  so `collection.resource('policy').delete()` silently wiped the collection's
  access-control policy (same collision for `backend` / `quota` / `linkset` /
  `meta`). The reserved-id guard now runs at `Resource` construction, covering
  read / delete / meta / policy / put uniformly.
- **`configure()` now invalidates the memoized codec when it enables
  encryption.** A read caches the identity (plaintext) codec while a collection
  is still plaintext; `configure({ encryption: { scheme: 'edv' } })` flipped the
  collection encrypted server-side but left the cached codec in place, so a
  subsequent `put` wrote server-visible plaintext into the now-encrypted
  collection. `configure()` now drops the cached codec whenever it sets the
  `encryption` marker, and child resource handles obtained via
  `collection.resource(id)` delegate to the parent's codec on every call so the
  invalidation propagates to them too.

## 0.9.2 - 2026-06-28

### Fixed

- Update to `@interop/http-client@1.0.4`, fixes `json` content-type parsing.

## 0.9.1 - 2026-06-27

### Fixed

- **`application/jsonl` (and other `json`-substring content-types) are no longer
  JSON-parsed on read.** `parseResource` decided a response was JSON by testing
  whether its content-type _contained_ the substring `json`, so a JSON-Lines /
  NDJSON / JSON-seq resource was run through `JSON.parse` (which throws on a
  multi-line body) instead of being returned as a `Blob`. The check now anchors
  the `json` token to the end of the media type, matching only
  `application/json` and `application/<prefix>+json` (e.g.
  `application/ld+json`, `application/edv+json`); everything else reads back as
  binary.

## 0.9.0 - 2026-06-27

### Changed

- **Encrypted collections are now marker-driven, not keys-driven**. Whether a
  collection is encrypted is decided by its declared `encryption` marker (or a
  per-handle override), letting a delegated consumer **discover** an encrypted
  collection from its Description.
  - `createCollection({ encryption: { scheme: 'edv' } })` declares the marker;
    the returned handle is pre-seeded so the first write needs no extra
    round-trip. `collection.configure({ encryption })` declares it on an
    existing collection (set-once on the server).
  - A handle with no override reads the Collection Description once (cached) to
    discover the marker; plaintext-only clients and overrides skip that read.
  - **Fail-closed:** a collection declared encrypted for which the client holds
    no keys now throws the new `EncryptionError` instead of silently reading or
    writing plaintext.
  - `HandleOptions.encryption` (new `EncryptionOverride` type) forces the
    decision per handle: `{ scheme }`, `{ scheme, keys }`, or `'plaintext'`.

### BREAKING

- `EncryptionProvider` now exposes
  `codecFor({ spaceId, collectionId, scheme, keys? })` instead of
  `resolveCodec({ spaceId, collectionId })`; core calls it only after policy has
  decided a collection is encrypted. `createEdvEncryption`'s `resolveKeys` is
  now a pure keystore: returning `null` means "no keys for this collection"
  (which now fails closed), no longer "use plaintext" -- declare plaintext by
  simply omitting the marker/override. An existing encrypted collection created
  keys-only (no marker) must be re-declared once with
  `configure({ encryption: { scheme: 'edv' } })`, or read with a per-handle
  override.

### Added

- `EncryptionError`, `EncryptionOverride`, and the `CollectionEncryption` marker
  type to the public surface; `EdvKeys` from the `@interop/was-client/edv`
  subpath.

## 0.8.0 - 2026-06-26

### Added

- **Bring-Your-Own-Storage backend registration.** The Space controller can now
  register, re-consent, and deregister an `external` storage backend (e.g. a
  wallet connecting a user's Google Drive), the write side of the spec's
  "Backends" section:
  - `space.registerBackend(registration)` -- `POST /space/:id/backends`. The
    body carries the secret-bearing `connection` (an OAuth authorization code or
    refresh token); the server returns the **sanitized** `BackendDescriptor`
    (never the secrets). Throws `ConflictError` if the `id` already exists or
    the provider is not permitted.
  - `space.updateBackend(registration)` -- `PUT /space/:id/backends/:id`, the
    re-consent / create-or-replace path. Returns the descriptor on create (201)
    or `null` on an in-place replace (204, no body).
  - `space.deregisterBackend(backendId)` -- `DELETE /space/:id/backends/:id`,
    idempotent.
  - New `registeredBackend` path builder; re-exports the registration types
    `BackendRegistration`, `BackendConnectionInput`, and
    `BackendConnectionPublic`.

### Changed

- `BackendDescriptor` (from `@interop/storage-core@^0.2.5`) now carries the
  optional `provider` and sanitized `connection` fields a registered `external`
  backend exposes (`connection.status` is `registered` | `connected` | `expired`
  | `revoked` | `unreachable`), surfaced unchanged through `space.backends()` /
  `collection.backend()` for re-consent UI.
- Bumped `@interop/storage-core` from `^0.2.2` to `^0.2.5`.

## 0.7.1 - 2026-06-15

### Added

- `space.quotas({ includeCollections: true })` requests the per-Collection
  `usageByCollection` breakdown on each backend entry, via the spec's
  `?include=collections` opt-in. Called with no argument (or
  `includeCollections: false`), `quotas()` returns the lean report without the
  breakdown, as before.

## 0.7.0 - 2026-06-14

### Added

- **Conditional writes (optimistic concurrency).** Against a backend that
  advertises the `conditional-writes` feature, a Resource carries a strong
  `ETag` validator. `resource.put(data, { ifMatch })` /
  `collection.put(id, data, { ifMatch })` perform an update-if-unchanged and
  `{ ifNoneMatch: true }` a create-if-absent; `resource.delete({ ifMatch })`
  deletes only if unchanged. A failed precondition throws the new typed
  `PreconditionFailedError` (HTTP 412, mapped from the `precondition-failed`
  problem type). Reads surface the validator: `resource.meta()` returns an
  `etag`, and `put` / `add` return the new `etag`. Recover from a 412 by
  re-reading the current `etag`, re-applying the change, and retrying.
- **The EDV `sequence` is now enforced (lost-update-safe).** On an encrypted
  collection the EDV codec drives conditional writes automatically: each
  `put`/`add` pre-reads the current envelope, advances its `sequence`
  (previous + 1), and pins the write to the server's current `ETag` via
  `If-Match` (a fresh insert is guarded by `If-None-Match: *`). A stale write
  surfaces as a `PreconditionFailedError` rather than the old advisory
  last-writer-wins. Against a backend without `conditional-writes` (no ETag) it
  degrades to advisory. The codec seam gains an optional
  `ResourceCodec.conditionalWrites` flag and `EncodedWrite.ifMatch` /
  `ifNoneMatch`. Uses the `precondition-failed` type from
  `@interop/storage-core@^0.2.2`.

- Encrypted collections (EDV-over-WAS), Increment 2: a pluggable **resource
  codec** seam folds client-side encryption into the ordinary
  `Collection`/`Resource` handles. Construct a `WasClient` with an `encryption`
  provider and `collection.add()` / `put()` / `get()` transparently encrypt and
  decrypt on any collection the client holds keys for. The encrypting codec
  (`createEdvEncryption`) is on the opt-in `@interop/was-client/edv` subpath so
  plaintext consumers keep the crypto graph out of core. Core exports the seam
  types (`ResourceCodec`, `EncryptionProvider`, `EncodedWrite`); the default is
  an identity codec, so plaintext behavior is unchanged.

  The switch is **keys**: a handle encrypts a collection exactly when the
  `encryption` provider's `resolveKeys` returns keys for it -- a per-collection
  client concern, not a backend feature, so it needs no backend round-trip.
  Encrypted collections are a stricter, documents-only contract: `add()` mints
  an EDV id and `put()` rejects human-readable ids; `setName`/`setTags` are
  forbidden (server-visible plaintext); small binaries are stored as a single
  JWE and larger ones rejected; `getText`/`getBytes` are raw (do not decrypt).

### Changed

- `BackendDescriptor` (re-exported from `@interop/storage-core@^0.2.0`) now
  carries an optional `features` capability array, surfaced unchanged through
  `collection.backend()` and `space.backends()`. `features` advertises optional
  server affordances (e.g. `conditional-writes`). No API change -- the field
  flows through the existing descriptor type; documented in the README and the
  method JSDoc.

## 0.6.0 - 2026-06-14

### Added

- `Resource.put()` now guesses a binary write's `Content-Type` from the resource
  id's file extension when none is supplied (and the data carries no
  `Blob.type`), for the common static-web types (`html`, `css`, `js`/`mjs`,
  `json`, `svg`, `png`, `jpg`/`jpeg`, `gif`, `webp`, `ico`, `woff2`, `txt`,
  `wasm`) -- so `collection.resource('index.html').put(bytes)` is sent as
  `text/html`. An explicit `contentType` (or a non-empty `Blob.type`) still
  wins, and an unrecognized/absent extension sends no header (the server then
  applies its own required-`Content-Type` rule). Implemented with a tiny inline
  table to avoid a `mime-db`-sized dependency. `Collection.add()` is unaffected
  (its id is server-generated, so there is no extension to read).
- Encrypted collections (EDV-over-WAS), Increment 1, on the opt-in
  `@interop/was-client/edv` subpath. `WasTransport` is an `@interop/edv-client`
  `Transport` that maps EDV document operations onto ordinary WAS resource CRUD,
  so client-side end-to-end encryption works against any WAS server with no
  server changes (the server stores opaque JWE envelopes; keys stay
  client-side). Documents-only scope (`insert` / `update` / `get`); blinded
  query, index updates, and chunked streams require server-side EDV affordances
  and are not yet supported. Also exports `EDV_CONTENT_TYPE`.
- A live-server integration test tier (`test/integration/`, run with
  `pnpm test:integration` against a `TEST_SERVER_URL`), with an EDV-over-WAS
  encrypt/write/read/decrypt round-trip. Skips when `TEST_SERVER_URL` is unset.

## 0.5.0 - 2026-06-13

### Added

- `collection.backend()` reads the storage backend a collection is stored on
  ("Collection Backend Selected", `GET /space/{id}/{cid}/backend`); returns a
  `BackendDescriptor`.
- `collection.quota()` reads the collection's storage usage report, scoped to
  its backend (spec "Quotas", `GET /space/{id}/{cid}/quota`); returns a
  `BackendUsage`.

### Changed

- `was.listSpaces()` is now functional against the reference server (which
  implements `GET /spaces/`). It returns a `{ url, totalItems, items }` listing
  of the spaces visible to the wrapped signer (per-controller visibility; an
  unauthorized caller gets an empty list rather than an error). No API change --
  the method shape was already in place.

## 0.4.0 - 2026-06-13

### Added

- `space.backends()` reads the storage backends available within a space
  (`GET /space/{id}/backends`); new `BackendDescriptor` type.
- `space.quotas()` reads the space's per-backend storage usage report
  (`GET /space/{id}/quotas`); new `SpaceQuotaReport` / `BackendUsage` /
  `StorageLimit` / `CollectionUsage` types.
- `resource.meta()` reads a resource's metadata object
  (`GET .../{resource_id}/meta`); `resource.setMeta({ custom })` replaces the
  user-writable `custom` object (`PUT .../meta`), with `resource.setName()` /
  `resource.setTags()` read-modify-write convenience wrappers. New
  `ResourceMetadata` / `ResourceMetadataCustom` types.
- New error subclasses `ConflictError` (409 `id-conflict` / `reserved-id` /
  `unsupported-backend`), `PayloadTooLargeError` (413 `payload-too-large`), and
  `QuotaExceededError` (507 `quota-exceeded`).
- Unauthenticated public-read methods `was.publicRead({ resourceUrl })` and
  `was.publicListCollection({ collectionUrl })` for consuming `PublicCanRead`
  links with no authorization (an unsigned plain `fetch`). Both go through a new
  low-level `unsignedRequest()` helper.
- Path builders `spaceBackends` / `spaceQuotas` / `resourceMeta`.

### Changed

- Adopt `@interop/storage-core` for the shared WAS wire model and error
  vocabulary. `src/types.ts` now re-exports the data-model shapes
  (`SpaceDescription`, `CollectionDescription`, `BackendDescriptor`,
  `ResourceMetadata`, the quota shapes, etc.) and the `Action` / `ActionInput`
  vocabulary from core, keeping only the client-local shapes (`Json*`,
  `AddResult`, `HandleOptions`, `GrantOptions`, `RequestInput`); the package's
  public type surface is unchanged except for two renames below. `mapError()`'s
  problem-kind dispatch is now keyed off core's `ProblemTypes` registry rather
  than hardcoded `type`-fragment strings.
- **Rename:** the collections-in-a-space listing (`space.collections()`) is now
  `CollectionsList` (was `CollectionListing`), and the resources-in-a-collection
  listing (`collection.list()`) is now `CollectionResourcesList` (was
  `ResourceListing`). This removes a name collision with the server's use of
  `CollectionListing`.
- `SpaceDescription.controller` is now typed `IDID` (a `did:${string}` branded
  string) rather than a bare `string`, matching the server's wire type.
- `mapError()` now dispatches on the `application/problem+json` `type` URI (the
  spec's Error Type Registry) when present, falling back to the HTTP status.
  `WasError` carries the raw problem-kind `type` URI as a new field. This lets,
  for example, a 507 `quota-exceeded` map to `QuotaExceededError` rather than
  the `WasServerError` 5xx catch-all.
- `Collection.configure()` now applies the reserved-path-segment guard, so a
  handle built directly on a reserved id (e.g. `space.collection('export')`)
  rejects with a `ValidationError` instead of PUTting.
- `SpaceDescription` and `CollectionDescription` gain an optional `url`
  property; `CollectionDescription` also gains an optional `backend` property.
  These populate as the reference server lands the spec's server-managed fields.

### Fixed

- `createSpace()` JSDoc no longer claims the server requires `name` (it is
  optional in both the spec and the reference server).

## 0.3.0 - 2026-06-09

### Added

- `isPublic()`, a read-only convenience that returns `true` when the Space,
  Collection, or Resource has a `{ type: 'PublicCanRead' }` policy -- that is,
  when it has been made public via `setPublic()` (or an equivalent `setPolicy()`
  call). It's meant to drive data-browser style UI, to show a "This
  space(/collection/resource) has been shared publicly" type of icon.

## 0.2.0 - 2026-06-06

### Added

- Access-control policy methods on the `Space`, `Collection`, and `Resource`
  handles: `getPolicy()`, `setPolicy(policy)`, `clearPolicy()`, and the
  `setPublic()` convenience (sugar for `setPolicy({ type: 'PublicCanRead' })`)
  for the "share via public link" case. `setPolicy()` is the generic,
  forward-compatible primitive; `setPublic()` is sugar over it.
- `space.linkset()` / `collection.linkset()` read the RFC9264 linkset (policy
  discovery); `SpaceDescription` / `CollectionDescription` gain an optional
  `linkset` property.
- New exported types `PolicyDocument`, `LinkSet`, `LinkSetEntry`; path builders
  `spacePolicy` / `collectionPolicy` / `resourcePolicy` and `spaceLinkset` /
  `collectionLinkset`.

### Changed

- `ImportStats` gains `policiesCreated` / `policiesSkipped` (policies now
  round-trip through space export/import on the reference server).

## 0.1.0-0.1.1 - 2026-06-06

### Added

- Initial implementation of the Wallet Attached Storage client.
- `WasClient` wrapping an `@interop/ezcap` `ZcapClient`, with `fromSigner()`
  convenience constructor.
- Lazy navigational handles: `Space`, `Collection`, `Resource`, with
  self-lifecycle (`describe`/`configure`/`delete`) and contained-item verbs
  (`add`/`get`/`put`/`list`).
- First-class JSON and binary resources (auto content-type detection on write;
  auto-parse plus `getText()`/`getBytes()` on read).
- Delegation: the general `was.grant()` primitive, `space`/`collection` grant
  sugar, `fromCapability()`, and capability-bound handles.
- `space.export()` / `space.import()`.
- Typed error hierarchy (`WasError` base plus `NotFoundError`,
  `ValidationError`, `AuthRequiredError`, `NotImplementedError`,
  `WasServerError`) with null-on-404 read semantics and idempotent `delete()`.
- Reserved path-segment id guard on `createCollection`/`put`.
- The `was.request()` signed escape hatch.
