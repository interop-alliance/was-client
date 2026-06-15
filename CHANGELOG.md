# @interop/was-client Changelog

## 0.7.0 - TBD

### Changed

- `BackendDescriptor` (re-exported from `@interop/storage-core@^0.2.0`) now
  carries an optional `features` capability array, surfaced unchanged through
  `collection.backend()` and `space.backends()`. `features` containing
  `'encrypted-documents'` is the signal a client gates client-side encryption on
  (the future EDV codec). No API change -- the field flows through the existing
  descriptor type; documented in the README and the method JSDoc.

## 0.6.0 - 2026-06-14

### Added

- `Resource.put()` now guesses a binary write's `Content-Type` from the resource
  id's file extension when none is supplied (and the data carries no `Blob.type`),
  for the common static-web types (`html`, `css`, `js`/`mjs`, `json`, `svg`,
  `png`, `jpg`/`jpeg`, `gif`, `webp`, `ico`, `woff2`, `txt`, `wasm`) -- so
  `collection.resource('index.html').put(bytes)` is sent as `text/html`. An
  explicit `contentType` (or a non-empty `Blob.type`) still wins, and an
  unrecognized/absent extension sends no header (the server then applies its own
  required-`Content-Type` rule). Implemented with a tiny inline table to avoid a
  `mime-db`-sized dependency. `Collection.add()` is unaffected (its id is
  server-generated, so there is no extension to read).
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
