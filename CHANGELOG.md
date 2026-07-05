# @interop/was-client Changelog

## 0.13.1 - 2026-07-04

### Changed

- Update to latest `edv-client` and `minimal-cipher` (with AES-KW pure JS
  fallback).

## 0.13.0 - 2026-07-04

### Added

- **`space.exportStream()` and `space.exportBlob()`.** Two additive companions
  to `export()` for large-space and container use cases:
  - `exportStream()` returns the export response's `ReadableStream<Uint8Array>`
    -- the constant-memory path, for piping the tar archive to a file, a
    `CompressionStream`, or another request without buffering the whole space
    into RAM. The stream must be consumed or cancelled.
  - `exportBlob()` returns a `Blob` typed `application/x-tar` (normalizing the
    type when the server omits or mislabels it), pairing directly with
    `import(tar)` so a space copy is `spaceB.import(await spaceA.exportBlob())`.
    Note: in Node a Blob is memory-backed, so it does not lower peak memory
    versus `export()`; it is a typed-container convenience.

  All three variants share one request helper that fails with a typed
  `WasServerError` -- rather than a raw "body stream already read" `TypeError`
  -- if a non-conformant server mislabels the archive as JSON (which makes the
  transport pre-consume the body).

### Fixed

- **Wrong-target request safety.** Id validation now lives at the layer that
  owns the path grammar, closing several silent path-collision holes:
  - The `Collection` constructor rejects reserved ids (mirroring `Resource`), so
    `space.collection('policy').delete()` can no longer silently DELETE the
    space's access-control policy (same for `backends` / `quotas` / `linkset` /
    `export` / `import` / `query`). The redundant guard inside `configure()` was
    removed; `createCollection()` keeps its pre-flight guard.
  - `collection.get(id)` delegates to the resource handle, so the reserved-id
    guard applies to reads, not just writes.
  - The path builders reject empty and dot-segment ids (`''` / `.` / `..`),
    which WHATWG URL resolution would collapse into a different endpoint
    (`resource('.').delete()` used to target the collection listing).
  - `fromCapability()` classifies the invocation target with a real path parser
    (`parseSpacePath`) instead of destructuring the first three segments: a
    sub-resource target (`/space/s/policy`, `/space/s/c/r/meta`, ...) now throws
    a clear `ValidationError` instead of silently returning a handle whose
    derived URLs mismatch the capability.
- **`getText()` / `getBytes()` no longer throw on JSON-typed resources.** The
  request layer pre-consumes JSON bodies, so the raw escape hatches re-serialize
  the parsed value instead of crashing on the consumed stream (documented
  caveat: not byte-identical for JSON, since insignificant whitespace is not
  preserved).
- **UTF-8 BOM survives the encrypted text round-trip.** The EDV codec's decoder
  no longer strips a leading BOM (`ignoreBOM: true`), so BOM-prefixed text/\*
  bytes round-trip byte-exact.
- **`configure()` fails closed when the current description is unreadable.**
  When `describe()` is masked (404) and neither `backend` nor `encryption` is
  supplied, `configure()` throws instead of sending a merge body that would
  silently drop an existing collection's backend or trip `encryption-immutable`.
  Pass `force: true` (new option) to create a new collection through a handle.
- **Conditional writes against an unreadable existing document get a clear
  error.** With a PUT-only capability on an existing encrypted document, the 412
  from the fresh-insert precondition is re-thrown naming the real cause
  (document exists but is unreadable), instead of an inexplicable failed create.
- **`setName()` / `setTags()` are lost-update-safe.** Both now pin their
  full-replacement metadata write to the `meta()` read's ETag (`If-Match`), so a
  concurrent metadata write surfaces as `PreconditionFailedError` instead of
  being silently erased.
- **`put()`/`add()` honor an explicit content type for JSON data** (e.g.
  `application/ld+json`) on plaintext collections, matching the encrypted path,
  instead of silently storing `application/json`.
- `mapError()` tolerates malformed `problem+json` `errors` entries (`null` /
  primitives) instead of masking the real error with a `TypeError`.
- `collection.add()` resolves a relative `Location` header against the request
  URL, so `AddResult.url` is always absolute.
- The pagination cycle guard canonicalizes the first page URL, so a next-link
  back to page 1 cannot yield duplicate items when the caller-supplied URL was
  not in canonical form.
- The EDV codec validates the prior envelope's `sequence` on update, so a
  foreign envelope without one fails as a typed `EncryptionError` instead of a
  raw `Error` from the cipher.
- `dataOrNull` maps an undefined response body (non-JSON content-type or 204) to
  `null` instead of casting `undefined` through as the read result.

### Changed

- **`WasTransport.insert()` no longer doubles round trips.** When the
  collection's backend advertises `conditional-writes`, an insert is a single
  atomic `PUT` with `If-None-Match: *` (412 maps to `DuplicateError`); otherwise
  the existence pre-check uses a bodiless `HEAD` instead of downloading the
  stored envelope.
- Base64 encoding of encrypted binary writes is chunked (no more per-byte string
  concatenation on multi-MiB blobs).
- Internal dedup: shared `readData` / `delegateGrantAt` / `buildPageWalk` /
  `resolvePayload` / `envelopeBytes` helpers; the conditional-write
  orchestration moved into `internal/write.ts` (`upsertResource`); the
  `Resource` codec plumbing collapsed to a single resolver; `resolveCodec` reads
  the marker itself. Removed the unused `spaceLocation()` builder.

## 0.12.0 - 2026-07-01

### Added

- **Content-derived EDV document ids**
  (`createEdvEncryption({ idDerivation: 'content' })`). In `'content'` mode,
  `add()` on an encrypted collection encrypts first, derives the document id
  from the envelope's JWE ciphertext (`EdvDocumentCipher.deriveId` from
  `@interop/edv-client` 17.4.0 -- a truncated SHA-256 in the standard 128-bit
  multibase id format), stamps it on the envelope, and writes under that id --
  making documents content-addressed: the id is byte-stable across replicas with
  no mapping table, and hashing only the ciphertext leaks nothing about the
  plaintext (and survives adding a recipient). The trade-off is immutability --
  an "update" is delete-old + add-new -- so `'content'` suits write-once /
  append-only collections (e.g. a replicating credential store). The default
  stays `'random'` (the classic mutable-document `generateId()` model), and the
  explicit-id `put(id, ...)` path is unchanged in both modes.

### Changed

- Bumped `@interop/edv-client` to `^17.4.0` (adds `EdvDocumentCipher.deriveId`).

## 0.11.0 - 2026-07-01

### Changed

- **Encrypted resource metadata (`name` / `tags`).** On an encrypted collection,
  a resource's user-writable metadata (`custom`) is now encrypted into an EDV
  Document envelope by the codec before it is sent, symmetric with how content
  is stored -- so `setName` / `setTags` / `setMeta` **no longer throw** on an
  encrypted collection (the previous behavior) but instead round-trip
  transparently: `meta()` decrypts `custom` back to plaintext `{ name, tags }`
  for a keyed reader, while the server only ever sees an opaque envelope. The
  codec seam's `allowsServerMetadata: boolean` is replaced by
  `metadataMode: 'plaintext' | 'encrypted'`, with new `encodeMeta` /
  `decodeMeta` transforms (identity for the plaintext codec, encrypt/decrypt for
  `EdvCodec`).
- **`resource.setMeta()` returns the `/meta` ETag and accepts conditional
  options.** It now returns `{ etag }` (the metadata's own `metaVersion`,
  independent of the content ETag) and accepts `{ ifMatch, ifNoneMatch }` for a
  lost-update-safe metadata write (412 on a stale precondition). `meta().etag`
  is now this `/meta` validator (absent until a metadata write), not the content
  version -- use the content write/read ETag for conditional content writes.
- **EDV content is stored as `application/json`.** No client change was needed
  (the codec already defaulted to `application/json`); this note records that
  the server's `edv` scheme profile was corrected to match what the codec stores
  (an EDV Encrypted Document, `{ jwe, ... }`), so the codec's content writes now
  pass a marker-enforcing server end-to-end.

## 0.10.0 - 2026-07-01

### Changed

- **BREAKING**: Encrypted resources now carry their content type and encoding in
  the EDV document `meta`, with the payload inline in `content`. A decrypted EDV
  document is `{ content, meta }`: `meta.contentType` holds the plaintext MIME
  type and `meta.encoding` is the payload discriminator -- absent for JSON
  (`content` is the value verbatim), `"utf-8"` for text (`content.text` is a
  legible UTF-8 string, no base64 inflation), `"base64"` for binary
  (`content.bytes`). This replaces the in-band `@interop/was-client:edvBlob`
  marker record, which lived in the caller's `content` namespace. The change (1)
  closes a caller-data collision -- a JSON object shaped like `{ bytes: '…' }` /
  `{ text: '…' }` now round-trips as itself rather than being reconstructed as a
  `Blob`; (2) makes encrypted resources readable by any profile-conformant
  client (the format is a documented profile, not a private key); and (3) adds
  first-class encrypted **text** (HTML / plain-text / CSS / SVG / XML) stored
  legibly without the ~33% base64 inflation. Text and binary both read back as a
  `Blob` typed `meta.contentType`, matching the plaintext `get()` contract.
  Breaking: binary previously written with the old marker will not decode under
  the new reader (a clean cut -- the EDV inner-document profile was still being
  drafted). The single-document inline cap is raised from 1 MiB to 5 MiB.
- **`collection.add()` reports the plaintext content type of an encrypted
  resource.** `add(png, { contentType: 'image/png' })` now returns
  `AddResult.contentType: 'image/png'` (from the resolved `meta.contentType`)
  instead of the opaque envelope type `application/json`.
- **`EdvCodec` now uses edv-client's public `documentCipher` surface.** It
  encrypts/decrypts through `EdvClientCore.documentCipher`
  (`createDefaultRecipients` / `encrypt` / `decrypt`, the new public
  `EdvDocumentCipher` added in `@interop/edv-client@17.3.0`) instead of the
  private `_createDefaultRecipients` / `_encrypt` / `_decrypt` methods. The
  codec seam is unchanged (the WAS `Collection`/`Resource` remains the
  transport); no public API or behavior change.
- **The preferred EDV envelope content type is now `application/jose+json`**
  (the JWE JSON Serialization media type, RFC 7516), replacing the previous
  `application/edv+json`. This aligns with the WAS spec's Encryption Scheme
  Registry, which maps the `edv` scheme to `application/jose+json`. The exported
  constant is renamed `EDV_CONTENT_TYPE` to `JOSE_CONTENT_TYPE` (breaking) and
  now holds the new value; the zero-server-change `application/json` default is
  unchanged.
- **`put` / `add` no longer type-accept a top-level JSON primitive.** Their
  `data` parameter was typed `Json | Blob | Uint8Array`, so
  `collection.put('greeting', 'hello')` / `add(42)` / `add(null)` type-checked
  but threw a `ValidationError` at runtime (on both the plaintext and EDV paths
  -- the wire and EDV-content encoders only carry container JSON). The parameter
  is narrowed to the new exported `ResourceData` type
  (`JsonObject | JsonArray | Blob | Uint8Array`), so a bare primitive is now a
  compile-time error; wrap it in an object or array to store it.

### Fixed

- **Reserved-id rejection is now split by kind to match the reference server.**
  The client guarded both collections and resources against one flat union of
  reserved segments, so it over-rejected ids the server accepts
  (`resource('export')`, `resource('collections')`,
  `createCollection({ id: 'backend' })`) and omitted the server's non-spec
  `import` endpoint, letting `createCollection({ id: 'import' })` pass the
  client guard only to 409 at the server. `assertNotReserved` now selects
  `RESERVED_COLLECTION_IDS` or `RESERVED_RESOURCE_IDS` by kind, mirroring the
  server's per-kind sets.
- **A non-envelope document in an encrypted collection now throws a typed
  `EncryptionError`.** `EdvCodec.decode` passed whatever JSON it read straight
  to the cipher, and the conditional-write update path did the same with the
  pre-read prior document; a plaintext or foreign resource (one with no `jwe`
  field) made the EDV core throw a raw `TypeError` instead of a `WasError`. Both
  paths now validate the EDV envelope shape and surface an `EncryptionError`.
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
  `resourcePath(s, c, 'policy')` is byte-identical to the collection policy
  path, so `collection.resource('policy').delete()` silently wiped the
  collection's access-control policy (same collision for `backend` / `quota` /
  `linkset`). The reserved-id guard now runs at `Resource` construction,
  covering read / delete / meta / policy / put uniformly.
- **`configure()` now invalidates the memoized codec when it enables
  encryption.** A read caches the identity (plaintext) codec while a collection
  is still plaintext; `configure({ encryption: { scheme: 'edv' } })` flipped the
  collection encrypted server-side but left the cached codec in place, so a
  subsequent `put` wrote server-visible plaintext into the now-encrypted
  collection. `configure()` now drops the cached codec whenever it sets the
  `encryption` marker, and child resource handles obtained via
  `collection.resource(id)` delegate to the parent's codec on every call so the
  invalidation propagates to them too.
- **A stored top-level JSON `null` no longer crashes reads.**
  `@interop/http-client` pre-consumes the body into `.data` for JSON
  content-types, so a stored `null` arrived as `.data === null`;
  `readJsonData`'s `response.data ?? response.json()` treated that as "absent"
  and re-invoked `.json()` on the already-consumed stream, throwing
  `Body has already been used`. The check now tests for `undefined`, so `get()`
  / `publicRead()` return `null` as stored.
- **A transient marker-discovery failure no longer permanently poisons a
  handle.** `Collection`/`Resource` memoized the in-flight codec _promise_ with
  `??=`, so a transient 500 / network error during marker discovery cached a
  rejected promise and every later `get` / `put` / `add` on that handle re-threw
  the stale error with no retry, even after the server recovered. The memo is
  now cleared on rejection (guarded against clobbering a newer in-flight
  promise), so the next call retries; a successful resolution is still memoized
  once per handle.
- **`list()` / `publicListCollection()` no longer silently return only the first
  page.** A collection larger than the server's page size yielded a listing with
  `items.length < totalItems` and no error, because neither method followed the
  response's `next` continuation link. Both now transparently follow `next` from
  page to page (each dereferenced with the same authorization), aggregating
  every page into a single listing; the returned envelope omits `next`, since
  the whole list has been collected. A self-referential or already-seen `next`
  ends the traversal defensively rather than looping forever.
- **`Collection.configure()` no longer drops `backend` / `encryption`.** It
  carried only `name` forward from the fetched description, so on a
  replace-semantics server `configure({ name })` dropped an EDV collection's
  `backend` or cleared its `encryption` marker (tripping
  `encryption-immutable`), and the returned `CollectionDescription` reported
  `encryption === undefined` unconditionally. It now merges every current field
  forward (mirroring `Space.configure`), so omitted fields are preserved in both
  the PUT body and the returned description.
- **`mapError` no longer throws a `TypeError` on a non-array `errors` field.** A
  non-conformant `application/problem+json` body with `errors` as a non-array
  (e.g. `{ "errors": "boom" }`) passed the optional-chaining guard but threw
  inside `.map`, replacing the intended `WasError` subclass with an opaque
  `TypeError`. The `errors` field is now guarded with `Array.isArray` before
  mapping its details.
- **`collection.resource(id, { encryption })` now honors the per-resource
  override.** `HandleOptions.encryption` was advertised on the `resource()`
  factory but silently dropped: the method forwarded only `capability` and
  always pinned the resource to the parent collection's shared codec, so a
  per-resource override had no effect. When an override is passed, the resource
  now resolves its own codec from it (winning over the Collection's marker and
  skipping marker discovery, per `EncryptionOverride`); without one, the
  resource still shares the collection's codec to avoid a redundant
  marker-discovery round-trip.
- **`toUrl` no longer drops a base-path prefix on `serverUrl`.** A leading-slash
  path resolved with `new URL('/space/x', 'https://host/was/')` is
  origin-absolute, silently dropping the `/was` prefix, so every signed request
  and derived zcap `invocationTarget` targeted the wrong path and 404'd for any
  WAS deployment mounted under a sub-path. The path is now joined onto the
  server's base path (a trailing slash is ensured and the path made relative),
  so a sub-path mount is preserved; a bare-origin `serverUrl` is unaffected.
- **`fromCapability` now validates `invocationTarget` and round-trips encoded
  ids.** A missing / relative / malformed target threw a raw `TypeError` from
  `new URL(...)`; it now throws a typed `ValidationError` (carrying the original
  error as `cause`). Each path segment is also `decodeURIComponent`'d before the
  path builders re-encode it, so an id containing non-unreserved characters is
  no longer double-encoded.
- **Create responses no longer assume a JSON body with `id`.** `createSpace` /
  `createCollection` / `add` read `data.id` directly, so a body-less 2xx that
  returned the id only in the `Location` header threw a `TypeError`. A shared
  `createdId` helper now prefers the body `id`, falls back to the last (decoded)
  segment of the `Location` header, and throws a typed `WasServerError` when the
  response carries neither.
- **`publicRead` / public listing now return `null` on 401/403, not just 404.**
  `unsignedRequest`'s read mode mapped only 404 to `null`, so a server that
  answers a missing capability with 401/403 made these methods throw instead of
  honoring their "null if not publicly readable" contract. Reads now resolve
  401/403 to `null` alongside 404.
- **`mapError` now maps 403 and 415.** A bare 403 fell through to the base
  `WasError`, so `instanceof AuthRequiredError` missed an authenticated-but-
  forbidden response; 403 now maps to `AuthRequiredError` and 415 (unsupported
  media type) to `ValidationError`.

### Added

- **Streaming pagination iterators for large listings.** `list()` /
  `publicListCollection()` buffer the entire collection in memory; for large
  collections, four new async iterators stream one page at a time and allow
  stopping early (following `next` on demand, in constant memory):
  `Collection.listPages()` / `Collection.listItems()` and
  `WasClient.publicListCollectionPages()` /
  `WasClient.publicListCollectionItems()`. The `*Pages()` variants yield each
  `CollectionResourcesList` page; the `*Items()` variants flatten those into
  individual `ResourceSummary` entries. Unlike the buffering methods, the
  iterators yield nothing (rather than `null`) when the collection is
  missing/unauthorized.

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
