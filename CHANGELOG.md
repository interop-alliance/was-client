# @interop/was-client Changelog

## 0.16.0 - TBD

### Fixed

- **Conditional-codec creates fail closed on backends without
  `conditional-writes`.** An encrypted `put(id, ...)` whose pre-read returned
  nothing (which cannot distinguish "absent" from "exists but unreadable" -- WAS
  masks unauthorized reads as 404) used to send a fresh insert guarded only by
  `If-None-Match: *`; a backend that ignores that header would silently
  overwrite the existing envelope and reset its EDV sequence. The write path now
  probes the backend's advertised features and refuses the ambiguous insert with
  a clear `ValidationError` instead. Creates via `add()` (freshly minted ids)
  and readable-document updates are unaffected.
- `storeChunk` / `getChunk` are now gated on the backend advertising the
  `chunked-streams` affordance, throwing `NotSupportedError` when it is absent
  (mirroring `find`'s `blinded-index-query` gate) -- previously a server with no
  `/chunks/{n}` route produced misleading "parent document does not exist" /
  "chunk not found" errors.
- A read candidate key that fails to unwrap its own epoch entry
  (`KeyUnwrapError` from a lazy epoch key with a corrupt recipient entry) is now
  treated as a key miss -- the decrypt loop tries the next candidate -- instead
  of being misreported as ciphertext tampering (`IntegrityError`).
- The default single-document encrypted blob cap is now 512 KiB (was 5 MiB),
  sized so the encrypted envelope (~1.78x inflation for binary) stays under the
  ~1 MiB JSON body limit typical servers apply to the single-document path -- an
  oversized write now gets the codec's clear guidance toward the chunked path
  instead of an opaque server-side 413. Pass `maxBlobBytes` to raise it against
  a server with a larger limit.
- A lazy epoch key no longer caches a failed unwrap for the life of the handle:
  a transient failure is retried on the next read.
- `unwrapEpochSecret` now honors its "returns null for a corrupt entry" contract
  for malformed (non-base64url) `encrypted_key` / `epk.x` values, which
  previously escaped as raw decode errors past the callers' typed-error guards.
- Retrying `removeRecipient` after a transient revoke failure no longer appends
  a redundant rotated epoch per attempt: a retry that finds the departing reader
  already excluded from the current epoch skips straight to the revoke step.
- `collectPages` appends items without spreading them as call arguments, so a
  very large single page cannot hit the engine's max-arguments ceiling.

### Changed

- Backend-feature detection is now a single shared probe
  (`internal/features.ts`) consulted by both EDV write paths (`WasTransport` and
  the codec-seam write orchestration), with the same definitive-vs-transient
  caching rules in both.
- The reserved-path-segment guard now also runs inside the URL builders'
  collection/resource id slots, so every URL-forming entry point is covered
  uniformly (handle constructors still guard for the earlier failure).
- The masked-404 "fail closed on an unreadable description" policy is now stated
  once (`unreadableDescriptionError`) and shared by `Space.configure` /
  `Collection.configure` / codec resolution / recipient management; the error
  classes are unchanged, message wording is unified.
- `describeCollection` and `Collection.describeWithEtag` now share one request
  shape; the HTTP-status-to-named-error mapping in `WasTransport` is funneled
  through one helper; the `urn:zcap:root:` id grammar, the module `TextEncoder`,
  and the CodecHolder wiring are each declared once.
- New exported `CollectionWritableFields` type names the writable Collection
  Description fields used by `configure` / `replaceDescription`.
- `addRecipient` wraps its per-epoch keys concurrently (matching
  `initRecipients` / `removeRecipient`); `didKeyResolver` memoizes per key id;
  the JWE recipient descriptor is computed once per codec instead of per write.
- The encrypted codec now consumes upstream primitives instead of its own local
  approximations: a key-miss on read (wrong or rotated key, so the decrypt loop
  should try the next candidate) is discriminated from a ciphertext-integrity
  failure via the cipher's typed `KeyMissError` (matched by error name, so a
  duplicated cipher install does not defeat it) rather than by matching literal
  error message strings; and an explicit `put(id, ...)` id is validated with the
  EDV client's `assertDocId` (a full multibase decode plus multihash length
  check) rather than a local base58 charset regex, so a non-EDV id is rejected
  before it can leak onto the URL.

## 0.15.0 - 2026-07-19

### Added

- **Chunked encrypted blobs over WAS (transport half).**
  `WasTransport.storeChunk` / `getChunk` -- which previously threw
  `NotSupportedError` -- now bind the server's `/{resourceId}/chunks/{index}`
  chunk addressing (the `chunked-streams` backend feature): `storeChunk`
  serializes the EDV chunk object and `PUT`s it to the chunk's own URL as
  `application/octet-stream` (so the server's streaming binary path, not its
  bounded JSON parser, carries it), and `getChunk` fetches and parses it back,
  mapping an absent chunk or parent to the `NotFoundError` that `EdvClientCore`
  dispatches on. With these in place, `EdvClientCore.insert({stream})` /
  `getStream` drive chunked encrypted blobs over a WAS server end-to-end -- a
  blob larger than the single-document cap round-trips byte-for-byte (live
  integration coverage).
- New `resourceChunkPath` / `chunksContainerPath` builders in the internal path
  module.

### Changed

- The oversized-blob rejection in the EDV codec now points callers at the
  working chunked stream path (`EdvClientCore.insert({stream})` / `getStream`)
  instead of describing chunking as unavailable, and its `maxBlobBytes` JSDoc
  now states the actual 5 MiB default (the code is unchanged).

## 0.14.5 - 2026-07-12

### Added

- Export `writeHeaders` (with its `WritePrecondition` options type) from the
  root entry point, completing the conditional-write helper pair with the
  already-exported `readEtag`.

## 0.14.4 - 2026-07-11

### Added

- Export `parseSpaceTarget` (with its `ParsedSpacePath` result type) and
  `readEtag` from the root entry point, so consumers can reuse the server-URL
  target parsing and ETag reading instead of keeping parallel copies.

## 0.14.3 - 2026-07-11

### Changed

- Remove storage-core temporary type shims.

## 0.14.2 - 2026-07-11

### Changed

- Bump to latest `@interop/minimal-cipher` and `@interop/edv-client` deps.

## 0.14.1 - 2026-07-11

### Added

- **Multi-recipient encrypted Collections and key epochs.** An encrypted
  Collection can now give several apps read access, each holding its own X25519
  key-agreement key, and removing one of them means something cryptographically
  -- not only at the authorization layer. On the `@interop/was-client/edv`
  subpath:
  - `initRecipients({ collection, recipients })` mints the first key epoch and
    wraps its collection key to each initial reader.
  - `addRecipient({ collection, recipient, owner })` wraps every epoch's key to
    a new reader -- escrow semantics, so "add a reader" means it can read the
    Collection, history included. No rotation: adds are inexpensive.
  - `removeRecipient({ collection, space, recipientId, revoke })` is the full
    removal: it rotates the epoch, minting a fresh key wrapped only to the
    remaining readers (the read axis -- prospective), and once the rotation is
    durable revokes the reader's zcap(s) (the pull axis -- immediate,
    server-enforced). Already-revoked capabilities are tolerated, so the
    operation is safely retryable if a concurrent description update interrupts
    it. Resources written after the removal are unreadable to the removed reader
    even if it gets the ciphertext.

  The same `createEdvEncryption` provider transparently encrypts each write
  under the current epoch and decrypts any epoch a reader still holds, so
  `collection.put` / `get` are unchanged. Each write stamps the epoch it used
  (the `WAS-Key-Epoch` header), surfaced on `meta()`, listings, and the
  `changes` feed. Recipient edits use a compare-and-swap (`If-Match`) on the
  Collection Description and retry on a concurrent change, so two racing adds
  cannot clobber one another. A read that unwraps no epoch key throws the new
  `KeyUnwrapError` (a subtype of `EncryptionError`), never plaintext.

  Important: Rotation protects post-rotation writes only. It never claws back
  data a reader already downloaded, and a removed reader keeps every earlier
  epoch's key, so a pre-rotation resource whose ciphertext it gets stays
  readable to it. The pull axis (the zcap) and the read axis (the epoch key) are
  kept separate everywhere; neither alone removes a reader.

- **`Collection.describeWithEtag()` / `Collection.replaceDescription()`** --
  read the Collection Description with its `ETag`, and write it back with an
  optional `If-Match` compare-and-swap (`PreconditionFailedError` on a stale
  validator). The generic description-CAS primitive the recipient operations
  build on.

- New exports: `KeyUnwrapError` and `IntegrityError`; the
  `CollectionEncryptionEpoch` / `CollectionEncryptionRecipient` marker types;
  and, from the `edv` subpath, `initRecipients` / `addRecipient` /
  `removeRecipient`, `mintEpoch` / `epochKeyIdFor`, and the `OwnerKey` /
  `RecipientPublicKey` types.

- **`IntegrityError`** (a subtype of `EncryptionError`): reading a tampered or
  corrupted encrypted resource with a valid key now throws it, instead of
  misreporting the failure as a recipient-membership problem (`KeyUnwrapError`).

- `Space.configure()` now fails closed, like `Collection.configure()` already
  did: when the current description cannot be read (missing or unauthorized), it
  throws a `ValidationError` unless a full description or the new `force: true`
  option is supplied -- instead of silently defaulting the controller to the
  caller and dropping the existing name.

### Changed

- Recipient edits made through `Collection.replaceDescription()` (including
  `initRecipients` / `addRecipient` / `removeRecipient`) now take effect on the
  same Collection handle immediately: the handle re-resolves its codec after an
  encryption change instead of reusing the one from before the rotation.

- Historical epoch keys are unwrapped lazily on the first decrypt that names
  them (and cached); writes only unwrap the current epoch. The write-key
  fallback also selects the current epoch by id instead of relying on array
  order.

- `mintEpoch` no longer returns a `keyPair` property (both in-repo callers only
  used `epochId` / `secret`).

- Removed the unused `metadataMode` property from the `ResourceCodec` interface
  and both codecs; the metadata transform is fully owned by `encodeMeta` /
  `decodeMeta`.

- The X25519 multibase framing, raw-secret handling, and did:key resolution in
  the `edv` subpath now come from `@interop/x25519-key-agreement-key` (>= 5.2.0)
  instead of local implementations.

### Fixed

- `removeRecipient` now derives the surviving reader set from the current epoch
  only. Previously it unioned recipients across all epochs, so a reader removed
  in an earlier rotation was silently re-added (re-escrowed) by a later removal.

- An epoch-bearing `encryption` override passed to
  `space.collection(name, { encryption })` now resolves the epoch codec.
  Previously the epoch marker was dropped and the single-key path taken,
  breaking reads (spurious `KeyUnwrapError`) and writes (undecryptable by
  marker-based readers) -- including the override `Space.createCollection`
  pre-seeds.

- A transient failure probing the server's backend features no longer
  permanently degrades `WasTransport` for its lifetime (non-atomic inserts,
  `find()` throwing `NotSupportedError`). Definitive absence (404/405/501) is
  still cached as "no features"; transient errors now surface to the caller and
  the next call re-probes.

- `WasClient.fromCapability()` now resolves capability targets on servers
  mounted under a base path (e.g. `https://host/was/`), matching `revoke` and
  `grant`.

- Malformed percent-escapes in a space path (e.g. `%ff`) are treated as an
  invalid path and reported through the usual typed errors instead of crashing
  with a raw `URIError`.

- `Resource.meta()` throws a typed `WasServerError` on an empty or non-JSON 200
  response instead of crashing with a `TypeError`.

- Ids parsed from a `Location` response header no longer retain a query string
  or fragment.

- `AddResult.contentType` is populated on POST adds even when the server omits
  `content-type` from the 201 response body.

## 0.14.0 - 2026-07-10

### Added

- **Blinded-index content query (EDV `find` over WAS).** `WasTransport.find()`
  now binds the EDV-over-WAS profile to the server's `blinded-index` query
  profile (`POST .../query`, the `blinded-index-query` backend feature) instead
  of throwing. `EdvClientCore.find({ equals | has, count, limit })` therefore
  works against a WAS server: the client blinds the query with its HMAC key, the
  server matches it against the blinded `indexed` entries of stored documents by
  opaque string comparison (it does no crypto and never sees an attribute name
  or value in plaintext), and the matching encrypted envelopes come back and are
  decrypted client-side. Count queries return a bare `{ count }`.

  Pagination is native: `EdvClientCore.find` accepts a `cursor` option and
  surfaces the server's opaque `cursor` on its result alongside `hasMore: true`,
  so pages past the first are walked entirely through the client -- pass the
  previous page's `cursor` back in and read the next one off the (decrypted)
  result -- without reaching for the transport directly. This requires
  `@interop/edv-client` >= 17.6.0 and `@interop/data-integrity-core`

  > = 8.2.0. The profile has no ids-only mode, so an explicit
  > `returnDocuments: false` is dropped (like `returnDocuments: true`) and full
  > documents are returned -- the core's documented best-effort degradation for
  > that option.

  `find()` gates on the backend affordance: it throws `NotSupportedError` when
  the Collection's backend does not advertise `blinded-index-query` (without
  issuing the query), and maps a 404 from the query endpoint to `NotFoundError`.

  The server side also enforces the EDV unique-attribute invariant on writes: an
  insert (or update) claiming a `unique: true` blinded attribute already held by
  another live document in the Collection is rejected with a 409, which the
  client surfaces as `DuplicateError`. On `update`, a stale-write 412 (the
  stored document changed since it was read) surfaces as `InvalidStateError`,
  the recoverable re-fetch-and-retry case. (Note the codec-based encrypted
  collections -- `createEdvEncryption` -- construct their cipher without an HMAC
  and blind nothing at write time, so nothing they store is findable by this
  query yet; content search for that path is a separate follow-up.)

- **Capability revocation.** `space.revoke(zcap)` submits a delegated capability
  to its Space's revocation endpoint
  (`POST /space/:spaceId/zcaps/revocations/:capabilityId`); from then on the
  capability is rejected wherever a Space-rooted chain is verified -- writes,
  privileged routes, and the capability leg of reads. Previously the only lever
  against a leaked capability was a short `expires` and waiting it out.
  `was.revoke(zcap)` is the same operation with the Space derived from the
  capability's `invocationTarget`.

  Both parties the server authorizes can call it: the Space controller, and any
  controller in the capability's own delegation chain (so an application can
  revoke the capability it holds, without being granted anything extra). The
  client invokes the revocation URL's own root capability, whose synthesized
  controller covers both, so there is no shape to choose and no extra
  round-trip.

  Revocation is scoped to one Space -- there is no cross-Space or global
  revocation -- and it withdraws only what the _capability_ granted: because
  access-control policies are permissive, a `PublicCanRead` target stays
  publicly readable afterwards. It is also prospective: a revoked reader of an
  encrypted Collection still holds the keys for ciphertext it already fetched.

  `revoke()` is deliberately **not** idempotent. Revoking an already-revoked
  capability throws `ValidationError` (the server's 400), which it reports with
  the same problem type it uses for a tampered, expired, or foreign-rooted
  capability -- indistinguishable to the client, so none of them are swallowed.

### Changed

- **`WasTransport.updateIndex()` now says why it throws.** It still throws
  `NotSupportedError`, but the message (and JSDoc) now explain that this is by
  design, not a missing server affordance: in the EDV-over-WAS profile, index
  entries are not a separate server-side resource -- the `indexed` array rides
  inside the stored document envelope, so an ordinary `update()` of the full
  document is the re-index operation. Chunked streams (`storeChunk` /
  `getChunk`) remain unsupported, still pending the server's `chunked-streams`
  affordance.

- **A grant into the Space tree now roots its chain at the Space.** When no
  parent capability is given, `collection.grant(...)` (and a `was.grant(...)`
  whose `target` lies under the server's `/space` tree) delegates from the
  **Space's** root capability, carrying the narrower target as an attenuated
  `invocationTarget`, instead of delegating from the target's own root
  capability. Both forms grant exactly the same access, but only a Space-rooted
  chain can be revoked, so capabilities minted by the previous shape -- the
  leaked-session-key case revocation exists for -- could not be revoked at all.
  A grant that re-delegates a held capability, or whose target lies outside the
  Space tree (e.g. `/kms`, or another origin), is unaffected.

## 0.13.3 - 2026-07-09

### Added

- `collection.changes({ checkpoint, limit })` -- reads one page of a
  Collection's replication change feed (the `changes` query profile), returning
  `{ documents, checkpoint }`. Each `ChangeDocument` carries `id`, `_deleted`,
  `updatedAt`, `version`, and the optional `metaVersion` / `createdBy` / `data`
  / `custom`, so a replica learns each Resource's creator from the feed rather
  than fetching `/meta` per Resource; a tombstone keeps its `createdBy`.

  Deliberately a single page rather than an iterator: it is shaped for an RxDB
  `pull.handler(checkpoint, batchSize)`, which owns the iteration and persists
  the checkpoint between batches. Resume by passing the returned `checkpoint`
  back; a page shorter than `limit` means the caller has caught up.

  Requires the Collection's backend to advertise the `changes-query` feature (a
  backend without it answers `501`). On an encrypted Collection the documents'
  `data` / `custom` are the scheme's opaque envelopes -- `changes()` does not
  decrypt them, unlike `get()`.

  The `ChangeDocument` / `ChangesPage` / `ChangesCheckpoint` wire shapes are
  `@interop/storage-core` exports; import them from there.

## 0.13.2 - 2026-07-09

### Changed

- Update to latest `storage-core` (adds `createdBy` field).

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
