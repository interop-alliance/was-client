# WAS Client Roadmap Archive (completed items)

Completed WCL-N items move here **verbatim** (heading, field block, prose, with
their `done` date) from [ROADMAP.md](ROADMAP.md) as they land, append-only,
newest at the bottom -- so WCL-N references keep resolving. CHANGELOG.md remains
the record of what landed. Items completed before this archive existed
(everything through client 0.34.0) live only in git history of the
pre-conversion narrative roadmap.

---

### WCL-3: Client-driven bulk rewrap

- status: retired as obsolete 2026-08-12 (was todo)
- priority: low
- labels: encryption, key-epochs
- acceptance:
  - [ ] A bulk operation rewrites only the JWE `recipients` of each Resource to
        move it to a new epoch, never re-uploading ciphertext

A useful post-`removeRecipient` migration. Caveat: rewrap does not help against
a reader that cached the CEKs themselves.

Retirement note: written for a model where each Resource's JWE carried
per-reader recipient wraps; the landed key-epoch model forecloses both readings
of the acceptance criterion. Envelopes are roster-blind (exactly one JWE
recipient, the epoch key -- per-reader access rides the descriptor's
`epochs[].recipients[]` roster), so the useful rewrap shipped as the descriptor
roster operations (`addRecipient` every-epoch escrow, `removeRecipient`
rotate-then-revoke, `replaceRecipient` one-write rotation). And re-homing an
existing envelope to a new epoch without re-encrypting is cryptographically
impossible by design: `was.epoch` is AEAD-bound in the JWE protected header to
detect epoch swap/rollback, and the WAS-EC profile declares pushed envelopes
immutable. The re-encrypt-history variant is explicitly out of profile (WAS-EC
rotation-limitations) and a stated non-goal in freewallet (content-derived ids
would change) and wallet-core. Superseded by the "No client-driven bulk rewrap
of stored envelopes" recorded decision in ROADMAP.md.

---

### WCL-8: `Collection.meta()` / `Collection.setMeta()`

- status: done 2026-08-12
- priority: medium
- labels: api, metadata, encryption
- touches:
  - wallet-attached-storage-spec -- the endpoints must be specified first;
    tracked as WASS-9 in that repo's ROADMAP (done, WASS-9 moved to archive)
  - was-teaching-server -- resolved: WAS-55 shipped in was-teaching-server
    0.21.0, with conformance coverage in `@interop/was-conformance-suite` 0.5.0
  - was-client ARCHITECTURE.md + README.md -- resolved: the new handle surface
    is documented in both
- acceptance:
  - [x] `Collection.meta()` / `Collection.setMeta()` mirroring the Resource
        pair: full-replacement `custom` writes, an independent `metaVersion`
        ETag, `PreconditionFailedError` on a stale `ifMatch`, and the
        read-then-CAS patch sugar where it mirrors naturally
  - [x] On an encrypted collection, `custom` rides the codec's
        `encodeMeta`/`decodeMeta` envelope, exactly as at Resource level
  - [x] Node tests (stubbed transport) + integration tests against
        was-teaching-server (run green against a live 0.21.0 server)

discovered-from: WCL-1 (decision recorded 2026-08-12). The persisted
blinded-index schema needs a discoverable, conditionally-writable, encrypted
collection-level home; the Resource `/meta` model already provides the shape,
and mirroring it at Collection level also gives encrypted collections a
client-encrypted name/tags surface (today `name` rides the Collection
Description in plaintext, which encrypted collections refuse to populate). WCL-1
consumes this surface for its index schema and stays blocked on it (with WASS-9
/ WAS-55) for everything past key distribution.

### WCL-10: `was.collection` binding for the Collection Metadata envelope

- status: done
- done: 2026-08-12
- priority: medium
- labels: encryption, codec, metadata, breaking
- touches:
  - encrypted-collections-spec -- resolved: the rule shipped 2026-08-12 as ECS-1
    (see its archived-roadmap.md): a Collection Metadata envelope MUST bind
    `was.collection` (the Collection's `id`, no Space scoping) and MUST NOT bind
    `was.resource`; resource-slot envelopes MUST NOT bind `was.collection`
  - was-client CHANGELOG.md -- resolved: the 0.35.0 entry names the breaking
    change to the construction -- the interim collection-meta envelopes (which
    bind `v` + `epoch` only) are refused by the new verification
- acceptance:
  - [x] `encodeMeta` on the Collection-level path binds `was.collection` to the
        Collection's id and omits `resource` (the Resource-level path is
        unchanged)
  - [x] The Collection meta slot's verification requires a string
        `was.collection` equal to the Collection the read addressed
        (`IntegrityError` on mismatch or absence -- absence is no longer the
        accepted shape, it is some other slot's envelope), alongside the
        existing `forbidResourceBinding` refusal
  - [x] Resource-slot verification (content and resource metadata) refuses a
        present `was.collection` before any id comparison
  - [x] Node + integration coverage for the three refusals (resource envelope in
        the Collection slot, collection envelope in a resource slot, Collection
        X's meta served as Collection Y's)

discovered-from: ECS-1 (decision recorded 2026-08-12). Today `encodeMeta` binds
`v` + `epoch` only for the Collection slot and the reader distinguishes it
purely negatively (`forbidResourceBinding`), which cannot exclude a
content-derived content envelope (same member set) served in the Collection
Metadata slot, and leaves cross-collection swaps to key separation,
misclassified as `KeyUnwrapError`. Codec-only change: the binding lives inside
the AEAD, so no server or wire-type impact. Must land before WCL-1 resumes
persisting real index-schema envelopes, so schema envelopes are minted with the
final binding; blast radius of the break is otherwise nil (the slot is days
old).

### WCL-9: key-epochs integration test drift (`UnknownEpochError` vs `KeyUnwrapError`)

- status: done
- done: 2026-08-12
- priority: medium
- labels: encryption, key-epochs, integration-test
- touches:
  - freewallet -- resolved: the decrypt-failure classification gained a third
    bucket -- a row failing with `KeyUnwrapError` is skipped, warned about
    honestly ("not a recipient of its key epoch"), and left uncached, but never
    joins the purgeable `undecryptableRowIds` bucket that feeds
    `purgeUndecryptableCredentials` (which deletes locally and, in remote-direct
    mode, server-side); `decryptEnvelope` never spends the one-shot descriptor
    refresh on it (a refresh cannot help). Unit coverage proves the row survives
    a purge in both backends. Dead code against the published was-client until
    the release carrying this item's split
  - was-react -- resolved (doc-only, behavior verified unaffected):
    `sharedCollectionReader`'s catch JSDoc and ARCHITECTURE.md now describe a
    mid-session revoke surfacing directly as `KeyUnwrapError` with no refresh
    spent; the refresh guards test for `UnknownEpochError` specifically and
    rethrow everything else, so no code change
  - wallet-core -- resolved (doc-only, behavior verified unaffected): the
    self-refreshing cipher's module JSDoc describes the split; its guard and the
    create-loss re-mint keep working (a lost epoch[0] is absent from the adopted
    descriptor by construction, so it still raises `UnknownEpochError`).
    Re-exporting `KeyUnwrapError` through wallet-core's `/sync` surface awaits
    the next published was-client, whose `/sync` subpath now carries it
- acceptance:
  - [x] The `test/integration/key-epochs.test.ts` suite is green against a live
        was-teaching-server >= 0.21.0, with expectations that assert the
        intended contract (not just whatever currently throws)
  - [x] The `KeyUnwrapError` / `UnknownEpochError` JSDoc contract matches the
        settled behavior

discovered-from: WCL-8 (found during its live verification run, 2026-08-12). The
"removes a reader: pull dies, new ciphertext is unreadable" test expects
`KeyUnwrapError` when the removed readerB decodes a post-rotation envelope, but
gets `UnknownEpochError` -- readerB holds no epoch-2 candidate key, so the
codec's fail-fast unroutable-envelope path (the stale-descriptor signal) fires
before any unwrap attempt. Reproduced from a clean HEAD worktree against
was-teaching-server 0.21.0, so it is not caused by the WCL-8 changes; but the
suite ran green live on 2026-07-31 (after the fail-fast landed), so the drift's
origin is unresolved. Note the test hands readerB the _rotated_ descriptor, for
which `UnknownEpochError` ("your descriptor may be stale") reads semantically
off -- readerB's descriptor is current, it is simply no longer a recipient; if
the investigation lands on distinguishing those cases, that is a codec
error-contract change and this item gains `touches:` entries for it.

The drift reproduced identically on the 2026-08-12 live verification runs for
WCL-1 Stage B and WCL-10 (same assertion, same errors), confirming it is
independent of those changes.

Resolution (2026-08-12). Git archaeology settled the "origin unresolved" note:
the assertion has been byte-identical since 2026-07-11, and the 2026-07-31 green
run was genuine -- the codec-level fail-fast only landed 2026-08-06 (shipped in
0.27.1) and threw `UnknownEpochError` for every unroutable envelope without
updating this test. (The "after the fail-fast landed" clause above conflated it
with the sync DocCipher routing signal from 2026-07-22, which this test never
exercises: it calls `codec.decode()` directly.) The investigation did land on
distinguishing the cases. Decrypt routing now raises `KeyUnwrapError` when the
envelope's epoch is on the descriptor but wraps to no key this reader holds
(readerB's case: its descriptor is current, it is simply not a recipient), and
reserves `UnknownEpochError` for an epoch the descriptor does not list
(genuinely stale; a re-read can help). `EdvCodec` gained the required `epochIds`
option to carry the descriptor's full epoch roster; the `/sync` subpath
re-exports `KeyUnwrapError` / `EncryptionError` so crypto-free consumers can
classify the membership signal; node coverage pins both halves of the split and
the integration suite ran green against a live was-teaching-server 0.21.0. A
downstream-consumer survey found no unbounded refresh loops anywhere (every
guard is one-shot and rethrows non-`UnknownEpoch` errors); the one real hazard
-- freewallet's purgeable bucket -- is fixed per its `touches:` entry.

### WCL-7: Relocating `setName` / `setTags` into the JWE

- status: superseded (2026-08-12)
- priority: low
- labels: someday, encryption, metadata
- acceptance: none yet -- deferred only because apps can carry name/tags inside
  the encrypted content today

Increment 2 _forbids_ `setName` / `setTags` on encrypted collections (they write
server-visible plaintext custom metadata -- a leak). Reversal is cheap
code-wise: the resolved `ResourceCodec` carries an `allowsServerMetadata` flag
(flip it true) plus an optional `encode/decodeMetadata` hook the edv codec
implements to fold the values into the encrypted document. Additive, no public
API break (a previously-throwing call starts succeeding).

Superseded (2026-08-12) by the encrypted-metadata work: `setName` / `setTags` /
`setMeta` on encrypted collections now encrypt the custom metadata with the same
recipient set as content and store it opaquely under `/meta` (its own envelope
with a `metaVersion` ETag), decrypted transparently on read; the
Collection-level `meta()` / `setMeta()` surface runs through the same pair. The
mechanism sketched here (an `allowsServerMetadata` codec flag plus
`encode/decodeMetadata` hooks folding values into the content document) was
never built.

### WCL-2: `Collection.add(bigBlob)` auto-routing

- status: done (2026-08-12)
- priority: low
- labels: encryption, streams, ergonomics
- touches:
  - was-client ARCHITECTURE.md -- the request lifecycle and "The codec seam"
    sections describe `encode` as a pure single-request transform with the
    chunked path as a separate `EdvClientCore`-driven escape; auto-routing moves
    that decision into the write path and changes both descriptions
  - was-client README.md -- the encrypted-collections section documents the
    oversize `add()` as rejected with guidance toward the stream path; a
    previously-throwing call starts succeeding
  - "@interop/edv-client" -- expected unaffected (`insert({ stream })` /
    `getStream` already carry the whole chunked path); verify the codec can
    reach what it needs through the export map, else export upstream
  - encrypted-collections-spec -- expected unaffected (the chunked profile,
    `caad: 1` AAD, and sealed chunk counts are already specified; auto-routing
    is client ergonomics producing already-specified wire traffic) -- verify and
    waive
  - was-teaching-server -- expected unaffected (the server sees identical
    `chunked-streams` traffic either way); verify and waive
- acceptance:
  - [x] An oversize `add()` on an encrypted collection routes onto the
        chunked-stream path automatically instead of throwing

The codec seam is a pure single-write transform, so an oversize `add()`
currently throws and points callers at the (fully working)
`EdvClientCore.insert({stream})` / `getStream` path. Ergonomics only.

Landed 2026-08-12 (client 0.36.0). `codec.encode` now returns either the
single-request `EncodedWrite` or a `ChunkedWrite` plan; `insertResource` detects
the plan and hands it a signed `CodecRequestContext`, so core never imports
`src/edv`. The EDV codec builds the plan for oversize binaries (threshold stays
`maxBlobBytes`, now a routing threshold rather than a hard cap) and drives
`EdvClientCore.insert({ doc, stream, transport })` over a `WasTransport` built
from the passed requester, gated on `chunked-streams` before any write. `decode`
gained an optional request context and reassembles a chunked document from its
sealed `stream.chunks` via `getStream`, so `get()` round-trips the routed blob.
The update path (`put`) still refuses oversize blobs (filed as WCL-12);
content-addressed collections also refuse (no single ciphertext exists to derive
an id from -- same throw as before).

Touches sweep (2026-08-12): ARCHITECTURE.md (lifecycle step 2, codec seam, EDV
layer, feature detection) and README.md (Binary bullet, low-level pointer)
updated in the same pass, plus the stale chunked-streams note in
docs/edv-client-core-usage.md. "@interop/edv-client" verified unaffected:
everything the plan needs (`EdvClientCore.insert({ stream })`, `getStream`,
`additionalProtectedParams`) is reachable through the root export; one upstream
nit (the second stream write ignores a caller-suppressed hmac) filed as WCL-14.
encrypted-collections-spec and was-teaching-server waived as predicted: the
routed write produces already-specified `chunked-streams` wire traffic.

### WCL-15: WCL-2 review fixes (chunked auto-routing hardening)

- status: done
- done: 2026-08-12
- priority: high
- labels: encryption, streams, security
- acceptance:
  - [x] The two read-path security findings (F1, F2 below) are fixed with
        regression tests simulating the malicious-server cases
  - [x] The remaining confirmed findings (F3-F10) and the four cleanups are each
        either fixed or explicitly waived here with a reason
  - [x] `pnpm lint` and `pnpm run test:node` pass

discovered-from: WCL-2. A high-effort review of the WCL-2 diff (2026-08-12,
uncommitted, slated for 0.36.0) confirmed 14 findings; the fixes below gate the
0.36.0 release since the affected code is unpublished. Findings are listed
most-severe first, with the verified fix for each.

F1 (security, `src/edv/EdvCodec.ts:818`). The chunked read addresses chunk
resources by the server-controlled cleartext `stored.id` (the envelope's
top-level `id`), never comparing it to the AEAD-verified `expectedId`.
`decode()` verifies the sealed `was.resource` binding of document A, but
`#readChunked` then fetches `resourcePath(space, coll, stored.id)/chunks/N`; a
malicious server sets the cleartext id to B, and B's chunks decrypt cleanly (the
per-chunk AAD binds only the chunk's own protected header and index, not the
parent document id, and the epoch recipient key is shared), so
`resource.get('A')` silently returns B's bytes. This is exactly the envelope
swap the `was.resource` binding exists to detect. Fix: address chunks by
`expectedId` / the sealed `was.resource`, or assert `stored.id === expectedId`
before entering `#readChunked`. Regression test: serve A's authentic envelope
with the cleartext id swapped to B and assert the read throws rather than
returning B's bytes.

F2 (security, `src/edv/EdvCodec.ts:814`). `decode()` routes to the chunked path
on the unauthenticated cleartext `stream.chunks`, contradicting its own "never
the cleartext copy" comment. Upstream `EdvDocumentCipher.decrypt` spreads the
envelope's cleartext `stream` into the decrypted doc and only overrides it when
the JWE payload seals one; an honest single-document write seals no `stream`, so
for those docs `decrypted.stream` is entirely server-controlled. A server
bolting `stream: { chunks: N }` onto an honest small document masks its sealed
content and turns the read into chunk fetches (reproduced empirically: a forged
cleartext `stream` on a 3-byte blob triggered a GET to `.../chunks/0`). Fix:
route only on an AEAD-authenticated signal. Preferred shape: have the chunked
write seal a marker in the payload the codec controls (e.g.
`meta.encoding: 'chunked'` alongside the existing contentType meta) and route on
that; if the marker says chunked but no sealed `stream` arrived, throw
`EncryptionError`. Regression test: forge a cleartext `stream` onto a small-doc
envelope and assert the sealed content is returned with no chunk fetch.

F3 (correctness, `src/edv/EdvCodec.ts:747`). `ChunkedWrite.execute` has no
failure cleanup: `EdvClientCore.insert` writes the document stub (sealed
`stream: { pending: true }`) before streaming chunks, so a mid-write chunk
failure permanently orphans an undecryptable stub -- `list()` shows it, `get()`
throws, re-adding mints a new id, and no compensating delete exists. Also
`chunkSize` is validated against nothing despite the JSDoc saying it must stay
under the backend's `maxUploadBytes`. Fix: wrap the chunk-streaming phase; on
failure, best-effort DELETE the stub via the plan's requester, then rethrow with
`cause`. Validate `chunkSize` against the backend's advertised upload limit if
the features/quota probe exposes one; otherwise document the constraint at the
`createEdvEncryption` option.

F4 (correctness, `src/internal/write.ts:193`). The chunked path runs over
`rawRequest` with no `mapError`, bypassing the typed error mapping
(`WasTransport.mapTransportError` covers only 409/412). A document PUT 404
surfaces as a raw ky/ezcap error instead of the `NotFoundError` that `add()`'s
JSDoc promises. Worse, an unmemoized feature probe that 404s memoizes "no
features" (`DESCRIPTOR_ABSENT_STATUSES`) and the caller gets a misleading
`NotSupportedError` on a capable server whose collection was deleted. Fix: route
the `CodecRequestContext.request` through the same mapped send path core uses
(`send` with `mapError`), and make the descriptor-absent probe result
distinguishable from feature-absent so the gate error names the right cause.

F5 (consistency, `src/edv/WasTransport.ts:384` and `:474`). The transport still
throws `namedError({ name: 'NotSupportedError' })` (a bare `Error` with `name`
set) while the diff introduced a typed `NotSupportedError` class in
`src/errors.ts`, so `err instanceof NotSupportedError` matches the codec's gate
but not the transport's identical condition, and docs/edv-client-core-usage.md
now promises the class. Verified safe to fix: `EdvClientCore` never dispatches
on the name and existing tests assert only `err.name`. Fix: throw the class from
`src/errors.ts` in `#requireFeature` and `updateIndex`.

F6 (error quality, `src/edv/docCipher.ts:196`). The sync DocCipher encrypt path
now reports an oversize binary as a generic
`Error('EDV encrypt ... returned no id/envelope body.')`: `encode` returns a
`ChunkedWrite` plan, `readEncoded` sees no `body`, and the real cause is
misdescribed (at HEAD this threw a typed `ValidationError`). Reachable only via
an untyped JS caller with `idDerivation: 'random'`. Fix: guard `readEncoded` (or
its caller) with `isChunkedWrite` and throw a `ValidationError` naming the
oversize payload and the unsupported sync path.

F7 (tracking): the sync read-side gap is filed as WCL-16 below.

F8 (test coverage, `test/node/edv-codec.test.ts:445`). Deleting the 512 KiB
default-cap test left no coverage of `DEFAULT_MAX_BLOB_BYTES`; every remaining
threshold test overrides `maxBlobBytes` to tiny values, so a regression of the
default (sized so the ~1.78x inflation stays under a ~1 MiB server JSON body
cap) would ship silently. Fix: with a default-config codec, assert a 512 KiB
binary yields an `EncodedWrite` and 512 KiB + 1 yields a chunked plan, without
executing the plan.

F9 (efficiency, `src/edv/EdvCodec.ts:1398`). `#toDocument` buffers an entire
`Blob` via `arrayBuffer()` before the threshold check, so the exact target case
of the feature holds ~2x the payload in memory, only for `#chunkedWrite` to
re-wrap the bytes as a one-value stream that `EdvClientCore` re-chunks anyway.
Verified drop-in fix: gate routing on `blob.size` (synchronous), pass
`blob.stream()` on the over-threshold branch, and buffer only for the
under-threshold inline paths.

F10 (coupling, `src/edv/EdvCodec.ts:753`). The ETag capture wiretaps every
request (method + recomputed document path string match) to spot the document
PUT, coupling the codec to how edv-client happens to encode writes; an upstream
change silently yields `etag: undefined`. `WasTransport.#put` already receives
the `HttpResponse` for exactly the document writes and discards it. Fix: surface
the last document-write ETag from `WasTransport` (field or callback option,
alongside the `documentHeaders` option this diff added) and delete the wrapper
and the duplicated path computation.

Confirmed cleanups below the review's reporting cap, worth folding in: reuse
`writeHeaders({ epoch })` in `#chunkedWrite` instead of hand-building the
`Key-Epoch` header; the `SingleWriteCodec` narrowing type is triplicated across
three test files (hoist to a shared test helper); `bytesToStream` / `readAll`
hand-roll what `Blob.stream()` / `new Blob(parts)` provide; and
`src/internal/write.ts` hardcodes EDV-specific guidance text in a generic core
module (move the wording into the codec's thrown error or the plan).

Landed 2026-08-12 (client 0.36.0, same release as WCL-2). All findings and all
four cleanups fixed as prescribed. F1: `#verifyBinding` returns the verified
`was.resource` id and `#readChunked` addresses chunks by it, refusing an
envelope that binds none. F2: decode routes on the sealed
`meta.encoding: 'chunked'` marker (already sealed by the chunked write; no
write-side change), and the sealed `stream.chunks` is the only count used. F3: a
failed chunk phase best-effort DELETEs the stub (only when `lastDocumentWrite`
shows the document landed) and rethrows with `cause`; the `chunkSize` half is
waived to documentation -- `FeatureProbe` exposes affordance tokens only,
nothing numeric to validate against, so the `maxUploadBytes` constraint is
documented at the `createEdvEncryption` option. F4: `codecRequestContext` sends
through the mapped `send` path, and `CodecRequestContext.features` is now the
`FeatureProbe` itself with a `descriptorAbsent()` signal, so the gate error
distinguishes an unreadable descriptor from a missing feature. F5: transport
throws the typed `NotSupportedError` class. F6: `readEncoded` guards with
`isChunkedWrite` and throws `ValidationError`. F7 remains tracked as WCL-16. F8:
default-threshold test restored (512 KiB inline, +1 chunked). F9: routing gates
on `blob.size` and the chunked branch streams via `blob.stream()`. F10:
`WasTransport` exposes `lastDocumentWrite` (id + etag) set by `#put`, plus
`deleteDocument`; the codec's request wiretap is gone. Regression tests cover
the F1 envelope swap, the F2 forged cleartext `stream`, and the F3 cleanup
paths.

### WCL-11: `indexed` emission on the sync push path

- status: done
- done: 2026-08-13
- priority: medium
- labels: encryption, sync, query
- touches:
  - freewallet -- its sync wiring builds the cipher via `createEdvDocCipher`; if
    that function gains a schema input (or a refresh hook), the wiring must
    supply it; verify and update. Verified 2026-08-12: the wiring change is
    FW-133 (its item text now records the shipped API); it lands once was-client
    0.36.0 is published to npm (freewallet consumes the registry). Resolved:
    FW-133 shipped and archived 2026-08-13.
  - was-react -- same: its `src/sync/` DocCipher wiring is the other
    `createEdvDocCipher` consumer; verify and update. Verified 2026-08-12: the
    wiring change is WR-32 (item text updated likewise); also blocked on the
    0.36.0 npm publish. Resolved: WR-32 shipped in was-react 0.18.0 and is
    archived.
- acceptance:
  - [x] Envelopes written through the sync push path for a collection with a
        declared index schema carry `indexed` entries token-identical to
        direct-write envelopes for the same content
  - [x] A document pushed via sync is returned by `collection.find()` on the
        indexed attributes

discovered-from: WCL-1 (found while landing Stage B, 2026-08-12).
`createEdvDocCipher` builds its codec directly via the provider's `codecFor`,
bypassing `internal/codec.ts`'s schema load, and `indexed` emission is gated on
an applied schema -- so envelopes written through the sync push path carry no
`indexed` entries and are invisible to blinded-index queries. The envelope
passthrough itself is fine (`readEncoded` forwards the codec's envelope
verbatim, so `indexed` would survive once emitted); the gap is purely that the
sync cipher never learns the schema. Design question to settle: the sync replica
may write offline, so the schema likely arrives as a caller-supplied input on
`createEdvDocCipher` (the wallet already holds the descriptor and meta locally)
rather than a live Collection `/meta` read at cipher build; a schema declared
after the cipher was built also needs a staleness story consistent with the
handle-lifetime memoization on the direct path.

Progress (2026-08-12): the client half shipped. The design question resolved as
caller-supplied: `createEdvDocCipher` gained an optional `meta` input (the
collection's stored `/meta` value; its encrypted `custom` envelope is decoded
with `decodeMeta` and the `custom.indexSchema` it carries installed through the
codec's `indexing` capability -- the same routine `internal/codec.ts` runs at
codec resolution) and now returns `EdvDocCipher`, whose `applyMeta({ custom })`
is the staleness story: the consumer re-invokes it whenever its replica's copy
of the collection metadata changes (both known consumers rebuild or refresh
ciphers on descriptor changes only, so a meta-only change needs this hook, not
their epoch-gated rebuild). The input is optional and its absence changes
nothing, keeping offline/local-only replicas (which hold no meta) working; a
supplied value that cannot be decoded fails loudly, and the metadata envelope's
`was.collection` AEAD binding means `collectionId` must now be documented as the
real WAS collection id (both consumers already pass it). Unit coverage rides
`test/node/edv-doc-cipher.test.ts` (token-identical emission against the
direct-path codec); live coverage is the sync-push case in
`test/integration/blinded-find.test.ts`, verified against a locally-run teaching
server. Remaining: the two `touches:` wiring updates (FW-133 / WR-32), blocked
on the 0.36.0 npm publish -- both since shipped (see touches), closing the item
2026-08-13.

### WCL-1: Content search for the codec path

- status: done 2026-08-13
- priority: medium
- labels: encryption, codec, query
- touches:
  - encrypted-collections-spec -- resolved: ECS-2 shipped (archived 2026-08-12
    in the ECS roadmap), covering everything this entry called for: the
    descriptor's OPTIONAL `hmac` member with epoch-style recipient wraps, the
    installed-at-provisioning-or-never and no-rotation rules as normative text,
    the stored-envelope `indexed` entries, index-schema persistence under
    `custom.indexSchema` (with the per-attribute addition marker recording that
    matches may be partial), and Security Considerations for the revocation
    asymmetry and the schema's own sensitivity
  - wallet-attached-storage-spec -- resolved: the `blinded-index` query profile
    was already in the Query Profile Registry, and the schema's home, the
    Collection-level `/meta` endpoints, shipped as WASS-9 (archived in that
    repo's `_spec` roadmap)
  - was-teaching-server -- resolved: the schema home (Collection-level `/meta`,
    WAS-55) shipped in 0.21.0, and WAS-56 (archived 2026-08-12) closed the rest:
    the `blinded-index-api` conformance suite gained a codec-path group (equals
    round-trip, has + count, unique 409 conflict; conformance-suite 0.6.0,
    pending publish) and the Reverse-gaps preamble now cross-links the served
    blinded-index envelope semantics to ECS-2
  - freewallet -- resolved: FW-130 (mint, custody, and distribute the HMAC key;
    `ensureFirstEpoch` install) shipped 2026-08-12 and is archived; its residue
    (the wallet's sync doc-cipher writes do not load the index schema) is
    FW-133, riding upstream WCL-11, not this item
  - was-react -- resolved: WR-31 shipped in was-react 0.15.0 (2026-08-12,
    alongside was-client 0.35.0); its residue (sync-path writes emit no
    `indexed` entries) is WR-32, riding upstream WCL-11, not this item
  - "@interop/edv-client" -- resolved: no upstream export was needed; the
    concrete HMAC key class is `SHA256HMACKey` from
    `@interop/data-integrity-core` (used by `src/edv/hmacKey.ts`), and the
    codec's `BlindingKey` contract is structural, so edv-client's `IHMAC`
    implementations also satisfy it
  - was-client ARCHITECTURE.md -- resolved: the codec section now documents the
    optional `indexing` capability (`applySchema` / `schema` / `buildQuery`),
    blinded `indexed` emission on writes, and the `find()` binding
- acceptance:
  - [x] `createEdvEncryption`'s key set gains an `hmac` key, so the codec's
        cipher can blind attributes
  - [x] Codec-path writes emit blinded `indexed` entries alongside the JWE,
        matching what `EdvClientCore` documents carry
  - [x] `collection.find()` sugar binds the `blinded-index` profile for
        codec-stored documents
  - [x] The index schema (indexed attribute names, `unique`/compound flags) is
        persisted encrypted with the collection and discoverable by any
        recipient; declaring an index reconciles against the persisted schema
        instead of being app-local in-memory state

`WasTransport.find` binds the `blinded-index` profile, so `EdvClientCore` users
had content search from the start -- but `createEdvEncryption` built its cipher
with no HMAC, so codec-stored documents carried no blinded `indexed` entries and
were not findable. Closing that gap was a separate, larger design (below), now
implemented client-side.

Progress (2026-08-12): the key-distribution half shipped first -- the
descriptor's `hmac` member (mirrored locally as `EncryptionWithHmac` until the
storage-core 0.7.0 bump), `src/edv/hmacKey.ts` (mint / rebuild-from-secret /
`resolveHmacKey`), `ensureFirstEpoch({ blindedIndex })` provisioning-or-never
install, hmac roster edits riding the same CAS write in `addRecipient` /
`removeRecipient` / `replaceRecipient`, `EdvKeys.hmac` override, and the codec
resolving and exposing `blindingKey` (also handed to `EdvClientCore`). It was
**paused** on the persisted schema's home, the Collection-level `/meta`
envelope, which has since shipped on all three sides (client WCL-8, server
WAS-55 in was-teaching-server 0.21.0, spec WASS-9).

Progress (2026-08-12, second pass): the remaining halves are implemented, so all
four acceptance criteria are met. The schema lives under `custom.indexSchema` in
the Collection's encrypted `/meta` envelope
(`{ revision, indexes: [{ attribute, unique?, addedIn }] }`), written through
the read-reconcile-`setMeta({ ifMatch })` loop with a bounded retry and loaded
onto the codec at codec-resolution time for a descriptor that carries `hmac`.
`ResourceCodec` gained an EDV-type-free `indexing` capability (`applySchema` /
`schema` / `buildQuery`) so the handle layer stays codec-agnostic; the content
encrypt seam passes the blinding key once an attribute is declared, while
`encodeMeta` stays deliberately un-blinded (that envelope is not part of the EDV
content document). `Collection.indexes()`, `declareIndex()` and `find()` are the
public surface, with a client-side guard that refuses a query naming an
undeclared attribute (the underlying index helper would otherwise build a
term-less query that matches nothing). Unit coverage is
`test/node/blinded-index.test.ts`; live coverage is
`test/integration/blinded-find.test.ts`.

Touches sweep (2026-08-12): freewallet FW-130 and was-react WR-31 both shipped
(each leaving a sync-path residue item -- FW-133 and WR-32 -- that rides
upstream WCL-11, not this item), the edv-client question resolved via
`SHA256HMACKey` from `@interop/data-integrity-core`, ARCHITECTURE.md is updated,
and the storage-core widening cleanup landed (0.8.0; `EncryptionWithHmac` is now
a plain alias of `CollectionEncryption`). The item stayed `in-progress` on one
remaining `touches:` entry: the encrypted-collections spec text (hmac
distribution, `indexed` envelope entries, index-schema persistence, Security
Considerations), filed as ECS-2 in the ECS roadmap. The was-teaching-server half
(WAS-56: codec-path conformance coverage plus the Reverse-gap cross-link) was
archived 2026-08-12. WCL-10 (the `was.collection` binding decided as ECS-1)
landed alongside it on 2026-08-12, so the persisted schema envelopes are minted
with the final binding shape. ECS-2 shipped and was archived 2026-08-12,
resolving the last `touches:` entry and closing the item 2026-08-13.

Design point (recorded 2026-08-12): the index schema must be persisted and
discoverable, not app-local. `@interop/edv-client` keeps the schema as in-memory
state (`ensureIndex` populates a `Map` the app re-declares every run); that
fails the access-grant flow -- an app granted access to an existing collection
later must be able to learn which attributes are queryable without out-of-band
coordination, and stored `indexed` entries cannot teach it (their attribute
names are blinded). The schema is itself sensitive (attribute names reveal the
data model), so it cannot ride the Collection Description in plaintext; the home
is the collection's encrypted metadata envelope -- any epoch recipient can
already decrypt it, and its `metaVersion` ETag gives concurrent schema edits
conditional-write semantics. That envelope now exists at Collection level (WCL-8
/ WAS-55 / WASS-9, all shipped). The considered-and-rejected alternative
(2026-08-12) was persisting the schema as an ordinary encrypted Resource under a
blind-derived id (`HMAC(indexKey, 'index-schema')` in the EDV id layout):
discoverable by any key holder with no endpoint work, but the magic-id document
pollutes listings, change feeds, and sync replicas, counts against quota, and
can be destroyed by bulk deletes. Consequences of the persisted schema: the
`ensureIndex`-equivalent becomes a read-reconcile-write against the persisted
schema rather than a local declaration; and discovery must not promise complete
coverage -- an attribute added after documents were written has no tokens on
those documents until they are rewritten (the backfill is a re-blind sweep, the
same cost class as an HMAC key rotation), so the persisted schema should record
enough (e.g. a per-attribute addition marker) for a querier to know matches may
be partial.

### WCL-19: A conditional codec discards the caller's write precondition

- status: done
- done: 2026-08-21
- priority: high
- labels: encryption, conditional-writes, correctness
- touches:
  - was-client: `upsertResource` (`src/internal/write.ts`) chooses the
    precondition; `Resource.put`'s documented `ifMatch` is the surface that
    silently stops applying; `EncryptionDescriptorStore`
    (`src/edv/descriptorStore.ts`) and `resourceLogStore`
    (`src/log/logStore.ts`) carry the compensating prose to delete
  - freewallet, dcw: any caller relying on `put({ ifMatch })` for a lost-update
    guard against an encrypted collection is not getting one today; the fix
    turns that into a thrown error
- acceptance:
  - [x] A caller-supplied `ifMatch` / `ifNoneMatch` on an encrypted collection
        either pins the write to the caller's baseline or is refused loudly
  - [x] The "host this in a plaintext collection" paragraphs in
        `descriptorStore.ts` and `logStore.ts` are removed, and both stores work
        on an encrypted collection
  - [x] The insert path (`insertResource`) is settled the same way, or its
        divergence is recorded here

`upsertResource` computes
`codec.conditionalWrites ? encodedPrecondition(encoded) : precondition`, so on
any collection whose codec sets `conditionalWrites` (every encrypted one) the
caller's compare-and-swap baseline is dropped and replaced by the ETag the
codec's own pre-read just observed. The write still succeeds, pinned to current
server state rather than to what the caller last saw, so a lost-update guard
degrades to last-write-wins with no signal.

The compensation has already leaked into two seams as prose that nothing
enforces: both `descriptorStore.ts` and `logStore.ts` tell the reader to host
the resource in a plaintext collection because "the EDV codec computes the write
preconditions itself, so this store's `ifMatch` would not be honored". Both are
compare-and-swap loops where the precondition is the whole mechanism
(`casUpdateDescriptor` retries only on `PreconditionFailedError`; the resource
log's append profile requires it). The next store built on `Resource.put` needs
the same paragraph, and a caller who misses it loses the guard silently.

Two candidate fixes, and the choice is the decision this item needs: refuse the
combination (`ValidationError` when `codec.conditionalWrites` meets a
caller-supplied precondition), or forward the caller's precondition into
`codec.encode` so a conditional codec can pin to the caller's baseline instead
of its own pre-read. The second is the deeper fix and keeps CAS working on
encrypted collections; the first is contained to `internal/write.ts`. Either way
it is not behavior-preserving, which is why it was left out of 0.42.0.

Resolved 2026-08-21 by the second fix. `ResourceCodec.encode` takes an optional
`precondition` alongside `current`, supplied only for a codec that sets
`conditionalWrites`; the EDV codec pins the write to it and falls back to its
own pre-read derivation when the caller named none. `upsertResource` forwards
it, so `Resource.put`'s documented `ifMatch` / `ifNoneMatch` applies on an
encrypted collection exactly as on a plaintext one.

A caller baseline the pre-read has already moved past is refused locally, since
the pre-read makes the mismatch visible before the write is sent:
`assertPreconditionAgainstPreRead` (`src/internal/conditional.ts`) throws
`PreconditionFailedError` with status 412 when the caller's `ifMatch` names a
validator the current document no longer carries, when nothing is readable at
the path at all, or when `ifNoneMatch` meets a document that already exists. The
type matches what the server would have answered, so a compare-and-swap retry
loop needs no special case, and no sequence advance is encoded from a revision
the caller never saw.

The compensating paragraphs in `descriptorStore.ts` and `logStore.ts` are gone;
both stores now run on a plaintext or an encrypted collection. One constraint
replaces them: on an encrypted host the resource must be created under an id the
codec mints, because the EDV codec refuses to create a document under a
human-readable id (it would leak onto the URL).

The insert path diverges and stays as it is: `Collection.add()` exposes no
precondition option (`insertResource` dropped its unused one in 0.42.0), so
there is no caller baseline for it to discard. An insert names no target
revision to pin against, and the conditional codec's own `If-None-Match: *`
guard is the whole precondition there.

### WCL-27: Every local encrypt serializes an envelope body that is thrown away

- status: done
- done: 2026-08-21
- priority: low
- labels: encryption, sync, efficiency
- touches:
  - was-client: `EdvCodec.encode`'s return shape and `EncodedWrite.body`
    (`src/codec.ts`), a public seam -- a lazy `body` is observable to any
    consumer that spreads or clones the returned object
- acceptance:
  - [x] A local-replica encrypt does not pay a full stringify plus UTF-8 encode
        of the envelope on every write
  - [x] The HTTP write path is unchanged

`EdvCodec.encode` unconditionally sets `body: envelopeBytes(encrypted)`. On the
HTTP path that is the wire body. On the sync path, `readEncoded` only uses
`encoded.body` for an `instanceof Uint8Array` type check and then takes
`encoded.envelope`, the object form the codec already holds, so the bytes are
discarded. A 100 KB document pays roughly 280 KB of transient allocation and a
full serialization pass for nothing, on every replica write.

`EncodedWrite.body` is already optional, so the shape supports a lazy getter,
with `readEncoded`'s guard flipped to prefer `envelope` so it never forces it.
The reason this was left out of the cleanup pass is that a getter on a public
seam object behaves differently from a data property under spreading and
structured cloning, so it needs a deliberate decision about the seam rather than
a silent swap.

### WCL-24: `LOCAL_SPACE_ID` is a sentinel for a dependency the codec does not have

- status: done
- done: 2026-08-21
- priority: low
- labels: encryption, sync, layering
- touches:
  - was-client: `EdvCodec`'s constructor shape, `LOCAL_SPACE_ID`
    (`src/edv/constants.ts`), `createEdvDocCipher` and `encryptOnlyEdvCodec`
    (`src/edv/docCipher.ts`, `src/edv/EdvCodec.ts`) -- all internal to
    `src/edv/`
- acceptance:
  - [x] A local-replica codec cannot address a chunked write at a fabricated
        `/space/local/` route, structurally rather than by convention
  - [x] `LOCAL_SPACE_ID` is gone

`EdvCodec` requires a `spaceId` solely so `#transportFor` can build a
`WasTransport` for the chunked path. The two server-less builds have no space,
so they pass `LOCAL_SPACE_ID = 'local'`, and the constant's own comment concedes
that it "must never reach the transport path -- there is no `/space/local/`
route", relying on the DocCipher seam refusing chunked writes up front to keep
that true.

So an invariant about the codec's internals is enforced by guards in a different
module: `docCipher` refusing `isChunkedWrite`, plus `#readChunked`'s no-context
refusal. Two distant guards keep a fabricated address off the network, and
anyone adding a third path that addresses a resource by path has to rediscover
that the `spaceId` on a local codec is a lie.

The codec does not need a Space id, it needs a way to build a transport. Inject
that instead -- an optional `transportFactory` supplied by `createEdvEncryption`
(which knows the space) and omitted by the two local builds -- so a chunked
write on a local cipher fails structurally. Contained to `src/edv/` and
behavior-preserving.
