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
