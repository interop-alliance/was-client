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

### WCL-30: `initRecipients` refuses instead of adopting the winner of a lost create race

- status: done
- done: 2026-08-22
- priority: medium
- labels: encryption, cas, idempotence
- touches:
  - was-client `src/edv/recipients.ts` (`initRecipients`' `mutate`),
    ARCHITECTURE.md if the recipient-loop contract is stated there -- done
    2026-08-22 (ships in 0.44.3)
  - wallet-core `ensureUserKeyRoster` (its "converges on the winner's roster"
    contract becomes true), `credentialAnchoredGenesis` (the roster stage stops
    reporting a lost race as failed), `test/node/descriptors.test.ts` (the
    non-member create-race case pins today's `ValidationError` and flips to the
    adopted descriptor) -- done 2026-08-22 (wallet-core on
    `@interop/was-client@0.44.3`)
- acceptance:
  - [x] A lost guarded-create race (`store.create` throws
        `PreconditionFailedError`, or the store's pre-write pass reports one)
        ends with `initRecipients` resolving the winner's descriptor
  - [x] The `ValidationError` "already has key epochs" is kept for a caller
        whose store already held epochs on the first read

`src/edv/recipients.ts:584-592`, `:1199-1214`. After a lost create,
`casUpdateDescriptor` re-reads and calls `mutate` on the winner's descriptor;
`initRecipients`' `mutate` throws `ValidationError` whenever `epochs` is
non-empty, so the loser never reaches the "nothing to write" return. Returning
`null` from `mutate` when the descriptor already carries epochs is the signal
the loop already honors. Surfaced by the ceremony-reviewer pass over
wallet-core's log-governed store (vh-resource-log VRL-2, 2026-08-22), whose
`create` now translates a pre-write refusal against an existing log into this
race.

### WCL-31: `casUpdateDescriptor` matches `PreconditionFailedError` by `instanceof`

- status: done 2026-08-22
- priority: low
- labels: errors, cas
- touches:
  - was-client `src/edv/recipients.ts` (the two catch sites in
    `casUpdateDescriptor`)
- acceptance:
  - [x] The rebase branch matches the conflict by
        `err.name ===     'PreconditionFailedError'`, so a conflict minted by a
        consumer resolving its own was-client copy still rebases
  - [x] A test throws a same-named foreign class from a fake store's `replace`
        and `create` and sees the loop rebase

`src/edv/recipients.ts:1207`, `:1225`. wallet-core's log-governed descriptor
store mints the conflict from its own `@interop/was-client` import; in a tree
that resolves was-client twice every lost roster CAS, and now every lost genesis
race, becomes a hard ceremony failure instead of a rebase. The same two-copies
hazard is already handled by name for the log conflict (vh-resource-log
invariant 8). Found by the VRL-2 ceremony-reviewer pass, 2026-08-22.

### WCL-28: First `meta()` on a blinded-index collection fetches `/meta` twice

- status: done
- done: 2026-08-22
- priority: low
- labels: encryption, search, efficiency
- acceptance:
  - [x] Resolving a codec and then reading collection metadata costs one GET and
        one decrypt, not two
  - [x] Metadata reads after the first are never served from a stale snapshot

`buildEncryptingCodec` calls `loadIndexSchema`, which issues
`GET collectionMeta(...)` and runs a full `decodeMeta` JWE open.
`Collection.meta()` then issues the same GET on the same path and decodes the
same envelope again. `declareIndex` hits it too, since `#indexing(...)` resolves
the codec and then immediately calls `meta()`.

The cost is one extra round trip plus one extra decrypt, once per handle, on the
first `meta()` / `setName()` / `setTags()` / `declareIndex()` against an
encrypted collection that declares a blinding key. Collections without one do
not pay it, because `loadIndexSchema` returns early when the codec has no
`indexing`. The two requests race rather than serialize, so the latency cost is
smaller than the request and crypto cost.

Either have `loadIndexSchema` stash the response it read on the `CodecHolder`
for `meta()` to consume once and clear, or invert the flow so `meta()` resolves
the codec and feeds its own freshly-read `custom` to the indexing seam. The
consume-once variant is behavior-preserving; any variant that keeps the snapshot
alive past the first read would start returning stale metadata, which is the
trap to avoid when picking this up.

---

### WCL-35: Space delete that reports its 404 as an outcome

- status: done 2026-09-01
- priority: medium
- labels: space, errors, api
- discovered-from: freewallet FW-403 (Space deletion through a ladder-signed
  DELETE-only delegation)
- acceptance:
  - [x] `Space.deleteWithOutcome()` added beside `delete()`; `delete()` is
        unchanged
  - [x] A 404 is reported as `{ outcome: 'not-found' }`; other errors still
        throw the mapped `WasError`
  - [x] Unit tests cover both outcomes
  - [x] README documents the new method

A caller running a deletion ceremony must know whether the DELETE actually
removed anything. The server answers 404 both for an absent Space and for a
capability it refuses. `deleteWithOutcome()` reports that 404 as
`{ outcome: 'not-found' }`, which reads as absent or refused. Only a caller with
its own prior discovery can read it as absence.

It ships as a new method rather than a changed `delete()` return type. Existing
consumers keep working unchanged -- the conformance suite calls `space.delete()`
in seven suites.

Cross-repo context: this is was-client's part of freewallet's FW-403 (Space
deletion through a ladder-signed DELETE-only delegation). wallet-core's
`deleteSpaceWithCapability` currently goes through the raw `was.request()`
escape hatch and can switch to the new method as a follow-up in that repo.

---

### WCL-36: Collection snapshot over the changes feed

- status: done 2026-09-05
- priority: medium
- labels: collection, changes-feed, api
- acceptance:
  - [x] `Collection.documents()` walks the `changes` feed to its `null`
        checkpoint and reduces the pages to the live documents
  - [x] Only the `null` checkpoint ends the walk; a short page does not
  - [x] Server faults (bodiless 2xx, live entry with no `data`, repeated
        checkpoint) fail the walk with a `WasServerError`
  - [x] A first-page 404 resolves `null`; a later-page 404 throws
  - [x] Unit tests cover the walk, the reduction, the defaults, and each fault

A reader with no local replica needs the collection's current documents with
their bodies. `list()` returns summaries only, so reading bodies costs one GET
per resource. The `changes` feed already ships bodies and tombstones in
`(updatedAt, id)` order, so a walk from the beginning is a snapshot in a handful
of round trips.

Filed at completion. The malformed-page guards it needed belong in `changes()`
itself, so the sync port's pull path gets them too.

---

### WCL-20: Sync port re-derives error classification from raw HTTP status

- status: done 2026-09-05
- priority: medium
- labels: sync, errors, altitude
- touches:
  - was-client: `mapWriteError` and `readContent` in `src/sync/port.ts`; the
    `./sync` subpath's thrown-error contract
  - freewallet, dcw, was-react: sync drivers matching on the current raw ky
    error shapes for statuses outside 412/404 would see typed errors instead
- acceptance:
  - [x] The port's write and read paths classify through `errors.ts` rather than
        switching on raw HTTP status
  - [x] `WasSyncConflictError` / `WasSyncNotFoundError` carry the server's
        `problem+json` fields (`type`, `title`, `details`, `requestUrl`) and a
        `cause`
  - [x] A status outside the current small list (500, a 507 `quota-exceeded`)
        leaves the sync subpath as a typed error rather than a raw ky error

`mapWriteError` and `readContent` dispatch on `errorStatus(err)` over the raw
errors `was.request()` throws, and build `WasSyncConflictError` /
`WasSyncNotFoundError` with default messages, no `cause`, and none of the
server's problem details. `mapError` (`src/errors.ts`) already maps 412 to
`PreconditionFailedError` and 404 to `NotFoundError` carrying all of that, and
both sync classes are declared as subtypes of those.

The result is one object with two error regimes: `query()` rides
`Collection.changes()` through `send()` and throws mapped errors, while the
write and read paths throw hand-built ones. A new problem type added to
`ERROR_CLASS_BY_KIND` reaches the handle API but never the sync API, and the
412/404 status list has to be maintained in two places.

The fix is to route the port's writes through `internal/request.ts`'s `send()`
and classify with `instanceof`. The port's verbatim-bytes property comes from
bypassing the codec, not from bypassing the error mapper, so nothing about the
sync contract requires the current shape. `upsertResource` already does exactly
this when it re-throws a 412. Contained to `src/sync/port.ts`, and
`instanceof`-based consumers are unaffected because the sync classes stay
subtypes.

Done 2026-09-05. `mapWriteError`, `readContent`, the `/meta` read, the delete's
idempotent branch, and `query` all classify through `mapError` now. Each port
signal is built from the mapped error, so it carries the server's `type`,
`title`, `details`, and `requestUrl` and keeps the transport error as its
`cause`; a status with no port signal of its own is thrown as the mapped
`WasError` subclass. The port still reads and writes through `was.request()`,
since the verbatim-bytes property comes from bypassing the codec.

The `touches:` consumers are discharged by ordering rather than by an edit here:
this lands in 0.49.0 at the head of the extraction release train (freewallet
FW-448), before the three drivers move to a shared package, so each one adopts
the typed errors as part of that move. No consumer matched on a raw ky shape for
a status outside 412/404; the classes and their `name`s are unchanged, and the
subtype relationships hold.

---

### WCL-6: RxDB sync client follow-ons

- status: done 2026-09-05
- priority: low
- labels: someday, sync, cross-repo
- acceptance:
  - [x] The two RxDB driver copies are deduplicated into a standalone library
        (closed onto freewallet FW-448, which owns the extraction)
- touches:
  - was-rxdb-replication (new repo, from isomorphic-lib-template) -- the
    extracted RxDB replication driver package, consuming
    `@interop/was-client/sync` for the port, wire types, and error signals
  - freewallet -- `src/lib/sync/` (changesQuery, pushWrites, wasReplication,
    syncedDocSchema, types + tests) is one of the two diverged driver copies;
    replaced by the extracted package, with `stores/syncController.ts`
    re-pointed at it
  - was-react -- `src/sync/` is the other diverged copy, and it has grown pieces
    the freewallet copy lacks (feed-master port, LWW conflict handler, DocCipher
    wiring); the extraction must decide which of those move into the package and
    which stay was-react-side
  - was-client -- expected code-unaffected (the `./sync` subpath already carries
    the port and primitives the driver consumes); README gains a pointer to the
    new package
  - wallet-core -- expected code-unaffected (its `sync/` engine is the non-RxDB
    path and deliberately excludes the RxDB adapter); its ARCHITECTURE.md
    references to "freewallet's RxDB driver/adapter" get re-pointed at the
    extracted package
  - wallet-attached-storage-spec -- unaffected (the wire contract is already
    normative: Query Profile Registry appendix + Conditional Requests)

Most of what this item originally deferred has since landed, in a different
factoring than predicted. The `WasSyncPort` implementation and sync primitives
moved into the client itself as the `@interop/was-client/sync` subpath (0.19.0:
`createWasSyncPort`, whose pull path rides `Collection.changes()`), so
freewallet's hand-rolled `was.request()` changes query is gone -- its
`stores/syncController.ts` calls `createWasSyncPort` directly. `createdBy` is
threaded into the local RxDB document (freewallet `syncedDocSchema` bumped to
`version: 1` with a migration strategy; `epoch` followed at `version: 2`). And a
framework-agnostic pull/push engine was extracted into `@interop/wallet-core`
(`src/sync/`: `SyncEngine` with injected port/store/cipher seams, consumed by
dcw), which deliberately does not include an RxDB adapter.

What did not happen is the `was-rxdb-replication` extraction itself: the
RxDB-specific driver (wire-doc to RxDB mapping, pull/push handlers,
`replicateRxCollection` wiring, the `SyncedDoc` schema) now exists as two
diverged copies -- freewallet `src/lib/sync/` and was-react `src/sync/`. That
dedup is the only live residue of this item, and the second copy is also its
strongest argument.

Done 2026-09-05, closed onto freewallet FW-448. The extraction got its trigger
and its design; the package is `@interop/was-sync`, not the
`was-rxdb-replication` name parked above, since the name had to survive the
engine joining it later. FW-448 owns the merge of the two copies (was-react's is
the base, freewallet's five deltas port into it), the package's export map, and
the consumer walk this item's `touches:` sketched.

The one prediction that did not hold is this repo's own: "was-client -- expected
code-unaffected". Step 0 of the release train is a was-client change (0.49.0).
The three `err.name` predicates moved down here from `@interop/wallet-core/sync`
to sit beside the classes that assign the names they match, a fourth
(`isSyncAuthError`) was added because the merge base cannot drop its last
`instanceof` without one, the `SyncStatus` type moved in so the engine and the
driver share one owner, and WCL-20 was resolved so the package inherits typed
port errors rather than raw ky ones. The rule those predicates carry is recorded
as `decisions/0001-cross-package-errors-match-by-name.md`.

### WCL-17: Log-governed descriptor reads over the shared resource-log verifier

- status: done (2026-09-07)
- priority: medium
- labels: encryption, log, integrity
- blocked-by: none (freewallet FW-279, the verifier's move into
  `@interop/vh-resource-log`, landed 2026-08-22)
- touches:
  - was-client: the encryption-descriptor read path (`EncryptionDescriptorStore`
    / `src/edv/descriptorStore.ts`) learns the log-governed case over
    `@interop/vh-resource-log`'s `readResourceLog`, by EXTRACTION from
    wallet-core (decided 2026-09-07, below) rather than a fresh build;
    `src/log/` is already the WAS adapter of the library's store port (FW-279's
    was-client entry). Resolved 2026-09-07:
    `src/edv/logGovernedDescriptorStore.ts` (`logGovernedDescriptorStore`,
    `readGovernedEpochConfiguration`, `EPOCH_CONFIGURATION_STATE_TYPE`,
    `toEpochConfigurationState`) and `Collection.historyLogUrl`; placed under
    `src/edv/` because `src/log/` may not import `src/edv/` (the core-entry
    rule), so the store imports the log adapter, not the other way round
  - vh-resource-log: hosts the verifier, the pin port, and the append path after
    FW-279; this item consumes them as published and adds nothing there.
    Resolved: consumed at 0.4.1, nothing added
  - storage-core: unaffected (`resourceLog.ts` wire types and
    `CollectionEncryption.type`/`history` shipped; the verifier consumes them
    as-is) -- verify and waive. Waived 2026-09-07: `history` and `type` on
    `CollectionEncryption` and `RESOURCE_LOG_METHOD` used as shipped
  - wallet-core: the SOURCE of the moved code. `readGovernedEpochConfiguration`
    (`src/descriptors/logSource.ts`) and the generic halves of
    `logGovernedDescriptorSource` / `logGovernedDescriptorStore`
    (`src/keys/rosterLogStore.ts`: open the log, verify under an injected
    controller port and pin store, refuse a head whose `state.type` is not
    `WasEpochConfiguration`, strip `history` on the way in and stamp it on the
    way out) move here; wallet-core keeps the did:webvh controller adapter, the
    ceremony-tail license and its log class, the roster's placement and wiring,
    and wraps this package's reader. The collection-descriptor producer wiring
    stays FW-134's. Resolved 2026-09-07: `logSource.ts` and `rosterLogStore.ts`
    import the three helpers from `@interop/was-client/edv` and re-export the
    two names they exported before; the full wallet-core suite passes with its
    tests unchanged. Ships with wallet-core's next release, which needs the
    was-client 0.52.0 range bump
  - app-connect-spec / encrypted-collections-spec: profile of record (ECS-3
    settles which spec hosts it); no text change expected -- verify. Verified
    2026-09-07: the reader implements the profile's existing equality and
    `history` rules; no text change
  - freewallet / dcw: consumers -- FW-134 and DCW-43 build the producing half on
    this read path. Resolved: nothing for this item; neither app imports the
    moved names directly
  - was-client `src/log/`: `resourceLogStore` takes a Collection Resource
    handle; the governing log is the sub-resource
    `/space/{space_id}/{collection_id}/meta/log` (WASS-27, settled 2026-09-07),
    not a Resource, so the store gains a constructor over the Collection handle
    (or a raw URL) that speaks the same three operations. The roster's
    `key-map/user-key.jsonl` keeps the Resource form. Landed 2026-09-07:
    `resourceLogStore({ collection })` over the new `Collection.getHistoryLog` /
    `putHistoryLog` transport methods, with a live-server integration test
    (`test/integration/governed-log.test.ts`)
- acceptance:
  - [x] Decision recorded first (2026-08-22): wallet-core's shipped verifier
        (`src/resourceLog/` -- verify, append, pin, seal) moves to a new
        package, `@interop/vh-resource-log`, that was-client and wallet-core
        both depend on. Neither moving it into was-client (it would carry
        wallet-core's ladder-license semantics into a transport library, or
        leave them behind with a hook anyway, and creates a
        was-client/wallet-core cycle) nor leaving it in wallet-core behind a
        verifier port (the profile's reference verifier stuck inside a wallet
        package) was acceptable; a lower "hash log kernel" extraction from
        did-method-webvh was rejected with revisit criteria. The design is
        freewallet `_spec/designs/FW-279-vh-resource-log-extraction.md`; the
        move is FW-279. This item narrows to the descriptor read path
  - [x] Chain verification, the `{ scid, method, head }` pin behind a
        caller-supplied store port, and the negative-path suite (forged entry
        proof, truncated log behind the pin, forked log under the same SCID,
        `method` mismatch, extending past a terminal entry) ship in
        `@interop/vh-resource-log` under FW-279; this item does not reimplement
        any of them and adds only the projection-mismatch case below
  - [x] Built by extraction, the FW-279 shape: the generic governed read moves
        down from wallet-core (the touches entry names the functions) behind
        this package's descriptor-store seam, and wallet-core's roster path is
        re-pointed at it with no behavior change. The user key roster's existing
        tests in wallet-core, unchanged, are the extraction's acceptance test.
        Building the reader fresh here and re-plumbing wallet-core onto it
        afterwards is rejected
  - [x] The log-governed descriptor read path: a descriptor carrying `history`
        is accepted only after refusing a `history.method` that is not
        `RESOURCE_LOG_METHOD` before any fetch, opening the log at
        `history.resource` through `resourceLogStore`, running the library's
        `readResourceLog` with a caller-supplied controller port and pin store,
        and checking the point-state projection JCS-equals the verified head's
        `state` after stripping `history` (`type` carried on both sides makes
        the comparison land)
  - [x] The controller port and pin store are injected by the caller; was-client
        stays free of DID-method resolution (the library's dependency on
        did-method-webvh is the hashing and proof kernel only)
  - [x] A descriptor without `history` keeps today's behavior exactly (point
        state, epoch pin, unknown-epoch refresh); no new failure mode for
        non-log collections
  - [x] Negative-path tests on the read path: projection mismatch against the
        verified head, `history.method` mismatch, a log the library refuses (one
        representative integrity case and one continuity case, asserting the
        library's error classes pass through unwrapped)

The consuming half the `/log` transport has been waiting for -- scoped to
collection encryption descriptors, because the stack is not greenfield:
wallet-core's `resourceLog` module already verifies, appends, pins, and seals,
both wallets run it for the user key roster log, its
`logGovernedDescriptorSource` already checks `state.type` against
`WasEpochConfiguration`, and its verifier already enforces the history-reserved
rule. What exists nowhere is a producer or consumer for collection descriptors:
no code stamps `history` onto a point-state descriptor or follows one (the
members shipped as storage-core types and as WAS-EC normative text via WASS-14).
Sequence: FW-279 publishes the verifier as `@interop/vh-resource-log` with the
existing negative-path suite; this item builds the read path against it; FW-134
/ DCW-43 then produce real logs. Spec-side prerequisites WASS-22 (identifier)
and ECS-3 (profile home) are editorial for this item -- the profile's normative
content is already stable in the App Connect spec text.

Re-scoped 2026-09-07 from the FW-134 design pass. Two things changed. First, who
this reader is for. The wallets open a governed collection's log directly, by a
placement constant, and never read the projection, so they need only what
wallet-core already has; the pointer-following read here is for every reader
that holds a descriptor but not the convention: a was-react app on a shared
collection, the storage browser, an agent. Placement was settled with that
audience in mind (the log sits under the collection's own URL subtree, so the
read zcap those readers already hold covers it; FW-134 and DCW-43 record it).
Second, how it is built. wallet-core's governed read already does most of what
the acceptance list describes, and was-client sits below wallet-core, so the
reader is that code moved down a layer, with only the three things wallet-core
never needed added here: the `history.method` refusal before any fetch, opening
at `history.resource`, and the projection equality check. The item stays ahead
of FW-134 for that layering reason, not because the wallet would otherwise write
a log nobody checks. One spec reconciliation is pending beside it:
encrypted-collections-spec ECS-7 settles that the projection this reader opens
is a bound, non-authoritative copy of the head, and the equality check here is
what makes that binding checkable.

Landed 2026-09-07. What the store returns for a governed collection is the
verified head state with the served `history` pointer kept on it, so the value
handed out is itself a valid projection. Two calls made while landing: a
`history.resource` that is not the Collection's own `/meta/log` URL is refused
before any fetch (the reader's capability covers the Collection subtree and
nothing else, and the placement is settled), and without a `signer` the store is
read-only (`create` absent, `replace` refuses) rather than requiring every
reader to hold a signing key. The write path this store carries for governed
collections (build on the verified head, pre-write pass, compare-and-swap
append, read-back and pin) is a second copy of wallet-core's roster store's;
WCL-37 records the convergence.

### WCL-37: Two copies of the governed-log write path (was-client and wallet-core)

- status: done (2026-09-07)
- priority: low
- labels: log, reuse, layering
- touches:
  - was-client: the governed write path in
    `src/edv/logGovernedDescriptorStore.ts` (replace / create), generalized over
    a `ResourceLogStore` rather than a Collection if wallet-core is to reuse it
  - wallet-core: `src/keys/rosterLogStore.ts` re-pointed onto it, keeping only
    `seal`, `setMinimumControllerVersion`, and the did:webvh controller adapter.
    Resolved 2026-09-07: the roster store is the generic store wrapped with the
    minimum-controller-version resolver; `seal` delegates too, since the sweep
    has no wallet-specific logic. 297 lines to 25
- acceptance:
  - [x] The verified-head build, the pre-write pass, the compare-and-swap append
        with its conflict translation, and the read-back-and-pin settle exist
        once, in was-client
  - [x] wallet-core's roster tests pass unchanged after the re-point
  - [x] `sealResourceLog`'s reuse of the last verified log (the no-refetch
        sweep) survives, so wallet-core's login sweep does not re-read

`discovered-from: WCL-17`. WCL-17 moved the governed READ down from wallet-core,
as its scope said, and gave the collection store a write half so the recipient
primitives can drive a governed Collection. That write half (`replaceGoverned`,
`create`) is the generic part of wallet-core's `logGovernedDescriptorStore`
restated over a Collection handle: the same head build, the same controller-view
prefix check, the same conflict translation, the same settle. wallet-core's copy
adds the ceremony's minimum controller version and the seal sweep, neither of
which the generic path needs to know about, so the convergence is a generic
store over any `ResourceLogStore` in was-client with wallet-core wrapping it.
Not done under WCL-17 because the item's acceptance made wallet-core's unchanged
roster tests the extraction's proof, and moving the write path would have
changed what those tests exercise.

Landed 2026-09-07, in the same unreleased was-client 0.52.0 as WCL-17, so the
Collection store's rename cost nothing. wallet-core's full suite passes with its
roster tests untouched, including the seal cases that count log fetches.

### WCL-25: Two compare-and-swap retry policies that can drift

- status: done
- done: 2026-09-07
- priority: low
- labels: conditional-writes, reuse
- acceptance:
  - [x] `Collection.declareIndex` and `casUpdateDescriptor` share one retry
        implementation
  - [x] The attempt count and the exhaustion error are settled deliberately
        rather than differing by accident

`declareIndex` hand-rolls a `for (let attempt = 1; ; attempt++)` loop -- read
current state, reconcile, conditional write, continue on
`PreconditionFailedError` -- with its own local `maxAttempts = 4`.
`casUpdateDescriptor` (`src/edv/recipients.ts`) is the same loop, generic over a
read/replace store, with `MAX_CAS_ATTEMPTS = 3` and a null-means-no-op mutate
contract. It has since grown a second branch the index loop lacks: when the
store reports no descriptor yet, an optional `seed` is mutated in its place and
written create-if-absent, and a lost create race re-enters the loop like a stale
CAS.

Two retry policies with two attempt counts and two exhaustion behaviors:
`declareIndex` rethrows the raw 412 with no context, `casUpdateDescriptor`
throws an explanatory `PreconditionFailedError` naming the race. A third caller
wanting CAS has no obvious one to copy.

Lifting the loop into `src/internal/` as a store-shaped generic makes
`casUpdateDescriptor` a thin call and lets `declareIndex` drive it with a
`/meta`-backed store. The generic has to carry the seed/create branch (with the
"absent" refusal left to the caller, since its message is recipient-specific),
or `casUpdateDescriptor` keeps that branch wrapped around the shared loop. This
is not behavior-preserving for `declareIndex` (3 attempts instead of 4, and a
contextual error instead of the raw 412) unless the helper takes `maxAttempts`
as an option, which is the call to make when picking this up.

Resolved 2026-09-07: `src/internal/cas.ts` exports `compareAndSwap` over a
`CasStore` (read-with-validator, conditional replace, optional guarded create)
with an `onAbsent` seed hook. One shared default of 3 attempts; the helper takes
`maxAttempts` for a caller with a reason, and neither current caller has one, so
`declareIndex` moved from 4 to 3 and now surfaces the contextual exhaustion
error with the last 412 as its `cause`.

### WCL-33: Late encryption declaration writes without a precondition

- status: done
- done: 2026-09-07
- priority: low
- labels: conditional-writes, provisioning, encryption
- acceptance:
  - [x] The in-place `encryption` declaration in `ensureSpaceAndCollection`
        writes against the `ETag` it read, and a lost race retries instead of
        overwriting the concurrent change

discovered-from: WCL-32. The third `configure` call in
`src/sync/provisioning.ts` -- adding an `encryption` descriptor to a collection
that lacks one -- differs from the two create branches: it holds a real
description, and `If-Match` on a Collection Description is honored by the server
today. So this one is closable now, independently of the spec work WCL-32 needs.

`describeWithEtag()` in place of `describe()`, then
`replaceDescription(fields, { ifMatch })` in place of `configure`. Note that
`replaceDescription` does not merge, so the call has to pass every writable
field forward. The retry on 412 belongs in the shared `compareAndSwap` loop
(`src/internal/cas.ts`, from WCL-25) rather than as a hand-rolled one.

Resolved 2026-09-07: `ensureSpaceAndCollection` reads with `describeWithEtag`
(one read still serves the create branch) and the late declaration is a
`compareAndSwap` over `replaceDescription`, carrying `name` and `backend`
forward. A lost race re-reads; a descriptor the rival declared is adopted
untouched (mutate returns null), so the retry can no longer trip
`encryption-immutable` or replace a rival's roster.

### WCL-21: `Space.createCollection` hardcodes the EDV routability rule

- status: done
- done: 2026-09-07
- priority: medium
- labels: encryption, layering, altitude
- touches:
  - was-client: `Space.createCollection` (`src/Space.ts`), the
    `EncryptionProvider` seam (`src/codec.ts`), `EncryptionOverride`
    (`src/types.ts`), and the blind cast in `buildEncryptingCodec`
    (`src/internal/codec.ts`)
- acceptance:
  - [x] Core (`src/*.ts`) contains no `scheme !== 'edv'` test
  - [x] The "can this descriptor route" predicate has exactly one owner
  - [x] `EncryptionOverride` admits a full `CollectionEncryption`, so
        `encryption: override as CollectionEncryption` drops its cast

`Space.createCollection` decides whether to pre-seed the returned handle with a
codec using
`declared.scheme !== 'edv' || (declared.epochs !== undefined && declared.epochs.length > 0)`.
That is a scheme-specific fact living in core, which ARCHITECTURE.md says never
knows about `src/edv/`, and the same fact is already owned by
`guardEncryptionDescriptor` in `EdvCodec.ts`.

Two places now decide the same thing, so they can drift. Tighten the edv rule
(require `currentEpoch` to be listed, which the guard already does) and core
still pre-seeds a handle pinned to a permanently fail-closed codec. Add a second
scheme and core silently pre-seeds it as routable, because the test is written
as "not edv".

The fix puts the predicate behind the seam: an optional
`EncryptionProvider.canRoute({ scheme, encryption })` that `createCollection`
consults, or dropping the pre-seed decision so `resolveCodec` falls back to
descriptor discovery when an override cannot build. Widening
`EncryptionOverride` to `{ scheme, keys? } | CollectionEncryption` removes the
related cast. Behavior-preserving for the current single scheme.

### WCL-18: Refuse an unrecognized `meta.encoding` in `EdvCodec#fromDocument`

- status: done
- done: 2026-09-07
- priority: medium
- labels: encryption, spec-conformance, fail-closed
- touches:
  - was-client: `src/edv/EdvCodec.ts` (`#fromDocument`), a test in
    `test/node/edv-codec.test.ts`, CHANGELOG.md
  - encrypted-collections-spec: unaffected (spec.md `#plaintext-document`
    already requires the refusal; this item brings the code to it)
- acceptance:
  - [x] `#fromDocument` dispatches on `meta.encoding` as a closed set: absent
        means JSON (content returned verbatim), `"utf-8"` and `"base64"` decode
        as today, `"chunked"` stays on its existing route, and any other present
        value throws `EncryptionError` (a scheme refusal), instead of falling
        through to "return `content` as JSON"
  - [x] A test asserts that an envelope sealing
        `meta: { contentType,     encoding: "gzip" }` (or any unknown string,
        and a non-string value) is refused and not returned as JSON
  - [x] ARCHITECTURE.md's decode-path note, if it describes the fallthrough, is
        updated

discovered-from: WASS-15 (encrypted-collections-spec `#plaintext-document`,
2026-08-20). The spec's plaintext-document section makes `meta.encoding` a
closed set and, per the profile's fail-closed extensibility invariant, requires
a reader to refuse a value it does not recognize rather than pick any
interpretation of `content`. `#fromDocument` today handles `"utf-8"` and
`"base64"` and returns `content` verbatim for everything else, so an unknown
encoding silently decodes as JSON. Reading is unaffected for every envelope a
conforming writer produces; the change only closes the fallthrough.

### WCL-22: Metadata binding slot is inferred from an absent argument

- status: done
- done: 2026-09-07
- priority: medium
- labels: encryption, codec-seam, integrity
- touches:
  - was-client: `ResourceCodec.encodeMeta` / `decodeMeta` (`src/codec.ts`) -- a
    public seam, so third-party codec implementations are affected; both
    implementations (`src/internal/codec.ts` identity, `src/edv/EdvCodec.ts`)
    plus the call sites: `readMeta` / `writeMeta` in `src/internal/meta.ts` (the
    single chokepoint the `Resource` and `Collection` handles go through) and
    the direct `decodeMeta` in `src/edv/docCipher.ts`
  - wallet-attached-storage-spec / encrypted-collections spec: no wire change
    intended, but the `was.collection` vs `was.resource` binding this selects is
    normative text, so confirm the seam change does not imply one
- acceptance:
  - [x] The metadata slot is stated by the caller rather than deduced from
        whether `expectedId` was passed
  - [x] A caller that legitimately does not know a resource id can still decode
        metadata without silently getting collection-slot validation
  - [x] Stored envelope bytes are unchanged

`EdvCodec` selects the AEAD binding slot with
`collectionSlot: expectedId === undefined` on the read side and
`resourceId === undefined ? { collection } : { resource }` on the write side.
The seam types both ids as optional. The `decodeMeta` JSDoc does say that an
omitted id means a Collection-level read, but the interface shape still makes
the absence of an optional argument the mode selector between two mutually
exclusive bindings that `#verifyBinding` then refuses each other.

Today's callers happen to be correct (`Resource` threads `this.id` through
`readMeta` / `writeMeta`, `Collection` and `docCipher` pass none), so this is
latent rather than broken. The failure it invites is asymmetric: a decode path
that does not know the id gets collection-slot validation quietly, while a write
path that forgets to thread `id` stamps a collection-bound envelope into a
resource's `/meta`, and that only surfaces later on some other reader as an
`IntegrityError` naming server tampering.

The fix is to make the slot explicit in the seam --
`encodeMeta({ custom, slot: { kind: 'resource', id } | { kind: 'collection' } })`
and the same on `decodeMeta` -- so the binding is stated, not deduced, and "id
unknown" stays expressible. Behavior-preserving, but it changes a published
interface, so it needs sign-off before it is coded.

Landed 2026-09-07: `MetaWriteSlot` / `MetaReadSlot` on the seam, both codec
implementations, `readMeta` / `writeMeta`, and the `docCipher` schema read.

### WCL-23: `logStore` re-derives the body shape the content layer owns

- status: done (2026-09-07)
- priority: low
- labels: log, layering, altitude
- touches:
  - was-client: a new read shape on `Resource` (additive), consumed by
    `resourceLogStore.read` (`src/log/logStore.ts`)
- acceptance:
  - [x] `resourceLogStore.read` obtains text plus the ETag validator without
        re-implementing the content-type to value mapping
  - [x] The store no longer needs to know that a `text/jsonl` body comes back as
        a `Blob`

`resourceLogStore.read` needs text plus the validator, and no single read gives
it both: `Resource.getText()` produces the right text but no validator, and
`getWithEtag()` returns the validator with the `Json | Blob` shape
`parseResource` chose from the content type. So the store re-implements the
mapping with
`isBlob(current.data) ? await blobText(...) : typeof current.data === 'string' ? ... : undefined`.

That mapping lives in `parseResource` (`src/internal/content.ts`), and this is a
second partial copy of it in a consumer. If the content layer ever returns text
directly for `text/*` -- plausible, since the EDV codec already stores
text-family payloads as legible strings -- this branch quietly goes dead and the
`ValidationError` below it starts firing on healthy logs.

The fix adds the missing capability one layer down rather than compensating
above it: a `getText`-shaped read that also returns the validator, or letting
`getWithEtag` hand back the `ResponseLike` so the caller picks its own
projection. Then `logStore.read` is a destructure plus `parseResourceLog`.

### WCL-38: `ensureSpaceAndCollection` gains the `'governed'` collection mode

- status: done (2026-09-07)
- priority: medium
- labels: provisioning, encryption, log
- discovered-from: WCL-32
- touches:
  - wallet-core: `src/space/provisioning.ts` maps a roster `'edv'` collection to
    `'governed'` and declares the governance through the log's guarded create
- acceptance:
  - [x] `encryption: 'governed'` creates an absent collection with no
        `encryption` member, the same descriptor-less guarded create as
        `'plaintext'`
  - [x] An existing collection is never written to under that mode, whether
        already governed (the served `encryption` carries `history`) or
        descriptor-less
  - [x] An existing collection carrying a client-written descriptor (no
        `history`) is refused with `ValidationError`, since the server keeps a
        declared descriptor immutable and the caller's log create would fail
        with `encryption-immutable`

Discovered while landing WCL-32's guarded creates: wallet-core's provisioning
needs a collection whose `encryption` member the server derives from its history
log, and `'edv'` (the client-written descriptor) could never become that. The
mode is the container half only; declaring the governance is the caller's next
step, `logGovernedDescriptorStore(...).create` or
`resourceLogStore({ collection }).create`.

### WCL-39: The sync port type states what `createWasSyncPort` implements

- status: done (2026-09-08)
- priority: low
- labels: sync, types
- touches:
  - was-sync: shipped -- `src/controller.ts` drops the `unknown` cast and the
    runtime `putMeta` probe; `WireDoc` aliases this package's (WS-10)
  - was-react: shipped -- `src/storage/wasSyncPort.ts` drops the probe and the
    feed-page cast (WS-10)
- acceptance:
  - [x] `WasSyncPort.putMeta` is required
  - [x] `WireDoc` types `data` and `custom` as `Json`, and `SyncPage` carries
        those documents, so `query`'s return type matches the parsed JSON the
        port hands back
  - [x] The only cast left is inside `createWasSyncPort.query`, where the shared
        `ChangesPage`'s `unknown` bodies narrow to `Json`

Context: `putMeta` was typed optional while `createWasSyncPort` always supplied
it, and `query` returned the shared `ChangesPage`, whose bodies are `unknown`.
Neither matched what the port hands back, so both consumers of the port
(was-sync's controller and was-react's port wrapper) cast the whole port through
`unknown` and probed for `putMeta` at runtime. That cast hid every future
divergence in the other members as well, surfacing a rename only inside a push
or pull cycle. Two consumers carrying the same workaround was the signal the fix
belonged here; with the type complete, a divergence is a compile error at the
seam.

### WCL-39: Map the already-revoked problem type to its own error name

- status: done 2026-09-10
- priority: medium
- labels: errors, revocation
- touches:
  - storage-core: SC-2 minted `ProblemTypes.CAPABILITY_ALREADY_REVOKED`
    (`#capability-already-revoked`, 400) on 2026-09-09; published in 0.13.0
  - was-teaching-server: WAS-91 emits it on the revocation route
  - wallet-core: WC-135 dispatches on the new `err.name`
- acceptance:
  - [x] `mapError`'s kind table (`src/errors.ts`, `ERROR_CLASS_BY_KIND`) maps
        `ProblemTypes.CAPABILITY_ALREADY_REVOKED` to a new `WasError` subclass
        `AlreadyRevokedError` (`name` `'AlreadyRevokedError'`, the wire-level
        contract wallet-core dispatches on; settled 2026-09-09), exported from
        the package root beside `ValidationError`
  - [x] Every other revocation-route 400, and the two client-side refusals in
        `src/internal/revoke.ts` (root capability, target not on this server),
        still surface as `ValidationError`
  - [x] The "`revoke()` is not idempotent, deliberately" decision below is
        amended: the client still swallows nothing, but a caller can now make
        revoking twice a no-op by catching the new name alone rather than all of
        `ValidationError`
  - [x] Tests pin the mapping from a `problem+json` body carrying the new type,
        and pin that a body carrying `INVALID_REQUEST_BODY` on the same route
        still maps to `ValidationError`

Discovered 2026-09-09 from wallet-core WC-135. The mapper keeps `status`,
`type`, `title`, and `details` on the error, so the information already crosses
the wire; only the class name is lossy, and `err.name` is the one signal a
consumer can match across package copies.

### WCL-40: Map the typed capability denial reasons to their own error names

- status: done 2026-09-10
- priority: low
- labels: errors, zcap
- touches:
  - storage-core: SC-3 minted `ProblemTypes.CAPABILITY_REVOKED` and
    `CAPABILITY_EXPIRED` (`#capability-revoked` / `#capability-expired`, 404) on
    2026-09-09; published in 0.13.0
  - was-teaching-server: WAS-57 emits them from the capability-invocation
    verification path
- acceptance:
  - [x] `ERROR_CLASS_BY_KIND` maps the two kinds to `CapabilityRevokedError` and
        `CapabilityExpiredError`, `NotFoundError` subclasses (the wire status
        stays 404) told apart by `name`, exported from the package root
  - [x] A plain `not-found` 404 still maps to `NotFoundError` named
        `NotFoundError`
  - [x] Tests pin both mappings from a `problem+json` body
  - [x] CHANGELOG entry

Discovered 2026-09-09 from was-teaching-server WAS-57. A holder whose grant
stops working could not tell a revocation from an expiry or a plain denial; the
server now names the first two by `type`, and this maps that onto the one signal
a consumer can match across package copies. Lands with 0.57.0; stays open until
storage-core 0.13.0 is published and the link override dropped.

### WCL-98: An encrypted Collection's configuration write has no `custom` envelope to carry

- status: done
- done: 2026-09-12
- priority: high
- labels: was-v0.5, encryption, key-epochs, spec, blocking
- discovered-from: WCL-41
- touches:
  - wallet-attached-storage-spec: RESOLVED 2026-09-12 -- the envelope rule now
    applies to a `custom` that is present, and an omitted `custom` clears on an
    encrypted Collection. The Collection Metadata data model, its lifecycle and
    error list, the server-side write-validation rule, and the Resource-level
    counterpart all say so
  - was-teaching-server: `lib/customMetadata.ts` (`resolveMetadataCustom` /
    `assertEncryptedMetaConforms`): RESOLVED 2026-09-12 -- an empty or omitted
    `custom` clears at the Collection and Resource metadata call sites alike
  - was-client: RESOLVED 2026-09-12 -- no code change. `storedAnnotations`
    already omits `custom` when none is stored, so `ensureFirstEpoch`'s
    compare-and-swap and `replaceDescription` / `configure` send the write the
    new rule admits; `replaceDescription`'s JSDoc says so
- acceptance:
  - [x] `ensureFirstEpoch` installs the first key epoch on a Collection declared
        `{ scheme: 'edv' }` against a v0.5 server
  - [x] A configuration write (a rename, a `backend` change, a recipient
        rotation) on an encrypted Collection that carries no annotations
        succeeds
  - [x] The five live suites and the one `governed-log` case WCL-41 left red
        pass: `blinded-find`, `edv-chunked-add`, `edv-codec-roundtrip` (both
        encrypted blocks), `key-epochs`, and "a direct encryption write on the
        Description is refused"

The v0.5 merge put the `encryption` descriptor and the `custom` envelope in one
object, and the spec requires every write of that object on an encrypted
Collection to carry a conforming envelope -- an omitted `custom` is a 422,
because an encrypted Collection's annotations cannot be cleared to a plaintext
state. A configuration write can satisfy that by forwarding the stored envelope
verbatim, which is what the client now does, but only when one is stored.

Two flows have none to forward. The first is the documented two-step
provisioning of an encrypted Collection: declare it `{ scheme: 'edv' }`, then
call `ensureFirstEpoch` to install epoch 0. That second call is a
compare-and-swap of `encryption`, so it is a write of the merged object -- and
at that moment no key material exists anywhere, so no envelope can be sealed by
anyone. The server refuses it with 422. The flow is not recoverable by
reordering: creating the Collection with the full epoch-bearing descriptor in
one `POST` works (a create may omit `custom`), but that is not available to a
caller adopting a Collection that already exists, which is exactly what
`ensureFirstEpoch` is for. The second flow is a plain rename of an encrypted
Collection that has never been annotated.

The spec names the cleared state as "an envelope encrypting an empty object",
which suggests the client half: the epoch-installing write seals `{}` under the
epoch it just minted and sends it as `custom` with its `epoch` stamp. That is a
new permanent wire behavior (which epoch stamps the envelope, and whether every
rotation re-seals) and a new code path -- the recipient primitives do no
metadata sealing today -- so it is a maintainer decision, not a detail to pick
while landing WCL-41. The alternative is a spec and server carve-out: an omitted
`custom` on a Collection whose stored object has none is not a clearing attempt
and should be accepted.

Resolved 2026-09-12 by the maintainer, in favor of the second option and wider
than the carve-out: an omitted `custom` on a `PUT` of the Collection Metadata
object clears it on an encrypted Collection exactly as on a plaintext one, the
same full-replacement rule `epoch` already follows, and an empty `custom` object
clears it as well. A non-empty `custom` must still be a conforming envelope (422
otherwise). The "envelope encrypting an empty object" clearing convention is
retired. The spec text landed the same day (the Collection Metadata data model,
its lifecycle and error list, the content-types validation rule, and the
Resource-level counterpart), recorded as an amendment to the
container-descriptions decision.

The client needs no change: `storedAnnotations` already omits `custom` when the
stored object has none, so the two flows above send exactly the write the new
rule admits. What remains is the server half (drop the 422 for the omitted case)
and re-running the client's live suites against it -- the three acceptance boxes
stay open until that run is green.

Verified 2026-09-12 against the reference server carrying the rule: the full
was-client integration tier passes (11 files, 77 tests), including the five
suites and the `governed-log` case above.

### WCL-101: Discover the service description and select the spec version before the first structural request

- status: done (2026-09-13)
- priority: high
- labels: was-v0.5, discovery, api
- touches:
  - wallet-attached-storage-spec: waived -- the Service Description section is
    drafted on branch `service-description` (decision
    `_spec/decisions/0006-service-description.md`); the client implements that
    draft
  - storage-core: shipped -- SC-5 there, archived 2026-09-13; 0.15.0 exports
    `ServiceDescription`, `ServiceDescriptionVersionEntry`, and
    `PwsVersionEntry`, which this item consumes
  - was-teaching-server: shipped -- WAS-98 there (archived 2026-09-13) serves
    `GET /service` and the `Link: <...>; rel="service"` header on every response
  - was-client: shipped -- `src/internal/service.ts` (new), `src/WasClient.ts`
    (`service()`), `src/internal/request.ts` (the gate), `src/internal/paths.ts`
    (`spacesRoot` removed), `src/errors.ts` (`IncompatibleServerError`), README,
    ARCHITECTURE.md, and the 0.62.0 CHANGELOG entry
- acceptance:
  - [x] The public API names (the discovery method or helper, and any new error
        class) are settled with the maintainer before implementation (settled
        2026-09-13: `was.service()` returning `ServiceInfo`, discovery gating
        every signed request, `IncompatibleServerError`, and `NotSupportedError`
        for a missing `spaces` URL)
  - [x] The client finds the service description by following the
        `rel="service"` link from a response to any URL it holds, the 404 and
        308 responses included. It does not assume a fixed path, since the spec
        reserves none
  - [x] The document is fetched without a capability invocation and parsed into
        `ServiceDescription` from `@interop/storage-core`
  - [x] Version selection follows the spec's client rules: unknown `specs` keys
        are ignored, an entry without `version` is ignored, the highest version
        the client understands under `https://w3id.org/pws` is chosen, and no
        understood entry or a malformed document stops the client with a typed
        error
  - [x] A response without the `service` link identifies a pre-0.5 server. The
        client speaks only v0.5, so it stops there with the same typed error
        rather than falling back to v0.4
  - [x] The Spaces Repository URL comes from the chosen entry's `spaces` member
        instead of the hardcoded `spacesRoot()`. An entry with no `spaces` means
        the server does not implement the Spaces Repository
  - [x] `features` is exposed to callers as an open token list: unknown tokens
        are ignored, and an absent token reads as unsupported
  - [x] The client never gates behavior on `instance`
  - [x] Tests cover version selection against fixture documents, and the
        integration tier discovers the document from the reference server

Context: WAS v0.5 adds a negotiation step before any Space-scoped request. A
wallet choosing a host at signup, or deciding which URL layout to speak, has no
other server-level signal. Linksets and the Backend `features` array are
Space-scoped, and `/health` is not a protocol feature. The spec puts the
document behind a `Link` header with the `service` relation on every response,
served with `Access-Control-Allow-Origin: *` and with `Link` exposed to
cross-origin scripts, so a browser client can read it. The document also roots
the URL graph: with no fixed server-level paths, the client learns URLs such as
the Spaces Repository from it.

The `https://w3id.org/pws` key is provisional until the spec's rename registers
it. storage-core does not export it as a constant while it is provisional.

### WCL-42: A server-supplied `next` link is followed to any origin, with a signed zcap invocation

- status: done (2026-09-13)
- priority: high
- labels: security, api, correctness, fail-closed
- acceptance:
  - [x] A `next` that resolves outside the first page's origin, or outside its
        base path, ends the walk with a typed `WasServerError` instead of being
        fetched
  - [x] A test asserts the list of URLs actually requested during a walk, so a
        hostile `next` cannot silently receive an invocation
  - [x] `walkPages` takes a page-count bound with a generous default and raises
        a typed error naming the listing URL when it is exceeded
  - [x] The guard covers `WasClient.listSpaces`, `Space.collections()` /
        `collectionsPages()`, `Collection.list()` / `listPages()` /
        `listItems()`, and the public listing walk
  - [x] The CHANGELOG entry names this a security fix

`walkPages` (`src/internal/pagination.ts:122`) resolves the server's `next` with
`new URL(next, baseUrl)` and hands the absolute result to `fetchPage`. Nothing
compares it to `context.serverUrl`. Three verification agents reproduced the
same end-to-end result independently: a stub WAS server answering with
`next: "http://169.254.169.254/latest/meta-data/"` made the real client issue a
live request to that second origin, carrying an `authorization: Signature`
header keyed to the controller's `did:key` and a `capability-invocation` header
whose zcap id is `urn:zcap:root:<attacker url>`. The attacker's items were then
returned to the caller as the listing. The ezcap mechanism is settled: with no
bound capability, `ZcapClient.request` synthesizes `generateZcapUri({ url })`
for whatever URL it was given, and the confused-deputy prefix check lives in the
arm that only runs when a capability object was supplied.

The exposure is an arbitrary-URL dereference plus the controller DID and a
proof-of-possession handed to a third party, and attacker-chosen items merged
into a listing the caller believes came from its own server. It is a Node-side
problem in practice: in a browser the signature headers make the cross-origin
GET non-simple, so preflight blocks it. Correction to the original report,
widening the blast radius: this is not only `listSpaces` and the public walk.
`Collection.list()`, `listPages()` and `listItems()` are equally exposed
whenever the handle carries no capability, which is the ordinary owner case. The
page-count bound belongs here because it is the same trust boundary and the same
function: a stub whose every page returns a fresh cursor drove 5000 fetches with
`seen` and `items` growing without limit. No wire contract changes; a conformant
relative `next` is unaffected. discovered-from: whole-codebase review,
2026-09-11.

### WCL-41: v0.5 path layout -- container descriptions at `meta`, the merged Collection Metadata object, trailing-slash canonical URLs

- status: done (2026-09-13)
- priority: high
- labels: was-v0.5, breaking, paths, zcap, api
- blocked-by: nothing for the was-client half (the reference server serves the
  v0.5 route table as of was-teaching-server 0.31.0)
- touches:
  - wallet-attached-storage-spec: shipped -- WASS-29 landed the spec text
    2026-09-11 (decision
    `_spec/decisions/0005-container-descriptions-live-at-meta.md`, with its two
    2026-09-11 amendments)
  - was-client: `src/internal/paths.ts`, `src/Collection.ts`, `src/Space.ts`,
    `src/internal/describe.ts`, `src/internal/meta.ts`, `src/internal/grant.ts`,
    `src/edv/descriptorStore.ts`, the `./paths` subpath export (`src/paths.ts` +
    the `exports` block), and ARCHITECTURE.md -- which today states the
    invariants this change reverses (the independence of the `/meta`
    `metaVersion` ETag from the Collection Description's ETag, and the
    trailing-slash convention that "container endpoints carry a trailing slash,
    member endpoints do not")
  - storage-core: shipped -- storage-core 0.14.1 carries the merged wire type
    and `meta` in `RESERVED_COLLECTION_IDS`; this item consumes it
  - wallet-core: resolved -- WC-230 landed its code 2026-09-12 against
    was-client 0.61.0 (the single-verb Space capability's targets, and
    `readSpaceMetadata` at `meta`). Its merged-validator check found nothing to
    raise here. Every roster and epoch write goes through the governed arm,
    whose etag is the `meta/log` sub-resource's own validator, and wallet-core
    makes no annotation write. Its live round trip stays open on WC-230 itself
  - freewallet: waived 2026-09-13 to FW-523 -- its three `./paths` importers
    inherit the change, but several zcap minters hand-build WAS URLs and bypass
    the builders entirely; that item carries the fix
  - was-react: waived 2026-09-13 to WR-46 -- `WasRemoteStore.#putDescription`
    sends a partial body to the bare Collection URL, which after the merge would
    clear the `custom` envelope a description write cannot reach today; that
    item carries the fix
- acceptance:
  - [x] A `spaceMeta(spaceId)` builder exists beside `collectionMeta` and
        `resourceMeta`, and is exported from the `./paths` subpath
  - [x] `spaceCollections()` is deleted; `Space.collections()` walks
        `spacePath(spaceId)` -- the same `/space/{id}/` URL
        `Space.createCollection()` already posts to
  - [x] The Space description methods (`describe`, `describeWithEtag`,
        `replaceDescription`, `configure`) read and write `spaceMeta`
  - [x] The Collection description methods and the Collection metadata methods
        converge on one path and one validator. `describe()` and `meta()` return
        one merged object; `replaceDescription()` and `setMeta()` are one
        full-replacement write against `collectionMeta`; the two `readEtag` call
        sites become one
  - [x] `Collection.delete()` and `Space.delete()` target the trailing-slash
        container URLs
  - [x] `ifNoneMatch` on the merged Collection write means "create only if the
        Collection does not exist", and `Collection.configure` / `patchCustom`
        are re-expressed against the single validator: a configuration change
        now legitimately invalidates an in-flight annotation write, so the
        read-modify-write helpers retry rather than assume independence
  - [x] `delegateGrantAt`'s prefilled `target` and `spaceRootCapabilityId()`
        agree with the server's canonical `allowedTarget` for every operation.
        Signature verification fails on any mismatch, so this is checked against
        the reference server, not reasoned about
  - [x] `src/edv/descriptorStore.ts` (the encryption-descriptor store seam)
        reads and writes the descriptor through the merged object
  - [x] ARCHITECTURE.md's two affected statements are rewritten, and the
        CHANGELOG entry names this a breaking change
  - [x] The consumers listed under `touches:` are walked: every external call
        site that builds a root capability, an invocation target, or a pinned
        resource URL from the exported `spacePath` is re-audited against the
        canonical trailing-slash Space URL. Walked for wallet-core (WC-230); the
        freewallet and was-react walks were waived 2026-09-13 to FW-523 and
        WR-46

Context: WAS v0.5 moves a container's description to its `meta` sub-resource and
merges a Collection's description with its Metadata object. `GET`/`PUT` of a
Space description move from `/space/{id}` to `/space/{id}/meta`; the
Collection's move from `/space/{s}/{c}` to `/space/{s}/{c}/meta`, where they
join the object `meta()`/`setMeta()` already read and write. The two separate
ETags the client tracks today collapse into one `metaVersion`. Separately, a
container URL is now canonically written with a trailing slash, the Space became
an ordinary container (`GET` lists its Collections, `POST` creates one), and
`/space/{id}/collections/` is retired. The client currently encodes the opposite
of all three, and `internal/paths.ts` says why that matters: its trailing-slash
rules must match the server's per-operation `allowedTarget` exactly or signature
verification fails.

The blast radius outside this repo is the `./paths` subpath. `spacePath` is
imported directly by wallet-core and freewallet to mint root capabilities and
invocation targets, so retargeting it is not an internal refactor. Greenfield:
no alias for the v0.4 paths, and the version bump names the break.

Status 2026-09-12: the was-client half landed. `spacePath` / `collectionPath`
now return the canonical trailing-slash container URLs, and are the only
builders for them: a container lists its members, creates one and is deleted at
itself, so the `spaceItems` / `collectionItems` aliases are gone and no two
builders differ only by a slash or emit a bare container URL; `spaceMeta` joins
`collectionMeta` / `resourceMeta` and the `./paths` barrel. The Collection
handle reads and writes one object at `collectionMeta` under one `metaVersion`:
`describe` is the configuration read (no codec, so `custom` stays the stored
envelope) and `meta` the same read with `custom` decoded, while `configure`,
`replaceDescription`, `setMeta` and the `setName` / `setTags` patches are
full-replacement writes composed against a fresh read -- a configuration write
forwards the stored `custom` and `epoch` verbatim, an annotation write re-sends
the configuration -- each pinned to the version it composed against and rebased
on a 412 through the shared compare-and-swap loop. Descriptor discovery and
`meta()` now share one `GET`, since the descriptor and the persisted index
schema live in the same object. The canonical Space root target was verified
against was-teaching-server 0.31.0: the live
`test/integration/revocation.test.ts` passes against `/space/{s}/`.

Open: the cross-repo `touches:` entries (wallet-core WC-230, freewallet FW-523,
was-react WR-46), and the last acceptance box, which is the walk of those
consumers. storage-core 0.14.1 ships `meta` in `RESERVED_COLLECTION_IDS` and is
consumed. WCL-98, the encrypted-Collection blocker the live run surfaced, was
resolved the same day by the spec and server change that lets an empty or
omitted `custom` clear on an encrypted Collection; the full integration tier (11
files, 77 tests) passes against the reference server.

Closed 2026-09-13: wallet-core's entry resolved with WC-230's landed code, and
the freewallet and was-react entries were waived to FW-523 and WR-46, which the
maintainer takes on separately. Note that was-react still imports the deleted
`collectionItems` builder, so WR-46 is also a compile break against this
release.

### WCL-45: Rotation resolves its current epoch with the tolerant `pickEpoch`, re-admitting removed readers

- status: done (2026-09-13)
- priority: high
- labels: encryption, key-epochs, security, fail-closed
- touches:
  - freewallet, wallet-core, dcw: resolved 2026-09-13, no change needed. The
    call sites are wallet-core's `rotateUserKeyRoster` / `replaceUserKeyRoster`
    and the user-key cascade, and freewallet's app-revocation and unshare paths
    in `storageManager.ts`. Each lets the new `EncryptionError` propagate or
    logs it; none matches rotation errors by a name it would now misread.
    Freewallet's revocation pass already skips a descriptor with no
    `currentEpoch`. dcw calls neither function
- acceptance:
  - [x] `src/edv/recipients.ts:877` resolves the current epoch through the
        strict `currentEpochOf`, and `pickEpoch` is deleted once it has no
        callers
  - [x] A rotation against a descriptor whose `currentEpoch` is absent, or names
        an unlisted entry, refuses instead of computing a survivor set
  - [x] Both scenarios are covered by tests: the re-admission case and the
        silent-no-op case

Executed against the real `removeRecipient`. Served
`epochs: [E2{alice,mallory}, E1{alice,trent,mallory}]` with `currentEpoch`
omitted, Alice removing Mallory: the fresh epoch E3 was wrapped to Trent, and
Trent's key-agreement key unwrapped E3's secret to the same bytes Alice
unwrapped. A reader removed at the earlier rotation holds the post-rotation
collection key. The control run, with a correct `currentEpoch`, produced
`[alice]` alone. The second variant also reproduced: an unlisted `currentEpoch`
whose fallback lands on an epoch without the retiring kid makes `rotating`
false, so `removeRecipient` writes nothing and resolves successfully while the
removed reader keeps the epoch every writer is sealing under.

`pickEpoch` has exactly one caller in the repo, this line, and no test coverage.
The strict `currentEpochOf` was added in c02716f (2026-09-11) and routed only to
the seal-plaintext sites. The tolerant form's stated rationale does not hold for
its one caller: a rotation that cannot identify the current epoch is computing
its survivor set from an untrusted list, which is exactly when it should refuse.
The spec agrees -- `currentEpoch` is REQUIRED and must name an entry in `epochs`
-- so the fallback exists only to tolerate a descriptor that cannot conformantly
exist. No wire change.

discovered-from: whole-codebase review, 2026-09-11.

Landed 2026-09-13: the rotation refuses an absent `currentEpoch` itself, then
resolves the entry through `currentEpochOf`, which refuses an unlisted one.
`pickEpoch` is deleted. The seal-side callers of `currentEpochOf` still fall
back to the last listed epoch when `currentEpoch` is absent; this item did not
change that.

### WCL-48: A 412 raised by `store.read()` escapes `compareAndSwap` instead of rebasing

- status: done (2026-09-13)
- priority: high
- labels: cas, conditional-writes, log, correctness
- touches:
  - wallet-core: resolved 2026-09-13 -- its roster, cascade, and revocation
    suites (6 files, 132 tests) pass with `@interop/was-client` aliased to this
    change's source. The full suite's 86 failures are identical against the
    published 0.62.0, so this change causes none of them
- acceptance:
  - [x] A `PreconditionFailedError` from `store.read()` is treated as a rebase,
        the same as one from `store.replace()`
  - [x] A store whose `read()` throws a 412 once completes through the retry
        rather than surfacing the error to the caller
  - [x] `logGovernedDescriptorStore`'s module docstring and ARCHITECTURE.md
        agree with the code

`compareAndSwap`'s loop body is `const current = await store.read()`
(`src/internal/cas.ts:121`) with no enclosing try. The only two try/catch blocks
wrap `store.create` and `store.replace`. `readGoverned` raises
`PreconditionFailedError({ status: 412 })` at
`src/edv/logGovernedDescriptorStore.ts:534`, reached from the governed store's
`read()`, which `src/edv/recipients.ts:1192` adapts verbatim into the
`CasStore`. `recipients.ts` has a single catch, on the zcap-revoke step, so
nothing upstream rebases either.

Proven by execution: a fake store whose `read()` throws a 412 once yields
`reads === 1` and the raw `PreconditionFailedError` out of `compareAndSwap`,
while the identical 412 from `replace()` yields `reads === 2` and succeeds. The
documented rebase loops therefore fail on the first attempt against the governed
store. Both the module docstring and ARCHITECTURE.md claim the recipient loops
rebase on this class, so code and documentation disagree today. This sits
between two archived items: WCL-25 landed `src/internal/cas.ts` and WCL-17
landed the governed store whose `read()` can throw a 412; neither one's
acceptance covers the pair. No wire artifact changes. discovered-from:
whole-codebase review, 2026-09-11.

### WCL-102: The seal-side epoch lookup still falls back to the last listed epoch when `currentEpoch` is absent

- status: done (2026-09-13)
- priority: high
- labels: encryption, key-epochs, security, fail-closed
- touches:
  - freewallet, wallet-core, dcw, was-react: resolved 2026-09-13, no change
    needed. No source, test, or fixture in the four repos passes a descriptor
    with `epochs` but no `currentEpoch` to a codec or cipher build. Their
    descriptors come from `initRecipients` / `removeRecipient` or fixtures that
    set `currentEpoch`
  - storage-core: `CollectionEncryption.currentEpoch` is typed optional while
    the spec makes it REQUIRED; whether to tighten the type is a separate change
    there, and this item does not depend on it. Resolved 2026-09-13 as out of
    scope
- acceptance:
  - [x] `currentEpochOf` refuses a descriptor whose `currentEpoch` is absent,
        with the same `EncryptionError` family as an unlisted one
  - [x] The rotation's own absence check in `src/edv/recipients.ts` is removed,
        since `currentEpochOf` then covers it
  - [x] `resolveEpochKeys` and `encryptOnlyEdvCodec` refuse such a descriptor,
        each covered by a test
  - [x] The documented fallback is removed everywhere it is stated: the
        `currentEpochOf` JSDoc, the `encryptOnlyEdvCodec` JSDoc and inline
        comment, the `edv-doc-cipher.test.ts` case "falls back to the last
        listed epoch when currentEpoch is absent" (which flips to a refusal),
        and the `review-fixes.test.ts` header's "descriptor-order fallback"

WCL-45 made rotation refuse a descriptor whose `currentEpoch` is absent or
unlisted. The two seal-side callers of `currentEpochOf`, `resolveEpochKeys`
(`src/edv/epochKeys.ts:130`) and `encryptOnlyEdvCodec`
(`src/edv/EdvCodec.ts:2214`), still refuse only the unlisted case. With
`currentEpoch` absent they seal new writes to the last listed epoch, on the
stated assumption that the roster is append-ordered newest-last. Nothing on the
read path checks that order. `descriptorDefect` checks only the scheme version
and that `epochs` is non-empty, and the `hasKeyEpochs` predicate, which does
require `currentEpoch`, is not consulted before a codec opens.

The exposure is the one WCL-45 closed for rotation. A descriptor served as
`epochs: [current, older]` with `currentEpoch` omitted seals every new write to
`older`, whose key a reader removed at the later rotation still holds. This
follows from the code but was not reproduced end to end. A governed Collection
is covered by its log verification, since the projection must equal the verified
head. An ungoverned descriptor is not (see WCL-47). The spec makes
`currentEpoch` REQUIRED, so the fallback tolerates only a non-conformant
descriptor.

A probe making `currentEpochOf` refuse an absent `currentEpoch` failed exactly
one unit test, the doc-cipher case that asserts the fallback, so the change is
contained. No wire change.

discovered-from: WCL-45, 2026-09-13.

### WCL-103: Batch blinded-index declaration `Collection.declareIndexes`

- status: done (2026-09-14)
- priority: medium
- labels: blinded-index, search, api
- touches:
  - was-react (ARCHITECTURE.md, `src/storage/wasRemoteStore.ts`
    `declareBlindedIndexes`): not yet filed -- its per-attribute `declareIndex`
    loop is a candidate to switch to this batch form, one metadata write instead
    of N
- acceptance:
  - [x] `Collection.declareIndexes({ indexes })` settles every requested
        attribute in one compare-and-swap read and one conditional write,
        sharing one `revision` bump and one `addedIn` across newly added entries
  - [x] Per-entry semantics match `declareIndex`: an attribute already declared
        on the same terms is skipped; one already declared with different
        uniqueness throws `ValidationError`
  - [x] A duplicate attribute within one call is deduplicated when terms agree
        and rejected with `ValidationError` when they disagree
  - [x] `declareIndex` is a thin wrapper over `declareIndexes` (one entry), so
        the compare-and-swap logic exists once
  - [x] Unit coverage in `test/node/blinded-index.test.ts` for the batch write
        count, partial-missing writes, no-write-when-complete, and the
        uniqueness-mismatch throw

`@interop/was-react`'s `wasRemoteStore.ts` loops `declareIndex` once per missing
blinded-index attribute, each call its own compare-and-swap read+write of the
collection's `/meta` object. `declareIndexes` lets a caller declaring several
attributes at once -- a fresh collection's whole blinded-index schema, say --
settle them in one read and one conditional write.

### WCL-73: Space API hygiene

- status: done (2026-09-14)
- priority: low
- labels: space, api, correctness, conditional-writes, errors
- touches:
  - wallet-core (`src/clientAnnex/log.ts` `ensureClientAnnexSpace`): not yet
    filed -- it returns `space.configure()` as `Promise<SpaceMetadata>`, which
    no longer type-checks now that the returned `type` is optional. Its call
    supplies `type`, so the value at runtime is unchanged
- acceptance:
  - [x] `replaceDescription` builds its body with the handle's own `id` last, so
        a spread-in `id` cannot retarget the write
  - [x] `configure()`'s JSDoc matches the code on `type`, and the returned
        description does not claim a `type` it never read
  - [x] `writeHeaders` rejects `ifMatch` and `ifNoneMatch` together with a
        `ValidationError`
  - [x] `registerBackend()` and `import()` throw `WasServerError` naming the
        response content type instead of asserting non-null on an absent body
  - [x] `isPublic()`'s JSDoc carries the same "or it is not visible to you"
        caveat `getPolicy`'s already has, on all three handles

Five small defects in one file. `replaceDescription` spreads the caller's
description after the handle's own `id`, so a caller passing a read description
back with one field changed can retarget the write; proven at both the type
level (`tsc --strict` accepts it through a spread) and at runtime (the PUT went
to one Space carrying another Space's id). `configure()` computes
`desc.type ?? current?.type`, so a caller's `type` is forwarded on updates and
the server rejects a change with a 400, while the JSDoc claims the current
`type` is re-sent unchanged; the returned description also fabricates
`['Space']` on the `force` path where `current` is null, and the exposed
consumer is `wallet-core/src/keyring/unlockSpace.ts:90`. `writeHeaders` emits
`if-match` and `if-none-match: *` from independent branches, and the two can
never both pass, so the combination is an always-412 request the type system
accepts today. `registerBackend()` and `import()` assert non-null on a body that
is `null` for any 2xx the HTTP client did not parse as JSON, where the sibling
paths throw `WasServerError`. `isPublic()` answers `false` when the policy is
not visible to the caller; that is the conservative direction rather than the
wrong one, so this last one is a documentation fix. discovered-from:
whole-codebase review, 2026-09-11.

### WCL-104: Reject `ifMatch` with `ifNoneMatch` on every write route

- status: done (2026-09-14)
- priority: low
- labels: conditional-writes, errors, collection, edv
- acceptance:
  - [x] `Collection.configure()`, `replaceDescription()`, and `setMeta()` throw
        `ValidationError` for `ifMatch` plus `ifNoneMatch: true` instead of
        taking the create branch and dropping `ifMatch`
  - [x] A codec-driven `Resource.put` with both throws `ValidationError` rather
        than a local `PreconditionFailedError`
  - [x] Unit coverage for both routes

`writeHeaders` now rejects the pair, but two routes never reach it with both
members. `Collection#writeStored` checks `ifNoneMatch === true` first and sends
a create with `ifMatch` discarded, so the call succeeds or fails on the create
alone. The conditional codec write path runs `assertPreconditionAgainstPreRead`
before building headers, and it answers the pair with a 412 whichever way the
pre-read comes out. Both hide a caller bug behind a result that looks like a
race. discovered-from: WCL-73.

### WCL-100: `Space.configure()` writes the Space Metadata object without a validator

- status: done (2026-09-14)
- priority: medium
- labels: conditional-writes, cas, space, api
- acceptance:
  - [x] `Space.configure()` pins its `PUT` to the `ETag` of the read it merged
        against (the caller's `current`, or its own `describeWithEtag()`) when
        the backend serves one
  - [x] A `412` rebases through the shared `compareAndSwap` loop: re-read,
        re-merge, re-send, as `Collection.configure()` does
  - [x] The compose-against-baseline, pinned-write, rebase-on-412 shape lives in
        one internal helper that both `Collection.#writeStored` and the Space
        write use, rather than a second hand-rolled loop
  - [x] Unit tests cover the lost-race rebase and the no-validator backend for
        the Space write

`Space.configure()` is still the pre-v0.5 unconditional read-then-`PUT`: it
reads the current object (or takes the caller's), merges `name`, `controller`
and `type` over it, and sends a full replacement with no `ifMatch`. Two
concurrent configures (a rename and a controller change, say) silently clobber
each other. The v0.5 merge rebuilt the Collection side of the same shape --
`Collection.#writeStored` composes against a fresh baseline, pins the write, and
rebases on a `412` -- and ARCHITECTURE.md now describes both containers as one
object under one `metaVersion` validator, so the two are expected to behave the
same way and do not. `replaceDescription()` already accepts `ifMatch` for a
caller-driven compare-and-swap; this item makes the merging convenience safe by
default rather than leaving the pin to the caller.

discovered-from: simplify review of the WCL-41 diff, 2026-09-12.

### WCL-57: `epochRostersEqual` does not compare the whole epoch configuration

- status: done (2026-09-15)
- priority: medium
- labels: encryption, key-epochs, spec
- touches:
  - was-react, wallet-core: they use `epochRostersEqual` as a
    cipher-invalidation trigger, and a stricter comparator makes more
    descriptors compare unequal, so their refresh paths need a check. was-react
    (`src/storage/localStore.ts` `applyRemoteDescriptor`): filed as WR-48 -- a
    cached descriptor whose `version` differs from the served one (for example
    absent against `1`) now triggers one `rebuildCipher`, which is harmless.
    wallet-core: no action -- it does not call `epochRostersEqual`
- acceptance:
  - [x] `epochRostersEqual` compares `scheme` and `version` alongside
        `currentEpoch` and the ordered epoch ids
  - [x] Its JSDoc says it implements the spec's pinned epoch configuration, and
        that recipients inside an epoch and the `hmac` member are deliberately
        outside it

The spec defines the value a client pins as the epoch configuration: its
`scheme`, `version`, `currentEpoch`, and the ordered list of epoch ids. The
point-state integrity story rests entirely on that pin. `epochRostersEqual`
compares only `currentEpoch` and the ordered epoch ids, and never reads `scheme`
or `version`. It is the only comparator this package exports for the purpose,
and ARCHITECTURE.md presents it as roster identity, so a consumer pinning with
it believes it is implementing the spec's pin and is not. Concretely it reports
"same roster" for a descriptor whose `version` moved from 2 down to 1, or whose
`scheme` changed. No live impact while `EDV_SCHEME_VERSION` is 1 and `edv` is
the only scheme; it becomes live at the first version bump. The refusable
version decrease this closes is the pin half of what 60 observes on the codec
side.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-16: Sync read path cannot decode chunked documents

- status: done (2026-09-15)
- priority: medium
- labels: encryption, streams, sync
- acceptance:
  - [x] A chunked envelope arriving through a sync pull either decodes
        (context-carrying DocCipher) or is skipped/marked gracefully with a
        defined recovery story, instead of throwing per-envelope and wedging the
        pull pipeline

discovered-from: WCL-2 (review finding, 2026-08-12). `add()` can now mint
documents the package's own sync decrypt path structurally cannot read:
`docCipher.decrypt` calls `codec.decode` with no `CodecRequestContext`, so a
chunked envelope reaching a synced collection throws `EncryptionError`
per-envelope during pull, with no skip affordance in `src/sync/`. The fail-loud
behavior is deliberate and documented in ARCHITECTURE.md, but one routed blob
can wedge a downstream pull pipeline (freewallet, was-react). Design question:
either `createEdvDocCipher` gains an optional requester/context so sync replicas
can reassemble, or the sync layer gains a graceful-skip contract for
stream-profile envelopes (surface them as opaque and let the app fetch via a
live handle). Related: WCL-11 is the push-side sibling (schema emission), not
this.

Take the seam change once, together with WCL-43. `decode` takes
`(response, expectedId?, context?)`. This item is the third parameter, an
availability gap that `src/codec.ts` documents as deliberate for sync. WCL-43 is
the second, an integrity gap nothing documents as intended. Both are fixed by
giving `DocCipher.decrypt` the caller's resource id and context, so splitting
the breaking change across two releases would churn the same downstream
consumers twice.

Closed 2026-09-15 with WCL-43, in one `DocCipher.decrypt` change. The
context-carrying option was taken: `decrypt` takes an optional `context`
(`collection.codecContext()`, now public), and `createEdvDocCipher` /
`createRefreshingEdvDocCipher` take an optional `spaceId` that gives the codec a
route to the chunk resources. With both, a chunked envelope decodes to a `Blob`.
Without them it still throws, so a consumer that syncs chunked blobs must wire
them in.

### WCL-43: The sync decrypt seam carries no resource id, so the envelope-to-resource binding is never verified

- status: done (2026-09-15)
- priority: high
- labels: sync, encryption, integrity, codec-seam, security, breaking
- touches:
  - was-client: `DocCipher.decrypt` in `src/sync/types.ts`,
    `src/edv/docCipher.ts`, `src/sync/plaintextCipher.ts`, and ARCHITECTURE.md's
    "Tamper resistance" paragraph, which today asserts the binding is verified
    on decode: done in this item
  - wallet-core: `src/sync/engine.ts`, `src/sync/types.ts`,
    `src/keyring/record.ts`, `src/descriptors/index.ts`: filed as WC-234 --
    every `decrypt` call passes the resource id, including the `decryptDoc`
    sync-engine dependency. Open there: which id the unlock record's sealed
    members pass, since they are not stored as separate resources
  - was-sync: `src/conflictHandler.ts` and the feed mapping that would supply
    the id: filed as WS-14 -- the conflict handler's `decrypt` closure carries
    the row id, and an `IntegrityError` is rethrown instead of landing in the
    `undecryptable` bucket
  - freewallet, was-react: every `DocCipher.decrypt` call site: filed as FW-533
    and WR-49 -- same required `id`, plus an `IntegrityError` classification
    distinct from the no-key buckets. Neither syncs chunked blobs today, so
    `context` and `spaceId` stay unwired
  - dcw: `app/lib/sync/engineStart.ts` and `app/lib/sync/smokeTest.ts`: filed as
    DCW-78, after WC-234
- acceptance:
  - [x] `DocCipher.decrypt` takes the resource id and forwards it as `decode`'s
        `expectedId`
  - [x] A replication read of an authentic envelope for resource A presented
        under feed row id B throws `IntegrityError`
  - [x] The `./sync` subpath's breaking change is taken once, jointly with
        WCL-16, rather than twice
  - [x] ARCHITECTURE.md's tamper-resistance claim matches the code

`ResourceCodec.decode(response, expectedId?, context?)` has three parameters.
`docCipherOverCodec.decrypt` passes only the first (`src/edv/docCipher.ts:354`),
because `DocCipher.decrypt` has no id in its signature at all, so no sync
consumer can supply one. Both id checks in `EdvCodec.#verifyResourceSlot` are
gated on `expectedId !== undefined`, so both are skipped on every replication
read. Proven by execution: the same envelope throws `IntegrityError` when
decoded with the wrong id and resolves silently with no id. Under the default
`idDerivation: 'content'` the skipped check is the ciphertext re-derivation
rather than the `was.resource` comparison; the defect is the same either way. A
consumer sweep found nothing compensating: every downstream call site either
passes no id or uses one only for a log line or a cache key.

Relationship to WCL-16, stated precisely because the two share a call site and a
signature change: WCL-16 is about the third parameter, `context`, and its harm
is availability (a chunked envelope wedges a pull). That omission is deliberate
and documented in `src/codec.ts`. This item is about the second parameter,
`expectedId`, and its harm is integrity. That omission is documented nowhere as
intended, and ARCHITECTURE.md asserts the opposite guarantee. A context-carrying
`DocCipher` that still calls `decode(response, undefined, context)` skips
exactly the same two checks, so WCL-16 does not close this. Sequence the two so
one breaking `DocCipher` change covers both. WCL-51 rides the same signature
change. No new wire artifact: the binding already exists and is unchanged.

discovered-from: whole-codebase review, 2026-09-11.

Closed 2026-09-15 (was-client 0.66.0), jointly with WCL-16 and the was-client
half of WCL-51. `decrypt` is `{ id, envelope, context? }` with `id` required,
and resolves `Json | Blob`.

### WCL-51: A content id is minted at write time and never verified at read time

- status: done (2026-09-15)
- priority: high
- labels: sync, integrity, correctness
- touches:
  - freewallet: `src/stores/remoteDirectStore.ts:340` and
    `src/stores/browserStore.ts:764` / `:1021` recompute the content id from the
    decrypted payload and never compare it: filed as FW-534. Those collections
    use `idDerivation: 'content'`, so the resource id hashes the ciphertext and
    legitimately differs from the plaintext `cidFrom(vc)`. The sites feed a
    dedup index, not a WCL-51 check
  - dcw: `app/lib/walletBackupCore.ts` and `app/lib/publicLink.ts` call the same
    helpers: walked in DCW-78. `publicLink.ts` mints the resource id of the
    plaintext `public-credentials` collection, so the seam check covers it once
    DCW-78 threads the id. `walletBackupCore.ts` uses it only as a backup-format
    dedup key
- acceptance:
  - [x] `createPlaintextDocCipher.decrypt` refuses when the recomputed content
        id does not match the id it was handed, as a typed `IntegrityError` the
        sync predicates can classify
  - [x] A tampered envelope presented under an honest id is rejected rather than
        resolved
  - [x] The downstream recompute sites are walked and either compare or delegate
        to the seam

`createPlaintextDocCipher.encrypt` returns
`{ id: contentCid(data), envelope: data }` and `decrypt({ envelope })` is
`return envelope`, verbatim, with nothing to compare against
(`src/sync/plaintextCipher.ts:30-43`). Proven: encrypt(A) mints one id, then
`decrypt({ envelope: B })` resolves B unchanged while `contentCid(B)` is a
different value that nothing observes. For a plaintext content-addressed
collection the content id is the only integrity mechanism, so this is an unused
check rather than a missing one. A plaintext collection is server-visible
anyway, so the threat model is a tampering server; what makes it high rather
than medium is replica-to-replica propagation, since the next push re-asserts
the forged document under the old id.

Correction to the original evidence, which strengthens the item rather than
weakening it: the claim that `contentCid` / `cidFrom` have no read-side caller
is false. Freewallet and dcw both recompute the value from the decrypted payload
and store it beside the resource id, feeding a dedup index. A mismatch is never
checked at any of them. So consumers already compute exactly the value the check
needs and simply do not compare it. This rides the same `DocCipher.decrypt`
signature change as WCL-43 and belongs in the same pass. Not a new wire
artifact: the content id derivation already exists and is unchanged, and only
the read-side comparison is new -- so no byte-level sign-off is needed here.

2026-09-15: the was-client half landed with WCL-43 (was-client 0.66.0).
`createPlaintextDocCipher.decrypt` throws `IntegrityError` on a content-id
mismatch, and `isIntegrityError` is on the `./sync` subpath. The downstream walk
is done: see the `touches:` annotations. No site needed a new comparison, and
the dcw plaintext site delegates to the seam through DCW-78.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-50: Preconditions are emitted without probing that the backend enforces them

- status: done (2026-09-15)
- priority: high
- labels: conditional-writes, fail-closed, cas, log, encryption, correctness
- touches:
  - wallet-core: `ensureUserKeyRoster`, the log-governed descriptor store, and
    the sync engine, which classify the port's thrown errors by name: filed as
    WC-235 for the `keys-collectionLogStore` test fake, which lacks a `features`
    probe. No production change: `NotSupportedError` matches no classified name,
    so it propagates as fatal
  - was-sync: the same error-name classification on the `./sync` subpath: filed
    as WS-15 -- `pushWrites.ts` retries every non-conflict error with backoff,
    so the permanent refusal would be retried forever
  - freewallet, dcw: `addRecipient` / `removeRecipient` / `replaceRecipient`,
    `ensureSpaceAndCollection`, and any supported backend that would be left
    unable to write a log: no action -- both target only the reference server,
    whose server-managed backends all advertise `conditional-writes`, and
    neither registers an external backend
- acceptance:
  - [x] A shared refusal helper lives beside `writeHeaders` in
        `src/internal/conditional.ts`, so the refusal messages do not drift
  - [x] `compareAndSwap` refuses when `read()` returns a value with no
        validator, with an explicit opt-out for a caller that wants the
        unconditional write
  - [x] `src/log/logStore.ts` refuses `append` and `create` on a backend that
        advertises no `conditional-writes`
  - [x] `src/sync/port.ts` refuses a precondition-bearing write against a
        backend advertising no `conditional-writes`
  - [x] `Resource.put` / `Resource.delete` gate a caller-named precondition on
        the same probe when the codec is non-conditional
  - [x] `resourceDescriptorStore` reaches the probe the `Resource` handle
        already holds

Four modules assert that their guards "ride the backend's `conditional-writes`
feature" while only the EDV insert path actually consults it -- grep confirms
`internal/write.ts` is the sole `conditional-writes` call site in `src/`. The
family has one root and three independent instances. `src/internal/cas.ts:160`
is the root for the CAS group: driven with a store whose `read()` resolves
`{ value, etag: undefined }`, `compareAndSwap` calls `replace` once with
`ifMatch: undefined` and reports success, and `writeHeaders` emits no header for
an undefined validator, so the request is a plain PUT. Every CAS caller inherits
that with no local defect of its own: `Collection.declareIndex`,
`casUpdateDescriptor` for the recipient primitives, the late encryption
declaration in provisioning, and both plain descriptor stores, which only
forward the `ifMatch` the loop hands them. `src/log/logStore.ts:154`,
`src/sync/port.ts` (`putContent`, `deleteContent`, `writeAck`) and
`Resource.put` / `Resource.delete` on the non-conditional branch are separate
instances of the same policy gap, each with its own owner. The counter-evidence
that this is an omission rather than a design choice sits in the same codebase:
`logGovernedDescriptorStore.replace` and `upsertResource`'s masked-404 branch
already refuse for exactly this reason.

Two scope limits the item must carry. WCL-32 settled the description-endpoint
case the opposite way -- a precondition on the Collection Description or Space
endpoint is a property of those endpoints rather than a backend feature token,
so no client gate is possible there -- which refutes the
`collectionDescriptorStore` half of this family. Scope the work to the sites
where the feature token actually exists: Resource writes, EDV document writes,
the log store, and the sync port. And the CAS guard must key on "the read
returned no validator" rather than on the feature token alone. The residual
exposure this closes is the backend that emits an `ETag` on GET but ignores
`If-Match` / `If-None-Match` on PUT, which is the common case for BYOS object
stores and is why WAS carries the token at all. One item rather than five, so
the decision is made once.

discovered-from: whole-codebase review, 2026-09-11.

2026-09-15: landed in was-client 0.66.0. The refusals throw the existing
`NotSupportedError`, built by `unenforcedPreconditionError` in
`src/internal/conditional.ts`. `composeAndSwap` (Collection and Space Metadata
writes) and `patchCustom` (`setName` / `setTags`) take the `allowUnconditional`
opt-out. `logGovernedDescriptorStore.replace`'s no-validator refusal moved to
the same helper, so it is now `NotSupportedError` rather than `ValidationError`.
The handles expose their probe as `Collection.features` / `Resource.features`.
Resource metadata writes (`Resource.setMeta`) remain ungated, as the acceptance
list scoped them out.

### WCL-105: The affordance gate refuses where the spec says degrade to last-writer-wins

- status: done (2026-09-16)
- priority: medium
- labels: conditional-writes, conformance, spec-alignment
- touches:
  - wallet-attached-storage-spec: WASS-40 settles the surrounding question; this
    item is the client-side conformance half and stands whichever way that goes
- acceptance:
  - [x] The divergence is resolved in one direction: either the spec gains text
        sanctioning a fail-closed refusal, or was-client stops refusing
  - [x] Whichever way it goes, the reason is recorded rather than left implicit
        in `unenforcedPreconditionError`'s message
  - [x] `touches:` entries resolved

Context: `assertPreconditionEnforced` refuses a guarded write with
`NotSupportedError` when the collection's backend advertises no
`conditional-writes` (`src/internal/conditional.ts:180-221`), on the reasoning
that a backend which ignores the header turns a guarded push into a silent
overwrite. The spec does not ask for that. Its Conditional Requests section is
only a SHOULD: "a client SHOULD use these preconditions only against a backend
that advertises support." The EDV-over-WAS profile is more explicit in the other
direction, where the mapping "degrades to advisory: the `sequence` is still
carried in the envelope but is not enforced, and writes are last-writer-wins".
No normative text anywhere tells a client to refuse the write. (Section names
rather than line numbers: spec.md was mid-edit when this was filed. Both
quotations verified against the working tree 2026-09-16.)

So this client is stricter than the specification it implements, and a
conformance suite written from the spec would not predict its behavior. The
refusal is probably the better engineering choice, which is the point: if it is,
the spec should say so, and if it is not, the client should stop doing it. Note
the inconsistency is already internal as well -- `patchCustom`
(`src/internal/meta.ts:237-252`) degrades rather than refusing, dropping its
compare-and-swap pin so `setName` / `setTags` become last-write-wins, which is
exactly what the spec describes and exactly what the rest of the gate refuses to
do.

If WASS-40 lands as proposed this item mostly evaporates, since there would be
no non-advertising backend left for either behavior to apply to. It is filed
separately because it is a live conformance question today and does not depend
on that outcome.

discovered-from: was-sync WS-15.

2026-09-16: WASS-40 shipped. Conditional writes are now a baseline server
requirement in spec.md, so the divergence this item tracked is resolved by
outcome (b): the client stops refusing, because there is no longer a
non-advertising backend for the refusal to apply to. The removal work is
WCL-106.

2026-09-16: closed by WCL-106. The client stops refusing: the gate and the whole
backend-feature probe behind it are deleted, and `patchCustom` is now an
always-guarded compare-and-swap rather than the pin-dropping outlier this item
named. `unenforcedPreconditionError` keeps only the no-validator reason, whose
message now says why a validator can be missing (a browser client whose CORS
configuration does not expose `ETag`).

### WCL-106: Remove the backend-feature-vocabulary gates now that they are baseline or moved

- status: done (2026-09-16)
- priority: medium
- labels: conditional-writes, cleanup, breaking, wire-contract
- touches:
  - storage-core: `BackendDescriptor.features` (`src/was.ts:664`) and
    `BackendRegistration.features` (`src/was.ts:727`) are removed from the wire
    type entirely, since no backend-level token remains once
    `conditional-writes` is baseline and `chunked-streams` moves to WAS-EC
    conformance; `PwsVersionEntry.features` (`src/was.ts:859`) gains the note
    that `changes-query` lives there. Suggest filing an SC-N item there to make
    the type change; not filed by this item. ANNOTATED (2026-09-16): still
    unfiled. This client no longer reads either member, so the stale wire types
    cost nothing until someone removes them
  - was-client (this repo): README.md and ARCHITECTURE.md carry the backend
    `features` examples and the "Feature detection" section documenting the
    probe this item deletes; both need rewriting alongside the code. DONE
    (2026-09-16): the README's backend walkthrough now reads the service
    description's `features`, and ARCHITECTURE's section is rewritten as
    "Conditional writes"
  - encrypted-collections-spec ECS-9: `blinded-index-query` and
    `governed-history-logs` move to a version entry ECS-9 has not yet registered
    an identifier for; the `WasTransport` gate on `blinded-index-query` cannot
    move until that identifier exists (partial blocker on this item's own
    acceptance box for that gate; everything else proceeds without it). VERIFIED
    (2026-09-16): ECS-9 is still `status: todo` and encrypted-collections-spec
    declares no identifier, so the gate is removed here rather than moved, and
    `find()` relies on the server's `501` in the meantime
- acceptance:
  - [x] `assertPreconditionEnforced`'s `no-feature` reason and
        `preconditionsEnforced` (`src/internal/conditional.ts:130-243`) are
        deleted; `no-validator` stays, since a read with no `ETag` is a separate
        problem that survives (CORS can hide the header from a browser client)
  - [x] `WasTransport.insert`'s non-atomic `HEAD`-then-`PUT` fallback
        (`src/edv/WasTransport.ts:313-345`) and `#exists()`
        (`src/edv/WasTransport.ts:445-455`) are deleted; insert is always the
        atomic `PUT` with `If-None-Match: *`
  - [x] `compareAndSwap`'s `allowUnconditional` opt-out
        (`src/internal/cas.ts:98-134,186,275`) and `patchCustom`'s pin-dropping
        fallback (`src/internal/meta.ts:203-252`) are deleted; `setName` /
        `setTags` become an always-guarded compare-and-swap
  - [x] `Collection.ts:451-458`'s no-client-side-remedy limitation (a descriptor
        rotation landing between a compose read and an unconditional write) is
        deleted; the write is always conditional now
  - [x] `chunked-streams` leaves the vocabulary:
        `EdvCodec.#assertChunkedStreams` and its `chunked-streams` /
        `descriptorAbsent` checks (`src/edv/EdvCodec.ts:778-800`, called at
        `:863` and `:1093`) are deleted; serving the chunk endpoints is a bare
        requirement of WAS-EC conformance and needs no client-side gate,
        matching the pattern `Collection.find()` already uses for
        `blinded-index-query` ("no client-side feature probe -- a backend that
        does not implement the profile answers 501")
  - [x] `changes-query` moves to the service description: `Collection.ts:1693`
        and `:1787`'s doc comments ("Requires the collection's backend to
        advertise the `changes-query` feature") are rewritten to say it is
        advertised server-wide (`client.service().features`, already readable
        via the existing `PwsVersionEntry` machinery in
        `src/internal/service.ts`); no new client-side gate is added, since
        `changes()` already has none and relies on the server's `501`
  - [x] `WasTransport.#requireFeature('blinded-index-query', ...)`
        (`src/edv/WasTransport.ts:462-490`) moves from probing the collection
        backend descriptor to reading the WAS-EC version entry in the service
        description, once ECS-9 names that entry (see the `touches:` note above;
        left as the open half if ECS-9 has not landed yet). RESOLVED
        (2026-09-16) by removal rather than by moving: ECS-9 has not landed, so
        the gate is deleted with the rest of the probe and `find()` relies on
        the server's `501`. Re-adding it over the WAS-EC version entry is
        WCL-108, a new mechanism rather than a survivor of this one
  - [x] With no backend-level token left to probe, the backend-descriptor probe
        itself is deleted: `src/internal/features.ts` in full (`FeatureProbe`,
        `BackendFeatures`, `collectionBackendFeatures`, `descriptorAbsent()`,
        `DESCRIPTOR_ABSENT_STATUSES`), its exports from `src/index.ts` and
        `src/codec.ts`, `Collection.#features` and the public
        `Collection.features` getter, `Resource.#features`, and every
        `features:` parameter threaded through `src/internal/write.ts`,
        `src/internal/meta.ts`, `src/internal/conditional.ts`,
        `src/sync/port.ts`, `src/edv/EdvCodec.ts`, and
        `src/edv/WasTransport.ts`. A future probe over the WAS-EC version entry
        (the item above) is a new, separate mechanism, not a survivor of this
        one
  - [x] `Collection.backend()`'s doc comment (`src/Collection.ts:1935-1948`)
        drops the `features` advertisement paragraph; the `BackendDescriptor`
        type no longer carries a `features` member once the storage-core touches
        entry lands
  - [x] Public types whose `etag?` was optional only because a non-conditional
        backend could omit the validator become required; types whose `etag?`
        reflects the CORS-visibility caveat on a read stay optional. (Flagged
        for verification during implementation: this repo's `etag?:` occurrences
        were not individually classified while filing this item.)
  - [x] Test fixtures across `test/node/write.test.ts`,
        `test/node/edv-codec.test.ts`, `test/node/edv.test.ts`,
        `test/node/sync-port.test.ts`, `test/node/storage.test.ts`,
        `test/node/review-fixes.test.ts`,
        `test/node/log-governed-descriptor-store.test.ts`, and
        `test/helpers/codec.ts` (`stubFeatures`, `featureProbeFrom`) drop the
        backend `features` array and the deleted probe helpers; a backend
        descriptor in a fixture carries no `features` member at all.
        `test/node/service.test.ts`'s server-wide `features` fixtures are
        unaffected -- that is the service description, not a backend
  - [x] `NotSupportedError` and `isNotSupportedError` (the `./sync` re-export)
        stay: they still cover the moved `blinded-index-query` /
        `governed-history-logs` gates and other `NotImplementedError`-adjacent
        cases; only the call sites this item deletes stop throwing it
  - [x] README.md's backend-`features` walkthrough (around the "Backend
        affordances" section, roughly lines 740-755, 920, and 991) and
        ARCHITECTURE.md's "Feature detection" section (roughly lines 640-710)
        and its invariants-table row for "New server feature gate" (line 892)
        are rewritten to match: no backend-level probe, `changes-query` and the
        WAS-EC-entry tokens documented at the service-description level
  - [x] A CHANGELOG.md bullet records the breaking removal (baseline conditional
        writes and key epochs; `changes-query` moved to the service description;
        `blinded-index-query` / `governed-history-logs` pending the WAS-EC
        version entry), under a new version, dated TBD
  - [x] `touches:` entries resolved

Context: if conditional writes become a baseline requirement, an audit puts
roughly 525 source and 730 test lines in this package attributable to their
being optional. The shape of the removal: `preconditionsEnforced` and
`assertPreconditionEnforced`'s `no-feature` reason go, while the `no-validator`
reason stays, since a read that returned no ETag is a separate problem that
survives (CORS can hide the header from a browser client). `FeatureProbe` keeps
its other consumers but loses `descriptorAbsent()`. `isNotSupportedError` and
the `NotSupportedError` re-export leave the `/sync` subpath, though the class
stays on the core entry for `chunked-streams` and the other affordances. The
degraded fallbacks go with it: `WasTransport.insert`'s non-atomic
`HEAD`-then-`PUT` path and `#exists()`, `compareAndSwap`'s `allowUnconditional`
opt-out, and `patchCustom`'s pin-dropping. Several public types tighten from
optional `etag` to required. `Collection.ts:451-458`'s no-client-side-remedy
limitation closes.

discovered-from: was-sync WS-15.

2026-09-16: WASS-40 shipped, widening this item beyond `conditional-writes`. The
spec removes the Backend `features` property entirely rather than leaving
`conditional-writes` as the sole survivor, which changes the shape of this
item's third paragraph above: `FeatureProbe` does not "keep its other consumers"
-- with `conditional-writes` baseline, `chunked-streams` moved to a gateless
WAS-EC conformance requirement, and `changes-query` / `blinded-index-query` /
`governed-history-logs` all moved to server-wide or WAS-EC-version-entry tokens,
no backend-level token is left for `src/internal/features.ts`'s probe to answer,
so the probe itself is deleted rather than trimmed. The acceptance checklist
above reflects the full removal; the original paragraph is left in place as the
record of what this item looked like before WASS-40 settled its scope.

2026-09-16: implemented, except the one box ECS-9 blocks.
`src/internal/ features.ts` is deleted outright, along with
`Collection.features`, `CodecRequestContext.features`, `WasTransport`'s
`features` option, the `FeatureProbe` export, and the `backendFeatures` map on
`ClientContext`; no handle reads `GET .../backend` any more. `WasTransport.find`
and the two chunk methods lost their gates with it, so `find()` now relies on
the server's `501` the way `Collection.find()` already did -- re-adding the gate
over the WAS-EC version entry is new work for whoever lands ECS-9, not a
survivor of this probe. `compareAndSwap` is unconditionally guarded over a
stored value, which also closed WCL-105's `patchCustom` outlier; `patchCustom`
refuses an unreadable metadata read with `NotFoundError` rather than patching
onto an empty object, since dropping the pin is no longer an option.
`composeAndSwap` grew an explicit create path for the one write that
legitimately carries no pin: a baseline that reads as absent, which is what
`configure({ force })` sends.

On the `etag?` classification the checklist asked for: every optional `etag` in
this repo is reachable from a response header the client reads, and CORS can
hide `ETag` from a browser client on a write response as easily as on a read, so
none of them tightened to required. Their doc comments changed instead -- from
"absent against a backend without `conditional-writes`" to naming the
CORS-visibility caveat.

### WCL-109: `configure` answers with the write's `etag`, at both container levels

- status: done (2026-09-16)
- priority: medium
- labels: conditional-writes, api, space, collection

- touches:
  - wallet-core: `ensureClientAnnexSpace` (`src/clientAnnex/log.ts`) bypasses
    `Space.configure` today for exactly this gap, hand-rolling the guarded
    create, the 412 rebase, and the rival re-read that `compareAndSwap` /
    `composeAndSwap` already run. Filed there as WC-240, whose acceptance is
    taking that call site back through `configure` once this lands
- acceptance:
  - [x] `Space.configure` returns the written Description together with the
        write's `etag`
  - [x] `Collection.configure` returns its `CollectionMetadata` the same way
  - [x] The two `replaceDescription` return shapes and these two are consistent,
        so a caller needing a compare-and-swap baseline reads it off whichever
        call it made
  - [x] `touches:` entries resolved

Context: a caller that configures a container and then immediately writes it
again under a compare-and-swap needs the validator the configure wrote. Both
`replaceDescription` methods hand one back; neither `configure` does, so such a
caller either pays for a re-read or drops to `replaceDescription` and
reimplements the create-race handling `configure` exists to own. The second is
what wallet-core did.

The value is already in hand at both sites, and is discarded on the way out.
`Space.configure`'s `composeAndSwap` `write` closure (`src/Space.ts`) calls
`this.replaceDescription(body, precondition)` and returns `body`, dropping the
`{ description?, etag? }` that call resolved. `Collection.configure`
(`src/Collection.ts:580`) destructures
`const { metadata } = await this.#writeStored({...})` from a helper already
typed `Promise<{ metadata?: CollectionMetadata; etag?: string }>`. So this is a
return-shape decision rather than new plumbing.

Two things to settle while here. Whether the return widens in place (a breaking
change for anyone spreading the result) or a sibling method carries the
validator. And the asymmetry between the two `replaceDescription` returns:
`Collection`'s `description` is required, `Space`'s is optional, which is what
makes a `Space` caller write a body-less-create fallback that a `Collection`
caller does not need.

discovered-from: the wallet-core cleanup pass over the 0.67 adaptation.

Resolved: the return widened in place at both levels to
`{ description, etag? }`, the shape both `replaceDescription` methods already
answered in, rather than a sibling method. `replaceDescription` was left alone:
`Collection`'s PUT is replace semantics, so echoing the sent body IS the new
state and `description` is honestly required; `Space`'s PUT is a server-side
merge (an omitted `name` keeps the stored one), so an echo would be a guess and
`description` stays optional there. Both `configure` methods compose a full
body, so both answer with a required `description` regardless, and both take it
from the server's answer on a create, where the server is the authority on the
members it settles (a Space's `type`).

### WCL-110: `isNotSupportedError` outlived the replication path its docs describe

- status: done (2026-09-17)
- priority: low
- labels: sync, errors, docs, conditional-writes, cleanup
- touches:
  - was-sync: SHIPPED (WS-16, 2026-09-17). The driver removed its classification
    of the refusal, the controller's `isPermanentRefusal`, and the give-up path
    behind it; it imports the predicate no longer. Nothing left to file there
  - wallet-core: unaffected. WC-237 would have been the second consumer and was
    closed `done (2026-09-16; withdrawn without implementation)` on this same
    spec change, so no code there ever matched the name
- acceptance:
  - [x] `isNotSupportedError`'s doc (`src/sync/predicates.ts:130-142`) stops
        placing the refusal on a replication path. The sync port raises it on
        neither a read nor a write, so "On a replication path it is the guarded
        write refused because the read it is pinned to returned no `ETag`
        validator" names a thing that cannot happen, and "the one refusal a
        replication driver must NOT retry" prescribes a path no driver has
  - [x] The `/sync` entry's header (`src/sync/index.ts:41-43`) drops the same
        claim: the affordance gate is not something "a guarded write raises
        before any request" on this subpath, and the trailing "so a replication
        driver stops rather than retries" is the sentence that cost a driver a
        give-up path it has now deleted
  - [x] Both rewrites say where the refusal IS raised, so the next reader can
        tell whether it can reach them: `src/log/logStore.ts:167`,
        `src/edv/logGovernedDescriptorStore.ts:300`, and
        `src/internal/cas.ts:181`, all through `unenforcedPreconditionError`,
        plus `EdvCodec`'s chunked-envelope refusal (`src/edv/EdvCodec.ts:744`)
        and `WasTransport`'s (`src/edv/WasTransport.ts:440`)
  - [x] Whether the predicate stays exported from `./sync` is decided and
        recorded rather than left implicit. It has no consumer anywhere in the
        ecosystem today (swept 2026-09-17: only this repo's own definition,
        re-export, and test). Keeping it is defensible -- a consumer of the log
        store or the EDV transport meets the error, and the `err.name` rule
        applies there as everywhere -- but the subpath it is exported from is
        the one place it cannot arise, which is what made the docs wrong
  - [x] If it is removed: a CHANGELOG entry under a new version, marked
        breaking, dated TBD, naming was-sync 0.5.0 as the release that stopped
        importing it. If it stays: no CHANGELOG entry, since a doc correction
        changes no behavior
  - [x] `touches:` entries resolved

Context: the predicate was added in 0.67.0 for one caller -- was-sync's push
handler, which needed to tell a permanent refusal from a transient write failure
so RxDB's backoff would stop re-sending a batch no attempt could land. WCL-106
then removed the reason that refusal existed on the sync path: with conditional
writes a baseline server requirement, `createWasSyncPort` passes `ifMatch` /
`ifNoneMatch` straight into `writeHeaders` with no gate, and it bypasses the
codec besides, so neither the precondition refusal nor the chunked one can reach
a replication driver. was-sync WS-16 deleted its half on 2026-09-17 after
verifying that reachability. What is left here is a predicate with no consumer
and, more to the point, two doc comments that still tell a replication driver to
build the path WS-16 just removed.

The removal half is a judgment call rather than an obvious yes, which is why it
is an acceptance box rather than the item's title. The doc half is not: the
sentences are wrong today, and they are the kind of wrong that gets read as a
requirement.

discovered-from: was-sync WS-16.

Resolved: option A, the docs-only fix. The predicate stays exported from
`./sync` and nothing about its behavior changed, so there is no CHANGELOG entry.
Removing it would have left a `/log` or `/edv` consumer that meets the refusal
with no predicate at all, hand-writing the `err.name` match that
`decisions/0001-cross-package-errors-match-by-name.md` exists to supply, in
exchange for tidying a subpath that has no consumer to tidy it for. Moving the
export to the entries that raise the refusal was considered and declined as out
of scope.

Three comments were rewritten rather than the two the acceptance boxes named:
the module header of `src/sync/predicates.ts` opened on "the errors a
replication path can meet" and listed the affordance gate among them, the same
claim as the predicate's own doc. All three now say the refusal's two forms and
where each is raised, and say plainly that this subpath raises it on neither a
push nor a pull, so the export reads as a convenience for `/log` and `/edv`
consumers rather than as a path a driver must handle.

### WCL-111: Import the EDV kernel from a transport-free `@interop/edv-client` entry

- status: done (2026-09-18)
- priority: low
- labels: encryption, packaging, import-graph, cross-repo
- touches:
  - edv-client: LANDED (2026-09-18), pending publish. `src/core.ts` is the new
    barrel and `./core` the export-map entry, carrying `EdvClientCore`,
    `EdvDocumentCipher`, `assertDocId` and the `Transport` base class. The root
    entry re-exports all four and adds `EdvClient`, `EdvDocument` and
    `HttpsTransport` on top, so its export list is unchanged.
    `test/node/55-CoreEntryImportGraph.test.ts` pins the graph upstream. The
    CHANGELOG entry is 17.9.0, dated TBD; the version has to be published before
    this repo's `^17.9.0` range resolves
  - edv-client: SHIPPED. README.md gained an "Entry points" section naming both
    entries and what `./core` leaves out; ARCHITECTURE.md's module map lists
    `core.ts`; CHANGELOG.md carries the 17.9.0 entry
  - was-client (this repo): SHIPPED. ARCHITECTURE.md's layering section names
    `@interop/edv-client/core` in the `src/edv/*.ts` block and in the
    entry-point paragraph, and a new paragraph after the import-graph rule says
    why the core entry rather than the root
- acceptance:
  - [x] `@interop/edv-client` publishes an entry whose static import graph
        reaches neither `@interop/http-client` nor
        `@interop/http-signature-zcap-invoke`
  - [x] `src/edv/EdvCodec.ts` and `src/edv/WasTransport.ts` import from that
        entry, and no file under `src/` imports the `@interop/edv-client` root
  - [x] The core-entry rule in `test/node/import-graph.test.ts` still refuses
        the new specifier. Its `ENCRYPTION_PACKAGES` match already covers a
        subpath specifier of a listed package, so this is a check and needs no
        code change
  - [x] The minimum `@interop/edv-client` version in package.json is the one
        that ships the entry
  - [x] A CHANGELOG.md entry, under a new version, dated TBD

Context: `@interop/edv-client` publishes one entry. Its `src/index.ts` is a
single barrel that exports `EdvClient` and `HttpsTransport` beside the pieces
was-client uses. `HttpsTransport.ts` imports `@interop/http-client` and
`@interop/http-signature-zcap-invoke` at module scope, and `EdvClient.ts`
imports `HttpsTransport`. So any import from the package evaluates the HTTP
client and the zcap signing code. was-client brings its own transport
(`WasTransport`) and uses neither class. Of the three reaches into transport
code in `src/edv/`, this is the only one that loads external HTTP packages, so
it is the one that matters most to an offline consumer.

Mechanics. was-client has two runtime imports of the package:
`src/edv/EdvCodec.ts:68` takes `EdvClientCore` and `assertDocId`, and
`src/edv/WasTransport.ts:48` takes the `Transport` base class that
`WasTransport` extends. The barrel is `edv-client/src/index.ts:4-10`, and the
package's export map (`edv-client/package.json`) has the single `.` entry. The
HTTP imports sit at `edv-client/src/HttpsTransport.ts:5-6` and
`edv-client/src/EdvClient.ts:5,18`. `EdvClientCore.ts` itself imports only
`@interop/minimal-cipher`, `@interop/data-integrity-core` and local modules, so
the new entry needs no code moved inside edv-client. It is a second barrel and
an export-map entry with the four keys the other `@interop/*` packages use
(`types`, `react-native`, `import`, `default`).

edv-client has no ROADMAP.md, so the upstream half is tracked here through the
`touches:` entries.

Resolved: the entry is named `./core`, after the `EdvClientCore` it carries and
the domain-noun subpath convention the other `@interop` packages use. Rather
than write a second barrel with its own copy of the four exports, `src/index.ts`
now re-exports them from `./core.js` and adds the three server-side classes, so
there is one list and the root cannot drift from it. The upstream test walks
`core.ts` the way this repo's `import-graph.test.ts` walks a core entry, and
refuses both HTTP packages plus the three modules that pull them; it also
asserts the root entry does reach them, so an emptied barrel cannot pass.

was-client's own `test/node/import-graph.test.ts` needed no change, as the item
predicted. Its core rule matches `specifier === pkg` or a `pkg/` prefix, and its
guard case matches on prefix, so `@interop/edv-client/core` is covered by both.

### WCL-112: `internal/describe.ts` imports the request wrapper for one function

- status: done
- done: 2026-09-18
- priority: low
- labels: encryption, import-graph, internal
- acceptance:
  - [x] `src/internal/describe.ts` has no import from `./request.js`, runtime or
        type
  - [x] `readCollectionMetadata` lives in a module that is allowed to import the
        request wrapper, and its callers import it from there
  - [x] `src/edv/descriptorStore.ts` and `src/edv/logGovernedDescriptorStore.ts`
        no longer reach `internal/request.ts` through their static imports
  - [x] No behavior change: the existing node and browser suites pass unedited
        apart from import paths

Context: `internal/describe.ts` holds the Collection Metadata object helpers.
All of them are pure shape checks and projections except one,
`readCollectionMetadata`, which performs the read and so imports
`readDataWithEtag` from `internal/request.ts`. Two modules on the encrypted side
import a pure helper from `describe.ts` and get the request wrapper with it.
`edv/descriptorStore.ts` wants `unreadableDescriptionError`.
`edv/logGovernedDescriptorStore.ts` wants that and `isGovernedDescriptor`. The
second module is the home of `EPOCH_CONFIGURATION_STATE_TYPE` and
`toEpochConfigurationState`, which an offline reader of an archived resource log
needs. The request wrapper loads no external package at runtime (its
`@interop/ezcap` and `@interop/http-client` imports are type-only), so the cost
here is small. It still puts the transport layer's entry module in the graph of
code that only parses a descriptor, and it would fail the test WCL-114 adds.

Mechanics. `src/internal/describe.ts:22` is the import. Its one use is
`readCollectionMetadata` at lines 244-249. The pure helpers two `edv/` modules
take are `isGovernedDescriptor` (line 96) and `unreadableDescriptionError` (line
278). The importers are `src/edv/descriptorStore.ts:34` (used at line 123,
inside `collectionDescriptorStore` only) and
`src/edv/logGovernedDescriptorStore.ts:52-55` (used at line 556). The other
importers of `describe.ts` are `Collection.ts:63`, `Space.ts:33` and
`sync/provisioning.ts:37`. Moving the one function is smaller than splitting
`descriptorStore.ts` in two, which the scoping pass proposed. It also leaves
`recipients.ts` and its `{ collection }` shorthand (`descriptorStoreFor`,
`recipients.ts:1153-1170`) untouched, since `collectionDescriptorStore` then
imports nothing but pure helpers and takes its `Collection` as a type.

The scoping pass reported `logGovernedDescriptorStore.ts` as already free of
transport imports. It is not, for the reason above.

Resolution: `readCollectionMetadata` moved to `src/internal/meta.ts`, which
already owns the `meta` I/O both handles share and already imports the request
wrapper. `Collection.ts` and `internal/codec.ts` -- the two callers, not
`Space.ts`, which never imported it -- take it from there; `Space.ts` keeps its
`collectionWritableFields` and `unreadableDescriptionError` import unchanged.
`describe.ts` dropped its `./request.js`, `./paths.js` and `IZcap` imports with
the function, and its module header now states that nothing in it performs a
request. A runtime-edge walk of both `edv/` modules confirms neither reaches
`internal/request.ts`; their `Collection` and `Resource` imports are type-only.
Node suite green (1037 tests); the one browser test fails identically on clean
`main`, so it is unrelated.

### WCL-113: `EdvCodec.ts` and `docCipher.ts` load `WasTransport` for callers with no server

- status: done
- done: 2026-09-18
- priority: low
- labels: encryption, import-graph, codec-seam
- touches:
  - was-client (this repo): SHIPPED. ARCHITECTURE.md's `EdvCodec` bullet in "The
    EDV layer" now names the injected `CodecTransportFactory` and
    `transportFactory.ts` as the only module that constructs a `WasTransport`;
    the `src/edv/*.ts` block in the layering section lists the two new modules
    and states the reach rule; the codec-seam module list and the `EdvCodec`
    Glossary entry point at `encryption.ts` for `createEdvEncryption`
- acceptance:
  - [x] `src/edv/EdvCodec.ts` imports `WasTransport` as a type only
  - [x] `wasTransportFactory` and `createEdvEncryption` live outside
        `EdvCodec.ts`, in a module (or modules) on the online side, and
        `edv/index.ts` still exports both under the same names
  - [x] `createEdvDocCipher` called without `spaceId` evaluates no module that
        imports `WasTransport`. Called with `spaceId`, it behaves as today,
        including the chunked-stream paths
  - [x] `createEdvEncryptOnlyDocCipher`, `buildEdvCodec` and
        `encryptOnlyEdvCodec` are reachable without `WasTransport` in their
        static graph
  - [x] No behavior change: the existing node and browser suites pass unedited
        apart from import paths

Context: `EdvCodec` does the encrypting and decrypting for a collection. It can
also write and read chunked streams, and for that it drives a `WasTransport`
against the server. The class does not construct that transport. A
`CodecTransportFactory` is injected by whichever build knows where the
Collection lives, and a codec built without one refuses the chunked path. The
design already separates the codec from the server. The file layout does not:
the one function that constructs a `WasTransport`, and the `EncryptionProvider`
that uses it, sit in the same file as the class. So every importer of the codec,
including the offline doc cipher, evaluates `WasTransport.ts`.

Mechanics. `src/edv/EdvCodec.ts:104` imports `WasTransport` at runtime. The only
runtime use is `new WasTransport(...)` inside `wasTransportFactory` (lines
181-198). Every other mention in the file is a type: the `CodecTransportFactory`
return type (lines 166-169), the private factory field (line 359), and the
`WasTransport` return and parameter types at lines 742 and 859. The one caller
of the factory inside the file is `createEdvEncryption` (line 1884, the call at
1927), which is the online `EncryptionProvider` and belongs with the transport.
Moving those two functions out turns the import at line 104 into `import type`.
`buildEdvCodec` (line 1969) and `encryptOnlyEdvCodec` (line 2151) stay.

`src/edv/docCipher.ts:71-75` imports `wasTransportFactory` statically and calls
it only when the caller passes `spaceId` (lines 228-236). An offline caller
passes none. `createEdvDocCipher` is already async, so loading the factory with
a dynamic `import()` inside that branch keeps the signature and drops the static
edge. The alternative is a caller-supplied `transportFactory` option. That is a
public API addition and needs the maintainer's decision, so the dynamic import
is the default here.

After WCL-111, `WasTransport.ts` (549 lines) imports only the transport-free
edv-client entry and light internal modules (`errors`, `internal/content`,
`internal/conditional`, `internal/paths`). What remains is one module evaluated
for nothing. This item is what lets WCL-114 state its rule without an allowance.

Landed as described. `wasTransportFactory` moved to
`src/edv/transportFactory.ts` and `createEdvEncryption` to
`src/edv/encryption.ts`; `EdvCodec.ts` keeps the `CodecTransportFactory` type,
the class and both codec builds, and imports `WasTransport` with `import type`.
`DEFAULT_MAX_BLOB_BYTES`, `EDV_SCHEME`, `guardEncryptionDescriptor` and
`descriptorDefect` are exported from `EdvCodec.ts` so the provider can reach
them; none is re-exported from `edv/index.ts`, so the public surface is
unchanged. `docCipher.ts` loads the factory with
`await import('./transportFactory.js')` inside the `spaceId` branch. A
runtime-edge walk confirms `edv/docCipher.ts` and `edv/EdvCodec.ts` reach no
transport module, while `edv/encryption.ts` and `edv/transportFactory.ts` do.
Node suite green (1037 tests), browser suite green, lint and typecheck clean.

### WCL-114: Publish a transport-free entry for the offline codec, and pin its import graph

- status: done (2026-09-18)
- priority: low
- labels: encryption, packaging, import-graph, cross-repo
- blocked-by: WCL-111, WCL-112, WCL-113
- touches:
  - was-client (this repo): SHIPPED. package.json `exports` carries
    `./edv/core`; ARCHITECTURE.md's layering section explains the two encrypted
    entries, "Subpaths, not packages" records the new entry as a further use of
    that decision, invariant 10 states the rule (the old invariant 10 is now
    11), and the Glossary gained the entry's term; README.md's encrypted
    collections section introduces `@interop/was-client/edv/core` beside `./edv`
  - wallet-backup: FOLLOW-UP, its WBU-3. A survey of that repo confirms the
    entry covers it: every name its four `/edv` importers take
    (`createEdvDocCipher` in `src/migrate/generations.ts`,
    `EPOCH_CONFIGURATION_STATE_TYPE` in `src/migrate/descriptorLog.ts`,
    `createEdvEncryptOnlyDocCipher`, `mintEpoch`, `ownerRecipient`,
    `toEpochConfigurationState`, `wrapEpochSecret`, `EDV_SCHEME_VERSION` and the
    `RecipientPublicKey` type in its fixtures and tests) is on the offline
    entry, and it uses no online-only name at all. Its other was-client
    dependency is the root `CollectionEncryption` type
  - wallet-core: FILED as WC-247. Its offline-only importers
    (`keyring/record.ts`, `keys/userKey.ts`, `keys/userKeyCascade.ts`,
    `keys/userKeyRoster.ts`, `keys/rosterLogStore.ts`, `keys/spaceEpochs.ts`,
    `webvh/didWebvh.ts`, `clientAnnex/credentialAnchoredGenesis.ts`, and the
    files taking only the `EncryptionDescriptorStore` type) can repoint whole.
    One production file, `src/descriptors/logSource.ts`, also takes
    `EncryptionDescriptorSource`, and that is a type import, so it is erased at
    build time and costs nothing at runtime
  - was-react: unaffected (imports keep resolving from `./edv`). Confirmed: its
    storage layer needs `createEdvEncryption`, `createRefreshingEdvDocCipher`,
    `DescriptorRefreshPolicy` and the two descriptor seam types in `src/`
  - freewallet: unaffected (imports keep resolving from `./edv`). Confirmed:
    `stores/storageManager.ts`, `stores/wasRemoteStore.ts`,
    `stores/refreshingCollectionCipher.ts`, `session/persistence.ts` and
    `session/collectionLogStore.ts` take online-only names
  - dcw: unaffected (imports keep resolving from `./edv`). Confirmed: its whole
    sync stack (`sync/engineStart.ts`, `sync/syncManager.ts`,
    `sync/docCipher.ts`) takes `wasDescriptorSource`,
    `createRefreshingEdvDocCipher` and the descriptor seam types
  - encrypted-collections-spec: unaffected. The "Parties to this contract" row
    for was-client cites modules under `src/edv/` -- the codec, the chunked
    paths, `epochCrypto` / `epochKeys`, the recipient operations,
    `x25519RecipientFromDidKey` and the descriptor-store seam -- not the barrel
    files, and the directory is unchanged. Every module it names except
    `WasTransport` is in the offline half, and `WasTransport` is already called
    out by name for the chunked-stream path. Row left as written
- acceptance:
  - [x] package.json `exports` gains one entry, with the four keys the other
        entries carry. The name is the maintainer's call and is settled before
        any code lands
  - [x] The entry re-exports the offline set and nothing else: the doc cipher
        factories, the `EdvCodec` class, the epoch and recipient primitives
        (`mintEpoch`, `wrapEpochSecret`, `unwrapEpochSecret`, `epochKeyIdFor`,
        `ownerRecipient`, `x25519RecipientFromDidKey`, `didKeyResolver`),
        `resolveEpochKeys`, the epoch roster helpers, the blinding key
        functions, the recipient operations that take an explicit
        `EncryptionDescriptorStore` (`initRecipients`, `addRecipient`,
        `removeRecipient`, `replaceRecipient`, `ensureFirstEpoch`),
        `resourceDescriptorStore`, the log-governed descriptor store with
        `EPOCH_CONFIGURATION_STATE_TYPE`, `toEpochConfigurationState` and
        `readGovernedEpochConfiguration`, the constants, and the types those
        need. The exact list is checked against what wallet-backup and
        wallet-core import
  - [x] `@interop/was-client/edv` re-exports the new entry and adds the online
        set on top (`WasTransport`, `createEdvEncryption`,
        `wasTransportFactory`, `collectionDescriptorStore`, `acquire.ts`,
        `DescriptorRefreshPolicy`, `createRefreshingEdvDocCipher`). Its export
        list is unchanged
  - [x] `test/node/import-graph.test.ts` gains a block for the new entry. It
        walks runtime edges only (the existing walker counts `import type` on
        purpose, which is right for the core rule and wrong for this one) and
        asserts the entry reaches none of `edv/WasTransport.ts`,
        `internal/request.ts`, `WasClient.ts`, `Space.ts`, `Collection.ts`,
        `Resource.ts`, and none of `@interop/http-client`,
        `@interop/http-signature-zcap-invoke`, `@interop/ezcap`
  - [x] The test has a positive case too: the entry does reach
        `@interop/minimal-cipher` and the transport-free edv-client entry, so an
        emptied barrel cannot pass
  - [x] ARCHITECTURE.md records the rule as a numbered invariant and explains
        the two entries in the layering section
  - [x] A CHANGELOG.md entry, under a new version, dated TBD
  - [x] `touches:` entries annotated

Context: the file-level cuts in WCL-111 to WCL-113 do nothing for a consumer on
their own. `@interop/was-client/edv` resolves to `src/edv/index.ts`, a barrel
that re-exports the online and offline halves side by side (`WasTransport`,
`createEdvEncryption` from `encryption.js`, `wasTransportFactory` from
`transportFactory.js`, the refresh policy and the refreshing cipher). ESM
evaluates every module a barrel names, whichever export the importer wants. An
offline consumer needs an entry whose barrel names only offline modules. That is
the same mechanism the package already uses to keep the core entries off the
encrypted graph, applied one level further in.

The rule also needs a test, because nothing else will hold it. Invariant 9 and
`test/node/import-graph.test.ts` exist because a stray import is invisible in
review. The current test walks the four core entries (`index.ts`, `paths.ts`,
`log/index.ts`, `sync/index.ts`) and deliberately does not walk `./edv` or
`./identity`. Its one assertion about `edv/index.ts` is that it does reach the
encrypted-collection packages. The new block is the first to constrain anything
under `src/edv/`.

Two details to settle while doing it. `recipients.ts` imports
`collectionDescriptorStore` for the `{ collection }` shorthand. After WCL-112
that import reaches only pure helpers and a type, so the recipient operations
can sit in the offline entry as they are. Confirm it with the new test before
deciding anything about the shorthand. And `edv/acquire.ts` has no transport
import at runtime (its `WasClient` import is type-only), but its purpose is an
online descriptor read, so it stays in the online set with the refresh policy.

New export names are public API shared across `@interop/*`, so the entry's name
and its Glossary term are the maintainer's decision. Nothing here is a wire
artifact: no field, label, salt or encoding changes.

Landed as described. `src/edv/core.ts` is the new barrel and `./edv/core` the
export-map entry. The CHANGELOG entry went under 0.70.0, the existing TBD-dated
version at the top, beside WCL-111 to WCL-113; a new version on top of an
unreleased one is not how this repo's changelog works. `src/edv/index.ts` is now
`export * from './core.js'` plus the online set, so its export list grew by
exactly one name, `didKeyResolver`, which was already the resolver the codec
hands the cipher and was reachable only by deep import. Nothing was removed.

Both details in the Context paragraph settled as predicted. The new test
confirms `recipients.ts` keeps its `collectionDescriptorStore` import: after
WCL-112 that reaches `descriptorStore.ts`, `internal/describe.ts` and
`errors.ts` and stops, so the recipient operations sit in the offline entry
unchanged and the `{ collection }` shorthand needs no decision. `edv/acquire.ts`
stays online with the refresh policy.

`test/node/import-graph.test.ts` gained `runtimeReachableFrom`, a second walker
that skips `import type` and `export type`, and a
`describe('the transport-free edv entry')` block over it. The original walker
still counts type imports for the core-entry rule. A runtime walk from
`edv/core.ts` reaches 25 modules under `src/` and eight packages, and none of
the six transport modules or three HTTP packages. Removing an export from the
barrel is caught by the positive cases, and adding `WasTransport` back to it
fails the rule, both verified by mutation. Node suite green (1041 tests, up from
1037), browser suite green, lint and typecheck clean.

### WCL-94: `WasClient` API hygiene -- dropped options, eager signer, unreachable types

- status: done
- done: 2026-09-18
- priority: low
- labels: api, types, ergonomics
- acceptance:
  - [x] Passing `encryption` to `space()` is either honored as the default for
        `Space.collection()` or a compile error
  - [x] A `ZcapClient` with a delegation signer and no invocation signer can
        `grant()`
  - [x] `IRootZcap`, `IDID` and `CustomWithIndexSchema` are reachable from an
        entry point
  - [x] `grant()` without `target` or `capability` throws `ValidationError`
        rather than a raw ezcap `TypeError`
  - [x] The `zcaps` comment in `internal/paths.ts` states the real reasons the
        segment cannot be shadowed

Five small defects on the root entry point. `space()` is typed `HandleOptions`,
which declares `encryption`, but constructs a `Space` from three fields and
drops it; `Space.collection()` and `Collection.resource()` both forward the same
option, so this one hop is the only place it is lost, and it fails closed (an
intended plaintext override still encrypts). `#context` eagerly evaluates
`controllerDid`, so a delegation-only client throws
`ValidationError: The wrapped ZcapClient has no invocationSigner id` from both
`grant()` and `space()` -- naming a signer neither operation uses.
`controllerDid` is needed only by `createSpace`'s controller default and
`rootCapability`'s client-side controller, so a lazy getter covers it; confirm
no external consumer constructs a `ClientContext` first, since it is threaded
into `src/edv` and the sync port. `IRootZcap` and `IDID` are exported from
`types.ts` but not from `index.ts`, `paths.ts` exports the `rootCapability`
value without the type of its own return, and `CustomWithIndexSchema` lives
under `internal/` with no `./internal` subpath in the exports map, so an
`indexSchema` reader has no reachable annotation. `GrantOptions` type-permits a
call with neither `target` nor `capability`, which ezcap rejects with a
`TypeError` a consumer catching `WasError` misses entirely. Last, `zcaps` is
absent from `RESERVED_COLLECTION_IDS`, and the comment claiming the revocation
route is deeper than any Collection route is wrong (both are four segments). The
shadowing is still unreachable, because a zcap id must be an absolute URI and
the routes are method-disjoint, so the fix is to correct the comment's
reasoning. The reference server repeats the same faulty argument in its own
comment.

discovered-from: whole-codebase review, 2026-09-11.

Resolution: `WasClient.space()` forwards `options.encryption` into the `Space`
constructor, which stores it and uses it as the fallback in `Space.collection()`
(`options.encryption ?? this.#encryption`), so the override now flows Space to
Collection to Resource. `createCollection` builds its `Collection` directly
rather than through `collection()`, so the handle it returns reflects the
collection's own `encryption` declaration instead of inheriting the Space
handle's default. `WasClient.#context` backs `controllerDid` with a getter over
the client's own accessor; `ClientContext` keeps its `controllerDid: string`
shape, and the only constructor of one is `WasClient` itself (the `src/edv` and
sync consumers take a context, they never build one), so no consumer changed.
`index.ts` exports `IRootZcap`, `IDID` and `CustomWithIndexSchema`; `paths.ts`
exports `IRootZcap` beside the `rootCapability` value it types. `delegateGrant`
refuses a call with neither `target` nor `capability` with a `ValidationError`
before reaching ezcap; the scoped sugar always prefills `target`, so only a
direct `was.grant()` can hit it. The `zcaps` comment now states the two real
reasons (a zcap id is an absolute URI, so the final segment matches no reserved
sub-resource segment; and the routes are method-disjoint). `GrantOptions` was
left as-is rather than split into a union: `Space.grant` and `Collection.grant`
legitimately take options with neither member, since `delegateGrantAt` fills
`target`. Node suite green (1049 tests, up from 1042), browser suite green, lint
and typecheck clean. The same faulty depth argument in was-teaching-server's own
comment is unfixed and needs an item in that repo.
