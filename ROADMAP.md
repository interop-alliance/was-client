# WAS Client Roadmap (open items)

Status as of 2026-08-12 (was-client 0.34.0). Converted on this date from the
prior narrative gap-analysis roadmap (produced 2026-07-20 by comparing `spec.md`
in the
[w3c-ccg/wallet-attached-storage-spec](https://github.com/w3c-ccg/wallet-attached-storage-spec)
repo and the `was-teaching-server` feature set against the client) into the
formalized item structure shared with the freewallet, was-teaching-server,
was-react, and isomorphic-lib-template roadmaps.

Scope: open work items only. This document tracks the **remaining** items;
completed items move verbatim to [archived-roadmap.md](archived-roadmap.md) as
they land, so WCL-N references keep resolving (CHANGELOG.md remains the record
of what landed). Everything shipped through 0.34.0 -- resource metadata
read/write, backend/quota reads at both levels, public reads, conditional
writes, BYOS backend registration (write side), zcap revocation, both
encrypted-collections increments, the blinded content `/query` binding,
multi-recipient Collections + key epochs, chunked-stream transport, listing
pagination, the encryption-descriptor store seam, the sync port, and the
`./paths` subpath -- is recorded in the CHANGELOG and not itemized here.
(Earlier revisions of this doc carried the full shipped history; items completed
before this conversion live only in git history of the pre-2026-08 spec-repo
notes.)

Companion document: the server-side gap analysis at
[was-teaching-server/ROADMAP.md](https://github.com/interop-alliance/was-teaching-server/blob/main/ROADMAP.md).

## Item format

Each work item is a `### WCL-N: Title` heading followed by a field block and
free prose context. Ids are permanent and never reused; new items take the next
unused number regardless of section. Statuses: `todo`, `in-progress`, `draft`
(no actionable done-state yet -- blocked externally or a parking record); `done`
items move to [archived-roadmap.md](archived-roadmap.md) once shipped. The full
conventions -- including the `touches:` field, required for any item changing a
spec, a wire contract, or a shared `@interop/*` API, and blocking `done` while
any of its entries is unresolved -- live in isomorphic-lib-template's AGENTS.md
under "Roadmap & Task Conventions" and apply to WCL-N items too.

---

## Encrypted collections -- remaining work

Client-side end-to-end encryption is modeled as a backend **feature**; the keys
live in the wallet, never on the server (the server stores opaque JWEs). Both
increments (the `WasTransport` EDV mapping and the `ResourceCodec` /
`createEdvEncryption` seam), multi-recipient key epochs, the blinded `/query`
binding, chunked encrypted blobs end-to-end (transport binding plus the
`caad: 1` per-chunk AAD hardening and JWE-sealed chunk counts), all three
Cryptomator-comparison hardening items (the `was` protected-header binding, the
`epochsMac` authenticated epoch configuration -- since retired stack-wide in
0.32.0, its coverage being a strict subset of log-chain verification -- and the
scheme version), and the marker-store seam for the recipient primitives (the
`MarkerStore` port with the Collection Description and plain-JSON-Resource
adapters, the parameterized pull axis, the `resolveRecipientKey` skip contract,
and `Resource.getWithEtag`; scoped by freewallet's FW-58, shipped in client
0.21.0; since renamed the encryption-descriptor store seam --
`EncryptionDescriptorStore` -- in 0.23.0) have shipped -- see the CHANGELOG. The
spec-side write-ups for the hardening items are tracked as Reverse gaps in the
server repo's ROADMAP.

### WCL-1: Content search for the codec path

- status: in-progress
- priority: medium
- labels: encryption, codec, query
- touches:
  - encrypted-collections-spec -- the descriptor/epoch format gains index-key
    (HMAC) distribution: recipients must receive the blinding key the same way
    they receive epoch keys (on a log-governed descriptor the entry proof covers
    the new member(s) automatically); plus a section specifying the `indexed`
    entries codec envelopes carry; plus index-schema persistence (which
    attributes are indexed, `unique`/compound flags), stored encrypted so a
    later-added recipient can discover what is queryable (see prose). Two
    decisions recorded 2026-08-12 (with FW-130) that the spec text must reflect:
    the HMAC key is installed at collection provisioning or never (greenfield
    only -- no mid-life key addition, so an indexable collection is a property
    fixed at birth), and the key does not rotate on recipient removal (blinded
    tokens must compare across the collection's history); the resulting
    revocation asymmetry -- a removed recipient keeps the blinding key and can
    confirm guessed attribute values if the server colludes -- needs Security
    Considerations text
  - wallet-attached-storage-spec -- the `blinded-index` query profile is already
    in the Query Profile Registry and document shape is WAS-EC territory, but
    the persisted index schema now needs the Collection-level `/meta` endpoints,
    tracked as WASS-9 in that repo's `_spec/ROADMAP.md`
  - was-teaching-server -- its `blinded-index-query` already matches `indexed`
    entries for the `EdvClientCore` path, but the schema home needs the
    Collection-level `/meta` endpoints (WAS-55 in its ROADMAP.md); conformance
    tests must gain codec-path coverage, and its ROADMAP Reverse-gap cross-links
    updated
  - freewallet -- the keystore (`wasRemoteStore` `resolveKeys`) must mint,
    custody, and distribute the HMAC key alongside the key-agreement key, and
    provisioning (`ensureFirstEpoch`) must install it; tracked as FW-130 in the
    freewallet roadmap
  - was-react -- `wasRemoteStore.queryCollectionByEquality` and
    `entityStore.query` fail closed on non-public collections ("blinded-index
    query path is not yet supported"); the encrypted path should be added (or
    the guard/JSDoc updated), its `createEdvEncryption({ resolveKeys })` seam
    must carry the new `hmac` key (a parallel module to freewallet's same-named
    keystore, not covered by that entry), and `declareCollectionIndexes`
    (plaintext, public-only) does not cover the encrypted persisted-schema
    model; tracked as WR-31 in the was-react roadmap
  - "@interop/edv-client" -- blinding already implemented (`IndexHelper`, `hmac`
    params); verify a concrete HMAC key class (`id`/`sign`/`verify`) is exported
    for consumers, or export one upstream (do not hand-roll here)
  - was-client ARCHITECTURE.md -- the codec seam is documented as a pure
    single-write transform; emitting `indexed` entries and binding `find()`
    changes that contract description
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

The item stays `in-progress`: the cross-repo `touches:` entries (the
encrypted-collections spec text, the WAS spec's schema-home note, the server's
codec-path conformance tests, freewallet FW-130, was-react WR-31, and the
storage-core widening cleanup) are still unresolved. WCL-10 (the
`was.collection` binding decided as ECS-1) landed alongside it on 2026-08-12, so
the persisted schema envelopes are minted with the final binding shape.

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

### WCL-2: `Collection.add(bigBlob)` auto-routing

- status: todo
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
  - [ ] An oversize `add()` on an encrypted collection routes onto the
        chunked-stream path automatically instead of throwing

The codec seam is a pure single-write transform, so an oversize `add()`
currently throws and points callers at the (fully working)
`EdvClientCore.insert({stream})` / `getStream` path. Ergonomics only.

### WCL-9: key-epochs integration test drift (`UnknownEpochError` vs `KeyUnwrapError`)

- status: todo
- priority: medium
- labels: encryption, key-epochs, integration-test
- acceptance:
  - [ ] The `test/integration/key-epochs.test.ts` suite is green against a live
        was-teaching-server >= 0.21.0, with expectations that assert the
        intended contract (not just whatever currently throws)
  - [ ] The `KeyUnwrapError` / `UnknownEpochError` JSDoc contract matches the
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

### WCL-11: `indexed` emission on the sync push path

- status: todo
- priority: medium
- labels: encryption, sync, query
- touches:
  - freewallet -- its sync wiring builds the cipher via `createEdvDocCipher`; if
    that function gains a schema input (or a refresh hook), the wiring must
    supply it; verify and update
  - was-react -- same: its `src/sync/` DocCipher wiring is the other
    `createEdvDocCipher` consumer; verify and update
- acceptance:
  - [ ] Envelopes written through the sync push path for a collection with a
        declared index schema carry `indexed` entries token-identical to
        direct-write envelopes for the same content
  - [ ] A document pushed via sync is returned by `collection.find()` on the
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

### WCL-4: Live Google Drive backend round-trip

- status: draft (blocked externally)
- priority: low
- labels: byos, gdrive, integration-test
- acceptance: none yet -- server-blocked; the client work is mostly an
  integration test, not new API

Blocked on the server: only after gdrive plan stages 4-5 give a provider
adapter + OAuth exchange does the registration API (shipped in client 0.8.0)
carry real `connection` material and `status` advance past `registered` to
`connected`. Until then, a round-trip test of the `connected` / `expired`
connection states stays server-blocked.

---

## Recorded decisions (kept so they are not re-litigated)

- **Effective-policy resolution: intentionally out of scope.** `isPublic()` /
  `getPolicy()` check only the handle's own level, and that is by design: it is
  not the client's job to compute server-side policy (the spec's
  most-specific-wins inheritance is evaluated by the server). `isPublic()`
  exists solely to drive data-browser style UI -- an own-level question. Do not
  add an `effectivePolicy()` helper; a Resource inside a public Space reporting
  `isPublic() === false` is the intended behavior.
- **No `collection.revoke()` / `resource.revoke()` sugar.** Revocation is
  Space-scoped, so those would ignore their receiver's own path and use only its
  `spaceId` -- `collection.revoke(zcap)` is exactly `space.revoke(zcap)`, and
  `Resource` has no `grant()` to mirror. `was.revoke()` already covers the
  convenience case by deriving the Space from the capability.
- **`revoke()` is not idempotent, deliberately.** Resubmitting a stored
  revocation is a 400, but the server reports it with the same problem type as a
  tampered, expired, or foreign-rooted capability. The client cannot tell them
  apart, so it swallows none of them and surfaces `ValidationError`; a caller
  who wants revoking twice to be a no-op catches it. (Swallowing would make
  `revoke(garbage)` resolve as though it had worked.)
- **Revocation semantics, documented and not overstated.** Because policies are
  permissive, revoking a capability withdraws only what _that capability_
  granted: a `PublicCanRead` target stays publicly readable. And revocation is
  prospective -- on an encrypted collection a revoked reader still holds keys
  for ciphertext it already fetched, which is what key epochs address
  (`removeRecipient` performs the revoke-and-rotate as one operation).
- **No client-driven bulk rewrap of stored envelopes** (retired WCL-3, see the
  archive). Envelopes are roster-blind -- each names exactly one JWE recipient,
  the epoch key -- so re-wrapping keys to a changed reader set is a single
  conditional descriptor write (`addRecipient` / `removeRecipient` /
  `replaceRecipient`), not a per-Resource operation. And an envelope cannot be
  moved to a new epoch without re-encryption: `was.epoch` is bound into the
  AEAD-authenticated protected header precisely to detect epoch swap/rollback,
  the WAS-EC profile declares pushed envelopes immutable, and re-encryption
  would change content-derived resource ids. The re-encrypt-history variant is
  explicitly outside the WAS-EC profile (its rotation-limitations section) and
  an explicit non-goal in freewallet and wallet-core; the residual exposure is
  the documented honest ceiling of prospective rotation.
- **The encryption switch is keys alone, not "feature AND keys".** A handle
  encrypts a collection exactly when the `encryption` provider's `resolveKeys`
  returns keys for it -- a pure per-collection client concern needing no backend
  round-trip. The backend `features` array is still read for the orthogonal
  `conditional-writes` affordance (which the EDV `sequence` rides), not as the
  encryption gate.
- **Grants into the Space tree root at the Space.** `internal/grant.ts`
  delegates unparented Space-tree grants from `urn:zcap:root:<spaceUrl>` with
  the narrower target as an attenuated `invocationTarget`, so every such chain
  is revocable at the Space's revocation endpoint. Re-delegation and non-Space
  targets (`/kms`, other origins) are unaffected.
- **`updateIndex` deliberately throws.** In the `blinded-index` profile the
  `indexed` array rides inside the stored envelope, so `update()` IS the
  re-index operation -- there is no `/{id}/index` endpoint to bind.

---

## Someday / Maybe

Items with no current trigger. Parked here so the active sections stay
actionable; recorded so they are not re-litigated as fresh each time.

### WCL-5: Blind-derived ids for human-readable `put()` on encrypted collections

- status: draft (parking record)
- priority: low
- labels: someday, encryption, api
- acceptance: none yet -- revisit only if keeping the human id inside the
  encrypted document proves insufficient

Increment 2 _rejects_ a human-readable id in `put('2020-01-01-hello', obj)` on
an encrypted collection (EDV needs a 128-bit multibase id; a human id on the URL
leaks to the server). The first fallback is simply to keep the human id inside
the encrypted document -- e.g. in the EDV doc's `content.name` (or the
forbidden-for-now `setName` value relocated into the JWE) -- which may be
sufficient on its own, so the human-readable label travels _inside_ the
ciphertext and the URL stays a blinded id. If addressing-by-human-id is later
wanted, derive the document id deterministically:
`docId = multibase(HMAC(indexKey, humanId))` (the gdrive plan's Q4 resource-id
mapping option 2). That hides the id from the provider while letting the client
re-derive the URL from the human id. Cost: an HMAC index key to manage and
distribute (alongside the content keys), plus collision/uniqueness handling --
why it is deferred past the first encrypted increment.

### WCL-6: RxDB sync client follow-ons

- status: draft (parking record)
- priority: low
- labels: someday, sync, cross-repo
- acceptance: none yet -- the one remaining half is deduplicating the two RxDB
  driver copies into a standalone library; revisit when that gets a trigger
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

### WCL-7: Relocating `setName` / `setTags` into the JWE

- status: draft (parking record)
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
