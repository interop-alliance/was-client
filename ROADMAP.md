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
`epochsMac` authenticated epoch configuration, and the scheme version), and the
marker-store seam for the recipient primitives (the `MarkerStore` port with the
Collection Description and plain-JSON-Resource adapters, the parameterized pull
axis, the `resolveRecipientKey` skip contract, and `Resource.getWithEtag`;
scoped by freewallet's FW-58, shipped in client 0.21.0; since renamed the
encryption-descriptor store seam -- `EncryptionDescriptorStore` -- in 0.23.0)
have shipped -- see the CHANGELOG. The spec-side write-ups for the hardening
items are tracked as Reverse gaps in the server repo's ROADMAP.

### WCL-1: Content search for the codec path

- status: todo
- priority: medium
- labels: encryption, codec, query
- touches:
  - encrypted-collections-spec -- the descriptor/epoch format gains index-key
    (HMAC) distribution: recipients must receive the blinding key the same way
    they receive epoch keys, and the new member(s) must be covered by
    `epochsMac`; plus a section specifying the `indexed` entries codec
    envelopes carry
  - wallet-attached-storage-spec -- expected unaffected (the `blinded-index`
    query profile is already in the Query Profile Registry; document shape is
    WAS-EC territory) -- verify and waive or update
  - was-teaching-server -- server code expected unchanged (its
    `blinded-index-query` already matches `indexed` entries for the
    `EdvClientCore` path); conformance tests must gain codec-path coverage,
    and its ROADMAP Reverse-gap cross-links updated
  - freewallet -- the keystore (`wasRemoteStore` `resolveKeys`) must mint,
    custody, and distribute the HMAC key alongside the key-agreement key, and
    provisioning (`ensureFirstEpoch`) must install it; needs its own FW-N item
  - "@interop/edv-client" -- blinding already implemented (`IndexHelper`,
    `hmac` params); verify a concrete HMAC key class (`id`/`sign`/`verify`) is
    exported for consumers, or export one upstream (do not hand-roll here)
  - was-client ARCHITECTURE.md -- the codec seam is documented as a pure
    single-write transform; emitting `indexed` entries and binding `find()`
    changes that contract description
- acceptance:
  - [ ] `createEdvEncryption`'s key set gains an `hmac` key, so the codec's
        cipher can blind attributes
  - [ ] Codec-path writes emit blinded `indexed` entries alongside the JWE,
        matching what `EdvClientCore` documents carry
  - [ ] `collection.find()` sugar binds the `blinded-index` profile for
        codec-stored documents

`WasTransport.find` binds the `blinded-index` profile, so `EdvClientCore` users
get content search -- but `createEdvEncryption` builds its cipher with no HMAC,
so codec-stored documents carry no blinded `indexed` entries and are not
findable. A separate, larger design.

### WCL-2: `Collection.add(bigBlob)` auto-routing

- status: todo
- priority: low
- labels: encryption, streams, ergonomics
- touches:
  - was-client ARCHITECTURE.md -- the request lifecycle and "The codec seam"
    sections describe `encode` as a pure single-request transform with the
    chunked path as a separate `EdvClientCore`-driven escape; auto-routing
    moves that decision into the write path and changes both descriptions
  - was-client README.md -- the encrypted-collections section documents the
    oversize `add()` as rejected with guidance toward the stream path; a
    previously-throwing call starts succeeding
  - "@interop/edv-client" -- expected unaffected (`insert({ stream })` /
    `getStream` already carry the whole chunked path); verify the codec can
    reach what it needs through the export map, else export upstream
  - encrypted-collections-spec -- expected unaffected (the chunked profile,
    `caad: 1` AAD, and sealed chunk counts are already specified; auto-routing
    is client ergonomics producing already-specified wire traffic) -- verify
    and waive
  - was-teaching-server -- expected unaffected (the server sees identical
    `chunked-streams` traffic either way); verify and waive
- acceptance:
  - [ ] An oversize `add()` on an encrypted collection routes onto the
        chunked-stream path automatically instead of throwing

The codec seam is a pure single-write transform, so an oversize `add()`
currently throws and points callers at the (fully working)
`EdvClientCore.insert({stream})` / `getStream` path. Ergonomics only.

---

## Live Google Drive backend

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
  - was-react -- `src/sync/` is the other diverged copy, and it has grown
    pieces the freewallet copy lacks (feed-master port, LWW conflict handler,
    DocCipher wiring); the extraction must decide which of those move into the
    package and which stay was-react-side
  - was-client -- expected code-unaffected (the `./sync` subpath already
    carries the port and primitives the driver consumes); README gains a
    pointer to the new package
  - wallet-core -- expected code-unaffected (its `sync/` engine is the
    non-RxDB path and deliberately excludes the RxDB adapter); its
    ARCHITECTURE.md references to "freewallet's RxDB driver/adapter" get
    re-pointed at the extracted package
  - wallet-attached-storage-spec -- unaffected (the wire contract is already
    normative: Query Profile Registry appendix + Conditional Requests)

Most of what this item originally deferred has since landed, in a different
factoring than predicted. The `WasSyncPort` implementation and sync primitives
moved into the client itself as the `@interop/was-client/sync` subpath (0.19.0:
`createWasSyncPort`, whose pull path rides `Collection.changes()`), so
freewallet's hand-rolled `was.request()` changes query is gone -- its
`stores/syncController.ts` calls `createWasSyncPort` directly. `createdBy` is
threaded into the local RxDB document (freewallet `syncedDocSchema` bumped to
`version: 1` with a migration strategy; `epoch` followed at `version: 2`). And
a framework-agnostic pull/push engine was extracted into `@interop/wallet-core`
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
