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
    Considerations text. Still open as of 2026-08-12: spec.md's stored-envelope
    section mentions `indexed` as optional but specifies none of the above;
    tracked as ECS-2 in the ECS `_spec` roadmap
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
a plain alias of `CollectionEncryption`). The item stays `in-progress` on one
remaining `touches:` entry: the encrypted-collections spec text (hmac
distribution, `indexed` envelope entries, index-schema persistence, Security
Considerations), filed as ECS-2 in the ECS roadmap. The was-teaching-server half
(WAS-56: codec-path conformance coverage plus the Reverse-gap cross-link) was
archived 2026-08-12. WCL-10 (the `was.collection` binding decided as ECS-1)
landed alongside it on 2026-08-12, so the persisted schema envelopes are minted
with the final binding shape.

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

### WCL-12: Chunked-stream auto-routing for `put()` (oversize update)

- status: todo
- priority: low
- labels: encryption, streams, ergonomics
- acceptance:
  - [ ] An oversize binary `put()` on an encrypted collection replaces the
        existing document via the chunked-stream path instead of throwing
  - [ ] Chunks orphaned by a shrinking rewrite (or by an update that leaves the
        chunked profile) are cleaned up or provably unreachable

discovered-from: WCL-2. `add()` auto-routes but `put(id, bigBlob)` still refuses
with the chunked-path guidance. An update is not a symmetric case: it must
reconcile an existing document's chunks with the new stream
(`EdvClientCore.update({ doc, stream })`) and deal with orphaned chunk resources
when the new stream is shorter, so it is a real feature rather than a follow-up
detail.

### WCL-13: Streaming `add()` (accept a `ReadableStream`)

- status: todo
- priority: low
- labels: streams, ergonomics
- acceptance:
  - [ ] `collection.add(stream)` (or an explicit stream option) writes a chunked
        document without buffering the whole payload in memory

discovered-from: WCL-2. The routed write takes bytes already in memory (`Blob` /
`Uint8Array`); the underlying `EdvClientCore.insert({ stream })` path is already
streaming, so the gap is only the public `add()` surface and the read-side
counterpart (a streaming `get` variant) for callers that cannot buffer.

### WCL-14: Upstream: `_updateStream` overrides caller hmac suppression

- status: todo
- priority: low
- labels: encryption, upstream
- touches:
  - "@interop/edv-client" -- `EdvClientCore._updateStream` re-updates the
    document with `hmac = this.hmac` regardless of what the caller passed to
    `insert`, so a caller cannot suppress indexing on the second write of a
    chunked insert
- acceptance:
  - [ ] A chunked insert whose caller passed no hmac (or a suppressed one)
        produces a final document whose `indexed` entries reflect the caller's
        choice

discovered-from: WCL-2. Harmless today -- routed blobs declare no indexable
attributes, so the extra hmac application emits nothing meaningful -- but it
means the WAS codec cannot fully control `indexed` emission on the chunked path
without this upstream fix.

### WCL-16: Sync read path cannot decode chunked documents

- status: todo
- priority: medium
- labels: encryption, streams, sync
- acceptance:
  - [ ] A chunked envelope arriving through a sync pull either decodes
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

### WCL-11: `indexed` emission on the sync push path

- status: in-progress
- priority: medium
- labels: encryption, sync, query
- touches:
  - freewallet -- its sync wiring builds the cipher via `createEdvDocCipher`; if
    that function gains a schema input (or a refresh hook), the wiring must
    supply it; verify and update. Verified 2026-08-12: the wiring change is
    FW-133 (its item text now records the shipped API); it lands once was-client
    0.36.0 is published to npm (freewallet consumes the registry).
  - was-react -- same: its `src/sync/` DocCipher wiring is the other
    `createEdvDocCipher` consumer; verify and update. Verified 2026-08-12: the
    wiring change is WR-32 (item text updated likewise); also blocked on the
    0.36.0 npm publish.
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
on the 0.36.0 npm publish.

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

### WCL-17: Resource-log chain verifier + log-governed descriptor reads

- status: todo
- priority: medium
- labels: encryption, log, integrity
- touches:
  - was-client: a new verifier module over the existing `/log` transport
    (`src/log/logStore.ts` is deliberately transport-only -- parse,
    read-with-etag, CAS append, guarded genesis create -- with chain
    verification explicitly left "to the consuming verifier"); the
    encryption-descriptor read path (`EncryptionDescriptorStore` /
    `src/edv/descriptorStore.ts`) learns the log-governed case
  - storage-core: unaffected (`resourceLog.ts` wire types and
    `CollectionEncryption.type`/`history` shipped; the verifier consumes them
    as-is) -- verify and waive
  - wallet-core: hosts the shipped verifier today (`src/resourceLog/`,
    `descriptors/logSource.ts`, `keys/rosterLogStore.ts`); the decision box
    settles whether it moves down here or stays put
  - app-connect-spec / encrypted-collections-spec: profile of record (ECS-3
    settles which spec hosts it); no text change expected -- verify
  - freewallet / dcw: consumers -- FW-134 and DCW-43 build the producing half on
    this verifier
- acceptance:
  - [ ] Decision recorded first: wallet-core already ships a complete verifier
        (`src/resourceLog/` -- verify, append, pin, seal) that both wallets run
        for the user key roster log. Settle whether this item moves that
        implementation down into was-client (wallet-core then consuming it from
        here) or leaves it in wallet-core and scopes this item to the descriptor
        read path only -- the never-reimplement rule forbids a second parallel
        verifier
  - [ ] Chain verification ships at the layer that decision picks: SCID
        recomputation over the genesis; per-entry hash and `versionId` checks;
        `eddsa-jcs-2022` entry-proof verification under the
        external-authorization rule, against a caller-supplied resolved
        controller document (a resolver port -- was-client stays free of
        DID-method machinery); terminal-entry recognition (verify a frozen log,
        refuse to extend one); format dispatch on `resource-log:0.1` (WASS-22
        spelling) confirmed against the genesis `parameters.method`, a
        `history.method` mismatch being a refusal
  - [ ] The chain-head pin: a persistent `{ scid, method, head }` pin behind a
        caller-supplied store port; a served log behind the pin is a continuity
        break, never silently accepted
  - [ ] The log-governed descriptor read path: a descriptor carrying `history`
        is accepted only after fetching the log at `history.resource`, verifying
        the chain, and checking the point-state projection JCS-equals the
        verified head's `state` after stripping `history` (`type` carried on
        both sides makes the comparison land)
  - [ ] A descriptor without `history` keeps today's behavior exactly (point
        state, epoch pin, unknown-epoch refresh); no new failure mode for
        non-log collections
  - [ ] Negative-path tests: forged entry proof, truncated log (rollback behind
        the pin), forked log under the same SCID, projection mismatch against
        the head, `method` mismatch, extending past a terminal entry

The consuming half the `/log` transport has been waiting for -- scoped to
collection encryption descriptors, because the stack is not greenfield:
wallet-core's `resourceLog` module already verifies, appends, pins, and seals,
both wallets run it for the user key roster log, its
`logGovernedDescriptorSource` already checks `state.type` against
`WasEpochConfiguration`, and its verifier already enforces the history-reserved
rule. What exists nowhere is a producer or consumer for collection descriptors:
no code stamps `history` onto a point-state descriptor or follows one (the
members shipped as storage-core types and as WAS-EC normative text via WASS-14).
Sequence: the verifier is self-contained against hand-built logs (the existing
`test/node/resource-log.test.ts` fixtures grow into the negative-path suite);
FW-134 / DCW-43 then produce real logs against it. Spec-side prerequisites
WASS-22 (identifier spelling) and ECS-3 (profile home) are editorial for this
item -- the profile's normative content is already stable in the App Connect
spec text.

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
