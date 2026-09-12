# WAS Client Roadmap (open items)

nextAvailableId: 98

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
free prose context. Ids are permanent and never reused. The `nextAvailableId`
line at the top of this file is the next id to take: filing an item takes that
number and rewrites the line to one higher, in the same edit. Never derive the
next id by scanning, since the highest id usually sits in `archived-roadmap.md`
rather than here. Statuses: `todo`, `in-progress`, `draft` (no actionable
done-state yet -- blocked externally or a parking record); `done` items move to
[archived-roadmap.md](archived-roadmap.md) once shipped. The full conventions --
including the `touches:` field, required for any item changing a spec, a wire
contract, or a shared `@interop/*` API, and blocking `done` while any of its
entries is unresolved -- live in isomorphic-lib-template's AGENTS.md under
"Roadmap & Task Conventions" and apply to WCL-N items too.

---

## WAS v0.5 protocol changes

### WCL-41: v0.5 path layout -- container descriptions at `meta`, the merged Collection Metadata object, trailing-slash canonical URLs

- status: todo
- priority: high
- labels: was-v0.5, breaking, paths, zcap, api
- blocked-by: the reference server serving the v0.5 route table
  (was-teaching-server's item for WASS-29)
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
  - storage-core: the merged wire type is its item (SC item for WASS-29); this
    one consumes it
  - wallet-core: WC-230 filed 2026-09-11 -- the single-verb Space capability's
    bare-URL target and the annex-mend Space Description probe. It also raises a
    question back at this item: whether the merged store should offer a way to
    avoid gratuitous compare-and-swap retries between an epoch rotation and an
    annotation write, now that both advance one `metaVersion`
  - freewallet: FW-523 filed 2026-09-11 -- its three `./paths` importers inherit
    the change, but several zcap minters hand-build WAS URLs and bypass the
    builders entirely
  - was-react: WR-46 filed 2026-09-11 -- `WasRemoteStore.#putDescription` sends
    a partial body to the bare Collection URL, which after the merge would clear
    the `custom` envelope a description write cannot reach today
- acceptance:
  - [ ] A `spaceMeta(spaceId)` builder exists beside `collectionMeta` and
        `resourceMeta`, and is exported from the `./paths` subpath
  - [ ] `spaceCollections()` is deleted; `Space.collections()` walks
        `spaceItems(spaceId)` -- the same `/space/{id}/` URL
        `Space.createCollection()` already posts to
  - [ ] The Space description methods (`describe`, `describeWithEtag`,
        `replaceDescription`, `configure`) read and write `spaceMeta`
  - [ ] The Collection description methods and the Collection metadata methods
        converge on one path and one validator. `describe()` and `meta()` return
        one merged object; `replaceDescription()` and `setMeta()` are one
        full-replacement write against `collectionMeta`; the two `readEtag` call
        sites become one
  - [ ] `Collection.delete()` and `Space.delete()` target the trailing-slash
        container URLs
  - [ ] `ifNoneMatch` on the merged Collection write means "create only if the
        Collection does not exist", and `Collection.configure` / `patchCustom`
        are re-expressed against the single validator: a configuration change
        now legitimately invalidates an in-flight annotation write, so the
        read-modify-write helpers retry rather than assume independence
  - [ ] `delegateGrantAt`'s prefilled `target` and `spaceRootCapabilityId()`
        agree with the server's canonical `allowedTarget` for every operation.
        Signature verification fails on any mismatch, so this is checked against
        the reference server, not reasoned about
  - [ ] `src/edv/descriptorStore.ts` (the encryption-descriptor store seam)
        reads and writes the descriptor through the merged object
  - [ ] ARCHITECTURE.md's two affected statements are rewritten, and the
        CHANGELOG entry names this a breaking change
  - [ ] The consumers listed under `touches:` are walked: every external call
        site that builds a root capability, an invocation target, or a pinned
        resource URL from the exported `spacePath` is re-audited against the
        canonical trailing-slash Space URL

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

### WCL-12: Chunked-stream auto-routing for `put()` (oversize update)

- status: todo
- priority: medium
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

Raised to medium by the 2026-09-11 review, which proved the orphan half is not
gated on the auto-routing feature. An ordinary small `put()` over a chunked
encrypted document already strands the old chunks. They stay stored, counted
against quota and decryptable, with no error. The second acceptance box covers
it, so no separate item was filed, but an interim refusal can land before the
routing work does. Detecting the chunked profile needs the pre-read envelope
decrypted, since `meta.encoding` is sealed inside the JWE rather than known at
encode time.

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

Take the seam change once, together with WCL-43. `decode` takes
`(response, expectedId?, context?)`. This item is the third parameter, an
availability gap that `src/codec.ts` documents as deliberate for sync. WCL-43 is
the second, an integrity gap nothing documents as intended. Both are fixed by
giving `DocCipher.decrypt` the caller's resource id and context, so splitting
the breaking change across two releases would churn the same downstream
consumers twice.

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

## Internal design follow-ons

Items raised by the 2026-08-21 cleanup review of `src/` (reuse, simplification,
efficiency, and altitude passes). The behavior-preserving half of that review
landed in 0.42.0; everything here was deliberately left out of it because the
fix changes observable behavior, crosses the codec seam, or needs a maintainer
decision first. Each carries `discovered-from: 2026-08-21 cleanup review`.

### WCL-26: Bare `Error` for `did:key` validation failures in the EDV recipient path

- status: todo
- priority: low
- labels: errors, encryption
- touches:
  - was-client: `didKeyRecipient.ts` and `epochCrypto.ts` throw sites
  - freewallet, dcw: any consumer matching these failures on `err.constructor`
    or on the bare message rather than on a class
- acceptance:
  - [ ] Caller-input `did:key` validation failures throw `ValidationError`, and
        key-material failures throw `EncryptionError`
  - [ ] `catch (err) { if (err instanceof EncryptionError) ... }` -- the
        documented fail-closed pattern -- sees them

Four validation failures throw untyped `Error`: two in `didKeyRecipient.ts`
("not an Ed25519 did:key DID", and the key-material case below it) and two in
`epochCrypto.ts` ("is not a did:key", "Cannot resolve non-did:key key id").
`ValidationError` and `EncryptionError` in `src/errors.ts` are the established
classes for exactly this, and `epochKeys.ts` and `recipients.ts` already use
them for the same class of failure.

A caller running the documented fail-closed handler misses all four. The change
is small, but it changes the thrown class, so it wants a check against the
freewallet and dcw call sites before landing rather than being folded into a
cleanup pass. The shared `DID_KEY_PREFIX` half of this finding already landed in
0.42.0.

### WCL-29: `codecFor` eagerly unwraps the blinded-index key for read-only handles

- status: draft
- priority: low
- labels: encryption, search, efficiency
- acceptance: none yet -- the fail-closed timing change below is the decision
  this needs before it becomes actionable

`buildEdvCodec` runs `resolveHmacKey` whenever the descriptor declares an `hmac`
member: an ECDH plus Concat KDF plus A256KW unwrap, then a WebCrypto raw HMAC
key import. The key is only ever consumed by `#writeBlindingKey()` (which
returns nothing while the schema declares no indexes) and by `#buildQuery`. So a
handle that only reads from a searchable collection, or writes to one before any
index is declared, pays a key derivation and import it never uses. Once per
handle, not per operation.

Holding it as a memoized thunk forced at the two consumers is the obvious fix,
but it is deliberately not behavior-preserving: `resolveHmacKey` fails closed
with an `EncryptionError` when the descriptor declares a key this reader cannot
unwrap, and making it lazy moves that failure from handle resolution to the
first write or search. Whether a reader that cannot open the blinding key should
fail at resolution or only when it tries to use it is a fail-closed policy
question, not a performance one, which is why this is parked as a draft rather
than filed as work.

### WCL-32: Provisioning creates cannot be made race-safe (no create-if-absent precondition)

- status: in-progress
- priority: low
- labels: conditional-writes, provisioning, spec
- touches:
  - wallet-attached-storage-spec: WASS-31 (shipped 2026-09-07: Update Collection
    documents `If-None-Match: *` and its 412; the Space Data Model gains the
    server-managed validator, Read Space the `ETag`, Update Space both
    preconditions)
  - was-teaching-server: WAS-90 (shipped 2026-09-07 for 0.29.0: both
    preconditions on Update Space and Update Collection, the Space `ETag`;
    publish pending)
  - was-client: `Space.describeWithEtag` / `replaceDescription` and
    `Collection.replaceDescription`'s `ifNoneMatch` (shipped 2026-09-07 for
    0.53.0)
  - freewallet, dcw: waived -- `ensureSpace` and `ensureSpaceAndCollection` keep
    their contract (a lost race is absorbed rather than thrown), so callers need
    no change
- acceptance:
  - [x] A concurrent create of the same Space or collection loses at the server
        instead of silently replacing the winner's description
  - [x] `ensureSpace` and `ensureSpaceAndCollection` stay idempotent under that
        race: a lost create is recovered by re-reading the winner rather than
        surfacing to the caller as a `PreconditionFailedError`
  - [x] `Space` gains the `describeWithEtag` / `replaceDescription` pair
        `Collection` already has

discovered-from: the review of the `ensureSpace` split. Both create branches in
`src/sync/provisioning.ts` read the description, find it absent, and pass that
`null` into `configure` as `current`. The merge then runs against a read one
round trip older than the `PUT`. A Space created concurrently inside that window
has its `type` array omitted from the body, and `type` is accepted at creation
only, so a replace-semantics server drops it for good. A collection created
concurrently loses its `backend`. The window predates the split: the second
`describe()` that used to run inside `configure` narrowed it without closing it,
and threading the description widened it again by one request.

As filed, no client-side change could close it: `If-None-Match: *` is the only
precondition that states create-if-absent, and at the time neither endpoint
honored it (the collection handler parsed the header and dropped it, and the
Space handler read no preconditions at all). Closing it was spec work first
(WASS-31), then server work (WAS-90), then the client half.

Resolution, 2026-09-07: both create branches in `src/sync/provisioning.ts` now
create through `replaceDescription` under `ifNoneMatch`, and a failed create is
recovered by re-reading and adopting the winner. The recovery keys on the
re-read rather than on a 412, because the server evaluates the
encryption-descriptor transition rules before the precondition: a rival that
already installed key epochs makes the loser's create fail with a 400 or 409
instead. The earlier interim mitigation (a `configure` re-read right before the
`PUT`) is superseded; `configure` is no longer on the provisioning path. Open
only for the server publish in `touches`. Against a server that ignores the
precondition the create is an unconditional upsert, and the loser of a race can
overwrite the winner's display name (the server merges the rest forward); no
client-side gate can detect that server, since the precondition is a property of
the description endpoints rather than a backend feature token.

### WCL-34: The integration tier never runs, and skips provisioning entirely

- status: todo
- priority: medium
- labels: testing, provisioning, ci
- discovered-from: freewallet FW-384's CI failure (2026-08-29)
- acceptance:
  - [ ] `test/integration/` covers `ensureSpace` and `ensureSpaceAndCollection`
        against a real server, including the already-provisioned second pass
  - [ ] The description that test threads comes from `ensureSpace`'s own return
        rather than a hand-written literal
  - [ ] `test:integration` runs in CI, or the reason it cannot is recorded here

Context: the integration tier exists and covers ten files, but it runs against a
server the developer starts by hand (`TEST_SERVER_URL`, absent means
`describe.skip`), appears in no CI workflow, and is documented nowhere outside
the test file headers. It also does not touch provisioning at all: `ensureSpace`
appears in exactly one test file in the repo, the fakes tier.

That combination let a real divergence through. `ensureSpaceAndCollection`
refuses a supplied `spaceDescription` whose `id` does not name the Space being
provisioned, and `ensureSpace` returns the served description verbatim on its
existing-Space path. So the guard depends on a member only a real server
supplies. The fakes tier tested the two halves separately, each against its own
hand-written description -- one of which carried no `id`, and the one that did
threaded a literal with an `as never` cast at exactly the join where the type
system would have objected. The seam was covered twice and never once end to
end. (The joined case now exists, added 2026-08-29; what is still missing is a
real server supplying the description.)

A live-server test is what pins "a served description always carries `id`". No
fake can assert that about a server, and this repo is where the guard lives.

The CI half is the larger point. Three live-server tiers exist across this repo,
freewallet, and freewallet's e2e, and none of them runs in any workflow. A tier
that runs when someone remembers catches nothing. The server publishes to npm
and exports `createApp` / `FileSystemBackend`, and its own suite already boots
it in-process on port 0 (`was-teaching-server/test/helpers.ts`), so an
in-process boot is available here too and would remove the `TEST_SERVER_URL`
handshake. Weigh the licence edge first: the server is AGPL-3.0-or-later and
this package is MIT, so a test-only devDependency needs a deliberate call rather
than a default.

Siblings, each owning its own repo's half: wallet-core WC-152, freewallet
FW-392.

## Whole-codebase review findings (2026-09-11)

Items filed from the review of 2026-09-11, which read every root module and
subdirectory of `src/` and verified each finding against the source, the
reference server and the spec. Findings that proved wrong, that an existing item
already covered, or that were too small to track are not itemized here.

### WCL-42: A server-supplied `next` link is followed to any origin, with a signed zcap invocation

- status: todo
- priority: high
- labels: security, api, correctness, fail-closed
- acceptance:
  - [ ] A `next` that resolves outside the first page's origin, or outside its
        base path, ends the walk with a typed `WasServerError` instead of being
        fetched
  - [ ] A test asserts the list of URLs actually requested during a walk, so a
        hostile `next` cannot silently receive an invocation
  - [ ] `walkPages` takes a page-count bound with a generous default and raises
        a typed error naming the listing URL when it is exceeded
  - [ ] The guard covers `WasClient.listSpaces`, `Space.collections()` /
        `collectionsPages()`, `Collection.list()` / `listPages()` /
        `listItems()`, and the public listing walk
  - [ ] The CHANGELOG entry names this a security fix

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

### WCL-43: The sync decrypt seam carries no resource id, so the envelope-to-resource binding is never verified

- status: todo
- priority: high
- labels: sync, encryption, integrity, codec-seam, security, breaking
- touches:
  - was-client: `DocCipher.decrypt` in `src/sync/types.ts`,
    `src/edv/docCipher.ts`, `src/sync/plaintextCipher.ts`, and ARCHITECTURE.md's
    "Tamper resistance" paragraph, which today asserts the binding is verified
    on decode
  - wallet-core: `src/sync/engine.ts`, `src/sync/types.ts`,
    `src/keyring/record.ts`, `src/descriptors/index.ts`
  - was-sync: `src/conflictHandler.ts` and the feed mapping that would supply
    the id
  - freewallet, was-react: every `DocCipher.decrypt` call site
- acceptance:
  - [ ] `DocCipher.decrypt` takes the resource id and forwards it as `decode`'s
        `expectedId`
  - [ ] A replication read of an authentic envelope for resource A presented
        under feed row id B throws `IntegrityError`
  - [ ] The `./sync` subpath's breaking change is taken once, jointly with
        WCL-16, rather than twice
  - [ ] ARCHITECTURE.md's tamper-resistance claim matches the code

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

### WCL-44: Chunked reads never verify a chunk against its parent document (cross-document chunk splice)

- status: todo
- priority: high
- labels: encryption, streams, security, integrity
- touches:
  - "@interop/edv-client": `getStream` needs to accept and enforce an expected
    chunk binding, or was-client wraps the transport it is handed
  - encrypted-collections spec: whether the chunk-to-parent binding rule is
    normative is spec text this would add
- acceptance:
  - [ ] A chunk body served from a different document is refused with a typed
        error before its plaintext reaches the caller
  - [ ] A regression test covers the cross-document splice, distinct from the
        existing cleartext-id swap test at `test/node/edv-codec.test.ts:788`
  - [ ] The two comment blocks in `src/edv/EdvCodec.ts` that over-claim the
        per-chunk AAD coverage are corrected

Each chunk's AAD is the chunk's own transmitted protected header plus its index,
so it binds position and nothing else, and the header it binds is the one the
server just handed over. The chunk header does carry `was.resource` -- verified,
because `_updateStream` forwards the additional protected parameters -- but
nothing in was-client or edv-client ever parses a chunk header, so the binding
is written and never read. Reproduced: a server that serves document A's
authentic envelope and answers A's chunk URLs with B's stored chunk bodies makes
`decode(A, idA, ctx)` return B's plaintext, typed with A's sealed content type,
with no error raised.

This is adjacent to archived WCL-15's F1, which recorded the same AAD limitation
but whose landed fix closed only the addressing half: chunks are now fetched by
the AEAD-bound `was.resource` rather than the cleartext id. The response-content
half is still open. The fix is read-side and changes no stored bytes, since the
binding is already present in every chunk header. It becomes a permanent wire
decision only if a new header member is added instead of reading the existing
one; that choice needs the maintainer's byte-level sign-off before it is coded.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-45: Rotation resolves its current epoch with the tolerant `pickEpoch`, re-admitting removed readers

- status: todo
- priority: high
- labels: encryption, key-epochs, security, fail-closed
- touches:
  - freewallet, wallet-core, dcw: `removeRecipient` / `replaceRecipient` gain a
    new `EncryptionError` on a descriptor whose `currentEpoch` is absent or
    unlisted, so the rotating call sites need a pass
- acceptance:
  - [ ] `src/edv/recipients.ts:877` resolves the current epoch through the
        strict `currentEpochOf`, and `pickEpoch` is deleted once it has no
        callers
  - [ ] A rotation against a descriptor whose `currentEpoch` is absent, or names
        an unlisted entry, refuses instead of computing a survivor set
  - [ ] Both scenarios are covered by tests: the re-admission case and the
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

### WCL-46: Rotation re-wraps the fresh epoch secret to every `kid` in the served roster

- status: todo
- priority: high
- labels: encryption, key-epochs, security, api
- touches:
  - freewallet, wallet-core, dcw: a `removeRecipient` / `replaceRecipient`
    signature change reaches every rotating call site
  - encrypted-collections spec: the rotation-side counterpart of its
    recipient-key-derivation MUST NOT may want stating explicitly
- acceptance:
  - [ ] A rotation wraps the fresh epoch secret only to caller-vouched
        recipients, the way `addRecipient` already takes them
  - [ ] `defaultResolveRecipientKey` -- resolving any well-formed `did:key` from
        the roster itself -- is reachable only behind an explicit opt-in
  - [ ] A junk roster entry injected into the current epoch receives no wrap of
        the fresh epoch, and a test proves it

Executed. Appending one entry to the current epoch --
`{ header: { kid: '<alice did:key>#<attacker X25519 fingerprint>' }, encrypted_key: '<garbage>' }`
-- and running `removeRecipient` produced a fresh epoch carrying that kid, which
the attacker's key-agreement key unwrapped to the same secret Alice unwrapped.
Nothing upstream authenticates the roster on the point-state path: the plain
descriptor store reads the Description with no signature over it,
`acquireDescriptor` applies no continuity check, and `epochRostersEqual`
deliberately ignores recipients inside an epoch, so even a pinning consumer
cannot see the injected entry. Only the log-governed store authenticates it.

Two corrections the verifier made to the original proposal, both of which belong
in the fix. First, checking the kid's fragment against its DID part does NOT
close this: an attacker can inject a fully self-consistent
`did:key:z6LSattacker#z6LSattacker` and pass any such check. Only sourcing
survivors from caller-vouched keys does. Second, a mitigation already ships:
`resolveRecipientKey` is an injectable option and may resolve `null` to drop a
kid, so a caller can allowlist today. So this is an unsafe default that is
documented nowhere, rather than a hole with no remedy. The spec already
prescribes the shape for its one document-backed case (resolve from the verified
controller document, drop any entry whose kid matches no verification method),
which makes the bare did:key default the outlier. The roster layout is
untouched, so no byte-level sign-off is needed; the API shape is the
maintainer's call.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-47: A governed descriptor read through `wasDescriptorSource` is trusted with no log verification

- status: todo
- priority: high
- labels: encryption, log, integrity, security, fail-closed
- touches:
  - encrypted-collections spec: ECS-7 settled that the projection is a bound,
    non-authoritative copy; whether an unverifying reader MUST refuse is the
    text this would add
  - wallet-core: `logSource.ts` / `rosterLogStore.ts` supply the
    governance-aware source and would opt in past the new refusal
  - freewallet, was-react: the affected readers
- acceptance:
  - [ ] `acquireDescriptor` refuses a fetched descriptor that declares `history`
        when the source did not declare itself governance-aware, pointing the
        caller at a log-governed source
  - [ ] The refusal is typed and covers every source, not only
        `wasDescriptorSource`
  - [ ] A governance-aware source still resolves the same descriptor unchanged

`grep -rn isGovernedDescriptor src/` returns three call sites: the definition,
the log-governed store, and sync provisioning. Neither `wasDescriptorSource` nor
`acquireDescriptor` is among them, so a served `encryption` member carrying
`history` is returned verbatim and written into the cache, and
`createRefreshingEdvDocCipher` hands it straight to `createEdvDocCipher`. The
exploit mechanics hold: the epoch id IS the X25519 public key, so a server that
mints an epoch it holds the secret for, and wraps a copy to the victim's public
key, gets every subsequent write sealed to itself. The `was.epoch` and
`was.resource` AEAD binding binds the epoch and the resource id, not the roster.

Archived WCL-17 is partial coverage. It named this exact audience -- "every
reader that holds a descriptor but not the convention: a was-react app on a
shared collection, the storage browser, an agent" -- and landed
`logGovernedCollectionDescriptorStore`, the write-side seam. The acquire seam
that same audience actually uses was never wired to it and was never made to
refuse, so the plain reader fails open on a descriptor it is not equipped to
verify. That contradicts the repo's fail-closed policy everywhere else.
Maintainer decision required before coding: the shape of the marker by which a
source declares itself governance-aware. discovered-from: whole-codebase review,
2026-09-11.

### WCL-48: A 412 raised by `store.read()` escapes `compareAndSwap` instead of rebasing

- status: todo
- priority: high
- labels: cas, conditional-writes, log, correctness
- touches:
  - wallet-core: `rosterLogStore` is the generic store wrapped by this loop, so
    its roster tests are the acceptance test and must be re-run
- acceptance:
  - [ ] A `PreconditionFailedError` from `store.read()` is treated as a rebase,
        the same as one from `store.replace()`
  - [ ] A store whose `read()` throws a 412 once completes through the retry
        rather than surfacing the error to the caller
  - [ ] `logGovernedDescriptorStore`'s module docstring and ARCHITECTURE.md
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

### WCL-49: `declareIndex`'s first write is unconditional, so a concurrent first declaration is lost

- status: todo
- priority: high
- labels: encryption, search, conditional-writes, correctness
- acceptance:
  - [ ] The CAS store behind `declareIndex` resolves `null` when `meta()`
        returned no validator, so the first write goes out as a guarded create
        under `If-None-Match: *`
  - [ ] Two interleaved first declarations produce a 412 and a retry, and both
        schemas survive
  - [ ] The repo's concurrency test stub stops serving an `ETag` at version 0,
        so it matches the reference server and can observe this case

Verified on both sides. The server strips `generation` and `metaVersion` and
emits the `ETag` header only when it has one, which it does not before the first
metadata write. The client's inline store then returns a non-`null`
`{ value: {}, etag: undefined }`, so `compareAndSwap` takes the `replace`
branch, `writeHeaders` emits no `if-match`, and nothing can 412. A scratch stub
matching the real server showed the first PUT carrying neither precondition, and
a rival's complete declaration interleaved between the read and the write being
overwritten: `metaVersion` reached 2 with no 412 and no retry, and a fresh
handle read back only the rival's attribute. The repo's own concurrency test
never catches this because its stub serves an ETag from version 0. The
`declareIndex` JSDoc promises exactly what does not happen. The same window
makes `setName` / `setTags` an unguarded full replacement, so a racing rename
erases a just-declared schema.

WCL-41 is partial and indirect coverage. Converging the description and metadata
paths onto one validator would give `/meta` a validator that exists from
Collection creation, closing this structurally, but no acceptance line there
names this race, WCL-41 is blocked on the server serving the v0.5 route table,
and under it `ifNoneMatch` is redefined to mean "create only if the Collection
does not exist" -- so the guarded-create fix here is not the WCL-41 fix. The
client stays exposed until v0.5 lands. Client-only, using preconditions the spec
and the reference server already define. discovered-from: whole-codebase review,
2026-09-11.

### WCL-50: Preconditions are emitted without probing that the backend enforces them

- status: todo
- priority: high
- labels: conditional-writes, fail-closed, cas, log, encryption, correctness
- touches:
  - wallet-core: `ensureUserKeyRoster`, the log-governed descriptor store, and
    the sync engine, which classify the port's thrown errors by name
  - was-sync: the same error-name classification on the `./sync` subpath
  - freewallet, dcw: `addRecipient` / `removeRecipient` / `replaceRecipient`,
    `ensureSpaceAndCollection`, and any supported backend that would be left
    unable to write a log
- acceptance:
  - [ ] A shared refusal helper lives beside `writeHeaders` in
        `src/internal/conditional.ts`, so the refusal messages do not drift
  - [ ] `compareAndSwap` refuses when `read()` returns a value with no
        validator, with an explicit opt-out for a caller that wants the
        unconditional write
  - [ ] `src/log/logStore.ts` refuses `append` and `create` on a backend that
        advertises no `conditional-writes`
  - [ ] `src/sync/port.ts` refuses a precondition-bearing write against a
        backend advertising no `conditional-writes`
  - [ ] `Resource.put` / `Resource.delete` gate a caller-named precondition on
        the same probe when the codec is non-conditional
  - [ ] `resourceDescriptorStore` reaches the probe the `Resource` handle
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

### WCL-51: A content id is minted at write time and never verified at read time

- status: todo
- priority: high
- labels: sync, integrity, correctness
- touches:
  - freewallet: `src/stores/remoteDirectStore.ts:340` and
    `src/stores/browserStore.ts:764` / `:1021` recompute the content id from the
    decrypted payload and never compare it
  - dcw: `app/lib/walletBackupCore.ts` and `app/lib/publicLink.ts` call the same
    helpers
- acceptance:
  - [ ] `createPlaintextDocCipher.decrypt` refuses when the recomputed content
        id does not match the id it was handed, as a typed `IntegrityError` the
        sync predicates can classify
  - [ ] A tampered envelope presented under an honest id is rejected rather than
        resolved
  - [ ] The downstream recompute sites are walked and either compare or delegate
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

discovered-from: whole-codebase review, 2026-09-11.

### WCL-52: The envelope `sequence` is unauthenticated and never validated on read

- status: todo
- priority: medium
- labels: encryption, security, conditional-writes, spec
- touches:
  - was-client: `src/edv/EdvCodec.ts` -- `wasParam`, `#sealParams`, `decode`,
    and the file header's "Enforced sequence" paragraph, which currently reads
    as a rollback guard
  - encrypted-collections-spec: the `was` parameter's member list, if the
    binding is to be normative
  - was-teaching-server, wallet-core, freewallet: any other writer or reader of
    the `was` header, once a member is added
- acceptance:
  - [ ] A replayed older envelope is refused on decode, or the "Enforced
        sequence" prose is rewritten so it no longer implies replay resistance
  - [ ] The maintainer has signed off on the header change before any code
        lands: the member name, its placement, and whether envelopes written
        before the change stay readable

`wasParam` emits exactly `v`, `resource` or `collection`, and `epoch`. The
parsed `was` header carries no `sequence` member. `sequence` lives only on the
cleartext envelope, where `#assertEnvelope` type-checks it and `decode` never
reads it. Proven: an old envelope decodes without complaint after a newer one
exists, and a write on top of the replayed envelope re-issues the next sequence,
so the codec counts up from whatever the server hands back. The only live
rollback guard is the server-supplied ETag, which the same adversary controls.
Binding `sequence` into `was` is a permanent wire artifact. It changes stored
bytes and is likely a scheme-version question, so it needs the maintainer's
byte-level sign-off before anything is coded; no encoding is proposed here.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-53: `#buildQuery` silently drops query terms a caller named

- status: todo
- priority: medium
- labels: encryption, query, search
- acceptance:
  - [ ] Every attribute the caller named contributes a token to each produced
        `equals` term, or the build throws `ValidationError` naming the
        attribute
  - [ ] A produced `equals` alternative that blinded to nothing is refused,
        rather than accepted because a sibling alternative is non-empty
  - [ ] `test/node/blinded-index.test.ts` gains a compound-index case

`declaredAttributeNames` admits every member of a compound index, while upstream
`_matchIndexes` emits a compound term only when the first attribute of that
index is present. A non-leading member therefore contributes nothing. Proven:
with a simple index on `content.type` and a compound index on
`['content.owner','content.status']`, a `find` on both `content.type` and
`content.status` produces a term set byte-identical to the `content.type`-only
query. A caller using `find` as a visibility filter gets every document. The
`termless` guard next to it has the same root cause and the same fix: it tests
`every`, so `find({ equals: [{ 'content.type': 'note' }, {}] })` posts an empty
alternative beside a real one, and `equals` is an OR, so the query matches the
whole collection. WCL-1 shipped `assertQueryAttributes` and the `termless`
guard; neither covers a partially blinded query. discovered-from: whole-codebase
review, 2026-09-11.

### WCL-54: A content-addressed collection accepts an in-place `put()` update

- status: todo
- priority: medium
- labels: encryption, sync, cas, api
- touches:
  - was-react `src/sync/`, freewallet: both build ciphers through
    `createEdvDocCipher`, whose default `idDerivation` is `content`; removing or
    throwing from `encryptUpdate` on that build is a behavior change, so sweep
    the call sites before landing
- acceptance:
  - [ ] `encode` refuses an update on a codec whose `idDerivation` is `content`,
        with a `ValidationError` pointing at delete-old plus add-new
  - [ ] The content-addressed `docCipherOverCodec` build does not expose
        `encryptUpdate`, matching what `src/sync/types.ts:196-200` already
        states

`#idDerivation` is consulted only when minting an id. Proven on a codec with
`idDerivation: 'content'`: `encode({ id, data, current })` succeeds, the new
envelope binds `was.resource` to the old id, and re-deriving the id from the new
ciphertext yields a different one. The stored document's id no longer derives
from its ciphertext, and a reader cannot notice, because the presence of
`was.resource` makes `#verifyResourceSlot` take the id-comparison branch instead
of re-deriving. `src/sync/types.ts:196-200` documents the opposite contract: a
content-addressed cipher either omits `encryptUpdate` or throws.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-55: Stale and foreign `indexed` entries are carried forward into the client's next write

- status: todo
- priority: medium
- labels: encryption, search, sync, security
- touches:
  - was-react `src/sync/`, freewallet: a refusal changes what a schemaless sync
    replica may push, so their `createEdvDocCipher` wiring needs a pass
- acceptance:
  - [ ] A write by a codec that cannot use the collection's declared blinding
        key refuses, or drops the prior envelope's blinded entries, instead of
        re-asserting them
  - [ ] Entries carried forward from the read envelope are limited to the ones
        whose `hmac.id` is this codec's blinding key; the rest are dropped
  - [ ] A foreign entry injected into the pre-read envelope does not survive
        into the next authored write

One line does both. `#writeBlindingKey()` returns `undefined` when the applied
schema is empty or the key is null, and upstream then stores the prior
document's `indexed` array verbatim. Proven: a codec with the schema applied
writes `status: 'active'` with one blinded entry; a second codec over the same
collection that never loaded the schema updates the document to `'archived'`,
and the resulting envelope's `indexed` deep-equals the old one, so the
`'active'` token is re-asserted. The rotated-off reader case, where
`resolveHmacKey` yields null, is the same code path. Separately, upstream
`updateEntry` replaces only the entry matching this codec's key and preserves
every other element of the array it was handed. Proven: an entry under a foreign
`hmac.id` injected into the pre-read envelope survives into the client's next
write, where it persists across rewrites, can force a match on a query the
server chose, and can trip a `unique` collision. Archived WCL-11 settled how the
schema reaches the sync cipher, as a caller-supplied optional `meta` input, and
recorded that its absence changes nothing; that is what the update path
falsifies.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-56: The write epoch goes stale with no signal on any write path

- status: todo
- priority: medium
- labels: encryption, key-epochs, codec-seam, security
- touches:
  - was-client: `src/edv/EdvCodec.ts` (`#writeEpoch`, `#recipients`),
    `src/internal/codec.ts` (`CodecHolder`), `src/edv/acquire.ts`,
    `src/edv/refreshingDocCipher.ts`, and the unqualified guarantee text in
    ARCHITECTURE.md and beside `removeRecipient`
  - wallet-core, freewallet, was-react: handle and cipher lifetimes, plus the
    repeated "resources written afterward are unreadable to the removed reader"
    wording; `ResourceCodec` / `EncryptionProvider` are published seams, so a
    write that now throws is consumer-visible
  - was-teaching-server, encrypted-collections-spec: the durable fix may be a
    server-side refusal of a write stamped with a non-current epoch, which is
    spec text the spec does not have today
- acceptance:
  - [ ] A write sealed under an epoch that is no longer the descriptor's
        `currentEpoch` is refused, or the codec is rebuilt, under a stated
        freshness rule
  - [ ] The refreshing cipher refreshes on the write path, not only on
        `UnknownEpochError` during decrypt
  - [ ] The exposure window is stated where the rotation guarantee is stated

Three findings, one mechanism. `#recipients` and `#writeEpoch` are computed once
in the codec constructor, nothing on the write path re-reads the descriptor,
`src/edv/acquire.ts` has no freshness horizon, and the server stores the
`Key-Epoch` header opaquely without comparing it to `currentEpoch`. The seam
level is handle identity rather than a descriptor-store bypass: both shipped
descriptor stores do reset through `replaceDescription` or the log append, but
`Space.collection(id)` mints a fresh `Collection` with its own `CodecHolder` on
every call, so `removeRecipient({ collection: space.collection('vault') })`
resets only the throwaway handle. Any other live handle, any other process, and
any handle pinned to an `encryption` override keeps sealing to the retired
epoch. `createRefreshingEdvDocCipher` closes the read half only: `encrypt` and
`encryptUpdate` are bare delegations, and `inner` is reassigned solely by the
`decrypt` path's `UnknownEpochError` handler, which a writer's own decrypts of
its own writes never trigger. Read staleness self-heals; the write side is
silent, and that asymmetry contradicts the unqualified guarantee at
`recipients.ts:677-681`. The recorded decision "No client-driven bulk rewrap of
stored envelopes" constrains the fix: already-stored ciphertext stays where it
is, so this is about the next write and about stating the window honestly.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-57: `epochRostersEqual` does not compare the whole epoch configuration

- status: todo
- priority: medium
- labels: encryption, key-epochs, spec
- touches:
  - was-react, wallet-core: they use `epochRostersEqual` as a
    cipher-invalidation trigger, and a stricter comparator makes more
    descriptors compare unequal, so their refresh paths need a check
- acceptance:
  - [ ] `epochRostersEqual` compares `scheme` and `version` alongside
        `currentEpoch` and the ordered epoch ids
  - [ ] Its JSDoc says it implements the spec's pinned epoch configuration, and
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

### WCL-58: A key-wrap authentication failure is reported as a membership decision

- status: todo
- priority: low
- labels: encryption, key-epochs, errors
- touches:
  - freewallet, wallet-core, was-react: all three classify decrypt failures by
    error class, so a third bucket on this path needs the same sweep archived
    WCL-9's `touches:` block did
- acceptance:
  - [ ] An entry selected by kid equality with this reader's own key id, whose
        AES-KW integrity check fails, surfaces as `IntegrityError` rather than
        as `KeyUnwrapError`
  - [ ] The message no longer tells the reader it was never a recipient or was
        removed and rotated, when the entry is addressed to it

`unwrapEpochSecret` collapses an AES-KW integrity failure, a malformed `epk`,
and a failed ECDH into one `null`. `unwrapEpochKey` selects the entry by kid
equality with this reader's own key id first, so a `null` there cannot mean "not
my entry". `lazyEpochKey` raises `KeyUnwrapError`, `isKeyMiss` treats that as
"try the next candidate", and the loop's final message tells the user it was
never a recipient. That is the inverse of the content path, which deliberately
raises `IntegrityError` for a kid-matched key whose AEAD fails. No key or data
is exposed, so the cost is a misleading message and a missing tamper signal.
Archived WCL-9 settled the two-bucket split, reserving `UnknownEpochError` for
an epoch the descriptor does not list and `KeyUnwrapError` for an epoch that
wraps to no key this reader holds; this third bucket was never considered.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-59: `addRecipient` treats an existing entry for the incoming kid as success

- status: todo
- priority: low
- labels: encryption, key-epochs, idempotence
- acceptance:
  - [ ] `addRecipient` verifies the existing entry unwraps before treating the
        kid as present, or simply re-wraps over it
  - [ ] Re-running `addRecipient` repairs a corrupt or partially written entry
        instead of resolving without writing

The presence test in `escrowInto` is `entry.header.kid === recipient.id` alone.
Proven: with a garbage entry pre-placed under Bob's kid, `addRecipient` resolved
successfully, never called `replace`, and Bob still could not unwrap. The
no-write short-circuit that turns this into a silent success is new; it landed
in 0.60.0 as "`addRecipient` skips the write when the reader is already a
recipient of every epoch". The non-adversarial path matters as much: a partially
written entry from any cause can never be repaired by re-running `addRecipient`,
which is the obvious operator response. The owner has already unwrapped the
roster secret at that point, so re-wrapping costs one ephemeral ECDH.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-60: `was.v` is taken from the unauthenticated descriptor, and `constants.ts` documents the opposite

- status: todo
- priority: low
- labels: encryption, security
- acceptance:
  - [ ] A descriptor whose `version` is below `EDV_SCHEME_VERSION` cannot
        silently pin a capable client back, per whichever refusal the maintainer
        picks
  - [ ] `EDV_SCHEME_VERSION`'s JSDoc at `src/edv/constants.ts:17-21` says the
        envelope stamp is the descriptor's `version` and the constant is this
        client's maximum

`descriptorDefect` refuses only a version greater than `EDV_SCHEME_VERSION`, so
a lowered one is accepted wholesale. Proven: a descriptor with `version: 0`
yields a codec that refuses every honestly written v1 envelope and stamps
`was.v: 0` on its own writes. Today that is denial of service on a plain,
non-log-governed descriptor. The substantive risk arrives with a v2 that
tightens the binding, when the same field pins a capable client back to v1
semantics. Note the spec makes the descriptor's `version` authoritative for both
the stamp and the decode limit, so stamping `EDV_SCHEME_VERSION` unconditionally
would be the non-conformant move; the actionable half is refusing a decrease,
which 57 implements in the pin helper. The doc fix is unconditional and belongs
here: `constants.ts:17-21` claims the constant is bound into every envelope's
`was.v` so descriptor and envelopes can never disagree, which is inaccurate.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-61: EDV key housekeeping -- unbounded resolver memo, duplicated first-epoch install

- status: todo
- priority: low
- labels: encryption, efficiency, reuse
- acceptance:
  - [ ] The `did:key` resolution memo is bounded or scoped to an instance,
        instead of a module-global `Map` keyed on host-supplied ids
  - [ ] `initRecipients` and `ensureFirstEpoch` share one internal
        implementation, with both exported names kept as wrappers
  - [ ] `initRecipients` stages its first-epoch mint lazily, so a call that
        adopts or refuses mints nothing

Two small items in the same layer. `RESOLVED_KEYS` in `src/edv/epochCrypto.ts`
is a module-scope `Map` with no eviction, populated in `didKeyResolver` from any
id it is asked to resolve, and rotation walks every kid the descriptor serves,
so growth is bounded only by how many distinct ids the process sees. Separately,
`initRecipients` and `ensureFirstEpoch` are the same operation twice: both
read-or-seed the descriptor, install through `withFirstEpoch`, and reconcile a
lost create race by adopting the winner. The differences reduce to
refuse-versus-adopt on a first read that already has epochs, an optional
pre-minted epoch, and the blinded-index install. `ensureFirstEpoch` stages its
mint behind `staged ??=`, while `initRecipients` calls `mintFirstEpoch`
unconditionally before the first read and discards it whenever it adopts or
refuses, wasting a keygen plus one wrap per initial recipient on every
non-first-install call. Archived WCL-30 changed `initRecipients`' lost-race
behavior and left the duplication in place. discovered-from: whole-codebase
review, 2026-09-11.

### WCL-62: Parked -- the `hmac` member is not pinnable, and wraps carry no purpose binding

- status: draft (parked, needs a maintainer decision)
- priority: low
- labels: encryption, spec, someday
- acceptance: none yet -- the docs half below is the only part actionable
  without a spec change, and the purpose-binding half needs the decision
  recorded here first

A parking record, not a defect. Both halves reproduce, and both are already
settled by the spec as accepted tradeoffs. First: `epochRostersEqual` returns
true across a wholesale `hmac` substitution, and `resolveHmacKey` then hands the
reader a blinding key built from the substituted secret without complaint. The
spec states that limitation verbatim -- on pure point state the `hmac` member
has no client-side guard of its own, the epoch pin does not cover it, and a host
serving a substituted member knows its secret; the log form is what closes that.
This client ships the log form, so the named remedy is present. The residue is
documentation: `epochRostersEqual`'s JSDoc and ARCHITECTURE.md's
descriptor-store section both present epoch pinning as the point-state integrity
story without saying it covers neither `hmac` nor the recipients inside an
epoch. That one paragraph rides with 57, which rewrites the same JSDoc. Second:
an epoch recipient entry copied verbatim into `hmac.recipients` is accepted by
`resolveHmacKey`, which returns an HMAC key built from the epoch's X25519
secret. The wrap layout is normative, with `PartyUInfo` the ephemeral public key
and `PartyVInfo` the UTF-8 recipient `kid` and nothing else, and epoch and
collection binding living outside the KDF in the AEAD-protected header. So the
client is conformant and a purpose label is a spec change. That change is a
permanent wire artifact: it alters the wrapped bytes and ends interchangeability
with a bare upstream wrap, so it needs the maintainer's byte-level sign-off plus
spec text before any encoding is proposed. On point state the move is also
strictly weaker than the `hmac` substitution above, since a host that can move
an entry can equally mint its own secret; on the log form the descriptor is
authenticated and the move is not available. discovered-from: whole-codebase
review, 2026-09-11.

### WCL-63: `Collection.configure()` is an unguarded read-modify-write that reverts a concurrent recipient grant

- status: todo
- priority: medium
- labels: conditional-writes, encryption, correctness, api
- touches:
  - was-client: `Collection.configure` (`src/Collection.ts:269-323`) gains a
    precondition, so a racing caller now sees a `PreconditionFailedError` where
    the write used to succeed
  - freewallet, wallet-core, was-react: each calls `Collection.configure`, and a
    rebase-on-412 contract is what they inherit
- acceptance:
  - [ ] `configure()` reads through `describeWithEtag()` and sends the merged
        description under that validator, driven by `compareAndSwap` so a 412
        rebases instead of surfacing
  - [ ] A `configure()` racing an `addRecipient` on the same collection either
        keeps the added recipient or fails loudly; it never drops the wrapped
        key
  - [ ] The option bag accepts an explicit `ifMatch` for callers that already
        hold a validator

`configure` merges `encryption` forward wholesale, and
`collectionWritableFields` passes the whole object -- `epochs` with their
`recipients`, and `hmac.recipients` -- into a PUT that calls no `writeHeaders`
at all. `replaceDescription` on the same class right above it does. The server
permits exactly that mutation (recipients within an existing epoch MAY change),
and `addRecipient` edits recipients inside the current epoch, so a stale merge
deletes a just-added reader's wrapped key with no error to anyone. The dangerous
direction is one-way: `removeRecipient` rotates to a new epoch, and the
append-only rule turns a racing `configure` into a loud 400 there. A
log-governed collection is safe, since a direct `encryption` write is refused.
PARTIAL: WCL-41 re-expresses `configure` and `patchCustom` against the single
validator, which closes this as a side effect, but only after v0.5 lands and
only while that item stays blocked on the server. discovered-from:
whole-codebase review, 2026-09-11.

### WCL-64: `Collection.setMeta()` silently destroys the persisted index schema

- status: todo
- priority: medium
- labels: encryption, search, api, correctness
- touches:
  - was-client: `Collection.setMeta` (`src/Collection.ts:511-527`) and
    `writeMeta` (`src/internal/meta.ts:120-161`)
  - freewallet, was-react: both write Collection metadata; a refusal or an
    implicit carry-forward changes what a full-replacement write means to them
- acceptance:
  - [ ] `setMeta({ custom })` on a collection with a declared schema either
        preserves the stored `indexSchema` or refuses the write; the chosen
        policy is stated in the method's JSDoc
  - [ ] A regression test declares an index, calls `setMeta`, and asserts a
        fresh handle still reads the declared indexes

Execution-proven. `setMeta` is a full replacement of `custom`, and the schema
lives inside `custom` under `indexSchema`. Neither `setMeta` nor `writeMeta`
carries it forward, while `patchCustom` does -- which is why `setName` and
`setTags` are safe. A scratch run declares `content.type`, calls
`setMeta({ custom: { name: 'Docs' } })`, and a fresh handle then reads no
indexes while the stored documents still carry their blinded tokens. The
`@param` note says this `custom` also carries the persisted schema, but nothing
warns that omitting it deletes it. Preserve-unless-supplied and refuse-the-drop
are both defensible, so the policy is a maintainer decision. WCL-41 makes the
collision sharper rather than softer, since `replaceDescription()` and
`setMeta()` become one full-replacement write, so design the fix knowing that.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-65: A codec resolved without read access to the Collection `/meta` silently writes un-indexed documents

- status: todo
- priority: medium
- labels: encryption, search, integrity, codec-seam
- acceptance:
  - [ ] `loadIndexSchema` distinguishes "read it, it declares nothing" from
        "could not read it"
  - [ ] On the second case a descriptor bearing a blinding key either fails
        resolution or marks the codec so writes refuse, rather than emitting no
        `indexed` entries
  - [ ] The fail-closed policy chosen here is the same one WCL-29 is parked on,
        and WCL-29 is resolved or restated against it

`readMeta` sends with `read: true`, so a masked 404 on `/meta` resolves to
`null`. `loadIndexSchema` then returns without calling `applySchema`, leaving
the codec's schema empty, and `#writeBlindingKey()` returns nothing whenever the
schema declares no indexes. The cipher emits no `indexed` entries and nothing
marks the document, so the owner's later `find()` on a properly declared
attribute omits it without a word. The asymmetry is the sharp part: one function
earlier, `resolveCodec` fails closed on the identical ambiguity, since an
unreadable Collection Description throws `EncryptionError` rather than
downgrading. The reachable population is narrow -- the writer must be able to
read the Description yet not `/meta` -- which is why this stays at medium.
PARTIAL: WCL-29 parks the identical fail-closed policy question, but it covers
only the unwrap of the blinded-index key and carries no acceptance criteria. The
choice between failing resolution and failing the write is a maintainer
decision, so ask before coding it. discovered-from: whole-codebase review,
2026-09-11.

### WCL-66: `Space.deleteWithOutcome()` reports a revoked or expired capability as `not-found`

- status: todo
- priority: medium
- labels: errors, zcap, space, api
- touches:
  - was-client: `Space.deleteWithOutcome` (`src/Space.ts:335`), the `send()`
    status shortcut in `src/internal/request.ts` that swallows a 404 before
    `mapError` runs, and the two `instanceof NotFoundError` branches in
    `src/sync/port.ts` (`:164`, `:302`)
  - wallet-core: `space/deleteSpace.ts:56` and `keyring/unlockSpace.ts:337` both
    re-export the outcome union and pass it through raw
  - freewallet: `stores/wasRemoteStore.ts:1292`, plus
    `session/accountSettings.ts:2858` and `:3116`
- acceptance:
  - [ ] A delete refused because the capability is revoked or expired is
        distinguishable from a delete of an absent Space
  - [ ] The five consumer call sites are walked; if the fix rethrows rather than
        widening the union, that is recorded and no consumer change is needed
  - [ ] The `send()` 404 shortcut and the two `src/sync/port.ts` branches are
        audited in the same pass

Execution-proven. `CapabilityRevokedError` and `CapabilityExpiredError` extend
`NotFoundError`, so the `instanceof` test catches both. A stub throwing a 404
carrying `type: .../capability-expired` resolves as `{ outcome: 'not-found' }`.
The library decodes the distinguishing signal in `mapError` and discards it one
frame later, so a caller cannot tell "the Space is gone" from "your capability
was revoked". Verified against the real consumers: five call sites, not four.
freewallet's `accountSettings` already grades the 404 against its own prior
discovery, so its worst case is a refusal rather than a false "removed";
wallet-core's two wrappers pass the outcome through raw. Adjacent to archived
WCL-40, which minted the two subclasses on 2026-09-10 but audited no
`instanceof NotFoundError` catch site. Rethrow or widen is a maintainer call.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-67: `Space.createCollection` pins a declared encryption descriptor the server may never have stored

- status: todo
- priority: medium
- labels: encryption, provisioning, fail-closed, api
- touches:
  - was-client: `Space.createCollection` (`src/Space.ts:406-432`), which parses
    the create response and then keeps only its id
  - was-teaching-server: confirm the description echo on Create Collection is
    contractual rather than incidental (`SpaceRequest.ts:525`)
  - wallet-attached-storage-spec: the Create Collection response text, if the
    client is going to depend on the echo
- acceptance:
  - [ ] `createCollection` reads the create response body and pins the
        per-handle override only when the stored `encryption` is present and
        matches the declaration
  - [ ] A create that declared `encryption` and got none back fails closed
        rather than returning an encrypting handle
  - [ ] A create response whose id differs from an explicitly requested `id` is
        refused with a `WasServerError`
  - [ ] The created description is returned to the caller, saving every consumer
        the `describe()` round trip

The reference server does echo the persisted description, `encryption` included,
and was verified to do so. The client parses that body into `response.data` and
then keeps only the created id. `resolveCodec` honours a per-handle override
before any descriptor read, so the handle encrypts on a declaration the server
may never have stored. A later handle resolving from the stored description gets
the identity codec and hands the caller a raw JWE object. That is ARCHITECTURE
invariant 1 -- an encryption-capable client never downgrades to plaintext
silently -- failing in the one direction nothing guards. The id half is the same
read of the same response: against the reference server a supplied `id` is
always honoured, so it costs one extra assertion inside this change.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-68: A `fromCapability` Resource on an encryption-capable client is unusable

- status: todo
- priority: medium
- labels: api, encryption, ergonomics
- touches:
  - was-client: `WasClient.fromCapability` (`src/WasClient.ts:351`, `:387`) and
    the `Resource` / `Collection` constructors it calls
  - freewallet, wallet-core: `fromCapability` is a public method of a shared
    `@interop/*` package, so the additive signature widening is named in the
    CHANGELOG and checked against their call sites
- acceptance:
  - [ ] `fromCapability(zcap, options)` accepts `HandleOptions` and forwards
        `options.encryption` to the constructed handle
  - [ ] A capability-scoped Resource on an encryption-capable client reads and
        writes when given an explicit encryption override
  - [ ] A test asserts the same handle works on a plaintext collection, which
        fails today for the same reason

Execution-proven, and `fromCapability.length === 1` is the whole of it.
`fromCapability` constructs the handle with no codec and no encryption option.
The standalone branch builds a codec holder with no override, and `resolveCodec`
then GETs the collection description under a resource-scoped capability. WAS
masks that refusal as a 404, the description resolves to `null`, and the handle
throws `EncryptionError` advising the caller to pass an explicit per-handle
encryption override -- which the returned handle cannot accept. The failure also
hits `get()` on a plaintext collection. A plaintext-only client is unaffected,
since it short-circuits before the descriptor read. `HandleOptions` already
exists and is already what `Collection.resource(id, options)` takes, so this is
a one-line forward.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-69: `Resource.setName` / `setTags` full-replace `custom` with no precondition when the `/meta` read resolves to null

- status: todo
- priority: low
- labels: conditional-writes, correctness
- acceptance:
  - [ ] `patchCustom` passes `ifNoneMatch: true` when the read resolved to
        `null`, so an existing `/meta` document surfaces as a
        `PreconditionFailedError` instead of being replaced
  - [ ] A test drives a 404 on the `/meta` GET and a successful PUT, and asserts
        the write carries a precondition

Execution-proven. `patchCustom` writes
`{ custom: { ...current?.custom, ...patch } }` under
`{ ifMatch: current?.etag }`. When the read resolves to `null`, both the merge
base and the precondition vanish, and the PUT goes out bare. The reachable shape
is narrow but real: for an existing resource the server always serves `/meta`,
and for a missing one the PUT would 404, so a null read plus a successful PUT is
exactly the write-but-cannot-read grant, which WAS scopes per verb. That makes
the guard nearly free. The fix inherits the separate gap that a backend without
`conditional-writes` ignores the header, so the two should land aware of each
other. PARTIAL: WCL-41 rewrites `patchCustom` for the merged-validator retry and
says nothing about the null-read case writing with no precondition at all.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-70: `Resource.meta()` reports the JWE envelope's `contentType` and `size` on an encrypted collection

- status: todo
- priority: low
- labels: encryption, api, metadata
- touches:
  - was-client: `Resource.meta` (`src/Resource.ts:390`) and `readMeta`
    (`src/internal/meta.ts:59-95`)
  - freewallet, was-react: needed only if the projecting fix is chosen, since it
    changes what `ResourceMetadata.contentType` means on an encrypted collection
    for every renderer
- acceptance:
  - [ ] `meta()` and `add()` agree about a resource's content type on an
        encrypted collection, or the `meta()` JSDoc states plainly that
        `contentType` and `size` are envelope-level there

`readMeta` spreads the server's metadata object through untouched and decodes
only `custom`. On an encrypted collection the stored representation is the JWE
envelope, written with the codec's own content type (`application/jose+json` by
default), while the plaintext type is sealed inside the envelope's `meta`. That
sealed value is surfaced elsewhere: `Collection.add` returns
`encoded.resourceContentType ?? encoded.contentType`. So `add()` reports
`image/png` and `meta()` reports `application/jose+json` for the same resource.
The JSDoc's existing caveat covers only `custom`. A documentation caveat and a
projecting fix are both defensible; the projecting one is the wider change and
is what the `touches:` entry is for. discovered-from: whole-codebase review,
2026-09-11.

### WCL-71: `Space.configure()` is a read-modify-write with no precondition and no way to supply one

- status: todo
- priority: low
- labels: conditional-writes, space, api
- acceptance:
  - [ ] `Space.configure` accepts an optional `ifMatch`, pairing with the
        existing `current` option, or its JSDoc states plainly that it is
        last-write-wins

`configure` reads the description, merges, and PUTs with `json` only. It calls
no `writeHeaders`, so no `If-Match` goes out, and the option bag exposes no way
for a caller to supply one. ARCHITECTURE.md says safety is optimistic (ETag/CAS)
throughout with no locks, so this is the one description write that opts out of
that. The lost-update scenario needs two concurrent writers under the same
controller, and the recent direction of travel -- WCL-32 and archived WCL-33 --
has been to move risky call sites off `configure` rather than harden it, which
is why this stays low. PARTIAL: WCL-41 lists `configure` among the Space
description methods it retargets, but its precondition bullet is scoped to
`Collection.configure`. Nothing in it gives `Space.configure` an `ifMatch`.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-72: Collection internal-state hygiene

- status: todo
- priority: low
- labels: collection, encryption, codec, search, changes-feed
- acceptance:
  - [ ] `indexes()` returns a copy, and the empty schema is frozen or minted
        fresh, so a caller mutating the result cannot reach another client's
        collection
  - [ ] `delete()` resets the memoized codec and the backend feature probe;
        `BackendFeatures` gains the `reset()` its `Memo` already has
  - [ ] `replaceDescription` resets the codec after any successful description
        write, not only when `encryption` is present
  - [ ] `documents()` is bounded against an advancing checkpoint as well as a
        repeated one, throwing `WasServerError` on exhaustion

Four small defects in one file, each execution-checked, none worth its own item.
`indexes()` returns the codec's live schema array by reference, and when nothing
is declared that array is a shared module-level constant, so a `push` on one
collection's result surfaces in an unrelated client's fresh collection and makes
its writes start emitting blinded `indexed` entries. No in-repo path mutates it,
so this is an encapsulation defect with a large blast radius rather than a live
failure. `delete()` resets neither the memoized codec nor the feature probe,
while `configure`, `replaceDescription` and `putHistoryLog` all reset in some
form; a handle that deletes and recreates a collection under a different scheme
then writes through the stale codec. The consequence is a confusing 422, not a
plaintext leak: the spec makes rejecting a non-conforming body a server MUST,
and the reference server implements it. `replaceDescription`'s conditional reset
is the same class and is included here. `documents()` exits only on a falsy or
already-seen checkpoint, so a server that advances the checkpoint forever is
walked forever; a scratch run reached 5001 requests. discovered-from:
whole-codebase review, 2026-09-11.

### WCL-73: Space API hygiene

- status: todo
- priority: low
- labels: space, api, correctness, conditional-writes, errors
- acceptance:
  - [ ] `replaceDescription` builds its body with the handle's own `id` last, so
        a spread-in `id` cannot retarget the write
  - [ ] `configure()`'s JSDoc matches the code on `type`, and the returned
        description does not claim a `type` it never read
  - [ ] `writeHeaders` rejects `ifMatch` and `ifNoneMatch` together with a
        `ValidationError`
  - [ ] `registerBackend()` and `import()` throw `WasServerError` naming the
        response content type instead of asserting non-null on an absent body
  - [ ] `isPublic()`'s JSDoc carries the same "or it is not visible to you"
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

### WCL-74: `isEncryptedEnvelope` is a fail-open routing predicate, and its JSDoc says to use it that way

- status: todo
- priority: medium
- labels: sync, encryption, fail-closed
- touches:
  - freewallet: `src/stores/remoteDirectStore.ts` returns a plaintext body as a
    credential when the predicate says "not an envelope", with no decrypt and no
    binding check
- acceptance:
  - [ ] The JSDoc on `isEncryptedEnvelope` no longer endorses plaintext
        tolerance as a read-path default, and states that the predicate does not
        decide whether to decrypt
  - [ ] A collection whose descriptor declares encryption refuses a plaintext
        row on read, matching `EdvCodec.decode`'s `#assertEnvelope(doc, 'read')`
  - [ ] Any remaining legacy-row tolerance is an explicit per-call opt-in on a
        migration path, not the default branch

The predicate at `src/sync/envelope.ts:19-26` is correct on its own. Its doc
comment is the defect: it says the predicate lets read paths stay tolerant of
legacy plaintext rows written before a collection declared encryption. That
inverts the codec's own rule, which refuses a body with no `jwe` on read. One
consumer acts on the invitation today and accepts a server-supplied plaintext
body as a credential. Closing this needs the doc change plus the consumer edit,
so the item is not done at the doc alone. discovered-from: whole-codebase
review, 2026-09-11.

### WCL-75: `parseEtag` hard-codes the reference server's ETag format, so spec-conformant tags acknowledge version 0

- status: todo
- priority: medium
- labels: sync, spec-conformance, conditional-writes
- touches:
  - "@interop/was-sync": `src/pushWrites.ts` treats `ack.version !== undefined`
    as "acknowledged" and `src/conflictHandler.ts` compares versions for
    equality, so both need the absent case
  - wallet-core: the sync engine reads `WriteAck` / `MasterState` version
- acceptance:
  - [ ] `WriteAck.version` and `MasterState.version` are left absent when no
        revision parses, instead of being coerced to `0`
  - [ ] An opaque validator such as `"a1b2c3"` or `"3"` round-trips as a
        precondition without producing a fabricated version
  - [ ] The `gen.version` parse is documented as a convenience for servers using
        that form, not as the wire contract

`parseEtag` (`src/sync/port.ts:192-203`) returns `undefined` for any validator
with no `.`, and the WAS spec's own examples are `"a1b2c3"`, `"3"`, `"1"` and
`"2"`. None of them parse. `readContent` and `writeAck` then substitute
`version ?? 0`, so a conformant server looks like it acknowledged revision zero
on every write. Downstream that reads as a real acknowledgement and then as a
permanent version mismatch, which is the conflict storm. The `W/` weak-validator
half of the original finding is out of scope here: the echoed `If-Match` is the
raw header from `readEtag`, and the spec calls for an opaque strong validator,
so a weak one is a non-conformant server rather than a case this client must
absorb.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-76: The late encryption-declaration CAS rebases only on 412, though the server answers that race with 400 or 409

- status: todo
- priority: medium
- labels: provisioning, cas, errors, idempotence
- acceptance:
  - [ ] A rival that declares the encryption descriptor and appends its first
        epoch between this client's read and write is adopted rather than
        rethrown
  - [ ] The adoption keys on a re-read finding a descriptor present, matching
        `readOrCreate`'s re-read-decides rule
  - [ ] `src/sync/provisioning.ts` stays idempotent under that race, with a test
        driving the 409 ordering

`readOrCreate`'s own header says the server answers a lost race with whatever
check the rival's description trips first, naming a 412 from the precondition
but also a 400 or 409 from the encryption-descriptor transition rules. The late
declaration path uses `compareAndSwap`, whose only rebase branch is
`isPreconditionFailed`; everything else rethrows. Corroborated against the
reference server: `assertEncryptionDescriptorTransition` runs before
`parseWritePreconditions` and before the atomic transition check, so once the
rival has appended its epoch roster the epoch-less descriptor trips the
append-only rule and returns 409 `encryption-immutable` with no 412 ever
evaluated. The window is narrow, since identical descriptors pass the transition
check and rebase normally, but it is realistic on a concurrent wallet boot.
Archived WCL-33 installed this CAS; its scope was the missing precondition, not
the error taxonomy the loop rebases on, so this residue is open. Keeping the
re-read local to `provisioning.ts` touches nothing outside this repo; giving
`compareAndSwap` a `rebaseOn` option instead would also reach
`src/edv/recipients.ts` and wallet-core's descriptor store. discovered-from:
whole-codebase review, 2026-09-11.

### WCL-77: `agentsFromSecret` accepts an empty secret and derives a well-known identity

- status: todo
- priority: medium
- labels: api, fail-closed, correctness
- touches:
  - freewallet, dcw: any login path that could pass an empty or unfilled field
    into the derivation
  - wallet-core: if it wraps the derivation
- acceptance:
  - [ ] `agentsFromSecret({ secret: '' })` throws `ValidationError`, matching
        `agentsFromSeed`'s fail-closed shape
  - [ ] The whitespace and minimum-length policy is settled with the maintainer
        and documented on the function
  - [ ] The consumers under `touches:` are walked for call sites that could
        supply an unfilled secret

Execution-proven: an empty secret resolves without error to
`did:key:z6MkjkHZwwFoQRN6wJu1t5UQVinLRK9UQohxsLoDPwJdoEQz`, and a
whitespace-only secret derives another fixed identity. Both are deterministic
and globally derivable, since the handle and key name are fixed public
constants, so a caller bug lands the user silently in a shared account whose
decryption key anyone can compute. `agentsFromSeed` twenty-five lines above
already validates its input, and `agentsFromSecret` is a public subpath export,
so the guard is this library's to own. The empty case is clear-cut. Whether
whitespace-only is rejected, whether the string is trimmed first, and whether
any minimum length applies are maintainer decisions, because they permanently
partition who can derive which account; ask before coding beyond the empty case.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-78: An undecryptable Collection `/meta` envelope fails the whole codec resolution

- status: todo
- priority: medium
- labels: encryption, search, codec, fail-closed
- acceptance:
  - [ ] `loadIndexSchema` treats a `KeyUnwrapError`, `UnknownEpochError` or
        `IntegrityError` from the `/meta` read the way it treats an unreadable
        `/meta`, leaving the schema empty
  - [ ] A reader holding valid content keys can still `get()` and `put()` on a
        collection whose `/meta` envelope it cannot open
  - [ ] `indexes()`, `declareIndex()` and `find()` surface the recorded failure
        rather than returning a silently empty schema

`loadIndexSchema` (`src/internal/codec.ts:380-414`) catches only
`NotImplementedError`, but `readMeta` awaits `codec.decodeMeta`, which opens the
envelope and can raise `KeyUnwrapError`, `UnknownEpochError` or
`IntegrityError`. All three escape codec resolution, and every `Resource.get`,
`getWithEtag` and `put` awaits that same holder, so one unreadable `/meta` makes
the whole collection unreadable for a reader whose document keys are fine. The
memo drops rejections, so it re-fails on each call rather than being cached.
Scope is collections declaring a blinding key, since `loadIndexSchema` returns
early when `codec.indexing` is absent. WCL-29 parks the identical
fail-closed-timing decision but covers only the eager hmac unwrap, is still
`draft`, and has no acceptance criteria; settle the two together.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-79: Local invariants the log store adapter can enforce itself

- status: todo
- priority: low
- labels: log, integrity, correctness
- touches:
  - "@interop/vh-resource-log": export `versionIdOrdinal` so the ordinal check
    can be written against the package's own parse rather than re-derived here
- acceptance:
  - [ ] `append` refuses an entry whose `versionId` ordinal does not follow the
        last read body, using the upstream `versionIdOrdinal`
  - [ ] `read()` clears `lastReadBody` on the `null` branch
  - [ ] A Resource-hosted log served under a JSON content type is refused with
        `ValidationError`, matching `Collection.getHistoryLog`
  - [ ] `putOrConflict` refuses a write naming neither a non-empty `ifMatch` nor
        `ifNoneMatch`, matching `Collection.putHistoryLog`

Four small local gaps in `src/log/logStore.ts`, all in the same file and worth
one pass. `append` extends `lastReadBody` with no ordinal check, which is
defense-in-depth on top of the backend's conditional-write behavior rather than
an independent hole; its fix needs `versionIdOrdinal` exported upstream, and the
parse must not be re-derived locally. `read()` leaves `lastReadBody` set when it
resolves `null`, a one-line port-contract gap. The Resource host runs
`getWithEtag({ as: 'text' })`, so a JSON-served log is re-serialized by
`decodedText` and a later append republishes history in that form, contradicting
the module's own property that an append does not re-serialize history; the
Collection host already refuses this. And `resourceTarget.put` sends no
precondition when `ifMatch` is absent or blank, where `putHistoryLog` refuses
outright; the adapter's current safety on that point is borrowed from
`appendResourceLog`'s own `!etag` guard. discovered-from: whole-codebase review,
2026-09-11.

### WCL-80: `singleKeyResolver` / `ProfileAgents.keyResolver` is required by the seam but never invoked

- status: todo
- priority: low
- labels: encryption, api, reuse
- touches:
  - wallet-core, freewallet, dcw: all construct `EdvKeys` / `ProfileAgents`, so
    removing or rewiring the field is a breaking shared-API change
- acceptance:
  - [ ] The direction is settled with the maintainer: drop `keyResolver` from
        `EdvKeys` / `ProfileAgents`, or have `buildEdvCodec` use the supplied
        resolver
  - [ ] Whichever direction lands, the module header no longer describes a
        restriction that is not in force
  - [ ] The consumers under `touches:` compile against the changed surface

Verified exhaustively: `EdvKeys` requires `keyResolver` and `createEdvDocCipher`
threads it into `buildEdvCodec`, but the only `keys.` reads inside `EdvCodec.ts`
are `keys.keyAgreementKey` and `keys.hmac`. Nothing reads `keys.keyResolver`.
Both `EdvClientCore` constructions hardcode the module-level `didKeyResolver`,
and the codec re-exposes that same hardcoded one. So the field is required and
discarded, and the module header's "Any other key id is an error" describes a
guarantee the code does not provide. There is no runtime defect; the cost is a
misleading security story in a module a reader will trust. Which direction to
take is a maintainer decision, not an assumption to code. See also WCL-81, which
hardens the resolver that is actually in use. discovered-from: whole-codebase
review, 2026-09-11.

### WCL-81: `didKeyResolver` resolves a key id by its fragment and ignores the DID part

- status: todo
- priority: low
- labels: encryption, key-epochs, correctness
- touches:
  - freewallet, dcw: confirm which recipient `kid` forms they mint before
    rejecting any, since the admissible forms are the recipient-id convention
- acceptance:
  - [ ] `didKeyResolver` refuses a key id whose fragment is not the DID's own
        X25519 key
  - [ ] Both admissible forms are accepted: a fragment equal to the
        method-specific id, and the Montgomery conversion of an Ed25519
        method-specific id
  - [ ] `defaultResolveRecipientKey` refuses a caller-supplied `kid` whose DID
        prefix and fragment disagree

`didKeyResolver` (`src/edv/epochCrypto.ts:302-331`) takes
`id.slice(id.indexOf('#') + 1)` and rebuilds the key from the fragment alone.
Nothing compares it to the method-specific id before the `#`, so
`did:key:<any A>#<B>` resolves to B's public key. The exposure is at
`recipients.ts`: a caller adding a recipient by a `kid` string it did not derive
itself wraps the epoch key to whatever fragment that string carries while the
DID prefix names someone else. The library's own producer path derives both
halves from the Ed25519 DID and is safe, which is why this stays low. The check
cannot be plain equality, since a native X25519 `did:key` has fragment equal to
the method-specific id while an Ed25519-derived key agreement key carries the
Montgomery form. WCL-26 names this function's throw sites, but only for the
error class; it adds no binding check. discovered-from: whole-codebase review,
2026-09-11.

### WCL-82: `query()` has no repeat-checkpoint guard

- status: todo
- priority: low
- labels: sync, changes-feed, correctness
- acceptance:
  - [ ] A non-empty page whose returned checkpoint equals the checkpoint that
        same call requested raises `WasServerError` naming the feed URL
  - [ ] The guard is stateless within the port, so a driver re-issuing an
        identical pull after a transient failure or a restart is unaffected

`query()` (`src/sync/port.ts:352-370`) returns `changes()` cast to `SyncPage`
with no cross-call state, and `changes()` validates one page in isolation with
no checkpoint memory. A non-advancing feed therefore spins with nothing in the
stack naming the fault; the was-sync pull handler fetches one page per call and
has no loop or cap of its own. The originally proposed fix is unsound: having
the port remember the last checkpoint it returned reports a legitimate retry or
resume as a server fault, because a driver re-issuing the same pull gets the
same page and the same checkpoint back. The comparison has to be the checkpoint
returned against the checkpoint requested within one call, or it belongs in the
driver's loop where the retry and resume distinction is visible. Archived WCL-36
moved the malformed-page guards into `changes()` but left the repeat-checkpoint
guard in `documents()`, where the cross-page `seen` set lives; this asymmetry is
that item's residue.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-83: Sync seam hygiene: unclassifiable cid errors, a broken capability probe, an unpaired validator, a loose wrapper type

- status: todo
- priority: low
- labels: sync, types, errors
- touches:
  - freewallet: `src/stores/remoteDirectStore.ts` and
    `src/stores/browserStore.ts` probe `cipher.encryptUpdate` for presence
- acceptance:
  - [ ] `contentCid` rethrows a non-finite number as `ValidationError` naming
        the offending value, so `predicates.ts` can classify it
  - [ ] `createPlaintextDocCipher` omits `encryptUpdate`, making presence a
        reliable probe of the content-addressed seam
  - [ ] `WireDoc` and `MasterState` document that `metaVersion` without
        `metaEtag` means no usable validator and is treated as absent
  - [ ] `cidFrom`'s parameter is narrowed from `object` to `Json`

Four small defects on the sync seam. `contentCid({ amount: 0/0 })` throws a bare
`Error` from the canonicalizer, and `NaN` is a valid `Json` number, so no type
violation is needed to reach it; none of the four `predicates.ts` classifiers
match a bare `Error`, so a driver's push loop falls into generic backoff on a
row that can never succeed. `createPlaintextDocCipher` defines `encryptUpdate`
even though the contract says a content-addressed cipher either omits it or
throws, and omitting it is the only option a caller can probe; both freewallet
probes are saved today only by their second clause. `metaVersion` and `metaEtag`
are independently optional in `MasterState` and in the upstream
`ChangeDocument`; `port.get` cannot produce the divergent state, but a feed
copied from the server can, so document the pairing rather than changing the
upstream type. `cidFrom` takes `doc: object` and casts to `Json`, so a `Date`,
`Map` or class instance is admitted where `contentCid` would refuse and the
canonicalizer mangles it quietly. `cidFrom` is not dead code: it has production
callers in freewallet and dcw, so only the narrowing applies and the export
stays. The narrowing may surface type errors at those call sites.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-84: Internal hygiene: a misleading 412 message, a lying response cast, a non-structural predicate, an abandoned body

- status: todo
- priority: low
- labels: errors, types, layering
- acceptance:
  - [ ] `upsertResource`'s 412 rewrite names both causes, a concurrent create
        and an existing-but-unreadable document, and leads with re-read and
        retry
  - [ ] `unsignedRequest` either populates `data` the way `@interop/http-client`
        does, or narrows its return type so the cast cannot mislead
  - [ ] `isGovernedDescriptor` is structural: `history` must be a non-null
        object with string `method` and `resource`, so a malformed pointer takes
        the plain branch or a typed `ValidationError`
  - [ ] `withCodec` cancels the response body before rethrowing a codec error

Four small internal defects. `upsertResource`'s rewrite fires on any 412 from
the `If-None-Match: *` insert, including a document a concurrent writer created
between the pre-read and the PUT, and the replacement message asserts a
capabilities cause and advises getting a broader capability, which is wrong for
the race; the HTTP client's own retry on 503 reaches the same message.
`unsignedRequest` casts a raw `fetch` `Response` to `HttpResponse`, so
`response.data` is `undefined` and `dataOrNull` returns `null` for a healthy 200
JSON body. Both current callers avoid `.data` deliberately, so this is latent
and is a trap for the next public-read caller. `isGovernedDescriptor` returns
`true` for a server-supplied `history: null` and then asserts a shaped object,
so `logGovernedDescriptorStore` dereferences it and raises a raw `TypeError` in
a module whose job is typed refusals. `withCodec` returns before consuming the
response promise when the codec rejects; for a JSON body the client has already
drained it, so the leak is confined to non-JSON responses such as a large blob
read through `Resource.getWithEtag`. discovered-from: whole-codebase review,
2026-09-11.

### WCL-85: `mapError` hardening -- prototype lookup, the unmapped 422, and unvalidated server strings

- status: todo
- priority: medium
- labels: errors, security, correctness
- acceptance:
  - [ ] A problem `type` whose fragment names an `Object.prototype` member falls
        through to the status switch, instead of returning a non-`Error` or
        throwing out of `mapError`
  - [ ] Every `ProblemTypes` key resolves to something other than the bare
        `WasError`, including the 422 `encryption-scheme-mismatch`
  - [ ] Dispatch keys on the full problem-type URI; the fragment is kept for
        display only
  - [ ] `WasSyncConflictError`, `WasSyncNotFoundError` and `WasSyncAuthError`
        keep their default status when the caller passes `status: undefined`
  - [ ] Server-supplied `title`, `details` entries and the joined `kids` are
        length-capped and stripped of control characters
  - [ ] A non-string `type` or `title` is normalized away rather than stored on
        the error and stringified into its message

Six defects in one function plus the three sync constructors, with one test file
between them. `ERROR_CLASS_BY_KIND` is an object literal indexed by a
server-controlled fragment, so `type: 'x#constructor'` returns a `String` object
from `mapError` and `'x#toString'` throws a `TypeError` out of it -- both proven
against a fresh build of `src/`. `send()` calls `mapError` from its catch block,
so a routine 412 then surfaces as that `TypeError`. `noUncheckedIndexedAccess`
hides this: the lookup types as possibly-undefined and the guard looks
sufficient. Separately, 422 is absent from both the kind map and the status
switch, so `encryption-scheme-mismatch` lands on a bare `WasError` while its
storage-core siblings map to `ConflictError`. `problemFragment` discards the URI
namespace, so any origin's JSON body can assert a kind; the threat model is weak
(a server that controls the body can send the canonical URI anyway), so this
part is hygiene. The three sync constructors disagree on spread order, which
erases the 412 and 404 defaults when the caller passes an explicit `undefined`.
And `type` and `title` are trusted as strings without the validation the
adjacent `errors` field already gets. If the 422 fix mints a new error name
rather than reusing `ValidationError` or `ConflictError`, that name is a public
contract and needs the maintainer's sign-off first. discovered-from:
whole-codebase review, 2026-09-11.

### WCL-86: `CapabilityRevokedError` and `CapabilityExpiredError` are unreachable on every read

- status: todo
- priority: medium
- labels: errors, zcap, api
- touches:
  - freewallet, was-react: read paths that get `null` from a revoked grant today
    would start seeing a throw, if the rethrow direction is chosen
- acceptance:
  - [ ] A read against a revoked or expired grant is distinguishable from an
        empty collection through the handle API, or both class docstrings state
        that they surface on write-shaped calls only
  - [ ] The chosen direction is applied consistently across the `read: true`
        call sites in `Collection`, `Resource`, `internal/meta.ts`,
        `internal/pagination.ts`, `WasClient` and `internal/write.ts`

`send()`'s short-circuit is evaluated on the raw error before `mapError` ever
runs: `(input.read || input.idempotent) && httpStatus(err) === 404` returns
`null`. Both capability kinds are 404 in `ProblemStatusCodes`, so the problem
body is discarded unread on every read-shaped call and a revoked grant reads as
an empty collection. Archived WCL-40 minted the two subclasses to let a holder
tell a revocation from an expiry from a plain denial; that motivation is
unrealized on reads. The signal does still surface on write-shaped and
POST-shaped calls, and the sync port absorbs the same 404 deliberately with its
reasoning written out. The gap is that the handle API makes the same trade
silently. Either document write-only reachability on both classes, or have the
short-circuit map first and rethrow these two kinds -- they are unambiguous
denials to a verified caller, so rethrowing leaks no existence. The rethrow
direction is an observable change on public read methods. Shares a root cause
with the `deleteWithOutcome` item (the same raw-status short-circuit ahead of
`mapError`); settle the two together. discovered-from: whole-codebase review,
2026-09-11.

### WCL-87: The `err.name` contract does not survive `structuredClone`, and `UnknownEpochError` sits outside the `WasError` tree

- status: todo
- priority: medium
- labels: errors, sync
- touches:
  - was-client: `decisions/0001-cross-package-errors-match-by-name.md` -- the
    Consequences bullet claiming a structured clone keeps the error's own `name`
  - "@interop/was-sync", wallet-core, freewallet: whether any of them classifies
    a was-client error after a worker boundary, which decides whether an
    explicit envelope is also needed
- acceptance:
  - [ ] decisions/0001's Consequences bullet states what actually survives a
        structured clone
  - [ ] `WasError` either carries an explicit serialization envelope, or the
        decision record names the fields a worker boundary has to carry by hand
  - [ ] `UnknownEpochError` extends `WasError`, keeps `collectionId` and `kids`
        as own properties, and accepts a `cause`
  - [ ] `UnknownEpochError` is exported from the root entry beside the `./edv`
        and `./sync` subpaths

Proven: `structuredClone(new WasSyncConflictError(...))` comes back with `name`
equal to `'Error'` and `status` dropped, with only `message` surviving. The loss
is the structured-clone algorithm's, which copies an `Error` as name, message
and stack and keeps the name only for the seven native error names. That
falsifies a load-bearing sentence in decisions/0001 ("An error passed through a
structured clone keeps its own `name` property"), which is one of the stated
reasons `instanceof` was rejected. No `name` string changes, so the decision
itself stands; its justification needs amending regardless of whether any
consumer crosses a worker today. Filed alongside it because it is the same
contract: `UnknownEpochError` extends `Error` rather than `WasError`, so
`mapError` re-wraps it and erases the name `isUnknownEpochError` matches on.
That re-wrap is latent today (decode runs outside the `send` try/catch), but the
class is also the only error missing from the root entry's exports, and its
`collectionId` and `kids` live only in prose, so a consumer that matched by name
has to parse the message to learn which collection to refresh. discovered-from:
whole-codebase review, 2026-09-11.

### WCL-88: Record the upstream-owned `NotFoundError` / `DuplicateError` names in decisions/0001

- status: todo
- priority: low
- labels: errors, encryption, upstream
- acceptance:
  - [ ] decisions/0001 records the collision under its Revisit Criterion 1: two
        names this package emits are owned upstream, carry no `WasError` fields,
        and are deliberately not renamed
  - [ ] The `WasTransport` header says the same, so the next reader does not
        file the rename

`WasTransport.namedError` mints plain `Error`s whose `name` is `NotFoundError`
or `DuplicateError`. They are not `WasError`s, carry no `status`, `type` or
`requestUrl`, and answer a name match identically to the real classes. The
obvious fix is actively harmful. Upstream `@interop/edv-client`'s own
`HttpsTransport` sets exactly these strings and `EdvClientCore` dispatches on
them, so `WasTransport` is implementing an upstream contract verbatim and a
rename would silently break that dispatch. decisions/0001 already has the slot
for this: Revisit Criterion 1 covers two packages needing error classes that
carry the same `name`, and says the answer is decided in that record. So this is
a documentation item. Open WCL-26 does not subsume it -- that item is scoped to
the `didKeyRecipient.ts` and `epochCrypto.ts` throw sites, where the bare
`Error`s are an oversight; these are deliberate. discovered-from: whole-codebase
review, 2026-09-11.

### WCL-89: A mid-walk 404 truncates a listing, and the walk throws untyped errors

- status: todo
- priority: medium
- labels: correctness, errors
- acceptance:
  - [ ] A followed `next` page that resolves to `null` ends the walk with a
        `WasServerError` rather than a silently short listing
  - [ ] `listSpaces` does not assert the truncated count as `totalItems`
  - [ ] A non-JSON body or a 200 carrying well-formed JSON that is not a listing
        surfaces as a typed `WasError` from the public walk

Reproduced against a local server: page 1 carrying 100 items and
`totalItems: 250`, then a 404 on page 2, makes `listSpaces()` resolve
`{ items: 100, totalItems: 100 }` with no error. `signedPageWalk` fetches every
page with `read: true`, so `send` maps the 404 to `null` and `walkPages` cannot
tell that from end-of-list. `listSpaces` then recomputes `totalItems` from the
truncated set, and the one comment explaining why the recompute is sound ("the
walk has gathered the complete listing") marks exactly where the premise fails.
The read-shaped flag belongs on the first page alone. The same walk is also the
landing site for untyped failures: the public page fetcher calls `readJsonData`
unconditionally with no content-type gate and casts the body to a listing, so an
HTML interstitial escapes as `SyntaxError` and a wrong-shape JSON body as
`TypeError: page.items is not iterable`. Gate on content type the way
`parseResource` does, and treat a body without an array `items` as
`WasServerError`, matching how `listSpaces` already treats a bodyless first
page.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-90: `was.request()` signs the caller's method verbatim, so a lowercase method 403s

- status: todo
- priority: medium
- labels: zcap, correctness, api
- acceptance:
  - [ ] `was.request({ method: 'put' })` and an explicit lowercase
        `input.action` produce the same zcap action as `grant()` does
  - [ ] The direction is signed off by the maintainer before it is coded

`rawRequest` passes the caller's method through as the zcap action while
`delegateGrant` uppercases, so `was.request({ method: 'put' })` signs
`action="put"` and the server refuses. Both sides of the wire are settled. The
reference server passes the raw `request.method` as `allowedAction`, which is
always uppercase because Node's HTTP parser does not lowercase a method, and
`@interop/zcap` does a strict `includes` followed by a strict inequality check
with no case folding. So the request fails even with no delegated zcap in play,
against the root invocation. The library's own call sites all pass uppercase, so
this bites the public escape hatch only, but `ActionInput` is
`Action | Lowercase<Action>` everywhere else, so lowercase is an advertised
input. The fix changes a wire-visible value (the `capability-invocation` action
parameter). It only normalizes toward the convention `grant.ts`'s header already
documents, but wire-level conventions are the maintainer's call, so the
direction stays open until signed off. discovered-from: whole-codebase review,
2026-09-11.

### WCL-91: `ActionInput` cannot express HEAD, which the library itself invokes

- status: todo
- priority: medium
- labels: zcap, types, upstream, cross-repo
- touches:
  - storage-core: `Action` / `ActionInput` is a shared `@interop/*` API and a
    wire vocabulary; adding `'HEAD'` needs the maintainer's sign-off
  - wallet-attached-storage-spec: whether the action registry names HEAD
- acceptance:
  - [ ] A delegate can be granted the HEAD action through `GrantOptions.actions`
        without casting past the type, or `WasTransport` probes with GET instead

The server does not treat HEAD as GET for the capability check. `authorize.ts`
passes `allowedAction: method`, so a HEAD request expects the action `'HEAD'`,
and the GET/HEAD merge a few lines earlier applies only to the policy fallback.
`@interop/zcap` then does a strict `allowedActions.includes('HEAD')`. So a
delegate holding `was.grant({ actions: ['GET', 'PUT'] })` cannot pass the EDV
degraded-insert HEAD probe, and the type gives no way to name the action. The
owner case works, because `WasTransport` passes no capability and the root
zcap's empty `allowedAction` skips the check. The server's own allowlist already
names HEAD (`WAS_ACTIONS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE']`), so the
client's vocabulary is the side out of step. discovered-from: whole-codebase
review, 2026-09-11.

### WCL-92: Buffered listings return the first page's `totalItems` beside fully-aggregated items

- status: todo
- priority: medium
- labels: correctness, reuse
- acceptance:
  - [ ] `collectPages` recomputes `totalItems` from the completed walk, and the
        duplicated recompute in `listSpaces` is removed
  - [ ] A first page that omits `totalItems` does not leave the field
        `undefined` under a type that declares it required

A two-page public collection (first page declaring `totalItems: 100` with 100
items, second page carrying 150) returns `{ items: 250, totalItems: 100 }`.
`collectPages` spreads the first page and replaces only `items`, so every
buffering call site other than `listSpaces` inherits the first page's count --
`publicListCollection` and `Collection.list` both. `listSpaces` is correct only
because it recomputes the field itself afterwards, which is the duplication this
item removes. Sequence with 89, which corrects the premise that recompute rests
on. Related: `CollectionResourcesList.totalItems` is declared a required
`number` upstream, so a first page that legitimately omits it yields `undefined`
under a non-optional type.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-93: Path builder edge cases -- raw-string prefix matching and misplaced trailing slash

- status: todo
- priority: low
- labels: paths, zcap, correctness
- acceptance:
  - [ ] `parseSpaceTarget` compares parsed origins and path prefixes, so a
        default port or a host-case difference no longer rejects a valid
        capability in `fromCapability` and `revoke`
  - [ ] `collectionItemsUrl` builds through `URL`: the trailing slash lands on
        the pathname, the query is preserved, and the fragment is dropped

Two edge cases in `internal/paths.ts`. `parseSpaceTarget` does a `startsWith`
against the raw server-URL string before any normalization, so
`https://was.example:443/space/s` and `https://WAS.example/space/s` both fail
the prefix test even though they normalize to the same origin. The same call
feeds `fromCapability` and `spaceIdOf`, so a mis-serialized `invocationTarget`
makes a capability both unusable and unrevocable through this client. The
trigger needs a peer that does not serialize with WHATWG URL, since no JS
implementation emits either form, so this is robustness against a non-JS
partner. Separately, `collectionItemsUrl` appends the trailing slash to the end
of the whole string, after any query or fragment: a public list of
`.../blog?limit=10` requested `GET /space/s/blog?limit=10/`, whose pathname is
the member endpoint. The fragment case is quieter still, since fetch strips it
before the wire. The predicted `null` result only happens when the server 404s
that URL; against a server that serves the Collection Description it throws a
raw `TypeError` instead, which is the failure 89 covers. WCL-41 rewrites this
same file and subsumes neither case (it changes which URLs are canonically
trailing-slash, and says nothing about the string comparison or about query and
fragment handling), so sequence this item with WCL-41 to avoid a conflicting
rewrite.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-94: `WasClient` API hygiene -- dropped options, eager signer, unreachable types

- status: todo
- priority: low
- labels: api, types, ergonomics
- acceptance:
  - [ ] Passing `encryption` to `space()` is either honored as the default for
        `Space.collection()` or a compile error
  - [ ] A `ZcapClient` with a delegation signer and no invocation signer can
        `grant()`
  - [ ] `IRootZcap`, `IDID` and `CustomWithIndexSchema` are reachable from an
        entry point
  - [ ] `grant()` without `target` or `capability` throws `ValidationError`
        rather than a raw ezcap `TypeError`
  - [ ] The `zcaps` comment in `internal/paths.ts` states the real reasons the
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

### WCL-95: `WasTransport` hardening -- feature gate, response validation, and 409 mapping

- status: todo
- priority: low
- labels: encryption, errors, integrity, fail-closed
- acceptance:
  - [ ] `#requireFeature` consults `descriptorAbsent()` and emits two distinct
        messages, matching `EdvCodec.#assertChunkedStreams`
  - [ ] `get()` rejects a non-object body the way `find()` does, and raises an
        integrity error when the returned document id is not the requested one
  - [ ] The non-conditional `insert()` refuses a masked 404 rather than
        upserting over a document it cannot see
  - [ ] `getChunk` reads its body through the content layer
  - [ ] A 409 that is not a unique-attribute collision is reported as what the
        server's problem type says it is

Five defects in the EDV transport, none of them live-critical on their own.
`#requireFeature` emits one message for both roads to "no features", so a
delegated zcap that cannot read the backend descriptor makes `find()` and
`getChunk()` report a capable server as incapable. `BackendFeatures` exposes
`descriptorAbsent()` precisely to separate the two, and the codec's own gate
already uses it -- archived WCL-15's F4 wired the codec gate and left the
transport's. `get()` casts the response body to `IEncryptedDocument` unchecked
and never compares the returned id to the requested one; at the EDV-native level
there is no `was.resource` AEAD binding to catch a swap, so a server answering
document A's GET with document B's envelope goes undetected. The non-conditional
`insert()` maps a 404 from its HEAD probe to "absent" and then PUTs with no
precondition, which is the exact combination `upsertResource` refuses on the
codec path, because WAS masks unauthorized as 404. `getChunk` is the only body
read in the file that calls `JSON.parse(await response.text())` instead of
`readJsonData`, which is latent only because the chunk content type is
`application/octet-stream`. And both `insert` and `update` register every 409 as
a unique-attribute collision, since `mapTransportError` dispatches on status
alone, so a quota or backend-state conflict is misreported with the real `type`
surviving on `cause` only. If a new error name is minted for the generic
conflict, that name needs the maintainer's sign-off first. discovered-from:
whole-codebase review, 2026-09-11.

### WCL-96: `resourceDescriptorStore.read()` reads a masked 404 as "no descriptor yet"

- status: todo
- priority: medium
- labels: encryption, fail-closed, errors, cas
- acceptance:
  - [ ] An encryption descriptor hosted on a resource this capability cannot
        read fails closed with the unreadable-description refusal, instead of
        reporting a lost compare-and-swap race or creating over the live roster

`resource.getWithEtag()` resolves `null` for both "absent" and "exists but not
readable with this capability", because WAS masks unauthorized as 404, and the
adapter maps that straight to `null`. `compareAndSwap` then takes the absent
branch and creates. This contradicts ARCHITECTURE.md invariant 1 and the repo's
own policy statement in `internal/describe.ts`. The sibling
`collectionDescriptorStore.read` fails closed on the identical ambiguity via
`unreadableDescriptionError`, so the two adapters disagree. On a backend that
honors preconditions the guarded create 412s on all three attempts and surfaces
a misleading "lost the compare-and-swap race" message; on a backend without
`conditional-writes` it overwrites the live roster. Archived WCL-30 does not
help: its adoption path depends on the re-read returning the winner, and an
unreadable resource keeps returning `null`, so the loop exhausts instead of
adopting. The cheapest fix is to translate a create-path 412 that persists into
the unreadable-host refusal.

discovered-from: whole-codebase review, 2026-09-11.

### WCL-97: Docstring corrections in the EDV transport and the refresh policy

- status: todo
- priority: low
- labels: encryption, conditional-writes
- acceptance:
  - [ ] `WasTransport.update()`'s docstring agrees with the module header about
        preconditions, and the unreachable 412 arm is gone
  - [ ] The `DescriptorRefreshPolicy` class docstring scopes its guarantee to a
        refresh that succeeded

Two docstrings that overclaim, both against behavior the code states
deliberately elsewhere. `WasTransport.update()` sends no precondition, so no
server can 412 it and the `412` to `InvalidStateError` arm is unreachable on
every backend. That is not an oversight: the module header says advisory writes
are the profile's contract for `update` ("the EDV `sequence` is not enforced"),
and the roadmap's recorded decision says the same. What is defective is the
narrower pair of unreachable mapping code and a method docstring promising a
conflict surface the method cannot produce. Separately, the refresh policy's
class docstring claims a bound ("let alone a refetch per resource") that only
holds when the refresh succeeds. The un-arming on failure is stated as the rule
by the method docstring and repeated by an inline comment, and
`refreshingDocCipher.ts` implements the same rule, so the residual is that a
persistently failing descriptor endpoint does produce one failing round trip per
unknown-epoch row. Correct the class docstring, or add a short cooldown on
repeated refresh failures.

discovered-from: whole-codebase review, 2026-09-11.

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
  revocation is a 400. The server names it with its own problem type
  (`capability-already-revoked`, since 2026-09-09), which the client maps to
  `AlreadyRevokedError`; a tampered, expired, or foreign-rooted capability stays
  a plain `ValidationError`. The client still swallows none of them; a caller
  who wants revoking twice to be a no-op catches `AlreadyRevokedError` alone,
  rather than all of `ValidationError`. (Swallowing would make `revoke(garbage)`
  resolve as though it had worked.)
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
- **The delegation-proof suite is fixed at `eddsa-jcs-2022`, not an option.**
  `fromSigner` hard-codes `EddsaJcs2022`; the rejected alternative was threading
  a `SuiteClass` option through it. The primary constructor already takes a
  caller-built `ZcapClient`, so the escape hatch exists without a second one,
  and a knob on the convenience constructor is one whose wrong setting is an
  interop failure a caller only discovers at the server. Scoped by freewallet
  FW-395, which also carries the condition under which the server drops
  `Ed25519Signature2020` from its verify side; this repo signs one suite and
  states no removal condition of its own.
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
