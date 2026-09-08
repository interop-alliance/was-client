# WAS Client Roadmap (open items)

nextAvailableId: 39

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
