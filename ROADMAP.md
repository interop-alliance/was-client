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

### WCL-18: Refuse an unrecognized `meta.encoding` in `EdvCodec#fromDocument`

- status: todo
- priority: medium
- labels: encryption, spec-conformance, fail-closed
- touches:
  - was-client: `src/edv/EdvCodec.ts` (`#fromDocument`), a test in
    `test/node/edv-codec.test.ts`, CHANGELOG.md
  - encrypted-collections-spec: unaffected (spec.md `#plaintext-document`
    already requires the refusal; this item brings the code to it)
- acceptance:
  - [ ] `#fromDocument` dispatches on `meta.encoding` as a closed set: absent
        means JSON (content returned verbatim), `"utf-8"` and `"base64"` decode
        as today, `"chunked"` stays on its existing route, and any other present
        value throws `EncryptionError` (a scheme refusal), instead of falling
        through to "return `content` as JSON"
  - [ ] A test asserts that an envelope sealing
        `meta: { contentType,     encoding: "gzip" }` (or any unknown string,
        and a non-string value) is refused and not returned as JSON
  - [ ] ARCHITECTURE.md's decode-path note, if it describes the fallthrough, is
        updated

discovered-from: WASS-15 (encrypted-collections-spec `#plaintext-document`,
2026-08-20). The spec's plaintext-document section makes `meta.encoding` a
closed set and, per the profile's fail-closed extensibility invariant, requires
a reader to refuse a value it does not recognize rather than pick any
interpretation of `content`. `#fromDocument` today handles `"utf-8"` and
`"base64"` and returns `content` verbatim for everything else, so an unknown
encoding silently decodes as JSON. Reading is unaffected for every envelope a
conforming writer produces; the change only closes the fallthrough.

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

## Internal design follow-ons

Items raised by the 2026-08-21 cleanup review of `src/` (reuse, simplification,
efficiency, and altitude passes). The behavior-preserving half of that review
landed in 0.42.0; everything here was deliberately left out of it because the
fix changes observable behavior, crosses the codec seam, or needs a maintainer
decision first. Each carries `discovered-from: 2026-08-21 cleanup review`.

### WCL-20: Sync port re-derives error classification from raw HTTP status

- status: todo
- priority: medium
- labels: sync, errors, altitude
- touches:
  - was-client: `mapWriteError` and `readContent` in `src/sync/port.ts`; the
    `./sync` subpath's thrown-error contract
  - freewallet, dcw, was-react: sync drivers matching on the current raw ky
    error shapes for statuses outside 412/404 would see typed errors instead
- acceptance:
  - [ ] The port's write and read paths classify through `errors.ts` rather than
        switching on raw HTTP status
  - [ ] `WasSyncConflictError` / `WasSyncNotFoundError` carry the server's
        `problem+json` fields (`type`, `title`, `details`, `requestUrl`) and a
        `cause`
  - [ ] A status outside the current small list (500, a 507 `quota-exceeded`)
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

### WCL-21: `Space.createCollection` hardcodes the EDV routability rule

- status: todo
- priority: medium
- labels: encryption, layering, altitude
- touches:
  - was-client: `Space.createCollection` (`src/Space.ts`), the
    `EncryptionProvider` seam (`src/codec.ts`), `EncryptionOverride`
    (`src/types.ts`), and the blind cast in `buildEncryptingCodec`
    (`src/internal/codec.ts`)
- acceptance:
  - [ ] Core (`src/*.ts`) contains no `scheme !== 'edv'` test
  - [ ] The "can this descriptor route" predicate has exactly one owner
  - [ ] `EncryptionOverride` admits a full `CollectionEncryption`, so
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

### WCL-22: Metadata binding slot is inferred from an absent argument

- status: todo
- priority: medium
- labels: encryption, codec-seam, integrity
- touches:
  - was-client: `ResourceCodec.encodeMeta` / `decodeMeta` (`src/codec.ts`) -- a
    public seam, so third-party codec implementations are affected; both
    implementations plus the `Resource` / `Collection` / `docCipher` call sites
  - wallet-attached-storage-spec / encrypted-collections spec: no wire change
    intended, but the `was.collection` vs `was.resource` binding this selects is
    normative text, so confirm the seam change does not imply one
- acceptance:
  - [ ] The metadata slot is stated by the caller rather than deduced from
        whether `expectedId` was passed
  - [ ] A caller that legitimately does not know a resource id can still decode
        metadata without silently getting collection-slot validation
  - [ ] Stored envelope bytes are unchanged

`EdvCodec` selects the AEAD binding slot with
`collectionSlot: expectedId === undefined` on the read side and
`resourceId === undefined ? { collection } : { resource }` on the write side.
The seam documents `expectedId` as an optional hint that "the identity codec
ignores", and says a caller that does not know the id omits it. In the EDV
implementation its absence is instead the mode selector between two mutually
exclusive bindings that `#verifyBinding` then refuses each other.

Today's two callers happen to be correct (`Resource.meta` passes `this.id`,
`Collection.meta` passes none), so this is latent rather than broken. The
failure it invites is asymmetric: a decode path that does not know the id gets
collection-slot validation quietly, while a write path that forgets to thread
`id` stamps a collection-bound envelope into a resource's `/meta`, and that only
surfaces later on some other reader as an `IntegrityError` naming server
tampering.

The fix is to make the slot explicit in the seam --
`encodeMeta({ custom, slot: { kind: 'resource', id } | { kind: 'collection' } })`
and the same on `decodeMeta` -- so the binding is stated, not deduced, and "id
unknown" stays expressible. Behavior-preserving, but it changes a published
interface, so it needs sign-off before it is coded.

### WCL-23: `logStore` re-derives the body shape the content layer owns

- status: todo
- priority: low
- labels: log, layering, altitude
- touches:
  - was-client: a new read shape on `Resource` (additive), consumed by
    `resourceLogStore.read` (`src/log/logStore.ts`)
- acceptance:
  - [ ] `resourceLogStore.read` obtains text plus the ETag validator without
        re-implementing the content-type to value mapping
  - [ ] The store no longer needs to know that a `text/jsonl` body comes back as
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

### WCL-24: `LOCAL_SPACE_ID` is a sentinel for a dependency the codec does not have

- status: todo
- priority: low
- labels: encryption, sync, layering
- touches:
  - was-client: `EdvCodec`'s constructor shape, `LOCAL_SPACE_ID`
    (`src/edv/constants.ts`), `createEdvDocCipher` and `encryptOnlyEdvCodec`
    (`src/edv/docCipher.ts`, `src/edv/EdvCodec.ts`) -- all internal to
    `src/edv/`
- acceptance:
  - [ ] A local-replica codec cannot address a chunked write at a fabricated
        `/space/local/` route, structurally rather than by convention
  - [ ] `LOCAL_SPACE_ID` is gone

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

### WCL-25: Two compare-and-swap retry policies that can drift

- status: todo
- priority: low
- labels: conditional-writes, reuse
- acceptance:
  - [ ] `Collection.declareIndex` and `casUpdateDescriptor` share one retry
        implementation
  - [ ] The attempt count and the exhaustion error are settled deliberately
        rather than differing by accident

`declareIndex` hand-rolls a `for (let attempt = 1; ; attempt++)` loop -- read
current state, reconcile, conditional write, continue on
`PreconditionFailedError` -- with its own local `maxAttempts = 4`.
`casUpdateDescriptor` (`src/edv/recipients.ts`) is the same loop, generic over a
read/replace store, with `MAX_CAS_ATTEMPTS = 3` and a null-means-no-op mutate
contract.

Two retry policies with two attempt counts and two exhaustion behaviors:
`declareIndex` rethrows the raw 412 with no context, `casUpdateDescriptor`
throws an explanatory `PreconditionFailedError` naming the race. A third caller
wanting CAS has no obvious one to copy.

Lifting the loop into `src/internal/` as a store-shaped generic makes
`casUpdateDescriptor` a thin call and lets `declareIndex` drive it with a
`/meta`-backed store. This is not behavior-preserving for `declareIndex` (3
attempts instead of 4, and a contextual error instead of the raw 412) unless the
helper takes `maxAttempts` as an option, which is the call to make when picking
this up.

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

### WCL-27: Every local encrypt serializes an envelope body that is thrown away

- status: todo
- priority: low
- labels: encryption, sync, efficiency
- touches:
  - was-client: `EdvCodec.encode`'s return shape and `EncodedWrite.body`
    (`src/codec.ts`), a public seam -- a lazy `body` is observable to any
    consumer that spreads or clones the returned object
- acceptance:
  - [ ] A local-replica encrypt does not pay a full stringify plus UTF-8 encode
        of the envelope on every write
  - [ ] The HTTP write path is unchanged

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

### WCL-28: First `meta()` on a blinded-index collection fetches `/meta` twice

- status: todo
- priority: low
- labels: encryption, search, efficiency
- acceptance:
  - [ ] Resolving a codec and then reading collection metadata costs one GET and
        one decrypt, not two
  - [ ] Metadata reads after the first are never served from a stale snapshot

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
