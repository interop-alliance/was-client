# Architecture

Internal design of `@interop/was-client` -- the layering, the request lifecycle,
the encryption seam, and the invariants that hold it together. For API usage see
the [README](./README.md); for toolchain and code style see
[AGENTS.md](./AGENTS.md).

## Layering

Three layers with a strict downward dependency rule:

```
src/*.ts            Public handle classes + contracts
  WasClient, Space, Collection, Resource
  codec.ts (interfaces only), errors.ts, types.ts, index.ts
        |
        v
src/internal/*.ts   Transport and orchestration
  request, write, content, paths, conditional, codec (identity + resolver),
  features, policy, grant, revoke, pagination, describe, reserved
        |
        v
external deps       @interop/ezcap, @interop/storage-core,
                    @interop/http-client, ...

src/edv/*.ts        Encryption subpath (sibling, opt-in)
  EdvCodec, WasTransport, docCipher, epochCrypto/epochKeys,
  recipients, descriptorStore
  Implements the interfaces in src/codec.ts; imports internal/* and the
  crypto deps (@interop/edv-client, @interop/minimal-cipher, @scure/base).

src/sync/*.ts       Sync subpath (sibling, opt-in, crypto-free)
  port (createWasSyncPort), types (WasSyncPort, DocCipher, MasterState),
  cid, plaintextCipher, envelope, provisioning
  Imports core (WasClient, errors, internal/conditional) but never
  src/edv/; src/edv/docCipher.ts imports its DocCipher/envelope types.
```

The load-bearing rule: **core never imports `src/edv/`, and neither does
`src/sync/`**. The package ships three entry points (`.`, `./edv`, and `./sync`
in the package.json exports map); `src/codec.ts` and `src/sync/types.ts` define
their seams as pure interfaces, so plaintext consumers never load the crypto
dependency graph. The dependency between the two opt-in subpaths points one way:
`src/edv/docCipher.ts` implements the `DocCipher` interface that
`src/sync/types.ts` declares.

## The handle model

`WasClient` (spaces repository) creates `Space` handles, which create
`Collection` handles, which create `Resource` handles. Handle construction does
**no network I/O**; requests happen only when a method is called.

All handles share one `ClientContext` by reference (`src/internal/request.ts`):
`{ serverUrl, zcapClient, controllerDid, encryption? }`. Per-handle state on top
of that:

- A bound `capability` (delegated zcap) flows from parent to child as the
  default (`options.capability ?? this.#capability`).
- `Collection` owns a memoized `CodecHolder` and a `BackendFeatures` probe;
  `collection.resource(id)` hands children resolver thunks so they share the
  parent's memoized codec and feature probe (and its `reset()`). A standalone
  `Resource` builds its own.
- `WasClient.fromCapability(zcap)` parses `invocationTarget` back into a handle
  at the right depth via `parseSpaceTarget`.

## Lifecycle of an authenticated request

Taking `resource.put(data)` as the canonical path:

1. **Codec resolution** (`internal/codec.ts`): the memoized resolver decides
   plaintext vs encrypting. Order: per-handle override wins; no keystore means
   identity codec; otherwise read the Collection description's `encryption`
   descriptor (fail closed if unreadable) and build the encrypting codec via
   `context.encryption.codecFor(...)`.
2. **Encode** (`codec.encode`): identity codec is byte-exact pass-through; the
   EDV codec seals content into a JWE envelope and attaches its own write
   precondition. A codec may instead answer with a `ChunkedWrite` plan -- a
   payload that cannot be one request -- which only the insert path runs.
3. **Conditional-write orchestration** (`internal/write.ts`, `upsertResource`):
   conditional codecs trigger a pre-read of the current document (to advance the
   EDV `sequence`); plaintext writes use the caller's explicit
   `ifMatch`/`ifNoneMatch`.
4. **Path building** (`internal/paths.ts`): percent-encoded ids, reserved-id
   guards, and exact trailing-slash discipline.
5. **Transport** (`internal/request.ts`): `zcapClient.request(...)` (ezcap)
   signs the zcap invocation. The zcap `action` is the **HTTP method**
   (`GET`/`PUT`/...), never ezcap's `read`/`write` -- WAS scopes capabilities by
   verb. With no bound capability, ezcap synthesizes the root capability for the
   target URL.
6. **Error mapping** (`src/errors.ts`): `mapError` dispatches on the
   `application/problem+json` type URI (from `@interop/storage-core`'s
   `ProblemTypes`), falling back to HTTP status.

Reads mirror this: signed GET, then
`codec.decode(response, expectedId, context)`, where `context` is the same
signed-request escape hatch a chunked write runs on. `getText`/`getBytes`
deliberately bypass the codec (they never decrypt).

### The 404-vs-null convention

WAS masks unauthorized as 404, so a 404 means "missing OR not visible to you".
Read-shaped methods (`get`, `list`, `describe`, `Resource.meta`,
`Collection.meta`, policy reads) resolve that to `null`; write-shaped calls
throw `NotFoundError`. This ambiguity drives the fail-closed rules below.

## The codec seam

- `src/codec.ts` -- the contract: `ResourceCodec` (`encode`/`decode` for
  content, `encodeMeta`/`decodeMeta` for the custom name/tags metadata, plus a
  `conditionalWrites` flag) and `EncryptionProvider` (one method, `codecFor`,
  which is **keys-only**: it supplies key material but never decides whether a
  collection is encrypted -- the Collection description's `encryption`
  descriptor does). `encodeMeta`/`decodeMeta` serve both metadata levels: the
  Resource `/meta` pair passes the resource `id` to bind, the Collection `/meta`
  pair passes none. `encodeMeta` also surfaces the `epoch` its envelope sealed
  under, which `Collection.setMeta` forwards as the PUT body's top-level stamp
  (a plaintext codec surfaces none, and the server then clears the stamp).
- `src/internal/codec.ts` -- the identity codec and the resolver policy.
- `src/edv/EdvCodec.ts` -- the encrypting implementation and the
  `createEdvEncryption` factory.

`encode` is a single-request transform in the ordinary case, with two
qualifications.

The first is the escape hatch for a payload one request cannot carry. `encode`
returns either an `EncodedWrite` or a `ChunkedWrite` plan (`isChunkedWrite`
discriminates them). A plan carries the resource id it will write to and an
`execute` method; `insertResource` runs it over a `CodecRequestContext` -- the
handle's signed `request` primitive plus its memoized feature probe -- instead
of sending one request. That `request` goes through the same mapped `send` path
core uses, so a codec-driven write fails with the typed `WasError` subclasses
the calling method documents (the raw `HttpResponse` still comes back, and the
typed errors carry the HTTP `status`, so a status-dispatching driver such as
`WasTransport` is unaffected). `upsertResource` refuses a plan, so auto-routing
is an `add()` affordance only; the refusal message is scheme-agnostic and
appends the plan's own `guidance` string, since only the codec knows which
low-level API drives that write directly. `decode` takes the same context, so a
codec whose stored form spans several resources can read the remainder; a caller
with no request layer (the sync `DocCipher`) omits it, and such a document then
fails loudly rather than decoding to a stub.

The second: a codec that indexes what it stores carries per-collection state --
the persisted index schema -- which the resolver loads onto it before handing it
over. That is the optional `indexing` capability (`applySchema` / `schema` /
`buildQuery`, all EDV-type-free), present only for an encrypted collection whose
descriptor declares a blinding key. Consequences worth knowing:

- Resolving such a codec costs one extra read (the Collection `/meta` slot,
  whose encrypted `custom` holds the schema under `indexSchema`); a collection
  without a blinding key pays nothing.
- The schema is as fresh as the handle. `declareIndex` updates the persisted
  copy and this handle's codec together, and `CodecHolder.reset()` re-reads it.
  The sync `DocCipher` has no request layer, so there the schema is
  caller-supplied instead: `createEdvDocCipher` decodes the same stored `/meta`
  value from its `meta` input (or a later `applyMeta` call) and installs it
  through the same `indexing` capability.
- Writes emit blinded `indexed` entries alongside the JWE once the schema
  declares an attribute. The metadata seam (`encodeMeta`) stays deliberately
  un-blinded: that envelope is the WAS `/meta` value, a different slot the
  search endpoint never reads.
- `Collection.find()` blinds through the same capability and posts the
  `blinded-index` profile to the collection `/query` endpoint (the way
  `changes()` posts its own), then decodes each returned envelope back through
  `decode`.

What the server sees for an encrypted collection: opaque JWE envelopes for
content and for the name/tags metadata, opaque EDV resource ids, blinded index
tokens and blinded query terms, and the plaintext descriptor scaffolding
(`scheme`, `version`, epoch ids, blinding-key id, `sequence`, ETags).

## The EDV layer

Two integration levels share `src/edv/`:

- **`EdvCodec`** (pass-through encryption): plugs into the codec seam so the
  normal `Collection`/`Resource` API transparently encrypts. Ids are minted by
  the codec (`random`, or `content`-derived for immutable content-addressed
  documents). A binary `add()` over `maxBlobBytes` is routed to the chunked
  path: the codec returns a plan that drives
  `EdvClientCore.insert({ doc, stream, transport })` over a `WasTransport` of
  its own, built from the write context. Routing is decided on the payload's
  size alone and the payload is passed on as a stream, so an over-threshold blob
  is never buffered whole by the codec. Reads reverse it through `getStream`,
  trusting only AEAD-authenticated inputs sealed in the JWE payload: the
  `meta.encoding` discriminator that says the document is chunked, the chunk
  count, and the bound resource id the chunks are addressed by (never the
  envelope's cleartext `id`). `maxBlobBytes` is therefore a routing threshold,
  not a cap. The write is two-phase, so a failure partway would orphan an
  undecryptable document stub: the plan best-effort deletes it and rethrows with
  the original failure as `cause`. Content-addressed collections are the
  exception: a chunked write stores the document twice, so no single ciphertext
  derives its id, and the write is refused.
- **`WasTransport`** (EDV-native): an `@interop/edv-client` `Transport` that
  maps EDV document operations onto WAS resource CRUD ("vault per collection",
  EDV doc id is the WAS resource id), including blinded-index `find` and chunked
  streams, gated on server features. The EDV core owns the write sequence and
  discards the responses, so the transport surfaces the outcome of its last
  document write (`lastDocumentWrite`: the id and the server's `ETag`) and
  offers a non-EDV `deleteDocument` -- the two things a driver needs to report a
  write's validator and to undo a half-finished one.

Multi-recipient sharing uses **key epochs** (`epochCrypto`/`epochKeys`/
`recipients`): an epoch is a fresh X25519 key whose secret is wrapped to each
reader's key-agreement key (`ECDH-ES+A256KW`) on the descriptor. Access has two
orthogonal axes: _pull_ (zcap, server-enforced, immediate) and _read_ (epoch-key
possession, client-side, prospective -- rotation never claws back already-held
keys or fetched ciphertext). `removeRecipient` does both halves because doing
only one is a footgun (the pull half is the default zcap revocation, or a
caller-supplied `pull` action for descriptors whose access lives elsewhere).
Descriptor mutations go through a CAS loop (read descriptor + validator, mutate,
conditional write, bounded retries) over the **descriptor-store seam**
(`descriptorStore.ts`): the Collection Description adapter (`describeWithEtag` /
`replaceDescription({ ifMatch })`, server-enforced descriptor invariants) or the
plain-JSON-Resource adapter (`getWithEtag` / `put({ ifMatch })`, first
descriptor created with `If-None-Match: *`; integrity rests on client-side epoch
pinning plus the hosting profile's governance -- for a log-governed descriptor,
the Resource Log Profile's verified entry proofs and chain-head pin -- so host
it in a plaintext collection).

Tamper resistance: each write binds an AEAD-authenticated `was` parameter
(scheme version, resource id, epoch) into the JWE protected header, verified on
decode (`IntegrityError` on envelope swap or epoch rollback). The Collection
`/meta` envelope belongs to no resource, so instead of a resource id it binds
the collection id (`was.collection`, no Space scoping). Each slot is thereby
declared positively by the member set of its envelope: `resource` marks a
resource slot, `collection` the Collection `/meta` slot, and a content-derived
envelope binds neither. The decode side enforces that both ways -- a
resource-bound (or unmarked) envelope served into the `/meta` slot is refused,
as is a collection-bound envelope served into a resource's slot, and a
`was.collection` naming a different collection is refused as one Collection's
metadata served as another's.

## The sync layer

`src/sync/` (the `./sync` subpath) is cross-replica synchronization support:
everything a wallet needs to replicate one Space + Collection over WAS. It is
deliberately **not** a sync engine -- it supplies the seams a change engine
plugs into:

- **`WasSyncPort`** (`types.ts`) is the injected WAS-access seam: `query` (one
  page of the change feed), `putContent`/`deleteContent`/`putMeta` (conditional
  writes), and `get` (single-resource master-state re-read for the 412-conflict
  path). `createWasSyncPort` (`port.ts`) implements it, bound to one Space +
  Collection.
- **`DocCipher`** (`types.ts`) is the per-collection encrypt/decrypt seam: it
  turns a JSON document into its stored body (minting the resource id) and back.
  `createPlaintextDocCipher` is the crypto-free identity implementation for a
  plaintext content-addressed collection; `createEdvDocCipher`
  (`src/edv/docCipher.ts`, on the `./edv` subpath) is the encrypting one,
  wrapping the same EDV codec the handles use but pointed at a local replica. On
  a collection with a blinded-index key, the caller hands it the stored
  Collection `/meta` value (the `meta` build input, or `applyMeta` on the
  returned cipher when the replica's copy changes mid-session), so pushed
  envelopes carry the same blinded `indexed` entries as handle writes.

The port's defining property: **it moves stored bodies verbatim and never
touches keys**. Writes and single-resource reads ride the raw signed
`was.request()` escape hatch, bypassing the codec seam entirely -- the change
feed already ships opaque stored bodies (plaintext or EDV envelope), and push
must write those same bytes back unchanged; running them through
`resource.put()` would re-encrypt an already-encrypted envelope. Encrypt and
decrypt therefore happen above the port, at the engine's `DocCipher`, which is
what reconciles plaintext, single-recipient, and multi-recipient (key-epoch)
collections behind one interface. The pull path rides `Collection.changes()`
(the signed `POST .../query`, profile `changes`), which likewise never resolves
the codec.

The wire model is shared, not local: `SyncCheckpoint`, `WireDoc`, and the feed
page re-export `@interop/storage-core`'s `ChangesCheckpoint` / `ChangeDocument`
/ `ChangesPage`. A checkpoint is the keyset position `{ id, updatedAt }` of the
last document returned -- server time only, an opaque resume token, never
compared against a device clock.

Conditional writes ride the server's monotonic content `version` (ETag)
uniformly for plaintext and encrypted resources, so there is no
plaintext-vs-encrypted fork; each write returns the server-acked `version`. Two
typed signals in `src/errors.ts` let a push loop catch exactly what it can
handle: `WasSyncConflictError` (412, a subtype of `PreconditionFailedError`)
triggers re-read-and-reconcile, and `WasSyncNotFoundError` (404 on delete, a
subtype of `NotFoundError`) marks an already-gone target as a settled outcome.
The port's `putContent` also stamps the `Key-Epoch` header so the server records
which key epoch a body was encrypted under.

Convergent identifiers make replicas agree without coordination (`cid.ts`): a
content id is `base64url(SHA-256(utf8(JCS-canonicalized JSON)))`, unpadded, so
the same logical document mints the same resource id on every replica;
`deriveSpaceId` derives the Space id the same way from the controller DID.
Hashing is synchronous pure-JS (`@noble/hashes`), byte-identical across Node,
the browser, and React Native. The exact hashed bytes are the canonical JSON
string itself -- that is the contract replicas must share for ids to converge.

The `DocCipher` id model follows the collection's mutability: a
content-addressed collection (`idDerivation: 'content'`, or plaintext) is
insert-only -- a changed document is a different id, so `encryptUpdate` is
omitted or throws; a mutable head-document collection uses `'random'` ids and
`encryptUpdate`, which re-encrypts in place under the existing id while
advancing the envelope `sequence`. Decrypt routing is owned by the EDV codec
itself (one codec per collection, for the handle and sync paths alike): it
matches the envelope's JWE recipient `kid`s against the reader's candidate keys
-- the per-epoch keys resolved from the descriptor, or the key-agreement key on
a single-key collection. An envelope naming only recipients no candidate matches
fails fast, and which error it raises depends on whether the descriptor lists
the named epoch. An epoch the descriptor does not list at all throws
`UnknownEpochError`, the signal that the cached Collection description is stale
(epoch rotation emits no change-feed entry) and the codec must be rebuilt from a
re-read descriptor. An epoch the descriptor lists but wraps only to other
recipients throws `KeyUnwrapError`: the descriptor is current and this reader is
simply not a recipient of that epoch (it never was, or it was removed and the
epoch rotated), so a refresh cannot help.

`ensureSpaceAndCollection` (`provisioning.ts`) is the idempotent setup step:
upsert the Space, configure the collection (declaring the `{ scheme: 'edv' }`
encryption descriptor, or plaintext with `force`), optionally grant world read.
Re-running it against an existing account is a no-op upgrade.

## Concurrency

No locks; safety is optimistic (ETag/CAS) throughout
(`internal/conditional.ts`):

- The server's per-resource version is the ETag; writes send `If-Match` /
  `If-None-Match: *`; 412 maps to `PreconditionFailedError`.
- Each metadata slot has its own validator: the Resource `/meta` and Collection
  `/meta` `metaVersion` ETags are independent of each other, of the Collection
  Description's ETag, and of every content version, so `Collection.setMeta` and
  the read-then-CAS `setName`/`setTags` sugar pin against the metadata's own
  etag.
- `declareIndex` reconciles against the persisted index schema with the same
  metadata ETag: read, merge, conditional write, bounded retry on 412, so two
  clients declaring different attributes at once do not erase each other.
- The EDV codec sets `conditionalWrites = true`, making the sequence check
  enforced automatically: updates pin `If-Match` to the pre-read ETag, fresh
  inserts guard with `If-None-Match: *`.
- `CodecHolder` memoizes the in-flight codec promise (concurrent callers share
  one round trip) and is `reset()` when `configure` or `replaceDescription`
  changes the encryption descriptor.

## Feature detection

`internal/features.ts` probes the Collection's backend descriptor once for its
advertised `features` tokens (`conditional-writes`, `blinded-index-query`,
`chunked-streams`, `changes-query`). Definitive absence (404/405/501) is cached
as "no features"; transient failures are not cached. The two roads to "no
features" stay distinguishable (`FeatureProbe.descriptorAbsent()`): a descriptor
that was read and lists none, versus one that could not be read at all (no such
endpoint, a deleted collection, or a capability that cannot read it). A gate
consults it so its error names the right cause instead of calling a capable
server incapable. Every gate **falls closed**: without `conditional-writes`, an
EDV insert against a masked 404 is refused rather than risking a silent clobber;
`WasTransport` degrades insert to non-atomic HEAD-then-PUT and throws
`NotSupportedError` for query/chunk operations. The codec's own chunked-blob
routing checks `chunked-streams` before its first write (and before a read
fetches chunks), so an unsupported server never ends up holding a document stub
with no chunks; it raises the typed `NotSupportedError` from `src/errors.ts`.

## Invariants worth knowing before you change things

1. **Fail closed on masked 404.** Any operation that must know current state
   (descriptor discovery, configure merges, conditional inserts, recipient CAS)
   refuses to proceed when the description is unreadable. An encryption-capable
   client never silently downgrades to plaintext.
2. **Trailing-slash discipline is a security invariant.** The zcap
   `invocationTarget` derives from the request URL and must byte-match the
   server's per-operation `allowedTarget`; item-create/listing endpoints take a
   trailing slash, member endpoints do not (`internal/paths.ts`).
3. **Reserved path segments are guarded in three places** (handle constructors,
   path builders, path parsing) so e.g. `collection('policy')` can never alias
   the space policy endpoint.
4. **zcap action equals HTTP method.** Never switch to ezcap's default
   `read`/`write` actions.
5. **Grants are rooted at the Space** so they are revocable at
   `/space/:s/zcaps/revocations/:capId`; the root capability there is built in
   object form because string root-cap ids break on `http://localhost`
   (`internal/revoke.ts`).
6. **`@interop/http-client` pre-consumes JSON bodies** into `.data`, which is
   why body handling funnels through `internal/content.ts` helpers and why
   `getText`/`getBytes` are not byte-exact for JSON content types.
7. **The wire model lives in `@interop/storage-core`** (description, listing,
   policy, backend, and problem types). Do not redefine wire types locally.

## Where to add what

| Change                            | Start in                                                                   |
| --------------------------------- | -------------------------------------------------------------------------- |
| New public API method             | The relevant handle class in `src/*.ts`                                    |
| New server endpoint or path shape | `src/internal/paths.ts` (+ wire types upstream in `@interop/storage-core`) |
| Request/transport behavior        | `src/internal/request.ts`                                                  |
| Write preconditions, ETags        | `src/internal/conditional.ts`, `src/internal/write.ts`                     |
| New server feature gate           | `src/internal/features.ts` + the call sites it gates                       |
| New error kind                    | `src/errors.ts` (`ERROR_CLASS_BY_KIND`), problem type upstream             |
| Encryption format or key handling | `src/edv/` (never in core; keep the seam interface-only)                   |
| Codec resolution policy           | `src/internal/codec.ts`                                                    |
| Cross-replica sync behavior       | `src/sync/` (port stays verbatim/keyless; ciphers implement `DocCipher`)   |
