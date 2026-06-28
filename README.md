# Wallet Attached Storage Client _(@interop/was-client)_

[![Node.js CI](https://github.com/interop-alliance/was-client/workflows/CI/badge.svg)](https://github.com/interop-alliance/was-client/actions?query=workflow%3A%22CI%22)
[![NPM Version](https://img.shields.io/npm/v/@interop/was-client.svg)](https://npm.im/@interop/was-client)

> A developer-friendly client for Wallet Attached Storage (WAS) servers, with a
> database-driver-inspired navigational API over zcap-authorized HTTP.

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
  - [Creating a client (signer + zcapClient)](#creating-a-client-signer--zcapclient)
  - [The handle model](#the-handle-model)
  - [Spaces](#spaces)
  - [Collections](#collections)
  - [Resources: JSON and binary](#resources-json-and-binary)
  - [Delegation and sharing](#delegation-and-sharing)
  - [Public sharing and access-control policies](#public-sharing-and-access-control-policies)
  - [Resource metadata](#resource-metadata)
  - [Conditional writes (optimistic concurrency)](#conditional-writes-optimistic-concurrency)
  - [Storage introspection: backends and quotas](#storage-introspection-backends-and-quotas)
  - [Registering a Bring-Your-Own-Storage backend](#registering-a-bring-your-own-storage-backend)
  - [Encrypted collections (EDV-over-WAS): pass-through encryption via the WAS client (recommended)](#encrypted-collections-edv-over-was-pass-through-encryption-via-the-was-client-recommended)
  - [Export and import](#export-and-import)
  - [The manual-request escape hatch](#the-manual-request-escape-hatch)
- [Errors and the 404/null caveat](#errors-and-the-404null-caveat)
- [Contribute](#contribute)
- [License](#license)

## Background

The WAS protocol exposes a general purpose database-like container model --
`SpacesRepository > Space > Collection > Resource` -- over HTTP, authorized with
[Authorization Capabilities (zcaps)](https://w3c-ccg.github.io/zcap-spec/).

`@interop/was-client` wraps that `ZcapClient` and exposes the containment model
through cheap, lazy navigational handles modeled on a document store's DX
(`client > db > collection`), using WAS-specific verbs
(`add`/`get`/`put`/`list`/`delete`) rather than `insertOne`/`findOne` (WAS has
no query-by-filter yet).

| Document db driver                  | WAS client                                 |
| ----------------------------------- | ------------------------------------------ |
| `new Client(url)`                   | `new WasClient({ serverUrl, zcapClient })` |
| `client.db('app')`                  | `was.space(spaceId)`                       |
| `db.collection('users')`            | `space.collection(collectionId)`           |
| `collection.insertOne(doc)`         | `collection.add(doc)`                      |
| `collection.findOne({ _id })`       | `collection.get(resourceId)`               |
| `collection.replaceOne({ _id }, d)` | `collection.put(resourceId, data)`         |
| `collection.find().toArray()`       | `collection.list()`                        |
| `collection.deleteOne({ _id })`     | `collection.resource(resourceId).delete()` |

## Install

- Node.js 24+ is recommended.

```
pnpm install @interop/was-client
```

## Usage

### Creating a client (signer + zcapClient)

A `WasClient` signs every request with a key you control. The key is held by an
ezcap `ZcapClient`, which you build from a `did:key` identity. You will need two
companion packages alongside this one (this library already depends on
`@interop/ed25519-signature`):

```
pnpm install @interop/ezcap @interop/did-method-key @interop/ed25519-verification-key
```

The primary form wraps a `ZcapClient` you build yourself. The `did:key` driver
generates a key pair and a matching DID document, wiring the signer's
`id`/`controller` correctly:

```ts
import { ZcapClient } from '@interop/ezcap'
import * as didKey from '@interop/did-method-key'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { WasClient } from '@interop/was-client'

// 1. Generate a did:key identity (didDocument + keyPairs).
const didKeyDriver = didKey.driver()
didKeyDriver.use({ keyPairClass: Ed25519VerificationKey })
const { didDocument, keyPairs } = await didKeyDriver.generate()

// 2. Build the ezcap ZcapClient (it holds the signer and signs every request).
const zcapClient = new ZcapClient({
  didDocument,
  keyPairs,
  SuiteClass: Ed25519Signature2020
})

// 3. Wrap it.
const was = new WasClient({ serverUrl: 'https://was.example', zcapClient })
```

If you already have a single signer, `WasClient.fromSigner()` builds the
`ZcapClient` internally (using the `Ed25519Signature2020` suite). A signer is
any object with `{ id, sign() }`; here we get one from a generated key. The
signer's `id` must be a `did:key` so the server can resolve and verify it:

```ts
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { WasClient } from '@interop/was-client'

// Pass a 32-byte `seed` for a deterministic key, or omit it for a random one.
const keyPair = await Ed25519VerificationKey.generate({ seed })
keyPair.controller = `did:key:${keyPair.fingerprint()}`
keyPair.id = `${keyPair.controller}#${keyPair.fingerprint()}`

const was = WasClient.fromSigner({
  serverUrl: 'https://was.example',
  signer: keyPair.signer()
})
```

The `seed` is where a passphrase-, stored-secret-, or KMS-derived key plugs in:
deriving the same 32-byte seed yields the same DID, and therefore access to the
same spaces. (Apps with user accounts often derive the signer from a passphrase
via `CapabilityAgent.fromSecret()` from `@digitalbazaar/webkms-client` -- not
required, just a common alternative.)

`serverUrl` is the base for both URL building and zcap `invocationTarget`s, so
the "server URL must equal the invocation target host:port" constraint holds by
construction.

### The handle model

The client exposes the WAS containment model
(`SpacesRepository > Space > Collection > Resource`) as navigational handles.
Handles are lazy and synchronous to obtain -- only the verb methods hit the
network. Lazy chains never throw: `was.space(x).collection(y)` does no I/O and
just accumulates URL context. Existence is checked on the first network verb.

```ts
const space = await was.createSpace({ name: 'Home' })

const collection = await space.createCollection({
  name: 'Verifiable Credentials'
})

await collection.put('vc-1', {
  type: ['VerifiableCredential'],
  name: 'Diploma'
})
const vc = await collection.get('vc-1') // parsed JSON object, or null on a miss

await collection.resource('vc-1').delete() // delete one resource by id
await space.delete() // delete the whole space (idempotent)
```

`delete()` is uniform at every level, takes no argument, and always deletes the
thing the handle points at -- so there is no "delete the collection" vs "delete
one item" footgun. The next sections cover each level in turn.

### Spaces

A Space is the top-level container, created from the spaces repository. The
server requires a `name`; `controller` defaults to the client's own DID, and the
server generates the id unless you pass one.

```ts
const space = await was.createSpace({ name: 'Home' }) // POST /spaces/

// Lazy handle to an existing space by id -- no I/O until a verb runs.
const same = was.space(space.id)

// Read the Space Description (null if missing or not visible to you).
const desc = await space.describe() // { id, type: ['Space'], name, controller } | null

// Upsert: merges the given fields over the current description.
await space.configure({ name: 'Home (renamed)' })

await space.delete() // idempotent
```

List the spaces in the repository visible to your signer with
`was.listSpaces()`. It returns a `{ url, totalItems, items }` listing holding
only the spaces whose controller your invocation is authorized for; an
unauthorized caller gets an empty list rather than an error. To enumerate what
is _inside_ a space, use `space.collections()` (below).

```ts
const { totalItems, items } = await was.listSpaces()
// items: [{ id, url, name? }, ...]
```

### Collections

A Collection lives inside a Space and holds resources. WAS does not auto-create
parents, so `createCollection` throws `NotFoundError` if the space does not
exist. The server generates the id unless you pass one (a handful of reserved
ids are rejected).

```ts
// Create.
const collection = await space.createCollection({
  name: 'Verifiable Credentials'
})

// Lazy handle to an existing collection by id.
const same = space.collection(collection.id)

// Read the Collection Description (null if missing or not visible).
const desc = await collection.describe() // { id, type: ['Collection'], name } | null

// Update (upsert; merges over the current description).
await collection.configure({ name: 'Credentials' })

// List the collections in a space.
const collections = await space.collections()
// { url, totalItems, items: [{ id, name, url }, ...] } | null

// List the resources inside this collection.
const resources = await collection.list()
// { id, url, totalItems, items: [{ id, url, contentType }, ...], ... } | null

await collection.delete() // deletes the whole collection; idempotent
```

To delete a single resource instead of the whole collection, use
`collection.resource(id).delete()`.

### Resources: JSON and binary

A Resource is a JSON object or binary blob keyed by id within a Collection. Use
`add()` for a server-generated id or `put(id, ...)` to create-or-replace at a
known id (both throw `NotFoundError` if the parent collection is missing):

```ts
// Server-generated id; returns { id, url, contentType? }.
const added = await collection.add({
  type: ['VerifiableCredential'],
  name: 'Diploma'
})

// Create or replace at a known id (upsert).
await collection.put('vc-1', {
  type: ['VerifiableCredential'],
  name: 'Diploma'
})

const vc = await collection.get('vc-1') // parsed JSON object, or null on a miss
await collection.resource('vc-1').delete() // idempotent
```

Writes detect the payload: a plain object/array is sent as JSON; a
`Blob`/`Uint8Array`/`Buffer` is sent as binary, with the content-type taken from
`options.contentType`, the `Blob.type`, or `application/octet-stream`.

```ts
// JSON
await collection.put('doc', { hello: 'world' })

// Binary
const bytes = new TextEncoder().encode('plain text body')
await collection.put('note.txt', bytes, { contentType: 'text/plain' })

const resource = collection.resource('note.txt')
await resource.get() // a Blob (whose .type carries the content-type)
await resource.getText() // 'plain text body'
await resource.getBytes() // Uint8Array
```

Reads auto-parse: `get()` returns a parsed object for a JSON content-type and a
`Blob` otherwise; `getText()` / `getBytes()` are explicit escape hatches.

### Delegation and sharing

`was.grant(...)` is the general delegation primitive; `space.grant(...)` and
`collection.grant(...)` are sugar that prefill the grant `target` with the
handle's URL. The recipient rebuilds access from the received zcap with
`fromCapability()`.

```ts
// Alice grants Bob read access to a resource.
const added = await collection.add({ secret: 'value' })
const zcap = await was.grant({
  to: bobDid,
  actions: ['GET'], // HTTP verbs: 'GET' | 'PUT' | 'POST' | 'DELETE'
  target: added.url
})

// Bob, holding the zcap, rebuilds a handle at the right depth.
const handle = bobWas.fromCapability(zcap) // a Resource here
await handle.get() // succeeds; a write would be denied by the GET-only grant
```

Actions are HTTP verbs (`GET` / `PUT` / `POST` / `DELETE`). The WAS server
authorizes on these case-sensitively (uppercase), but `grant()` also accepts the
lowercase forms and normalizes them to uppercase in the signed zcap -- so
`actions: ['get']` still validates server-side.

### Public sharing and access-control policies

A Space, Collection, or Resource can carry an access-control **policy** that
grants read access beyond capabilities -- most commonly making it world-readable
("share via public link"). The policy methods live on all three handles:

```ts
// Make a whole collection world-readable (the "create public link" case).
await collection.setPublic() // sugar for setPolicy({ type: 'PublicCanRead' })

// Anyone (even unauthenticated) can now read its resources.
const link = added.url // hand this URL out; a plain GET resolves it

// Inspect or revoke.
const policy = await collection.getPolicy() // { type: 'PublicCanRead' } | null
const isPublic = await collection.isPublic() // true if its own policy is PublicCanRead
await collection.clearPolicy() // revert to capability-only access (idempotent)

// setPolicy() is the generic, forward-compatible primitive; setPublic() is sugar.
await space.setPolicy({ type: 'PublicCanRead' }) // inherited by all contents
await resource.setPublic() // a single public resource
```

Policies are resolved most-specific-first (Resource over Collection over Space)
and are permissive-only -- they broaden access, never restrict a valid
capability holder. Managing a policy is a controller-level operation. Discover a
policy via `space.linkset()` / `collection.linkset()` (RFC9264) or the `linkset`
property on a description.

`isPublic()` is a read-only convenience that returns `true` when the Space,
Collection, or Resource has a `{ type: 'PublicCanRead' }` policy -- that is,
when it has been made public via `setPublic()` (or an equivalent `setPolicy()`
call). It's meant to drive data-browser style UI, to show a "This
space(/collection/resource) has been shared publicly" type of icon.

#### Consuming public links (unauthenticated reads)

The flip side of `setPublic()`: reading a `PublicCanRead` resource or collection
with no authorization, by its URL. These use an unsigned plain `fetch` (no
capability invocation), so they work for a consumer who only holds the link.

```ts
// Fetch a single public resource (auto-parses JSON, returns binary as a Blob).
const doc = await was.publicRead({
  resourceUrl: 'https://was.example/space/s/c/r'
}) // Json | Blob | null

// List a public collection -- e.g. a blog published as a public-read collection.
const listing = await was.publicListCollection({
  collectionUrl: 'https://was.example/space/s/c'
}) // ResourceListing | null
```

Both follow the read-method 404/null caveat: a missing or non-public target
resolves to `null`.

### Resource metadata

Each Resource has a metadata object at its reserved `/meta` path: server-managed
properties (`contentType`, `size`, optional `createdAt` / `updatedAt`) plus a
user-writable `custom` object (`name` and `tags`).

```ts
const resource = collection.resource('vc-1')

const meta = await resource.meta() // ResourceMetadata | null (null on a miss)

// setMeta() is a full replacement of `custom`; omitted properties are cleared.
await resource.setMeta({ custom: { name: 'Diploma', tags: { year: '2026' } } })

// setName() / setTags() are read-modify-write sugar that preserve the other.
await resource.setName('Renamed diploma') // keeps existing tags
await resource.setTags({ status: 'verified' }) // keeps existing name
```

The `custom.name` is the same value surfaced as a resource's `name` in
collection listings; updating one updates the other.

### Conditional writes (optimistic concurrency)

Against a backend that advertises the `conditional-writes` feature (see below),
a Resource carries a strong **`ETag`** validator that changes on every write.
Use it to prevent the lost-update problem -- two clients that both read version
_N_ and each write _N+1_, the second silently clobbering the first.

```ts
const { etag } = await collection.put('doc', { v: 1 }) // writes return the ETag
const meta = await collection.resource('doc').meta() // meta().etag also carries it

// Update-if-unchanged: succeeds only if `doc` is still at `etag`, else throws
// PreconditionFailedError (HTTP 412).
await collection.put('doc', { v: 2 }, { ifMatch: etag })

// Create-if-absent: succeeds only if `doc` does not yet exist (else 412).
await collection.put('new-doc', { v: 1 }, { ifNoneMatch: true })

// Delete-if-unchanged.
await collection.resource('doc').delete({ ifMatch: someEtag })
```

Recover from a `PreconditionFailedError` by re-reading the current `etag`,
re-applying your change on top of the new version, and retrying.

On an **encrypted collection** this is automatic: the EDV codec advances the
document `sequence` and pins each write to the current ETag for you, so a stale
write surfaces as a `PreconditionFailedError` (the EDV `sequence` becomes
enforced rather than advisory). The explicit `ifMatch` / `ifNoneMatch` options
above are for plaintext collections.

### Storage introspection: backends and quotas

A Space can report the storage backends available to it and a per-backend usage
report. Both are optional server features (a server without them surfaces a
`NotImplementedError`); both follow the read-method 404/null caveat.

```ts
const backends = await space.backends() // BackendDescriptor[] | null
const report = await space.quotas() // SpaceQuotaReport | null
// report.backends[i]: { id, state, usageBytes, limit, restrictedActions, ... }
```

A Collection can likewise report the backend it is stored on and its own usage,
scoped to that backend (same optional-feature and 404/null caveats).

```ts
const backend = await collection.backend() // BackendDescriptor | null
const usage = await collection.quota() // BackendUsage | null
// usage: { id, state, usageBytes, limit, restrictedActions, measuredAt, ... }
```

A `BackendDescriptor`'s optional `features` array advertises optional **server
affordances** -- things the backend actively does beyond the baseline read/write
API (e.g. `conditional-writes`, `blinded-index-query`, `chunked-streams`). An
absent token means the backend makes no claim to it, so treat it as unsupported
rather than assuming a default. (Client-side encryption is _not_ a backend
feature -- see below.)

```ts
const backend = await collection.backend()
if (backend?.features?.includes('conditional-writes')) {
  // backend enforces If-Match / If-None-Match write preconditions
}
```

### Registering a Bring-Your-Own-Storage backend

Beyond the server's built-in `default` backend, the Space controller can
register an `external` ("Bring Your Own Storage") backend -- e.g. a wallet
connecting a user's own Google Drive. Registration is a controller-authorized
write: the body carries the secret-bearing `connection` material (an OAuth
authorization code or refresh token), and the server stores it and returns the
**sanitized** descriptor (never the secrets).

```ts
const descriptor = await space.registerBackend({
  id: 'gdrive-personal', // unique within the Space
  name: 'My Google Drive',
  provider: 'google-drive', // selects the server-side adapter
  storageMode: ['document', 'blob'],
  connection: {
    kind: 'oauth2-google',
    authorizationCode: '4/0Ab...', // one-time PKCE code (or a refreshToken)
    redirectUri: 'https://wallet.example/oauth/callback'
  }
})
// descriptor.connection: { kind, status: 'registered', account?, scope?, ... }
```

Once registered, select it on a Collection by id; reads of the backend reflect
its connection `status` (`registered` | `connected` | `expired` | `revoked` |
`unreachable`), which a storage-management UI uses to prompt re-consent:

```ts
await space.createCollection({
  id: 'photos',
  backend: { id: 'gdrive-personal' }
})

const [, gdrive] = (await space.backends()) ?? []
if (gdrive?.connection?.status === 'expired') {
  // re-consent: swap in fresh connection material (create-or-replace by id)
  await space.updateBackend({
    id: 'gdrive-personal',
    provider: 'google-drive',
    connection: { kind: 'oauth2-google', authorizationCode: '4/0Cd...' }
  })
}

// Deregister (idempotent): forgets the record and its stored connection.
await space.deregisterBackend('gdrive-personal')
```

`registerBackend()` throws a `ConflictError` if the `id` already exists or the
server does not permit the `provider`; `updateBackend()` returns the descriptor
when it created a record and `null` when it replaced one in place (the server
sends no body on an in-place replace).

> A registered backend's record exists immediately, but whether its connection
> can actually serve bytes depends on the server having a live provider adapter
> for it. Until then it is registered but inert (`status: 'registered'`).

### Encrypted collections (EDV-over-WAS): pass-through encryption via the WAS client (recommended)

This is the recommended way to use encrypted collections. For the low-level
alternative -- driving an `EdvClientCore` directly via `WasTransport` -- see
[docs/edv-client-core-usage.md](docs/edv-client-core-usage.md).

Client-side end-to-end encryption is a per-collection concern -- **not** a
backend feature (an encrypted document is opaque JSON any document backend
stores faithfully). Two things drive it, kept separate:

- **Policy** (is this collection encrypted?) is declared on the collection
  itself: `createCollection({ encryption: { scheme: 'edv' } })` writes a
  non-secret `encryption` marker to the Collection Description. Any authorized
  reader -- including a delegated consumer that did **not** create the
  collection -- discovers it by reading the Description, so it knows to decrypt.
- **Keys** come from an `encryption` provider you pass to `WasClient` (built
  from the opt-in `@interop/was-client/edv` subpath, so plaintext consumers
  never pull the crypto graph). It is a pure **keystore**: `resolveKeys` returns
  the collection's keys, which live in your wallet. The server only ever stores
  opaque JWE envelopes.

The ordinary `Collection`/`Resource` handles then transparently encrypt on write
and decrypt on read for any collection the marker (or an override) declares
encrypted.

```ts
import { WasClient } from '@interop/was-client'
import { createEdvEncryption } from '@interop/was-client/edv'

const encryption = createEdvEncryption({
  // The keystore: return the collection's keys (from your wallet).
  async resolveKeys({ spaceId, collectionId }) {
    return { keyAgreementKey, keyResolver }
  }
})
const was = WasClient.fromSigner({ serverUrl, signer, encryption })

// Declare the collection encrypted (writes the marker). The returned handle is
// pre-seeded, so the first write encrypts with no extra round-trip.
const vault = await was
  .space(spaceId)
  .createCollection({ id: 'vault', encryption: { scheme: 'edv' } })
const { id } = await vault.add({ secret: 'hello' }) // encrypted; id is an EDV id
const back = await vault.get(id) // { secret: 'hello' } -- decrypted

// A consumer that did not create it discovers the marker and decrypts with its
// own keys -- no override needed; one cached read of the Description:
const same = was.space(spaceId).collection('vault')
await same.get(id) // reads the marker, then decrypts
```

The switch is the **marker**: a handle encrypts a collection when its
Description declares `encryption` (resolution reads the Description once, then
caches -- no round-trip for plaintext-only clients or when an override is set).
Keys are then **required**: if the collection is declared encrypted but your
keystore returns no keys, reads/writes throw `EncryptionError` (fail-closed) --
they never silently fall back to plaintext.

**Per-handle override (escape hatch).** Pass `encryption` in the handle options
to force the decision and skip the Description read -- `{ scheme: 'edv' }` (keys
from the keystore), `{ scheme: 'edv', keys }` (keys inline), or `'plaintext'`:

```ts
const vault = was.space(spaceId).collection('vault', {
  encryption: { scheme: 'edv' }
})
```

**Migrating a pre-marker vault** (created before the marker existed, keys-only):
re-declare it once with
`collection.configure({ encryption: { scheme: 'edv' } })` (the marker is
set-once: declaring it on a collection that lacks one is allowed, changing or
clearing an existing one is rejected). Until then, a per-handle override reads
it correctly.

Encrypted collections are a **stricter contract**, not a drop-in (documents-only
scope for now):

- **Ids.** `add()` mints an EDV id (a `z`-prefixed multibase value used verbatim
  as the WAS resource id). `put(id, ...)` accepts only an EDV-format id; a
  human-readable id is rejected (it would leak onto the URL) -- carry a
  human-readable label inside the encrypted content instead.
- **Metadata.** `resource.setName()` / `setTags()` throw on an encrypted
  collection (they write server-visible plaintext); store those values inside
  the encrypted content.
- **Binary.** A small `Blob`/`Uint8Array` is encrypted as a single document;
  larger binaries are rejected until chunked encrypted blobs land.
- **Raw reads.** `get()` decrypts; the `getText()` / `getBytes()` escape hatches
  do not (they return the stored representation).

### Export and import

```ts
const archive = await space.export() // Uint8Array (application/x-tar)
const stats = await otherSpace.import(archive)
// { collectionsCreated, collectionsSkipped, resourcesCreated, resourcesSkipped,
//   policiesCreated, policiesSkipped }
```

### The manual-request escape hatch

`was.request(...)` mirrors ezcap's generic `request()` for hand-built calls. As
a deliberate escape hatch it returns the raw `HttpResponse` and throws raw
ezcap/ky errors -- it does not apply the null-on-404 or typed-error
conveniences.

```ts
const response = await was.request({ path: `/space/${spaceId}`, method: 'GET' })
```

## Errors and the 404/null caveat

Read methods (`describe`/`get`/`list`) return `null` on a 404, following
MongoDB's `findOne` semantics. **WAS returns 404 for both not-found and
unauthorized**, so `null` means "not visible to you" rather than strictly "does
not exist". Write/delete methods throw a typed error instead.

| Status | Read methods           | Write / delete methods |
| ------ | ---------------------- | ---------------------- |
| 404    | `null`                 | `NotFoundError`        |
| 400    | `ValidationError`      | `ValidationError`      |
| 401    | `AuthRequiredError`    | `AuthRequiredError`    |
| 409    | `ConflictError`        | `ConflictError`        |
| 413    | `PayloadTooLargeError` | `PayloadTooLargeError` |
| 501    | `NotImplementedError`  | `NotImplementedError`  |
| 507    | `QuotaExceededError`   | `QuotaExceededError`   |
| 5xx    | `WasServerError`       | `WasServerError`       |

All error classes extend `WasError` (carrying `status`, the problem-kind `type`
URI, `title`, `details`, and `requestUrl`). When the server sends a
`problem+json` `type` (the spec's Error Type Registry), `mapError()` dispatches
on that kind first and falls back to the HTTP status -- so, for example, a 409
`id-conflict` from `createSpace({ id })` is catchable as a `ConflictError`, and
a 507 `quota-exceeded` (a client-actionable storage-full condition, not a server
fault) as a `QuotaExceededError`. `delete()` additionally treats a 404 as
success, so it is idempotent.

Spec endpoints a given server has not yet implemented surface as
`NotImplementedError` (the server's 501).

## Contribute

PRs accepted. See [CONTRIBUTING.md](CONTRIBUTING.md) for editor setup (Prettier,
ESLint, and EditorConfig) and how it maps to CI.

## License

[MIT License](LICENSE.md) © 2026 Interop Alliance.
