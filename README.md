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
  - [Storage introspection: backends and quotas](#storage-introspection-backends-and-quotas)
  - [Export and import](#export-and-import)
  - [Encrypted collections (EDV-over-WAS)](#encrypted-collections-edv-over-was)
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

### Export and import

```ts
const archive = await space.export() // Uint8Array (application/x-tar)
const stats = await otherSpace.import(archive)
// { collectionsCreated, collectionsSkipped, resourcesCreated, resourcesSkipped,
//   policiesCreated, policiesSkipped }
```

### Encrypted collections (EDV-over-WAS)

Client-side end-to-end encryption, where the server stores only opaque
ciphertext and the keys never leave the client. This is the "EDV-over-WAS"
layout profile (Layer 1): it maps
[Encrypted Data Vault](https://digitalbazaar.github.io/encrypted-data-vaults/)
documents onto ordinary WAS resources, so it works against **any** WAS server
with no server changes. It is shipped on the opt-in `@interop/was-client/edv`
subpath so plaintext consumers do not pull the crypto dependencies.

`WasTransport` is an `@interop/edv-client` `Transport`: pair it with
`EdvClientCore`, which does all encryption, decryption, and key handling
client-side. The WAS Collection is the vault; each encrypted document is one WAS
resource (its EDV id is used verbatim as the resource id).

This example assumes a WAS server is already running and you have created (or
have access to) a collection to use as the vault:

```ts
import { WasClient } from '@interop/was-client'
import { WasTransport } from '@interop/was-client/edv'
import { EdvClientCore } from '@interop/edv-client'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'

const was = WasClient.fromSigner({ serverUrl, signer })
const space = await was.createSpace({ name: 'My Wallet' })
const collection = await space.createCollection({ id: 'vault', name: 'Vault' })

// Client-side key material (never sent to the server). In a real app these come
// from the wallet's key store; here we generate a key-agreement key.
const kak = await X25519KeyAgreementKey2020.generate({
  controller: was.controllerDid
})
const keyResolver = async ({ id }: { id: string }) => {
  if (id !== kak.id) throw new Error(`Unknown key id "${id}".`)
  return {
    id: kak.id,
    type: kak.type,
    publicKeyMultibase: kak.publicKeyMultibase
  }
}

const edv = new EdvClientCore({ keyAgreementKey: kak, keyResolver })
const transport = new WasTransport({
  was,
  spaceId: space.id,
  collectionId: collection.id
})

// Encrypt + write: the server stores a JWE envelope, not the cleartext.
const doc = await edv.insert({ doc: { content: { secret: 42 } }, transport })

// Read + decrypt:
const decrypted = await edv.get({ id: doc.id, transport })
console.log(decrypted.content) // { secret: 42 }
```

Scope and caveats (this is the first, documents-only increment):

- **Documents only.** `insert` / `update` / `get` are supported. Blinded `find`
  / `count` / index updates and chunked blob streams throw -- they need
  server-side EDV affordances (a blinded `/query` endpoint, the
  `/{id}/chunks/{n}` sub-segment) a plaintext WAS server does not provide.
- **Advisory `sequence`.** Without server-side conditional writes, a stale
  `update` is not rejected (last-writer-wins). Safe for single-writer use.
- **Content type.** Envelopes are stored as `application/json` by default so any
  WAS server accepts them. The preferred marker `application/edv+json` (exported
  as `EDV_CONTENT_TYPE`) needs the server to register an `application/*+json`
  content-type parser -- the reference was-teaching-server does; pass
  `contentType: EDV_CONTENT_TYPE` to opt in.

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
