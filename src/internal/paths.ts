/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * URL path builders for the WAS server, encoding the trailing-slash
 * canonicalization once. The convention: a trailing slash marks a container in
 * canonical form (`/spaces/`, `/space/{s}/`, `/space/{s}/{c}/`), everything
 * else has none, and no two paths differ only by a trailing slash. Path
 * segments are percent-encoded so ids never break out of their slot.
 *
 * A container's own description is not at its URL: it lives at the reserved
 * `meta` segment (`spaceMeta`, `collectionMeta`), beside the Resource-level
 * `resourceMeta`. The bare (slash-less) form of a container URL only
 * 308-redirects, and a signed invocation covers the target it was signed for,
 * so no builder here emits the bare form -- a redirect would have to be signed
 * again.
 *
 * The parser is deliberately laxer than the builders. `parseSpacePath` accepts
 * the bare form too, because the targets it classifies are not this client's
 * own URLs: they are the `invocationTarget` strings of delegated capabilities
 * a third party minted, and those name containers in either form. Reading one
 * as the Space or Collection it addresses is what `WasClient.fromCapability`
 * and the revocation route's `spaceIdOf` do; refusing the bare form there would
 * reject valid capabilities over a spelling this client does not control.
 *
 * The zcap `invocationTarget` is derived from the request URL, so these
 * trailing-slash rules must match the server's per-operation `allowedTarget`
 * exactly or signature verification fails.
 *
 * This module also owns the inverse grammar: `parseSpacePath` classifies a
 * server pathname back into the handle depth it addresses (space / collection /
 * resource / sub-resource), so `WasClient.fromCapability` and the builders stay
 * in lockstep.
 */
import { ValidationError } from '../errors.js'
import {
  assertNotReserved,
  isReservedCollectionId,
  isReservedResourceId
} from './reserved.js'

/**
 * Rejects an id that would escape its path slot even after percent-encoding:
 * `encodeURIComponent` leaves `.` and `..` intact, and WHATWG URL resolution
 * collapses dot segments -- so `resource('.').delete()` would target the
 * collection items endpoint and `'..'` the parent space. An empty id likewise
 * collapses into the parent's trailing-slash endpoint. One guard here covers
 * every builder.
 *
 * @param segment {string}   the proposed id
 * @returns {void}
 */
function assertValidId(segment: string): void {
  if (segment === '' || segment === '.' || segment === '..') {
    throw new ValidationError(
      `Invalid id ${JSON.stringify(segment)}: an empty or dot-segment id ` +
        'would resolve to a different endpoint than its own.'
    )
  }
}

function encode(segment: string): string {
  assertValidId(segment)
  return encodeURIComponent(segment)
}

/**
 * Encodes a collection-id slot, additionally rejecting an id from the Reserved
 * Path Segment Registry: `collectionPath(s, 'policy')` is byte-identical to
 * the space policy path, so a reserved id would silently mis-target a
 * space-level endpoint. Guarding in the builders covers every URL-forming
 * entry point (handle constructors guard too, for the earlier failure).
 *
 * @param collectionId {string}
 * @returns {string}
 */
function encodeCollectionId(collectionId: string): string {
  assertNotReserved({ id: collectionId, kind: 'collection' })
  return encode(collectionId)
}

/**
 * Encodes a resource-id slot, additionally rejecting an id from the Reserved
 * Path Segment Registry: `resourcePath(s, c, 'policy')` is byte-identical to
 * the collection policy path, so a reserved id would silently mis-target a
 * collection-level endpoint.
 *
 * @param resourceId {string}
 * @returns {string}
 */
function encodeResourceId(resourceId: string): string {
  assertNotReserved({ id: resourceId, kind: 'resource' })
  return encode(resourceId)
}

/**
 * `/spaces/` -- the SpacesRepository (create / list spaces).
 */
export function spacesRoot(): string {
  return '/spaces/'
}

/**
 * `/space/:spaceId` -- the slash-less prefix the space-level sub-endpoints hang
 * off. Module-private: the bare form is not a path this client ever requests
 * (the server only 308-redirects it), so it is a prefix here and never a
 * builder's return value. It is still a form the parser below reads, since a
 * third party's capability target may be written that way.
 *
 * @param spaceId {string}
 * @returns {string}
 */
function spacePrefix(spaceId: string): string {
  return `/space/${encode(spaceId)}`
}

/**
 * `/space/:spaceId/` -- the Space container in canonical form: the target a
 * Space root capability names, the URL whose `GET` lists the Space's
 * Collections, whose `POST` creates one, and whose `DELETE` removes the Space.
 * The Space is an ordinary container, so its members are listed and created at
 * the container itself -- there is no second builder for that.
 *
 * @param spaceId {string}
 * @returns {string}
 */
export function spacePath(spaceId: string): string {
  return `${spacePrefix(spaceId)}/`
}

/**
 * `/space/:spaceId/meta` -- the Space Metadata object: the Space's description
 * (`name`, `controller`, `type`), read with `GET` and replaced with `PUT`.
 *
 * @param spaceId {string}
 * @returns {string}
 */
export function spaceMeta(spaceId: string): string {
  return `${spacePrefix(spaceId)}/meta`
}

/**
 * `/space/:spaceId/export` -- export a space as a tar archive.
 */
export function spaceExport(spaceId: string): string {
  return `${spacePrefix(spaceId)}/export`
}

/**
 * `/space/:spaceId/import` -- import a tar archive into a space.
 */
export function spaceImport(spaceId: string): string {
  return `${spacePrefix(spaceId)}/import`
}

/**
 * `/space/:spaceId/backends` -- the backends available within a space (list, and
 * register a new `external` backend).
 */
export function spaceBackends(spaceId: string): string {
  return `${spacePrefix(spaceId)}/backends`
}

/**
 * `/space/:spaceId/backends/:backendId` -- a single registered `external`
 * backend (replace / deregister by id).
 */
export function registeredBackend(spaceId: string, backendId: string): string {
  return `${spaceBackends(spaceId)}/${encode(backendId)}`
}

/**
 * `/space/:spaceId/quotas` -- the space-level storage quota report.
 */
export function spaceQuotas(spaceId: string): string {
  return `${spacePrefix(spaceId)}/quotas`
}

/**
 * `/space/:spaceId/policy` -- the space-level access-control policy resource.
 */
export function spacePolicy(spaceId: string): string {
  return `${spacePrefix(spaceId)}/policy`
}

/**
 * `/space/:spaceId/linkset` -- the space-level linkset (policy discovery).
 */
export function spaceLinkset(spaceId: string): string {
  return `${spacePrefix(spaceId)}/linkset`
}

/**
 * `/space/:spaceId/zcaps/revocations/:capabilityId` -- submit a revocation of a
 * Space-rooted capability. The capability's `id` (typically a `urn:uuid:`) is
 * percent-encoded into the single final segment.
 *
 * `zcaps` is not a reserved path segment: the route sits four segments deep,
 * deeper than any Collection or Resource route, so it shadows nothing.
 */
export function spaceRevocation(spaceId: string, capabilityId: string): string {
  return `${spacePrefix(spaceId)}/zcaps/revocations/${encode(capabilityId)}`
}

/**
 * `/space/:spaceId/:collectionId` -- the slash-less prefix the collection-level
 * sub-endpoints and the Resource ids hang off. Module-private, like
 * {@link spacePrefix}.
 *
 * @param spaceId {string}
 * @param collectionId {string}
 * @returns {string}
 */
function collectionPrefix(spaceId: string, collectionId: string): string {
  return `${spacePrefix(spaceId)}/${encodeCollectionId(collectionId)}`
}

/**
 * `/space/:spaceId/:collectionId/` -- the Collection container in canonical
 * form: the target a "share this collection" capability names, the URL whose
 * `GET` lists its Resources, whose `POST` adds one, and whose `DELETE` removes
 * the Collection.
 *
 * @param spaceId {string}
 * @param collectionId {string}
 * @returns {string}
 */
export function collectionPath(spaceId: string, collectionId: string): string {
  return `${collectionPrefix(spaceId, collectionId)}/`
}

/**
 * `/space/:spaceId/:collectionId/policy` -- the collection-level access-control
 * policy resource.
 */
export function collectionPolicy(
  spaceId: string,
  collectionId: string
): string {
  return `${collectionPrefix(spaceId, collectionId)}/policy`
}

/**
 * `/space/:spaceId/:collectionId/linkset` -- the collection-level linkset
 * (policy discovery).
 */
export function collectionLinkset(
  spaceId: string,
  collectionId: string
): string {
  return `${collectionPrefix(spaceId, collectionId)}/linkset`
}

/**
 * `/space/:spaceId/:collectionId/backend` -- the "Collection Backend Selected"
 * descriptor (the backend this collection is stored on).
 */
export function collectionBackend(
  spaceId: string,
  collectionId: string
): string {
  return `${collectionPrefix(spaceId, collectionId)}/backend`
}

/**
 * `/space/:spaceId/:collectionId/quota` -- the per-collection storage quota
 * report (spec "Quotas").
 */
export function collectionQuota(spaceId: string, collectionId: string): string {
  return `${collectionPrefix(spaceId, collectionId)}/quota`
}

/**
 * `/space/:spaceId/:collectionId/meta` -- the Collection Metadata object: the
 * Collection's configuration (`name`, `backend`, `encryption`, `generator`)
 * together with the server-managed timestamps / `createdBy` and the
 * user-writable `custom` and `epoch`, as one object under one validator.
 */
export function collectionMeta(spaceId: string, collectionId: string): string {
  return `${collectionPrefix(spaceId, collectionId)}/meta`
}

/**
 * `/space/:spaceId/:collectionId/meta/log` -- the Collection's governing
 * history log sub-resource (JSON Lines). Not a Resource of the Collection:
 * absent from listings and the `changes` feed, and versioned by its own ETag.
 */
export function collectionLog(spaceId: string, collectionId: string): string {
  return `${collectionMeta(spaceId, collectionId)}/log`
}

/**
 * `/space/:spaceId/:collectionId/query` -- the collection-level query endpoint,
 * whose body's `profile` selects the query (e.g. `changes`, `blinded-index`).
 */
export function collectionQuery(spaceId: string, collectionId: string): string {
  return `${collectionPrefix(spaceId, collectionId)}/query`
}

/**
 * `/space/:spaceId/:collectionId/:resourceId` -- get / put / delete a resource
 * (no trailing slash).
 */
export function resourcePath(
  spaceId: string,
  collectionId: string,
  resourceId: string
): string {
  return `${collectionPrefix(spaceId, collectionId)}/${encodeResourceId(resourceId)}`
}

/**
 * `/space/:spaceId/:collectionId/:resourceId/meta` -- the resource metadata
 * object (server-managed properties plus the user-writable `custom` object).
 */
export function resourceMeta(
  spaceId: string,
  collectionId: string,
  resourceId: string
): string {
  return `${resourcePath(spaceId, collectionId, resourceId)}/meta`
}

/**
 * `/space/:spaceId/:collectionId/:resourceId/policy` -- the resource-level
 * access-control policy resource.
 */
export function resourcePolicy(
  spaceId: string,
  collectionId: string,
  resourceId: string
): string {
  return `${resourcePath(spaceId, collectionId, resourceId)}/policy`
}

/**
 * `/space/:spaceId/:collectionId/:resourceId/chunks/:chunkIndex` -- a single
 * stored chunk of a chunked Resource (the `chunked-streams` feature). Member
 * form, no trailing slash: get / put / delete one chunk by its ordinal index.
 * The `chunkIndex` is a non-negative integer, emitted verbatim (it is never a
 * reserved or dot segment, so it needs no percent-encoding).
 *
 * @param spaceId {string}
 * @param collectionId {string}
 * @param resourceId {string}
 * @param chunkIndex {number}
 * @returns {string}
 */
export function resourceChunkPath(
  spaceId: string,
  collectionId: string,
  resourceId: string,
  chunkIndex: number
): string {
  return `${resourcePath(spaceId, collectionId, resourceId)}/chunks/${chunkIndex}`
}

/**
 * Resolves a path against the server base URL, producing an absolute URL
 * string suitable for zcap `invocationTarget`s.
 *
 * The path is joined onto `serverUrl`'s base path rather than its origin, so a
 * WAS deployment mounted under a sub-path (e.g. `https://host/was/`) keeps that
 * prefix. A bare-origin `serverUrl` behaves as before.
 *
 * @param options {object}
 * @param options.serverUrl {string}   the server base URL
 * @param options.path {string}        a leading-slash path (e.g. `/space/x`)
 * @returns {string}
 */
export function toUrl({
  serverUrl,
  path
}: {
  serverUrl: string
  path: string
}): string {
  // A leading-slash `path` is origin-absolute to `new URL`, which would drop
  // any base-path prefix on `serverUrl`. Ensure the base ends in a slash and
  // make the path relative so the prefix is preserved.
  const base = serverUrl.endsWith('/') ? serverUrl : `${serverUrl}/`
  const relative = path.startsWith('/') ? path.slice(1) : path
  return new URL(relative, base).toString()
}

/**
 * Canonicalizes an absolute collection URL to its items/listing endpoint --
 * the trailing-slash form (`/space/:id/:collectionId/`). This module owns the
 * trailing-slash rules, so callers that receive a collection URL from outside
 * (e.g. a public link) normalize it here rather than re-encoding the rule.
 *
 * @param collectionUrl {string}   an absolute collection URL
 * @returns {string}
 */
export function collectionItemsUrl(collectionUrl: string): string {
  return collectionUrl.endsWith('/') ? collectionUrl : `${collectionUrl}/`
}

/**
 * The classification of a WAS pathname by the depth it addresses. The three
 * containment kinds map onto navigational handles; `sub-resource` covers every
 * reserved sub-endpoint the builders above produce (`/space/:id/policy`,
 * `/space/:id/:c/backend`, `/space/:id/:c/:r/meta`, ...), which has no handle of
 * its own.
 */
export type ParsedSpacePath =
  | { kind: 'space'; spaceId: string }
  | { kind: 'collection'; spaceId: string; collectionId: string }
  | {
      kind: 'resource'
      spaceId: string
      collectionId: string
      resourceId: string
    }
  | { kind: 'sub-resource'; spaceId: string; segments: string[] }

/**
 * Classifies an absolute `target` URL that is expected to live on this server,
 * relative to `serverUrl`'s base path -- so a WAS mounted under a sub-path (e.g.
 * `https://host/was/`) resolves just as a bare-origin deployment does, which
 * `parseSpacePath` alone cannot do (it would see a leading `was` segment).
 *
 * Returns `null` when `target` is not beneath `serverUrl` (another origin, or
 * another base path) or addresses something outside the `/space` tree (e.g.
 * `/kms`). The caller chooses whether that is an error.
 *
 * @param options {object}
 * @param options.serverUrl {string}   the client's server base URL
 * @param options.target {string}      an absolute URL on that server
 * @returns {ParsedSpacePath | null}
 */
export function parseSpaceTarget({
  serverUrl,
  target
}: {
  serverUrl: string
  target: string
}): ParsedSpacePath | null {
  const base = serverUrl.endsWith('/') ? serverUrl : `${serverUrl}/`
  if (!target.startsWith(base)) {
    return null
  }
  let pathname: string
  try {
    ;({ pathname } = new URL(target))
  } catch {
    return null
  }
  const basePathname = new URL(base).pathname
  return parseSpacePath(`/${pathname.slice(basePathname.length)}`)
}

/**
 * Parses a server pathname back into the containment depth it addresses -- the
 * inverse of the builders above, kept next to them so the grammar is owned in
 * one place. Segments are percent-decoded (the builders re-encode them).
 * Returns `null` for a pathname outside the `/space/...` tree; the caller
 * chooses the error. A path that addresses a reserved sub-endpoint rather than
 * a space/collection/resource -- e.g. `/space/s/policy`, `/space/s/c/backend`,
 * or any 5-segment target like `/space/s/c/r/meta` -- is classified
 * `sub-resource`, never silently truncated to the nearest handle.
 *
 * Empty segments are dropped, so a container addressed in either form
 * classifies the same: `/space/s` and `/space/s/` are both the Space, and
 * `/space/s/c` and `/space/s/c/` both the Collection. That is deliberate. The
 * builders emit only the canonical trailing-slash form, but the targets parsed
 * here come from capabilities minted elsewhere, and a client that reads only
 * one spelling would refuse valid ones.
 *
 * @param pathname {string}   a URL pathname (e.g. from `new URL(...).pathname`)
 * @returns {ParsedSpacePath | null}
 */
export function parseSpacePath(pathname: string): ParsedSpacePath | null {
  let segments: string[]
  try {
    segments = pathname.split('/').filter(Boolean).map(decodeURIComponent)
  } catch {
    // A malformed percent-escape (e.g. `%ff`) makes `decodeURIComponent` throw
    // a `URIError`: the path is not a well-formed WAS target, so classify it as
    // unparseable (the caller converts `null` to its own typed error).
    return null
  }
  if (segments[0] !== 'space' || segments[1] === undefined) {
    return null
  }
  const [, spaceId, ...rest] = segments as [string, string, ...string[]]
  if (rest.length === 0) {
    return { kind: 'space', spaceId }
  }
  // A reserved segment directly under the space (`policy`, `backends`,
  // `export`, ...) addresses a space-level sub-endpoint, as does anything
  // nested beneath one (`/space/s/backends/:backendId`).
  if (isReservedCollectionId(rest[0] as string)) {
    return { kind: 'sub-resource', spaceId, segments: rest }
  }
  if (rest.length === 1) {
    return { kind: 'collection', spaceId, collectionId: rest[0] as string }
  }
  // A reserved segment under the collection (`policy`, `backend`, `quota`,
  // ...) addresses a collection-level sub-endpoint.
  if (isReservedResourceId(rest[1] as string)) {
    return { kind: 'sub-resource', spaceId, segments: rest }
  }
  if (rest.length === 2) {
    return {
      kind: 'resource',
      spaceId,
      collectionId: rest[0] as string,
      resourceId: rest[1] as string
    }
  }
  // Anything deeper (`/space/s/c/r/meta`, `/space/s/c/r/policy`, chunk
  // sub-segments, ...) is a resource-level sub-endpoint.
  return { kind: 'sub-resource', spaceId, segments: rest }
}
