/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * URL path builders for the WAS server, encoding the trailing-slash
 * canonicalization once. Item-create and listing endpoints use a trailing
 * slash; get/put/delete-by-id endpoints do not. Path segments are
 * percent-encoded so ids never break out of their slot.
 *
 * The zcap `invocationTarget` is derived from the request URL, so these
 * trailing-slash rules must match the server's per-operation `allowedTarget`
 * exactly or signature verification fails.
 */

function encode(segment: string): string {
  return encodeURIComponent(segment)
}

/**
 * `/spaces/` -- the SpacesRepository (create / list spaces).
 */
export function spacesRoot(): string {
  return '/spaces/'
}

/**
 * `/spaces/:spaceId` -- canonical location of a created space (POST response).
 */
export function spaceLocation(spaceId: string): string {
  return `/spaces/${encode(spaceId)}`
}

/**
 * `/space/:spaceId` -- get / update / delete a space (no trailing slash).
 */
export function spacePath(spaceId: string): string {
  return `/space/${encode(spaceId)}`
}

/**
 * `/space/:spaceId/` -- create a collection within a space (trailing slash).
 */
export function spaceItems(spaceId: string): string {
  return `/space/${encode(spaceId)}/`
}

/**
 * `/space/:spaceId/collections/` -- list collections (trailing slash).
 */
export function spaceCollections(spaceId: string): string {
  return `/space/${encode(spaceId)}/collections/`
}

/**
 * `/space/:spaceId/export` -- export a space as a tar archive.
 */
export function spaceExport(spaceId: string): string {
  return `/space/${encode(spaceId)}/export`
}

/**
 * `/space/:spaceId/import` -- import a tar archive into a space.
 */
export function spaceImport(spaceId: string): string {
  return `/space/${encode(spaceId)}/import`
}

/**
 * `/space/:spaceId/:collectionId` -- get / update / delete a collection
 * (no trailing slash).
 */
export function collectionPath(spaceId: string, collectionId: string): string {
  return `/space/${encode(spaceId)}/${encode(collectionId)}`
}

/**
 * `/space/:spaceId/:collectionId/` -- list items / add a resource
 * (trailing slash).
 */
export function collectionItems(spaceId: string, collectionId: string): string {
  return `/space/${encode(spaceId)}/${encode(collectionId)}/`
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
  return `/space/${encode(spaceId)}/${encode(collectionId)}/${encode(resourceId)}`
}

/**
 * Resolves a path against the server base URL, producing an absolute URL
 * string suitable for zcap `invocationTarget`s.
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
  return new URL(path, serverUrl).toString()
}
