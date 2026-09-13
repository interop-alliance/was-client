/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Service discovery: finds the server's service description by following the
 * `Link: <...>; rel="service"` header its responses carry, reads the document
 * without a capability invocation, and selects the WAS specification version
 * this client speaks. The spec reserves no path for the document, so nothing
 * here assumes one. The client speaks only v0.5, so a server whose responses
 * carry no `service` link (one that predates v0.5) is refused rather than
 * spoken to in the v0.4 layout.
 */
import type {
  PwsVersionEntry,
  ServiceDescription,
  ServiceDescriptionVersionEntry
} from '@interop/storage-core'
import { IncompatibleServerError, mapError } from '../errors.js'
import { fetchMapped } from './request.js'
import type { ServiceInfo } from '../types.js'

/**
 * The WAS specification's identifier, the `specs` key its version entries sit
 * under. Provisional until the spec's rename registers it.
 */
export const PWS_SPEC_ID = 'https://w3id.org/pws'

/**
 * The WAS specification versions this client speaks, newest first. Selection
 * takes the first one the server lists.
 */
export const SUPPORTED_PWS_VERSIONS = ['0.5']

/**
 * The link relation that names the service description.
 */
const SERVICE_RELATION = 'service'

/**
 * Splits a `Link` header value into its link-values: on commas outside a
 * `<...>` target and outside a quoted parameter value.
 *
 * @param header {string}
 * @returns {string[]}
 */
function splitLinkValues(header: string): string[] {
  const values: string[] = []
  let current = ''
  let inTarget = false
  let inQuotes = false
  for (let index = 0; index < header.length; index++) {
    const char = header[index] as string
    if (inQuotes) {
      current += char
      if (char === '\\' && index + 1 < header.length) {
        current += header[++index]
      } else if (char === '"') {
        inQuotes = false
      }
      continue
    }
    if (char === '<') {
      inTarget = true
    } else if (char === '>') {
      inTarget = false
    } else if (char === '"' && !inTarget) {
      inQuotes = true
    } else if (char === ',' && !inTarget) {
      values.push(current)
      current = ''
      continue
    }
    current += char
  }
  values.push(current)
  return values
}

/**
 * Reads the target of the first `service` link in a `Link` header (RFC 8288),
 * resolved against the URL of the response that carried it. Relation types
 * compare case-insensitively, a `rel` may list several space-separated types,
 * and only the first `rel` parameter of a link-value counts.
 *
 * @param options {object}
 * @param options.header {string | null}   the `Link` header value
 * @param options.baseUrl {string}   the URL the response came from
 * @returns {string | undefined}   the absolute service description URL
 */
export function serviceLinkTarget({
  header,
  baseUrl
}: {
  header: string | null
  baseUrl: string
}): string | undefined {
  if (header === null) {
    return undefined
  }
  for (const linkValue of splitLinkValues(header)) {
    const match = /^\s*<([^>]*)>(.*)$/s.exec(linkValue)
    if (match === null) {
      continue
    }
    const [, target, rest] = match as unknown as [string, string, string]
    const relParam = rest
      .split(';')
      .map(param =>
        /^\s*rel\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s;]*))/i.exec(param)
      )
      .find(paramMatch => paramMatch !== null)
    const relValue = relParam?.[1] ?? relParam?.[2] ?? ''
    const relations = relValue.toLowerCase().split(/\s+/)
    if (relations.includes(SERVICE_RELATION)) {
      try {
        return new URL(target, baseUrl).toString()
      } catch {
        continue
      }
    }
  }
  return undefined
}

/**
 * Whether a value is a JSON object (not `null`, not an array).
 *
 * @param value {unknown}
 * @returns {boolean}
 */
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Whether a value parses as an absolute URL.
 *
 * @param value {string}
 * @returns {boolean}
 */
function isAbsoluteUrl(value: string): boolean {
  try {
    new URL(value)
    return true
  } catch {
    return false
  }
}

/**
 * Applies the spec's version-selection rules to a service description: a
 * `specs` key other than the WAS identifier is ignored, a version entry
 * without a string `version` is ignored, and the newest version this client
 * speaks is chosen. The members the client acts on are checked before they are
 * used: `spaces` must be an absolute URL and `features` an array of strings.
 *
 * @param description {unknown}   the parsed service description
 * @returns {ServiceInfo}
 * @throws {IncompatibleServerError}   when the document lacks `url` or `specs`,
 *   when no entry names a version this client speaks, or when the chosen
 *   entry's `spaces` or `features` is malformed
 */
export function selectServiceVersion(description: unknown): ServiceInfo {
  if (
    !isObject(description) ||
    typeof description.url !== 'string' ||
    !isObject(description.specs)
  ) {
    throw new IncompatibleServerError(
      'The service description is not a JSON object with `url` and `specs`.'
    )
  }
  const candidates = description.specs[PWS_SPEC_ID]
  const entries = (Array.isArray(candidates) ? candidates : []).filter(
    (entry): entry is ServiceDescriptionVersionEntry =>
      isObject(entry) && typeof entry.version === 'string'
  )
  let chosen: PwsVersionEntry | undefined
  for (const version of SUPPORTED_PWS_VERSIONS) {
    chosen = entries.find(entry => entry.version === version)
    if (chosen !== undefined) {
      break
    }
  }
  if (chosen === undefined) {
    const offered = entries.map(entry => entry.version)
    throw new IncompatibleServerError(
      `The server at "${description.url}" lists no version of ` +
        `${PWS_SPEC_ID} this client speaks (offered: ` +
        `${offered.length === 0 ? 'none' : offered.join(', ')}; supported: ` +
        `${SUPPORTED_PWS_VERSIONS.join(', ')}).`
    )
  }
  const { spaces, features } = chosen as {
    spaces?: unknown
    features?: unknown
  }
  if (
    spaces !== undefined &&
    (typeof spaces !== 'string' || !isAbsoluteUrl(spaces))
  ) {
    throw new IncompatibleServerError(
      `The ${PWS_SPEC_ID} ${chosen.version} entry's \`spaces\` is not an ` +
        'absolute URL.'
    )
  }
  if (
    features !== undefined &&
    (!Array.isArray(features) ||
      !features.every(token => typeof token === 'string'))
  ) {
    throw new IncompatibleServerError(
      `The ${PWS_SPEC_ID} ${chosen.version} entry's \`features\` is not an ` +
        'array of strings.'
    )
  }
  const tokens = [...((features as string[] | undefined) ?? [])]
  return {
    description: description as unknown as ServiceDescription,
    version: chosen.version,
    entry: chosen,
    ...(spaces !== undefined && { spacesUrl: spaces }),
    features: tokens,
    hasFeature(token: string): boolean {
      return tokens.includes(token)
    }
  }
}

/**
 * The statuses that signal a transient failure (rate limiting, or a gateway
 * or server that is temporarily unavailable) rather than an answer about the
 * server's protocol. A lasting refusal such as 501, 505, or 507 is not in
 * this set.
 */
const TRANSIENT_STATUSES = new Set([429, 502, 503, 504])

/**
 * Rejects a discovery step that answered `status` without what discovery
 * needs: with the mapped transport error when the status is transient, since
 * it says nothing about the protocol the server speaks, and with an
 * `IncompatibleServerError` carrying `message` otherwise.
 *
 * @param options {object}
 * @param options.status {number}
 * @param options.requestUrl {string}
 * @param options.message {string}
 * @returns {never}
 */
function refuse({
  status,
  requestUrl,
  message
}: {
  status: number
  requestUrl: string
  message: string
}): never {
  if (TRANSIENT_STATUSES.has(status)) {
    throw mapError({ status, requestUrl })
  }
  throw new IncompatibleServerError(message, { requestUrl })
}

/**
 * Discovers the service description from a URL the client holds and selects
 * the version to speak: an unsigned `HEAD` of `url` for its `service` link
 * (the response status does not matter), then an unsigned `GET` of the linked
 * document.
 *
 * A network failure, and a rate limit or temporary outage (429, 502, 503,
 * 504) that comes without the link, reject with the mapped transport error,
 * since they say nothing about the protocol the server speaks.
 *
 * @param options {object}
 * @param options.url {string}   any WAS URL, typically the client's `serverUrl`
 * @returns {Promise<ServiceInfo>}
 * @throws {IncompatibleServerError}   when the response carries no `service`
 *   link, the linked document cannot be read or parsed, or version selection
 *   refuses it (see {@link selectServiceVersion})
 */
export async function discoverService({
  url
}: {
  url: string
}): Promise<ServiceInfo> {
  const probe = await fetchMapped(url, { method: 'HEAD' })
  const serviceUrl = serviceLinkTarget({
    header: probe.headers.get('link'),
    baseUrl: probe.url || url
  })
  if (serviceUrl === undefined) {
    refuse({
      status: probe.status,
      requestUrl: url,
      message:
        `The response from "${url}" (${probe.status}) carries no ` +
        'rel="service" link, so the server predates WAS v0.5, which this ' +
        'client requires.'
    })
  }
  const response = await fetchMapped(serviceUrl, {
    method: 'GET',
    headers: { accept: 'application/json' }
  })
  if (!response.ok) {
    refuse({
      status: response.status,
      requestUrl: serviceUrl,
      message:
        `The service description at "${serviceUrl}" answered ` +
        `${response.status}.`
    })
  }
  let description: unknown
  try {
    description = await response.json()
  } catch (err) {
    throw new IncompatibleServerError(
      `The service description at "${serviceUrl}" is not valid JSON.`,
      { requestUrl: serviceUrl, cause: err }
    )
  }
  return selectServiceVersion(description)
}
