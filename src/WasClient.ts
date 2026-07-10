/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The top-level WAS client. Wraps an ezcap `ZcapClient` (which holds the active
 * signer) and exposes the WAS containment model
 * (`SpacesRepository > Space > Collection > Resource`) through lazy
 * navigational handles. Also hosts the general delegation primitive
 * (`grant`), capability-rebuilding (`fromCapability`), and the signed
 * escape-hatch (`request`).
 */
import { ZcapClient } from '@interop/ezcap'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import type { HttpResponse } from '@interop/http-client'
import {
  collectionItemsUrl,
  parseSpacePath,
  spacesRoot
} from './internal/paths.js'
import type { ClientContext } from './internal/request.js'
import { send, rawRequest, unsignedRequest } from './internal/request.js'
import {
  createdId,
  dataOrNull,
  parseResource,
  readJsonData
} from './internal/content.js'
import {
  buildPageWalk,
  collectPages,
  walkPages
} from './internal/pagination.js'
import type { PageWalk } from './internal/pagination.js'
import { delegateGrant } from './internal/grant.js'
import { spaceIdOf, submitRevocation } from './internal/revoke.js'
import { ValidationError } from './errors.js'
import type { EncryptionProvider } from './codec.js'
import { Space } from './Space.js'
import { Collection } from './Collection.js'
import { Resource } from './Resource.js'
import type {
  GrantOptions,
  HandleOptions,
  IDelegatedZcap,
  ISigner,
  IZcap,
  Json,
  RequestInput,
  CollectionResourcesList,
  ResourceSummary,
  SpaceListing
} from './types.js'

export class WasClient {
  readonly serverUrl: string
  readonly zcapClient: ZcapClient
  readonly encryption?: EncryptionProvider

  /**
   * @param options {object}
   * @param options.serverUrl {string}    base URL for both URL building and
   *   zcap `invocationTarget`s
   * @param options.zcapClient {ZcapClient}   an ezcap client holding the signer
   * @param [options.encryption] {EncryptionProvider}   the keystore that
   *   supplies keys for collections declared encrypted (by their `encryption`
   *   marker or a per-handle override); built by the `@interop/was-client/edv`
   *   subpath. Omit for plaintext-only clients. It does not decide *which*
   *   collections are encrypted -- that is the marker/override -- so a missing
   *   key for an encrypted collection fails closed rather than silently
   *   downgrading to plaintext.
   */
  constructor({
    serverUrl,
    zcapClient,
    encryption
  }: {
    serverUrl: string
    zcapClient: ZcapClient
    encryption?: EncryptionProvider
  }) {
    this.serverUrl = serverUrl
    this.zcapClient = zcapClient
    this.encryption = encryption
  }

  /**
   * Convenience constructor that builds the ezcap `ZcapClient` internally from
   * a signer, using the `Ed25519Signature2020` suite.
   *
   * @param options {object}
   * @param options.serverUrl {string}
   * @param options.signer {ISigner}
   * @param [options.encryption] {EncryptionProvider}   see the constructor
   * @returns {WasClient}
   */
  static fromSigner({
    serverUrl,
    signer,
    encryption
  }: {
    serverUrl: string
    signer: ISigner
    encryption?: EncryptionProvider
  }): WasClient {
    const zcapClient = new ZcapClient({
      SuiteClass: Ed25519Signature2020,
      invocationSigner: signer,
      delegationSigner: signer
    })
    return new WasClient({ serverUrl, zcapClient, encryption })
  }

  /**
   * The DID controlling the wrapped signer (`signer.id` without the key
   * fragment). Used to default `controller` on `createSpace`.
   *
   * @returns {string}
   */
  get controllerDid(): string {
    const signer = this.zcapClient.invocationSigner
    if (!signer?.id) {
      throw new ValidationError(
        'The wrapped ZcapClient has no invocationSigner id.'
      )
    }
    return signer.id.split('#')[0] as string
  }

  private get _context(): ClientContext {
    return {
      serverUrl: this.serverUrl,
      zcapClient: this.zcapClient,
      controllerDid: this.controllerDid,
      encryption: this.encryption
    }
  }

  /**
   * Returns a lazy handle to a space by id. No I/O.
   *
   * @param spaceId {string}
   * @param options {object}
   * @param [options.capability] {IZcap}
   * @returns {Space}
   */
  space(spaceId: string, options: HandleOptions = {}): Space {
    return new Space({
      context: this._context,
      spaceId,
      capability: options.capability
    })
  }

  /**
   * Creates a space (server-generated id unless `id` is given). `name` is
   * optional (both in the spec and on the reference server); `controller` must
   * match the wrapped signer's DID (which is the default).
   *
   * @param desc {object}
   * @param [desc.id] {string}
   * @param [desc.name] {string}
   * @param [desc.controller] {string}
   * @returns {Promise<Space>}
   */
  async createSpace(
    desc: { id?: string; name?: string; controller?: string } = {}
  ): Promise<Space> {
    const controller = desc.controller ?? this.controllerDid
    const body: Record<string, unknown> = { controller }
    if (desc.id !== undefined) {
      body.id = desc.id
    }
    if (desc.name !== undefined) {
      body.name = desc.name
    }
    const response = await send(this._context, {
      path: spacesRoot(),
      method: 'POST',
      json: body
    })
    return this.space(createdId(response))
  }

  /**
   * Lists the spaces in the repository visible to the wrapped signer, as a
   * `{ url, totalItems, items }` listing. Visibility is per-controller: the
   * result holds only the spaces whose controller the signed invocation is
   * authorized for. An unauthorized caller is not an error -- the server
   * returns an empty `items` list (the spec's explicit exception to 404
   * masking), so nothing is revealed about which spaces exist.
   *
   * @returns {Promise<SpaceListing>}
   */
  async listSpaces(): Promise<SpaceListing> {
    const response = await send(this._context, {
      path: spacesRoot(),
      method: 'GET'
    })
    // A successful list always carries the listing body (an unauthorized
    // caller still gets an empty `items` list, not an error).
    return dataOrNull<SpaceListing>(response)!
  }

  /**
   * Reads a public (`PublicCanRead`) resource by its URL with no authorization
   * -- an unsigned `GET`, for consuming a shared public link. Auto-parses JSON
   * to an object and returns binary as a `Blob`. Returns `null` if the resource
   * is missing or not publicly readable (404 conflation caveat).
   *
   * @param options {object}
   * @param options.resourceUrl {string}   the absolute resource URL
   * @returns {Promise<Json | Blob | null>}
   */
  async publicRead({
    resourceUrl
  }: {
    resourceUrl: string
  }): Promise<Json | Blob | null> {
    const response = await unsignedRequest({
      url: resourceUrl,
      method: 'GET',
      read: true
    })
    return parseResource(response)
  }

  /**
   * Reads the first page of a public (`PublicCanRead`) collection listing with an
   * unsigned `GET` and packages the means to follow its `next` links. Returns
   * `null` if the collection is missing or not publicly readable (404 conflation
   * caveat).
   *
   * @param collectionUrl {string}   the absolute collection URL
   * @returns {Promise<PageWalk | null>}
   */
  private async _publicListWalk(
    collectionUrl: string
  ): Promise<PageWalk | null> {
    return buildPageWalk({
      // The collection listing endpoint is the trailing-slash items URL.
      firstUrl: collectionItemsUrl(collectionUrl),
      fetchPage: async pageUrl => {
        const pageResponse = await unsignedRequest({
          url: pageUrl,
          method: 'GET',
          read: true
        })
        // An unsigned response is a raw `fetch` `Response` (no pre-parsed
        // `data`), so the page body is read via `readJsonData`.
        return pageResponse === null
          ? null
          : ((await readJsonData(pageResponse)) as CollectionResourcesList)
      }
    })
  }

  /**
   * Lists a public (`PublicCanRead`) collection by its URL with no authorization
   * -- an unsigned `GET` -- e.g. to browse a blog published as a public-read
   * collection. Transparently follows the server's `next` pagination links,
   * buffering every page into a single list (the returned envelope omits `next`).
   * For a large collection prefer `publicListCollectionPages()` or
   * `publicListCollectionItems()`, which stream one page at a time and allow
   * stopping early. Returns `null` if the collection is missing or not publicly
   * readable (404 conflation caveat).
   *
   * @param options {object}
   * @param options.collectionUrl {string}   the absolute collection URL
   * @returns {Promise<CollectionResourcesList | null>}
   */
  async publicListCollection({
    collectionUrl
  }: {
    collectionUrl: string
  }): Promise<CollectionResourcesList | null> {
    const walk = await this._publicListWalk(collectionUrl)
    return walk === null ? null : collectPages(walk)
  }

  /**
   * Lazily yields a public collection listing one page at a time, following the
   * server's `next` links on demand with unsigned `GET`s. Use this to stream a
   * large public collection in constant memory or to stop early. Yields nothing
   * if the collection is missing or not publicly readable (404 conflation
   * caveat).
   *
   * @param options {object}
   * @param options.collectionUrl {string}   the absolute collection URL
   * @returns {AsyncGenerator<CollectionResourcesList>}
   */
  async *publicListCollectionPages({
    collectionUrl
  }: {
    collectionUrl: string
  }): AsyncGenerator<CollectionResourcesList> {
    const walk = await this._publicListWalk(collectionUrl)
    if (walk === null) {
      return
    }
    yield* walkPages(walk)
  }

  /**
   * Lazily yields each item of a public collection across every page, flattening
   * `publicListCollectionPages()`. Yields the listing's `ResourceSummary` entries
   * (id / url / contentType / name), not the resource bodies. Yields nothing if
   * the collection is missing or not publicly readable (404 conflation caveat).
   *
   * @param options {object}
   * @param options.collectionUrl {string}   the absolute collection URL
   * @returns {AsyncGenerator<ResourceSummary>}
   */
  async *publicListCollectionItems({
    collectionUrl
  }: {
    collectionUrl: string
  }): AsyncGenerator<ResourceSummary> {
    for await (const page of this.publicListCollectionPages({
      collectionUrl
    })) {
      yield* page.items
    }
  }

  /**
   * Rebuilds an access handle from a received capability, returning a handle at
   * the depth implied by the capability's `invocationTarget` (space /
   * collection / resource), pre-bound with that capability.
   *
   * @param zcap {IZcap}
   * @returns {Space | Collection | Resource}
   */
  fromCapability(zcap: IZcap): Space | Collection | Resource {
    let pathname: string
    try {
      ;({ pathname } = new URL(zcap.invocationTarget))
    } catch (err) {
      throw new ValidationError(
        `invocationTarget "${zcap.invocationTarget}" is not a valid ` +
          'absolute URL.',
        { cause: err }
      )
    }
    // `parseSpacePath` owns the path grammar (and percent-decodes each segment,
    // since the path builders re-encode every id). Classifying the full segment
    // list -- rather than destructuring the first three ids -- keeps a
    // sub-resource target (`/space/s/policy`, `/space/s/c/r/meta`, ...) from
    // being silently truncated to the nearest containment handle, whose derived
    // URLs would mismatch the capability's invocation target.
    const parsed = parseSpacePath(pathname)
    if (parsed === null) {
      throw new ValidationError(
        `Cannot derive a handle from invocationTarget "${zcap.invocationTarget}".`
      )
    }
    if (parsed.kind === 'sub-resource') {
      throw new ValidationError(
        `invocationTarget "${zcap.invocationTarget}" addresses a reserved ` +
          'sub-resource, which has no navigational handle. Invoke it via the ' +
          'owning handle instead (e.g. `space.getPolicy()` / ' +
          '`resource.meta()`), or use the `was.request()` escape hatch.'
      )
    }
    const context = this._context
    if (parsed.kind === 'resource') {
      return new Resource({
        context,
        spaceId: parsed.spaceId,
        collectionId: parsed.collectionId,
        resourceId: parsed.resourceId,
        capability: zcap
      })
    }
    if (parsed.kind === 'collection') {
      return new Collection({
        context,
        spaceId: parsed.spaceId,
        collectionId: parsed.collectionId,
        capability: zcap
      })
    }
    return new Space({ context, spaceId: parsed.spaceId, capability: zcap })
  }

  /**
   * The general delegation primitive. Delegates a capability per `GrantOptions`
   * and returns the signed zcap to hand off out-of-band. `target` (any URL) and
   * `capability` (a parent capability to attenuate) make this a superset of the
   * `space`/`collection` grant sugar.
   *
   * @param options {GrantOptions}
   * @returns {Promise<IDelegatedZcap>}
   */
  async grant(options: GrantOptions): Promise<IDelegatedZcap> {
    return delegateGrant(this._context, options)
  }

  /**
   * The general revocation primitive -- the inverse of {@link grant}. Derives the
   * owning space from the capability's `invocationTarget` (which a Space-rooted
   * capability always addresses at or beneath) and submits it to that space's
   * revocation endpoint. Equivalent to `was.space(id).revoke(zcap)`.
   *
   * Revocation is scoped to one space: there is no cross-space or global
   * revocation. See {@link Space.revoke} for who may call it, what it does and
   * does not withdraw, and why it is not idempotent.
   *
   * @param zcap {IDelegatedZcap}   the delegated capability to revoke
   * @returns {Promise<void>}
   */
  async revoke(zcap: IDelegatedZcap): Promise<void> {
    const context = this._context
    return submitRevocation(context, {
      spaceId: spaceIdOf(context, zcap),
      zcap
    })
  }

  /**
   * The signed escape hatch, mirroring ezcap's generic `request()`. Resolves
   * `path` against `serverUrl`, defaults `action` to `method`, and signs via the
   * wrapped client. Returns the raw `HttpResponse` and throws raw ky/ezcap
   * errors -- it does not apply the null-on-404 or typed-error conveniences.
   *
   * @param options {RequestInput}
   * @returns {Promise<HttpResponse>}
   */
  async request(options: RequestInput): Promise<HttpResponse> {
    return rawRequest(this._context, options)
  }
}
