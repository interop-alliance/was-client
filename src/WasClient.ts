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
import { spacesRoot } from './internal/paths.js'
import type { ClientContext } from './internal/request.js'
import { send, rawRequest, unsignedRequest } from './internal/request.js'
import { parseResource, readJsonData } from './internal/content.js'
import { delegateGrant } from './internal/grant.js'
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
   * @param [options.encryption] {EncryptionProvider}   supplies the encrypting
   *   codec for the collections the client holds keys for (built by the
   *   `@interop/was-client/edv` subpath); omit for plaintext-only clients
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
    const created = (response as { data?: unknown }).data as { id: string }
    return this.space(created.id)
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
    return (response as { data?: unknown }).data as SpaceListing
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
   * Lists a public (`PublicCanRead`) collection by its URL with no authorization
   * -- an unsigned `GET` -- e.g. to browse a blog published as a public-read
   * collection. Returns `null` if the collection is missing or not publicly
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
    // The collection listing endpoint is the trailing-slash items URL.
    const url = collectionUrl.endsWith('/')
      ? collectionUrl
      : `${collectionUrl}/`
    const response = await unsignedRequest({ url, method: 'GET', read: true })
    if (response === null) {
      return null
    }
    return (await readJsonData(response)) as CollectionResourcesList
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
    const { pathname } = new URL(zcap.invocationTarget)
    const segments = pathname.split('/').filter(Boolean)
    if (segments[0] !== 'space') {
      throw new ValidationError(
        `Cannot derive a handle from invocationTarget "${zcap.invocationTarget}".`
      )
    }
    const [, spaceId, collectionId, resourceId] = segments
    if (!spaceId) {
      throw new ValidationError(
        `invocationTarget "${zcap.invocationTarget}" has no space id.`
      )
    }
    const context = this._context
    if (resourceId) {
      return new Resource({
        context,
        spaceId,
        collectionId: collectionId as string,
        resourceId,
        capability: zcap
      })
    }
    if (collectionId) {
      return new Collection({
        context,
        spaceId,
        collectionId,
        capability: zcap
      })
    }
    return new Space({ context, spaceId, capability: zcap })
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
