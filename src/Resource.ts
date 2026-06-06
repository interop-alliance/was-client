/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A navigational handle to a single Resource (a JSON object or binary blob
 * keyed by id within a Collection). Sugar over the Collection item operations,
 * with explicit `getText()` / `getBytes()` escape hatches.
 */
import { resourcePath } from './internal/paths.js'
import { prepareBody, parseResource } from './internal/content.js'
import { assertNotReserved } from './internal/reserved.js'
import type { ClientContext } from './internal/request.js'
import { send } from './internal/request.js'
import type { IZcap, Json } from './types.js'

export class Resource {
  readonly spaceId: string
  readonly collectionId: string
  readonly id: string

  private readonly _context: ClientContext
  private readonly _capability?: IZcap

  /**
   * @param options {object}
   * @param options.context {ClientContext}
   * @param options.spaceId {string}
   * @param options.collectionId {string}
   * @param options.resourceId {string}
   * @param [options.capability] {IZcap}   capability attached to every request
   */
  constructor({
    context,
    spaceId,
    collectionId,
    resourceId,
    capability
  }: {
    context: ClientContext
    spaceId: string
    collectionId: string
    resourceId: string
    capability?: IZcap
  }) {
    this._context = context
    this.spaceId = spaceId
    this.collectionId = collectionId
    this.id = resourceId
    this._capability = capability
  }

  private get _path(): string {
    return resourcePath(this.spaceId, this.collectionId, this.id)
  }

  /**
   * Reads the resource, auto-parsing JSON to an object and returning binary as
   * a `Blob`. Returns `null` if the resource is missing or not visible to you
   * (WAS returns 404 for both not-found and unauthorized).
   *
   * @returns {Promise<Json | Blob | null>}
   */
  async get(): Promise<Json | Blob | null> {
    const response = await send(this._context, {
      path: this._path,
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return parseResource(response)
  }

  /**
   * Reads the resource body as text. Returns `null` on a missing/unauthorized
   * resource (404 conflation caveat).
   *
   * @returns {Promise<string | null>}
   */
  async getText(): Promise<string | null> {
    const response = await send(this._context, {
      path: this._path,
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : response.text()
  }

  /**
   * Reads the resource body as raw bytes. Returns `null` on a
   * missing/unauthorized resource (404 conflation caveat).
   *
   * @returns {Promise<Uint8Array | null>}
   */
  async getBytes(): Promise<Uint8Array | null> {
    const response = await send(this._context, {
      path: this._path,
      method: 'GET',
      capability: this._capability,
      read: true
    })
    if (response === null) {
      return null
    }
    return new Uint8Array(await response.arrayBuffer())
  }

  /**
   * Creates or replaces the resource by id (upsert). JSON for plain
   * objects/arrays, binary for `Blob`/`Uint8Array`. Throws `NotFoundError` if
   * the parent collection does not exist (WAS does not auto-create parents).
   *
   * @param data {Json | Blob | Uint8Array}
   * @param options {object}
   * @param [options.contentType] {string}   content-type for binary data
   * @returns {Promise<void>}
   */
  async put(
    data: Json | Blob | Uint8Array,
    options: { contentType?: string } = {}
  ): Promise<void> {
    assertNotReserved(this.id, 'resource')
    const prepared = prepareBody(data, options)
    await send(this._context, {
      path: this._path,
      method: 'PUT',
      capability: this._capability,
      json: prepared.json,
      body: prepared.body,
      headers: prepared.contentType
        ? { 'content-type': prepared.contentType }
        : undefined
    })
  }

  /**
   * Deletes the resource. Idempotent.
   *
   * @returns {Promise<void>}
   */
  async delete(): Promise<void> {
    await send(this._context, {
      path: this._path,
      method: 'DELETE',
      capability: this._capability,
      idempotent: true
    })
  }
}
