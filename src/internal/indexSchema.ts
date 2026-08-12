/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The persisted index schema of a searchable collection: where it is stored,
 * how an attribute is normalized into a stable key, and the guard that refuses
 * a query naming an attribute nobody declared.
 *
 * The schema lives under `indexSchema` inside the collection's `/meta`
 * `custom` object -- which on an encrypted collection is an opaque envelope, so
 * the attribute names (a description of the data model) are never
 * server-visible. Any recipient that can decrypt the collection can therefore
 * discover what is searchable, which is what an app granted access to an
 * existing collection needs: index declarations that lived only in one app's
 * memory would leave every other reader unable to learn them.
 */
import type { IndexSchema } from '../codec.js'
import { ValidationError } from '../errors.js'

/**
 * The property the schema is stored under inside the collection's metadata
 * `custom` object, alongside the user's own `name` / `tags`.
 */
export const INDEX_SCHEMA_PROPERTY = 'indexSchema'

/**
 * The schema of a collection that has declared nothing yet.
 */
export const EMPTY_INDEX_SCHEMA: IndexSchema = { revision: 0, indexes: [] }

/**
 * The metadata `custom` object as the index code sees it: the user's own
 * properties plus the schema this module owns.
 */
export type CustomWithIndexSchema = Record<string, unknown> & {
  indexSchema?: IndexSchema
}

/**
 * Normalizes an attribute declaration: a one-element array declares the same
 * simple index as the bare string (the same collapse the underlying index
 * helper applies), so the two spellings cannot produce two schema entries.
 *
 * @param attribute {string | string[]}
 * @returns {string | string[]}
 */
export function normalizeAttribute(
  attribute: string | string[]
): string | string[] {
  if (Array.isArray(attribute) && attribute.length === 1) {
    return attribute[0]!
  }
  return attribute
}

/**
 * The stable identity of an attribute declaration, for comparing a new
 * declaration against the persisted ones. Compound attributes join on `|` after
 * percent-encoding each part, so a name containing the separator cannot forge a
 * collision.
 *
 * @param attribute {string | string[]}
 * @returns {string}
 */
export function attributeKey(attribute: string | string[]): string {
  const parts = Array.isArray(attribute) ? attribute : [attribute]
  return parts.map(part => encodeURIComponent(part)).join('|')
}

/**
 * Reads the persisted schema out of a decoded metadata `custom` object,
 * returning {@link EMPTY_INDEX_SCHEMA} when none is stored (or when what is
 * stored is malformed -- a foreign writer's value must not crash a read path,
 * and treating it as "nothing declared" makes the next `declareIndex` rewrite
 * it).
 *
 * @param custom {unknown}   the decoded `custom` object from `/meta`
 * @returns {IndexSchema}
 */
export function readIndexSchema(custom: unknown): IndexSchema {
  const stored = (custom as CustomWithIndexSchema | undefined | null)?.[
    INDEX_SCHEMA_PROPERTY
  ]
  if (stored === null || typeof stored !== 'object') {
    return EMPTY_INDEX_SCHEMA
  }
  const { revision, indexes } = stored as Partial<IndexSchema>
  if (typeof revision !== 'number' || !Array.isArray(indexes)) {
    return EMPTY_INDEX_SCHEMA
  }
  const valid = indexes.filter(
    entry =>
      entry !== null &&
      typeof entry === 'object' &&
      (typeof entry.attribute === 'string' || Array.isArray(entry.attribute))
  )
  return { revision, indexes: valid }
}

/**
 * Every attribute name a schema makes searchable: each simple index's name and,
 * for a compound index, each of its member names (a compound index is queryable
 * by a leading prefix of its members, so any member can legitimately appear in
 * a query).
 *
 * @param schema {IndexSchema}
 * @returns {Set<string>}
 */
export function declaredAttributeNames(schema: IndexSchema): Set<string> {
  const names = new Set<string>()
  for (const entry of schema.indexes) {
    const parts = Array.isArray(entry.attribute)
      ? entry.attribute
      : [entry.attribute]
    for (const part of parts) {
      names.add(part)
    }
  }
  return names
}

/**
 * Refuses a search over an attribute the persisted schema does not declare.
 *
 * This guard is load-bearing rather than cosmetic: the underlying index helper
 * builds a query only from the attributes it has been told about, so an
 * undeclared attribute silently yields a term-less query -- which matches
 * nothing (or, worse, everything the other terms allow) instead of reporting
 * the mistake. Naming the attribute makes the "this app never declared it, and
 * neither did any other writer" case obvious.
 *
 * @param options {object}
 * @param options.schema {IndexSchema}   the collection's persisted schema
 * @param [options.equals] {object | object[]}   the query's equality terms
 * @param [options.has] {string | string[]}   the query's presence terms
 * @returns {void}
 */
export function assertQueryAttributes({
  schema,
  equals,
  has
}: {
  schema: IndexSchema
  equals?: Record<string, unknown> | Array<Record<string, unknown>>
  has?: string | string[]
}): void {
  const declared = declaredAttributeNames(schema)
  const queried: string[] = []
  if (equals !== undefined) {
    for (const term of Array.isArray(equals) ? equals : [equals]) {
      queried.push(...Object.keys(term))
    }
  }
  if (has !== undefined) {
    queried.push(...(Array.isArray(has) ? has : [has]))
  }
  for (const attribute of queried) {
    if (!declared.has(attribute)) {
      throw new ValidationError(
        `Cannot search on attribute "${attribute}": this collection's index ` +
          'schema does not declare it, so no stored document carries a token ' +
          'for it and the query would silently match nothing. Declare it with ' +
          'declareIndex({ attribute }) -- note that documents written before ' +
          'the declaration are not indexed until they are rewritten.'
      )
    }
  }
}
