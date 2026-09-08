/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The one compare-and-swap retry loop: read a versioned value, reconcile the
 * caller's change against it, write it back under `If-Match`, and rebase on a
 * lost race (a `412`) by re-reading. The recipient primitives drive it with an
 * `EncryptionDescriptorStore`; `Collection.declareIndex` drives it with a
 * `/meta`-backed store. A new caller wanting CAS adapts its host to
 * {@link CasStore} rather than hand-rolling a fourth loop.
 */
import { PreconditionFailedError, ValidationError } from '../errors.js'

/**
 * How many times {@link compareAndSwap} retries a stale (`412`) write before
 * surfacing `PreconditionFailedError`. One shared default, so two callers do
 * not drift apart by accident; a caller with a reason passes its own
 * `maxAttempts`.
 */
export const DEFAULT_CAS_ATTEMPTS = 3

/**
 * Where a compare-and-swapped value lives: a read-with-validator plus a
 * conditional replace, and optionally a guarded create for a host that may
 * hold no value yet.
 */
export interface CasStore<T> {
  /**
   * Reads the current value with the validator the next {@link replace} is
   * compare-and-swapped against. Resolves `null` when the host holds no value
   * yet and this store can {@link create} one.
   *
   * @returns {Promise<{ value: T; etag?: string } | null>}
   */
  read(): Promise<{ value: T; etag?: string } | null>

  /**
   * Replaces the value under `ifMatch`; a stale validator throws
   * `PreconditionFailedError` (412).
   *
   * @param value {T}
   * @param options {object}
   * @param [options.ifMatch] {string}
   * @returns {Promise<void>}
   */
  replace(value: T, options: { ifMatch?: string }): Promise<void>

  /**
   * Creates the FIRST value where {@link read} resolved `null`, guarded
   * create-if-absent; throws `PreconditionFailedError` (412) when a concurrent
   * writer created one first.
   *
   * @param value {T}
   * @returns {Promise<void>}
   */
  create?(value: T): Promise<void>
}

/**
 * Whether `err` is the compare-and-swap conflict a store raises
 * (`PreconditionFailedError`, 412). Matched by `name` as well as `instanceof`:
 * a store implemented by a consumer (wallet-core's log-governed store) mints
 * the conflict from its own `@interop/was-client` import, and in a tree that
 * resolves was-client twice that class is a different object from ours, so an
 * `instanceof`-only check would turn every lost race into a hard failure
 * instead of a rebase.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
export function isPreconditionFailed(err: unknown): boolean {
  return (
    err instanceof PreconditionFailedError ||
    (err instanceof Error && err.name === 'PreconditionFailedError')
  )
}

/**
 * Reads the store's value, applies `mutate`, and writes the result back with a
 * compare-and-swap (`If-Match`). Retries on a stale (`412`) validator,
 * re-reading the fresh value each time, up to `maxAttempts`; surfaces a
 * `PreconditionFailedError` naming `operation` if it keeps losing the race. A
 * `mutate` that resolves `null` signals "no change needed" (the value already
 * reflects the desired state, e.g. an idempotent retry): nothing is written
 * and the current value is returned as-is. Any other error `mutate` throws
 * propagates unchanged.
 *
 * When the store reports no value yet (`read()` resolves `null`), the optional
 * `onAbsent` supplies the seed to mutate instead, and the result is written
 * with the store's create-if-absent guard. Without `onAbsent`, or on a store
 * without `create`, an absent value is refused. Losing the create race (a
 * concurrent writer created the first value) re-enters the loop and re-reads,
 * like a stale CAS.
 *
 * @param options {object}
 * @param options.store {CasStore<T>}
 * @param options.mutate {function}   value to the next value (may be async), or
 *   `null` to skip the write
 * @param options.operation {string}   what the caller is doing, for the
 *   exhaustion error's message (e.g. `Recipient change`)
 * @param [options.onAbsent] {function}   returns the seed to mutate when the
 *   store holds no value yet; may throw a caller-specific refusal
 * @param [options.maxAttempts] {number}   defaults to {@link DEFAULT_CAS_ATTEMPTS}
 * @returns {Promise<T>}   the written (or current) value
 */
export async function compareAndSwap<T>({
  store,
  mutate,
  operation,
  onAbsent,
  maxAttempts = DEFAULT_CAS_ATTEMPTS
}: {
  store: CasStore<T>
  mutate: (value: T) => T | null | Promise<T | null>
  operation: string
  onAbsent?: () => T
  maxAttempts?: number
}): Promise<T> {
  let lastError: unknown
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const current = await store.read()
    if (current === null) {
      if (onAbsent === undefined) {
        throw new ValidationError(
          `Cannot ${operation.toLowerCase()}: this store holds no value yet.`
        )
      }
      const seed = onAbsent()
      if (store.create === undefined) {
        throw new ValidationError(
          `Cannot ${operation.toLowerCase()}: this store holds no value and ` +
            'does not support creating one.'
        )
      }
      const created = await mutate(seed)
      if (created === null) {
        return seed
      }
      try {
        await store.create(created)
        return created
      } catch (err) {
        if (isPreconditionFailed(err)) {
          // A concurrent writer created the first value: re-read and re-apply.
          lastError = err
          continue
        }
        throw err
      }
    }
    const next = await mutate(current.value)
    if (next === null) {
      // The value already reflects the desired state: nothing to write.
      return current.value
    }
    try {
      await store.replace(next, { ifMatch: current.etag })
      return next
    } catch (err) {
      if (isPreconditionFailed(err)) {
        // A concurrent write landed first: re-read and re-apply.
        lastError = err
        continue
      }
      throw err
    }
  }
  throw new PreconditionFailedError(
    `${operation} lost the compare-and-swap race after ${maxAttempts} ` +
      'attempts (another writer kept updating the stored value). Retry the ' +
      'operation.',
    { cause: lastError as Error }
  )
}
