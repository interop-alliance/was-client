/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The one compare-and-swap retry loop: read a versioned value, reconcile the
 * caller's change against it, write it back under `If-Match`, and rebase on a
 * lost race (a `412`) by re-reading. The recipient primitives drive it with an
 * `EncryptionDescriptorStore`; `Collection.declareIndex` drives it with a
 * `/meta`-backed store. The Collection and Space Metadata writes drive it
 * through {@link composeAndSwap}, which builds a write body from the stored
 * value. A new caller wanting CAS adapts its host to {@link CasStore} rather
 * than hand-rolling another loop.
 */
import { PreconditionFailedError, ValidationError } from '../errors.js'
import { unenforcedPreconditionError } from './conditional.js'

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
   * yet and this store can {@link create} one. Throws
   * `PreconditionFailedError` (412) when the read itself observes a concurrent
   * write (e.g. a served projection behind its governing log); the loop
   * rebases on it like a stale replace.
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
 * compare-and-swap (`If-Match`). Retries on a stale (`412`) validator, or a
 * `412` raised by the read itself, re-reading the fresh value each time, up to
 * `maxAttempts`; surfaces a `PreconditionFailedError` naming `operation` if it
 * keeps losing the race. A `mutate` that resolves `null` signals "no change
 * needed" (the value already reflects the desired state, e.g. an idempotent
 * retry): nothing is written and the current value is returned as-is. Any other error `mutate` throws
 * propagates unchanged.
 *
 * A read that returns a value with no validator is refused before the write
 * with `NotSupportedError`: the replace would carry no `If-Match`, so a lost
 * race would silently overwrite the rival write instead of rebasing on it. A
 * caller whose host legitimately offers only the unconditional write passes
 * `allowUnconditional`. A `mutate` that resolves `null` writes nothing and so
 * is never refused.
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
 * @param [options.allowUnconditional] {boolean}   send the replace without
 *   `If-Match` when the read returned no validator, instead of refusing
 * @returns {Promise<T>}   the written (or current) value
 */
export async function compareAndSwap<T>({
  store,
  mutate,
  operation,
  onAbsent,
  maxAttempts = DEFAULT_CAS_ATTEMPTS,
  allowUnconditional = false
}: {
  store: CasStore<T>
  mutate: (value: T) => T | null | Promise<T | null>
  operation: string
  onAbsent?: () => T
  maxAttempts?: number
  allowUnconditional?: boolean
}): Promise<T> {
  let lastError: unknown
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    let current: { value: T; etag?: string } | null
    try {
      current = await store.read()
    } catch (err) {
      if (isPreconditionFailed(err)) {
        // The read observed a concurrent write: re-read.
        lastError = err
        continue
      }
      throw err
    }
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
      // `null` from `mutate` means "the value already reflects the desired
      // state, nothing to write". On the replace path that is true of a value
      // the store already holds; here nothing is stored yet, so the seed
      // itself still has to be created -- returning it unwritten would resolve
      // a value that exists nowhere, and the next `read()` would still be
      // `null`.
      const created = (await mutate(seed)) ?? seed
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
    if (current.etag === undefined && !allowUnconditional) {
      throw unenforcedPreconditionError({
        operation: `${operation} was refused`,
        reason: 'no-validator'
      })
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

/**
 * A merging write over a versioned object, run through {@link compareAndSwap}.
 * `compose` is handed a baseline read and returns the write body, and `write`
 * sends that body pinned to the baseline's validator. A lost race (a `412`)
 * re-reads, re-composes, and re-sends, so a merge is only applied over a
 * version this write observed. A baseline carrying no validator makes its
 * attempt an unconditional write (`ifMatch` is `undefined`), which is all a
 * backend without `conditional-writes` offers. This is the loop's
 * `allowUnconditional` opt-out: the Collection and Space Metadata writes that
 * drive it keep working on such a backend.
 *
 * Unlike a plain {@link CasStore}, the body is not the stored value itself.
 * The stored value may be `null` (an absent or unreadable object), and
 * `compose` decides whether proceeding from it is safe; a refusal it throws
 * propagates unchanged. `compose` runs once per attempt, so a caller that
 * needs what was merged reads it from the value `write` resolves, which is the
 * last attempt's.
 *
 * @param options {object}
 * @param options.read {function}   reads a fresh baseline and its validator;
 *   may throw a caller-specific refusal (e.g. for an unreadable object)
 * @param [options.current] {object}   a baseline the caller has already read,
 *   used for the first attempt only; a rebase calls `read`
 * @param options.compose {function}   baseline to write body (may be async)
 * @param options.write {function}   sends the body under `ifMatch`; a stale
 *   validator throws `PreconditionFailedError` (412)
 * @param options.operation {string}   what the caller is doing, for the
 *   exhaustion error's message
 * @param [options.maxAttempts] {number}   defaults to {@link DEFAULT_CAS_ATTEMPTS}
 * @returns {Promise<R>}   what the successful `write` resolved
 */
export async function composeAndSwap<B, W extends object, R>({
  read,
  current,
  compose,
  write,
  operation,
  maxAttempts
}: {
  read: () => Promise<{ value: B; etag?: string }>
  current?: { value: B; etag?: string }
  compose: (baseline: B) => W | Promise<W>
  write: (body: W, precondition: { ifMatch?: string }) => Promise<R>
  operation: string
  maxAttempts?: number
}): Promise<R> {
  let seed = current
  let written: { result: R } | undefined
  await compareAndSwap<B | W>({
    store: {
      read: async () => {
        // The caller's baseline is consumed once, so a rebase always re-reads.
        const baseline = seed ?? (await read())
        seed = undefined
        return { value: baseline.value, etag: baseline.etag }
      },
      replace: async (body, { ifMatch }) => {
        written = { result: await write(body as W, { ifMatch }) }
      }
    },
    // The store only ever reads a baseline and only ever replaces a body.
    mutate: value => compose(value as B),
    operation,
    allowUnconditional: true,
    ...(maxAttempts !== undefined && { maxAttempts })
  })
  if (written === undefined) {
    // Unreachable for a typed caller: `compose` always returns a body.
    throw new ValidationError(`${operation} composed no write body.`)
  }
  return written.result
}
