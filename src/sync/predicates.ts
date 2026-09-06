/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `err.name` predicates that classify the errors a replication path can
 * meet: the port's two wire signals (`WasSyncConflictError` /
 * `WasSyncNotFoundError`), its opt-in revoked-access signal
 * (`WasSyncAuthError`), and the cipher's stale-descriptor signal
 * (`UnknownEpochError`).
 *
 * They live beside the classes that assign the names they match (`errors.ts`)
 * because every one of those errors is raised inside a seam the consuming app
 * injects -- the port for the wire signals, the caller's `DocCipher` for the
 * unknown epoch -- and that seam can resolve to a SECOND copy of this package
 * (a `link:` dev setup, a dedupe miss through a dependency tree). So the match
 * is on the `name` string alone and never `instanceof`, which cannot see across
 * that boundary. The cost of a miss is silent and expensive: every push 412
 * becomes a fatal cycle error, and a create-loss re-mint rethrows instead of
 * re-minting. Each class assigns its `name` explicitly, which is what makes the
 * string a contract (`decisions/0001-cross-package-errors-match-by-name.md`).
 *
 * Each returns a plain boolean rather than a type guard: the guard would narrow
 * to this copy's class, the very identity the rule declines to depend on. A
 * caller reading a property after the match (`err.status` on an auth error)
 * reads it off the value itself.
 */

/**
 * Reads the `name` off an unknown caught value, without raising on a nullish
 * or non-object rejection.
 *
 * @param err {unknown}   the caught error
 * @returns {unknown}
 */
function nameOf(err: unknown): unknown {
  return (err as { name?: unknown } | null)?.name
}

/**
 * Whether an error is the replication port's rejected-conditional-write signal
 * (`WasSyncConflictError`, HTTP 412): a lost-update `If-Match` mismatch, or a
 * create-if-absent whose target already exists. The push loop's one settle-and-
 * reconcile branch; everything else propagates to the engine's backoff.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
export function isSyncConflictError(err: unknown): boolean {
  return nameOf(err) === 'WasSyncConflictError'
}

/**
 * Whether an error is the replication port's absent-target signal
 * (`WasSyncNotFoundError`, HTTP 404). On a delete that is a settled outcome
 * -- already gone, or the write never reached the server -- not a conflict.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
export function isSyncNotFoundError(err: unknown): boolean {
  return nameOf(err) === 'WasSyncNotFoundError'
}

/**
 * Whether an error is the replication port's refused-authorization signal
 * (`WasSyncAuthError`), raised only by a port built with `mapAuthErrors`. It
 * covers `401`, `403`, and the `404` a WAS server returns when it masks an
 * authorization failure as "not found", so a caller that needs the three apart
 * reads `status` off the matched value as a plain property.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
export function isSyncAuthError(err: unknown): boolean {
  return nameOf(err) === 'WasSyncAuthError'
}

/**
 * Whether an error is the cipher's unknown-epoch signal (`UnknownEpochError`):
 * an envelope naming recipient key ids whose epoch the descriptor this reader
 * holds does not list at all. Distinct from a key the reader simply does not
 * have (`KeyUnwrapError`), which re-reading the descriptor cannot fix.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
export function isUnknownEpochError(err: unknown): boolean {
  return nameOf(err) === 'UnknownEpochError'
}
