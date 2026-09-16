/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `err.name` predicates that classify the errors a replication path can
 * meet: the port's two wire signals (`WasSyncConflictError` /
 * `WasSyncNotFoundError`), its opt-in revoked-access signal
 * (`WasSyncAuthError`), the cipher's two no-key signals (the stale-descriptor
 * `UnknownEpochError` and the not-a-recipient `KeyUnwrapError`), its tamper
 * signal (`IntegrityError`), and the client's affordance gate
 * (`NotSupportedError`), raised before the request when the backend advertises
 * no `conditional-writes`.
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
 * The affordance gate is raised outside a seam, in this copy, but is matched
 * the same way: one rule for the set, so a consumer needs no per-signal memory
 * of which ones an `instanceof` would have survived.
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
 * (`WasSyncNotFoundError`, HTTP 404), raised by the default port's
 * `deleteContent` and `putMeta`. On a delete that is a settled outcome --
 * already gone, or the write never reached the server -- not a conflict. On a
 * metadata write it marks a race with a remote delete.
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

/**
 * Whether an error is the cipher's not-a-recipient signal (`KeyUnwrapError`):
 * the envelope's epoch IS on the descriptor this reader holds, but the reader
 * has no key for it -- never a recipient of that epoch, or removed and the
 * epoch rotated since. Real data, unreadable by this reader, and never
 * garbage: a caller scanning rows skips such a row and leaves it in place,
 * where a scan that missed the class would drop it into an undecryptable
 * bucket a host is entitled to purge. Re-reading the descriptor cannot help,
 * which is what tells it from `isUnknownEpochError`.
 *
 * @param err {unknown}   the caught error
 * @returns {boolean}
 */
export function isKeyUnwrapError(err: unknown): boolean {
  return nameOf(err) === 'KeyUnwrapError'
}

/**
 * Whether an error is the cipher's tamper signal (`IntegrityError`): a stored
 * body failed verification against the resource id it was read under, or an
 * envelope this reader holds a key for failed to authenticate. The server
 * altered the data or served it under another id. Retrying the read or
 * refreshing the descriptor cannot fix it, and the row must not be applied.
 *
 * @param err {unknown}   the caught error
 * @returns {boolean}
 */
export function isIntegrityError(err: unknown): boolean {
  return nameOf(err) === 'IntegrityError'
}

/**
 * Whether an error is the client's affordance-gate refusal
 * (`NotSupportedError`): the operation needs an optional backend feature the
 * collection's backend does not advertise. On the sync port it is the guarded
 * write refused before any request, when `putContent`, `deleteContent` or
 * `putMeta` names `ifMatch` / `ifNoneMatch` against a backend listing no
 * `conditional-writes`. Permanent, and the one refusal a replication driver
 * must NOT retry: a backend that does not advertise the feature will not start
 * enforcing preconditions on a later attempt, so a retry loop would re-send the
 * same batch forever. Raised before the request, so the matched value carries
 * no `status`.
 *
 * @param err {unknown}   the caught error
 * @returns {boolean}
 */
export function isNotSupportedError(err: unknown): boolean {
  return nameOf(err) === 'NotSupportedError'
}
