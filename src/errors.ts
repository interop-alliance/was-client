/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Typed error hierarchy for the WAS client. A `WasError` base carries the
 * server's `application/problem+json` fields (`status` / `title` / `details` /
 * `requestUrl`); `mapError()` translates a thrown ky/ezcap error into the
 * appropriate subclass.
 */
import { ProblemTypes } from '@interop/storage-core'

/**
 * Structured fields attached to a `WasError`, sourced from the server's
 * `application/problem+json` response body.
 */
export interface WasErrorOptions {
  status?: number
  /**
   * The problem-kind URI from the response body's `type` (e.g.
   * `https://wallet.storage/spec#quota-exceeded`), when the server sent one.
   */
  type?: string
  title?: string
  details?: string[]
  requestUrl?: string
  cause?: unknown
}

/**
 * Base class for all errors thrown by the high-level client methods.
 */
export class WasError extends Error {
  status?: number
  type?: string
  title?: string
  details?: string[]
  requestUrl?: string

  constructor(message: string, options: WasErrorOptions = {}) {
    const { status, type, title, details, requestUrl, cause } = options
    super(message, cause !== undefined ? { cause } : undefined)
    this.name = 'WasError'
    this.status = status
    this.type = type
    this.title = title
    this.details = details
    this.requestUrl = requestUrl
  }
}

/**
 * The target was not found -- or it exists but is not visible to the caller.
 * WAS returns 404 for both not-found and unauthorized, so a `NotFoundError`
 * means "not visible to you" rather than strictly "does not exist".
 */
export class NotFoundError extends WasError {
  constructor(message: string, options: WasErrorOptions = {}) {
    super(message, options)
    this.name = 'NotFoundError'
  }
}

/**
 * The request was malformed or rejected as invalid (HTTP 400).
 */
export class ValidationError extends WasError {
  constructor(message: string, options: WasErrorOptions = {}) {
    super(message, options)
    this.name = 'ValidationError'
  }
}

/**
 * Authorization headers were missing or could not be verified (HTTP 401), or
 * the caller is authenticated but not permitted to act on the target (HTTP
 * 403).
 */
export class AuthRequiredError extends WasError {
  constructor(message: string, options: WasErrorOptions = {}) {
    super(message, options)
    this.name = 'AuthRequiredError'
  }
}

/**
 * The endpoint exists in the spec but is not yet implemented by the server
 * (HTTP 501).
 */
export class NotImplementedError extends WasError {
  constructor(message: string, options: WasErrorOptions = {}) {
    super(message, options)
    this.name = 'NotImplementedError'
  }
}

/**
 * A client-supplied id or backend conflicts with existing state (HTTP 409):
 * `id-conflict` (the id already exists), `reserved-id` (the id collides with a
 * reserved path segment), or `unsupported-backend` (the backend id is not in
 * the space's available list). The specific kind is on the `type` URI.
 */
export class ConflictError extends WasError {
  constructor(message: string, options: WasErrorOptions = {}) {
    super(message, options)
    this.name = 'ConflictError'
  }
}

/**
 * A conditional write's precondition evaluated false (HTTP 412): an `ifMatch`
 * ETag did not match the Resource's current version (a lost-update conflict), or
 * an `ifNoneMatch` create-if-absent target already exists. Recover by re-reading
 * the current Resource (its new `etag`), re-applying the change, and retrying.
 * Distinct from `ConflictError` (409), which is the header-less id/backend
 * conflict family.
 */
export class PreconditionFailedError extends WasError {
  constructor(message: string, options: WasErrorOptions = {}) {
    super(message, options)
    this.name = 'PreconditionFailedError'
  }
}

/**
 * A single upload exceeded the target backend's `maxUploadBytes` constraint
 * (HTTP 413). Unlike `QuotaExceededError`, this is per-request -- a smaller
 * upload may still succeed.
 */
export class PayloadTooLargeError extends WasError {
  constructor(message: string, options: WasErrorOptions = {}) {
    super(message, options)
    this.name = 'PayloadTooLargeError'
  }
}

/**
 * A write was rejected because the target backend's storage quota is exhausted
 * (HTTP 507). This is a client-actionable storage-full condition, not a server
 * fault.
 */
export class QuotaExceededError extends WasError {
  constructor(message: string, options: WasErrorOptions = {}) {
    super(message, options)
    this.name = 'QuotaExceededError'
  }
}

/**
 * A client-side, fail-closed encryption error: a collection is declared
 * encrypted (by a per-handle override or its `encryption` marker) but this
 * client cannot build the codec -- no `encryption` provider is configured, or
 * the keystore holds no keys for the collection (or does not handle its
 * scheme). Raised before any request, so it carries no HTTP status; recover by
 * supplying the collection's keys (your keystore's `resolveKeys`, or a
 * per-handle `encryption` override). Never silently downgrades to plaintext.
 */
export class EncryptionError extends WasError {
  constructor(message: string, options: WasErrorOptions = {}) {
    super(message, options)
    this.name = 'EncryptionError'
  }
}

/**
 * A fail-closed key-epoch error: a reader could not unwrap any epoch key it
 * needs to decrypt a resource on a multi-recipient encrypted Collection -- none
 * of the marker's `recipients` entries yielded a key for this reader's
 * key-agreement key (it was never a recipient, or has been removed and the
 * epoch rotated). A subtype of {@link EncryptionError}, so existing
 * `catch (EncryptionError)` fail-closed handling still catches it.
 *
 * This is the **read** axis only. It says nothing about **pull**: the reader may
 * still be served the ciphertext by the server (a separate zcap decision) and
 * may still hold earlier epochs' keys for resources written before it was
 * removed -- rotation is prospective and never claws back what a reader can
 * already decrypt.
 */
export class KeyUnwrapError extends EncryptionError {
  constructor(message: string, options: WasErrorOptions = {}) {
    super(message, options)
    this.name = 'KeyUnwrapError'
  }
}

/**
 * A fail-closed integrity error: a stored EDV envelope this reader DOES hold a
 * key for failed to authenticate on decrypt -- its AEAD tag did not verify, so
 * the ciphertext is corrupt or has been tampered with. Distinct from
 * {@link KeyUnwrapError}: that is the read/membership axis ("no key for this
 * epoch"), whereas this is a data-integrity failure by a legitimate recipient.
 * A subtype of {@link EncryptionError}, so existing `catch (EncryptionError)`
 * fail-closed handling still catches it, but a security-conscious caller can
 * `instanceof IntegrityError` to tell tampering apart from an authorization
 * problem. Raised client-side before/independent of any HTTP status.
 */
export class IntegrityError extends EncryptionError {
  constructor(message: string, options: WasErrorOptions = {}) {
    super(message, options)
    this.name = 'IntegrityError'
  }
}

/**
 * The replication-port signal for a rejected conditional write (HTTP 412): an
 * `ifMatch` ETag did not match (a lost-update conflict) or an `ifNoneMatch`
 * create-if-absent target already exists. Thrown by a `WasSyncPort`
 * (`@interop/was-client/sync`) so a push loop can catch exactly the conflict
 * signal and re-read-and-reconcile, letting every other error propagate to its
 * backoff. A subtype of {@link PreconditionFailedError}, so a caller that
 * already handles 412 via `instanceof PreconditionFailedError` still catches it.
 */
export class WasSyncConflictError extends PreconditionFailedError {
  constructor(
    message = 'WAS conditional write precondition failed.',
    options: WasErrorOptions = {}
  ) {
    super(message, { status: 412, ...options })
    this.name = 'WasSyncConflictError'
  }
}

/**
 * The replication-port signal for a delete whose target resource is absent
 * (HTTP 404). For a delete this is a settled outcome (already gone, or the write
 * never reached the server), not a conflict, so a `WasSyncPort`
 * (`@interop/was-client/sync`) raises this distinct type rather than
 * {@link WasSyncConflictError}. A subtype of {@link NotFoundError}.
 */
export class WasSyncNotFoundError extends NotFoundError {
  constructor(
    message = 'WAS resource not found.',
    options: WasErrorOptions = {}
  ) {
    super(message, { status: 404, ...options })
    this.name = 'WasSyncNotFoundError'
  }
}

/**
 * The server encountered an internal fault (HTTP 5xx).
 */
export class WasServerError extends WasError {
  constructor(message: string, options: WasErrorOptions = {}) {
    super(message, options)
    this.name = 'WasServerError'
  }
}

/**
 * The shape of a thrown ky/ezcap error after `@interop/http-client` has
 * augmented it.
 */
interface HttpClientError {
  status?: number
  requestUrl?: string
  message?: string
  response?: { status?: number }
  data?: { type?: string; title?: string; errors?: Array<{ detail?: string }> }
}

/**
 * A `WasError` subclass constructor (the base and every subclass share this
 * `(message, options)` signature).
 */
type WasErrorClass = new (
  message: string,
  options?: WasErrorOptions
) => WasError

/**
 * Extracts the fragment of a problem-type URI (the part after `#`, e.g.
 * `quota-exceeded` from `https://wallet.storage/spec#quota-exceeded`).
 * @param problemType {string}   a `ProblemTypes` URI
 * @returns {string}
 */
function problemFragment(problemType: string): string {
  return problemType.split('#')[1] ?? ''
}

/**
 * Maps each problem-kind fragment to the `WasError` subclass that represents
 * it. Keyed off the shared `ProblemTypes` registry from `@interop/storage-core`
 * (via `problemFragment`) so the kinds stay in lockstep with the server instead
 * of being duplicated as literal strings here.
 */
const ERROR_CLASS_BY_KIND: Record<string, WasErrorClass> = {
  [problemFragment(ProblemTypes.NOT_FOUND)]: NotFoundError,
  [problemFragment(ProblemTypes.INVALID_ID)]: ValidationError,
  [problemFragment(ProblemTypes.INVALID_REQUEST_BODY)]: ValidationError,
  [problemFragment(ProblemTypes.MISSING_CONTENT_TYPE)]: ValidationError,
  [problemFragment(ProblemTypes.INVALID_AUTHORIZATION_HEADER)]: ValidationError,
  [problemFragment(ProblemTypes.CONTROLLER_MISMATCH)]: ValidationError,
  [problemFragment(ProblemTypes.INVALID_IMPORT)]: ValidationError,
  [problemFragment(ProblemTypes.MISSING_AUTHORIZATION)]: AuthRequiredError,
  [problemFragment(ProblemTypes.RESERVED_ID)]: ConflictError,
  [problemFragment(ProblemTypes.ID_CONFLICT)]: ConflictError,
  [problemFragment(ProblemTypes.UNSUPPORTED_BACKEND)]: ConflictError,
  [problemFragment(ProblemTypes.ENCRYPTION_IMMUTABLE)]: ConflictError,
  [problemFragment(ProblemTypes.PRECONDITION_FAILED)]: PreconditionFailedError,
  [problemFragment(ProblemTypes.PAYLOAD_TOO_LARGE)]: PayloadTooLargeError,
  [problemFragment(ProblemTypes.QUOTA_EXCEEDED)]: QuotaExceededError,
  [problemFragment(ProblemTypes.UNSUPPORTED_OPERATION)]: NotImplementedError,
  [problemFragment(ProblemTypes.STORAGE_ERROR)]: WasServerError,
  [problemFragment(ProblemTypes.INTERNAL_ERROR)]: WasServerError
}

/**
 * Constructs a `WasError` subclass from a problem-kind anchor (the fragment of
 * the `type` URI, e.g. `quota-exceeded`). Returns `null` for an unrecognized or
 * absent kind so the caller can fall back to status-based dispatch.
 *
 * @param options {object}
 * @param [options.kind] {string}   the `type` URI fragment
 * @param options.message {string}
 * @param options.options {WasErrorOptions}
 * @returns {WasError | null}
 */
function errorForKind({
  kind,
  message,
  options
}: {
  kind?: string
  message: string
  options: WasErrorOptions
}): WasError | null {
  const ErrorClass = kind === undefined ? undefined : ERROR_CLASS_BY_KIND[kind]
  return ErrorClass ? new ErrorClass(message, options) : null
}

/**
 * Reads the HTTP status from a raw ky/ezcap error, checking both the flat
 * `status` and the nested `response.status` shapes.
 *
 * @param err {unknown}   the caught error
 * @returns {number | undefined}
 */
export function httpStatus(err: unknown): number | undefined {
  const raw = err as { status?: number; response?: { status?: number } }
  return raw?.status ?? raw?.response?.status
}

/**
 * Translates a thrown ky/ezcap error into the appropriate `WasError` subclass,
 * carrying through the server's `problem+json` fields. Dispatches on the
 * problem-kind `type` URI when the server sent one, falling back to the HTTP
 * status otherwise.
 *
 * @param err {unknown}   the caught error
 * @returns {WasError}
 */
export function mapError(err: unknown): WasError {
  if (err instanceof WasError) {
    return err
  }

  const httpError = (err ?? {}) as HttpClientError
  const status = httpStatus(httpError)
  const data = httpError.data
  const type = data?.type
  const title = data?.title
  // Guard with `Array.isArray`, not just optional chaining: a non-conformant
  // `problem+json` body with `errors` as a non-array (e.g. `"boom"`) is truthy,
  // so `?.map` would throw a `TypeError` and mask the real `WasError`. Each
  // entry is likewise unvalidated server JSON (may be `null` or a primitive),
  // so read `detail` defensively; the string filter drops the misses.
  const details = Array.isArray(data?.errors)
    ? data.errors
        .map(entry => (entry as { detail?: string } | null)?.detail)
        .filter((detail): detail is string => typeof detail === 'string')
    : undefined
  const requestUrl = httpError.requestUrl
  const message = title ?? httpError.message ?? 'WAS request failed'
  const options = { status, type, title, details, requestUrl, cause: err }

  const kind = typeof type === 'string' ? problemFragment(type) : undefined
  const byKind = errorForKind({ kind, message, options })
  if (byKind !== null) {
    return byKind
  }

  switch (status) {
    case 400:
      return new ValidationError(message, options)
    case 401:
    case 403:
      return new AuthRequiredError(message, options)
    case 404:
      return new NotFoundError(message, options)
    case 415:
      return new ValidationError(message, options)
    case 409:
      return new ConflictError(message, options)
    case 412:
      return new PreconditionFailedError(message, options)
    case 413:
      return new PayloadTooLargeError(message, options)
    case 501:
      return new NotImplementedError(message, options)
    case 507:
      return new QuotaExceededError(message, options)
  }

  if (typeof status === 'number' && status >= 500) {
    return new WasServerError(message, options)
  }

  return new WasError(message, options)
}
