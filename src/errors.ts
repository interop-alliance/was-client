/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Typed error hierarchy for the WAS client. A `WasError` base carries the
 * server's `application/problem+json` fields (`status` / `title` / `problems` /
 * `details` / `requestUrl`); `mapError()` translates a thrown ky/ezcap error into the
 * appropriate subclass. It dispatches on the full problem-type URI, then on
 * the HTTP status, and strips control characters from and length-caps every
 * server string it carries through.
 */
import { ProblemTypes, type Problem } from '@interop/storage-core'

/**
 * Structured fields attached to a `WasError`, sourced from the server's
 * `application/problem+json` response body.
 */
export interface WasErrorOptions {
  status?: number
  /**
   * The problem-kind URI from the response body's `type` (e.g.
   * `https://w3id.org/pws#quota-exceeded`), when the server sent one.
   */
  type?: string
  title?: string
  /**
   * The body's `errors` entries as sent: each occurrence's `detail` with its
   * optional JSON `pointer` into the request body (e.g. `#/checkpoint`).
   */
  problems?: Problem[]
  /**
   * The `detail` strings of `problems`, in order, for callers that only need
   * the prose.
   */
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
  problems?: Problem[]
  details?: string[]
  requestUrl?: string

  constructor(message: string, options: WasErrorOptions = {}) {
    const { status, type, title, problems, details, requestUrl, cause } =
      options
    super(message, cause !== undefined ? { cause } : undefined)
    this.name = 'WasError'
    this.status = status
    this.type = type
    this.title = title
    this.problems = problems
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
  override name = 'NotFoundError'
}

/**
 * The invocation was refused because a capability in its delegation chain
 * has been revoked (`capability-revoked`). Still a 404 on the wire, and still
 * a `NotFoundError`, since the server keeps the merged not-found status for
 * every denial; the `name` is the one signal a consumer matches across
 * package copies. The server sends it only to a caller whose request
 * signature and chain verified, so it always means "your grant was revoked".
 */
export class CapabilityRevokedError extends NotFoundError {
  override name = 'CapabilityRevokedError'
}

/**
 * The invocation was refused because the invoked capability, or one in its
 * delegation chain, has expired (`capability-expired`). Same terms as
 * `CapabilityRevokedError`: a 404 and a `NotFoundError`, told apart by name.
 */
export class CapabilityExpiredError extends NotFoundError {
  override name = 'CapabilityExpiredError'
}

/**
 * The request was malformed or rejected as invalid (HTTP 400), or well-formed
 * but unprocessable (HTTP 422, e.g. `encryption-scheme-mismatch`).
 */
export class ValidationError extends WasError {
  override name = 'ValidationError'
}

/**
 * A revocation was refused because the capability is already revoked
 * (`capability-already-revoked`). Still a 400 on the wire, and still a
 * `ValidationError`, so a caller that treats every revocation-route 400 as a
 * refusal keeps doing so; the `name` is the one signal a consumer matches
 * across package copies. Catch this name alone to make revoking twice a
 * no-op without also swallowing a tampered, expired, or foreign-rooted
 * capability, which the server denies with a masked `NotFoundError`.
 */
export class AlreadyRevokedError extends ValidationError {
  override name = 'AlreadyRevokedError'
}

/**
 * Authorization headers were missing or could not be verified (HTTP 401), or
 * the caller is authenticated but not permitted to act on the target (HTTP
 * 403).
 */
export class AuthRequiredError extends WasError {
  override name = 'AuthRequiredError'
}

/**
 * The endpoint exists in the spec but is not yet implemented by the server
 * (HTTP 501).
 */
export class NotImplementedError extends WasError {
  override name = 'NotImplementedError'
}

/**
 * A client-side, fail-closed affordance gate: the operation cannot be carried
 * out as asked (a guarded write whose read returned no `ETag` validator, a
 * `DocCipher` built with no route to a chunked document's chunk resources, a
 * transport method the EDV-over-WAS profile does not define). Raised before any
 * request is sent, so it carries no HTTP status. A server that does not
 * implement an optional part of the protocol answers `501`
 * (`NotImplementedError`) instead; this is the client refusing on its own.
 */
export class NotSupportedError extends WasError {
  override name = 'NotSupportedError'
}

/**
 * The server speaks no version of the WAS specification this client
 * understands, so the client stops rather than guess a URL layout. Raised by
 * service discovery before the first signed request when the server's
 * responses carry no `rel="service"` link (a server that predates v0.5), when
 * the service description is not valid JSON or lacks `url` or `specs`, or
 * when no version entry under the WAS specification identifier names a
 * version this client understands. Not a transient failure: retrying against
 * the same server gives the same answer.
 */
export class IncompatibleServerError extends WasError {
  override name = 'IncompatibleServerError'
}

/**
 * A client-supplied id or backend conflicts with existing state (HTTP 409):
 * `id-conflict` (the id already exists), `reserved-id` (the id collides with a
 * reserved path segment), or `unsupported-backend` (the backend id is not in
 * the space's available list). Also the immutability and replica refusals:
 * `encryption-immutable`, `encryption-history-log-governed`,
 * `revisions-immutable`, `resource-immutable`, and `replica-refused`. The
 * specific kind is on the `type` URI.
 */
export class ConflictError extends WasError {
  override name = 'ConflictError'
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
  override name = 'PreconditionFailedError'
}

/**
 * A single upload exceeded the target backend's `maxUploadBytes` constraint
 * (HTTP 413). Unlike `QuotaExceededError`, this is per-request -- a smaller
 * upload may still succeed.
 */
export class PayloadTooLargeError extends WasError {
  override name = 'PayloadTooLargeError'
}

/**
 * A write was rejected because the target backend's storage quota is exhausted
 * (HTTP 507). This is a client-actionable storage-full condition, not a server
 * fault.
 */
export class QuotaExceededError extends WasError {
  override name = 'QuotaExceededError'
}

/**
 * A client-side, fail-closed encryption error: a collection is declared
 * encrypted (by a per-handle override or its `encryption` descriptor) but this
 * client cannot build the codec -- no `encryption` provider is configured, or
 * the keystore holds no keys for the collection (or does not handle its
 * scheme). Raised before any request, so it carries no HTTP status; recover by
 * supplying the collection's keys (your keystore's `resolveKeys`, or a
 * per-handle `encryption` override). Never silently downgrades to plaintext.
 */
export class EncryptionError extends WasError {
  override name = 'EncryptionError'
}

/**
 * A fail-closed key-epoch error: a reader holds no key for an epoch it needs
 * on a multi-recipient encrypted Collection. Raised on two paths. Building a
 * codec raises it when none of the descriptor's `recipients` entries yield a
 * key for this reader's key-agreement key (it is a recipient of no epoch at
 * all). Decrypt routing raises it when a stored envelope's epoch IS on the
 * descriptor but wraps to no key this reader holds (it was never a recipient
 * of that epoch, or has been removed and the epoch rotated) -- the descriptor
 * is current, so re-reading it cannot help; contrast {@link UnknownEpochError},
 * where it can. A subtype of {@link EncryptionError}, so existing
 * `catch (EncryptionError)` fail-closed handling still catches it.
 *
 * This is the **read** axis only. It says nothing about **pull**: the reader may
 * still be served the ciphertext by the server (a separate zcap decision) and
 * may still hold earlier epochs' keys for resources written before it was
 * removed -- rotation is prospective and never claws back what a reader can
 * already decrypt.
 */
export class KeyUnwrapError extends EncryptionError {
  override name = 'KeyUnwrapError'
}

/**
 * A fail-closed integrity error: a stored EDV envelope this reader DOES hold a
 * key for failed to authenticate on decrypt -- its AEAD tag did not verify, so
 * the ciphertext is corrupt or has been tampered with -- or a stored body does
 * not verify against the resource id it was read under (an envelope bound to
 * another resource, or a content-addressed document whose content id differs
 * from its resource id). Distinct from
 * {@link KeyUnwrapError}: that is the read/membership axis ("no key for this
 * epoch"), whereas this is a data-integrity failure by a legitimate recipient.
 * A subtype of {@link EncryptionError}, so existing `catch (EncryptionError)`
 * fail-closed handling still catches it, but a security-conscious caller can
 * `instanceof IntegrityError` to tell tampering apart from an authorization
 * problem. Raised client-side before/independent of any HTTP status.
 */
export class IntegrityError extends EncryptionError {
  override name = 'IntegrityError'
}

/**
 * A decrypt was attempted on an encrypt-only cipher. Raised by the cipher
 * `createEdvEncryptOnlyDocCipher` builds, which holds no key-agreement secret
 * at all: it seals writes to the descriptor's current epoch public key (the
 * epoch id IS the epoch key's did:key) and can never open anything. Its own
 * class so a caller that wired an encrypt-only cipher into a read path gets a
 * wiring signal, not a key-material failure; a subtype of
 * {@link EncryptionError}, so fail-closed handling still catches it. Matched
 * by `err.name` where the seam may resolve to another copy of this package.
 */
export class EncryptOnlyCipherError extends EncryptionError {
  override name = 'EncryptOnlyCipherError'
}

/**
 * A fail-closed descriptor-acquisition error: a fetched encryption descriptor
 * declares a governing log (it carries `history`), but the source that served
 * it does not verify that log (it does not declare `verifiesHistory`). The
 * served descriptor is a non-authoritative projection. Adopting it unverified
 * would let a host seal every later write to an epoch it minted. Also raised
 * under `requireGoverned` for any source that does not declare
 * `verifiesHistory`, before the source is asked. Recover by acquiring through
 * a log-governed source, such as wallet-core's `logGovernedDescriptorSource`.
 * Raised client-side, before anything is cached, so it carries no HTTP status.
 * A subtype of {@link EncryptionError}, so existing `catch (EncryptionError)`
 * fail-closed handling still catches it.
 */
export class UnverifiedDescriptorError extends EncryptionError {
  override name = 'UnverifiedDescriptorError'
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
    super(message, { ...options, status: options.status ?? 412 })
    this.name = 'WasSyncConflictError'
  }
}

/**
 * The replication-port signal for a delete or a metadata write whose target
 * resource is absent (HTTP 404). For a delete this is a settled outcome
 * (already gone, or the write never reached the server); for a metadata write
 * it is a race with a remote delete. Neither is a conflict, so a `WasSyncPort`
 * (`@interop/was-client/sync`) raises this distinct type rather than
 * {@link WasSyncConflictError}. A subtype of {@link NotFoundError}.
 */
export class WasSyncNotFoundError extends NotFoundError {
  constructor(
    message = 'WAS resource not found.',
    options: WasErrorOptions = {}
  ) {
    super(message, { ...options, status: options.status ?? 404 })
    this.name = 'WasSyncNotFoundError'
  }
}

/**
 * The replication-port signal for a request a WAS server refused on
 * authorization grounds: `401` (no verifiable invocation), `403` (authenticated
 * but not permitted), or the `404` a server returns when it MASKS an
 * authorization failure as "not found" so an unauthorized caller cannot probe
 * which resources exist. Carries the originating HTTP `status` so a caller can
 * tell the three apart.
 *
 * Opt-in: a `WasSyncPort` raises it only when built with `mapAuthErrors: true`
 * (`@interop/was-client/sync`), because the `404` reading is safe exactly when
 * the invoked Space and Collection are known to exist -- then a `404` can only
 * mean the invocation itself was rejected, i.e. the grant expired or was
 * revoked. A subtype of {@link AuthRequiredError}, so a caller that already
 * handles 401/403 via `instanceof AuthRequiredError` still catches it.
 */
export class WasSyncAuthError extends AuthRequiredError {
  constructor(status: number, options: WasErrorOptions = {}) {
    super(`WAS storage access denied (HTTP ${status}).`, {
      ...options,
      status
    })
    this.name = 'WasSyncAuthError'
  }
}

/**
 * The replication-port signal for a `changes` pull whose checkpoint the server
 * did not issue (HTTP 400, `invalid-request-body` at `#/checkpoint`): a
 * checkpoint stored against another server, or one from a retired layout. A
 * `WasSyncPort` (`@interop/was-client/sync`) raises it from `query` so a pull
 * loop can restart the feed from the beginning rather than retry a request
 * the server will keep refusing. A 400 of the same kind that points elsewhere
 * stays a plain {@link ValidationError}, of which this is a subtype.
 */
export class WasSyncCheckpointError extends ValidationError {
  constructor(
    message = 'WAS changes checkpoint not issued by this server.',
    options: WasErrorOptions = {}
  ) {
    super(message, { ...options, status: options.status ?? 400 })
    this.name = 'WasSyncCheckpointError'
  }
}

/**
 * The server encountered an internal fault (HTTP 5xx).
 */
export class WasServerError extends WasError {
  override name = 'WasServerError'
}

/**
 * Thrown on decrypt when a stored envelope names JWE recipient (`kid`) ids
 * whose epochs the Collection Metadata object does not list at all. It signals
 * that the caller's cached descriptor may be stale and should be re-read
 * before retrying: an epoch rotation emits no change-feed entry, so a codec
 * built from a pre-rotation descriptor meets envelopes stamped with a newer
 * epoch it has never seen.
 *
 * Distinct from {@link KeyUnwrapError}: when the descriptor DOES list the
 * envelope's epoch but this reader holds no key for it (it was never a
 * recipient of that epoch, or it was removed and the epoch rotated), decrypt
 * raises `KeyUnwrapError` instead -- the descriptor is current and re-reading
 * it cannot help.
 */
export class UnknownEpochError extends Error {
  constructor({
    collectionId,
    kids
  }: {
    collectionId: string
    kids: string[]
  }) {
    super(
      `Cannot decrypt a resource in collection "${collectionId}": its ` +
        `envelope names recipient key id(s) ` +
        `[${cleanText(kids.join(', '), MAX_KIDS_LENGTH)}] whose key ` +
        'epoch is not on the Collection Metadata object this reader holds. ' +
        'The cached descriptor may be stale (an epoch rotation emits no ' +
        'change-feed entry); re-read it and rebuild the cipher.'
    )
    this.name = 'UnknownEpochError'
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
  // Unvalidated server JSON: `type` and `title` may be any JSON value.
  data?: {
    type?: unknown
    title?: unknown
    errors?: Array<{ detail?: string }>
  }
}

/**
 * A `WasError` subclass constructor (the base and every subclass share this
 * `(message, options)` signature).
 */
type WasErrorClass = new (
  message: string,
  options?: WasErrorOptions
) => WasError

// Client-side hygiene limits on server-supplied strings carried into errors.
const MAX_TYPE_LENGTH = 2048
// Applies to `title`, each `errors[].detail`, and each `errors[].pointer`.
const MAX_TEXT_LENGTH = 1024
// Applies to the joined recipient key ids in an `UnknownEpochError` message.
const MAX_KIDS_LENGTH = 1024

/**
 * Normalizes an untrusted string for display: strips C0 and C1 control
 * characters and truncates to `maxLength`.
 *
 * @param value {unknown}   the untrusted value
 * @param maxLength {number}   the longest string to keep
 * @returns {string | undefined}   `undefined` when `value` is not a string
 */
function cleanText(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== 'string') {
    return undefined
  }
  return value.replace(/\p{Cc}/gu, '').slice(0, maxLength)
}

/**
 * Extracts the fragment of a problem-type URI (the part after `#`, e.g.
 * `quota-exceeded` from `https://w3id.org/pws#quota-exceeded`). Used only to
 * make a fallback message readable, never for dispatch.
 *
 * @param problemType {string}   a problem-type URI
 * @returns {string}
 */
function problemFragment(problemType: string): string {
  return problemType.split('#')[1] ?? ''
}

/**
 * Maps each problem-type URI to the `WasError` subclass that represents it.
 * Keyed by the full URIs of the shared `ProblemTypes` registry from
 * `@interop/storage-core`, so the kinds stay in lockstep with the server and a
 * foreign namespace that reuses a fragment does not match. A `Map` (rather than
 * a plain object) means a `type` such as `x#constructor` cannot resolve to an
 * inherited property.
 */
const ERROR_CLASS_BY_TYPE = new Map<string, WasErrorClass>([
  [ProblemTypes.NOT_FOUND, NotFoundError],
  [ProblemTypes.CAPABILITY_REVOKED, CapabilityRevokedError],
  [ProblemTypes.CAPABILITY_EXPIRED, CapabilityExpiredError],
  [ProblemTypes.INVALID_ID, ValidationError],
  [ProblemTypes.INVALID_REQUEST_BODY, ValidationError],
  [ProblemTypes.INVALID_CURSOR, ValidationError],
  [ProblemTypes.MISSING_CONTENT_TYPE, ValidationError],
  [ProblemTypes.INVALID_AUTHORIZATION_HEADER, ValidationError],
  [ProblemTypes.CONTROLLER_MISMATCH, ValidationError],
  [ProblemTypes.INVALID_IMPORT, ValidationError],
  [ProblemTypes.UNSUPPORTED_ENCRYPTION_SCHEME, ValidationError],
  [ProblemTypes.ENCRYPTION_SCHEME_MISMATCH, ValidationError],
  [ProblemTypes.CAPABILITY_ALREADY_REVOKED, AlreadyRevokedError],
  [ProblemTypes.MISSING_AUTHORIZATION, AuthRequiredError],
  [ProblemTypes.RESERVED_ID, ConflictError],
  [ProblemTypes.ID_CONFLICT, ConflictError],
  [ProblemTypes.UNSUPPORTED_BACKEND, ConflictError],
  [ProblemTypes.REPLICA_REFUSED, ConflictError],
  [ProblemTypes.ENCRYPTION_IMMUTABLE, ConflictError],
  [ProblemTypes.ENCRYPTION_HISTORY_LOG_GOVERNED, ConflictError],
  [ProblemTypes.REVISIONS_IMMUTABLE, ConflictError],
  [ProblemTypes.RESOURCE_IMMUTABLE, ConflictError],
  [ProblemTypes.PRECONDITION_FAILED, PreconditionFailedError],
  [ProblemTypes.PAYLOAD_TOO_LARGE, PayloadTooLargeError],
  [ProblemTypes.QUOTA_EXCEEDED, QuotaExceededError],
  [ProblemTypes.UNSUPPORTED_OPERATION, NotImplementedError],
  [ProblemTypes.STORAGE_ERROR, WasServerError],
  [ProblemTypes.INTERNAL_ERROR, WasServerError]
])

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
 * Normalizes an unknown caught value into a display string: the `Error`'s
 * `message` when it is one, else its `String(...)` coercion. The companion to
 * {@link httpStatus} for the "log or surface what went wrong" half of a catch
 * block.
 *
 * @param err {unknown}   the caught error
 * @returns {string}
 */
export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/**
 * Refuses a `DocCipher.decrypt` call that carries no resource id. Both
 * built-in ciphers verify the stored body against that id, and a missing one
 * would silently skip the check.
 *
 * @param options {object}
 * @param options.id {string}   the resource id the replica read the body under
 * @param options.collectionId {string}   labels the error
 */
export function requireResourceId({
  id,
  collectionId
}: {
  id: string
  collectionId: string
}): void {
  if (typeof id !== 'string' || id === '') {
    throw new ValidationError(
      `Cannot decrypt a resource of collection "${collectionId}" without its ` +
        'resource id: pass the id the replica read it under, so the stored ' +
        'body can be verified against it.'
    )
  }
}

/**
 * Translates a thrown ky/ezcap error into the appropriate `WasError` subclass,
 * carrying through the server's `problem+json` fields. Dispatches on the
 * full problem-type URI in `type` when it is a known `ProblemTypes` entry,
 * falling back to the HTTP status otherwise. Server strings (`type`, `title`,
 * each problem's `detail` and `pointer`) are stripped of control characters
 * and length-capped; a non-string `type` or `title` is dropped.
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
  const type = cleanText(data?.type, MAX_TYPE_LENGTH)
  const title = cleanText(data?.title, MAX_TEXT_LENGTH)
  // Guard with `Array.isArray`, not just optional chaining: a non-conformant
  // `problem+json` body with `errors` as a non-array (e.g. `"boom"`) is truthy,
  // so `?.map` would throw a `TypeError` and mask the real `WasError`. Each
  // entry is likewise unvalidated server JSON (may be `null` or a primitive),
  // so read it defensively; an entry without a string `detail` is dropped, and
  // a non-string `pointer` is dropped from its entry.
  const problems = Array.isArray(data?.errors)
    ? data.errors.flatMap((entry): Problem[] => {
        if (entry === null || typeof entry !== 'object') {
          return []
        }
        const { detail, pointer } = entry as {
          detail?: unknown
          pointer?: unknown
        }
        const cleanDetail = cleanText(detail, MAX_TEXT_LENGTH)
        if (cleanDetail === undefined) {
          return []
        }
        const cleanPointer = cleanText(pointer, MAX_TEXT_LENGTH)
        return [
          {
            detail: cleanDetail,
            ...(cleanPointer !== undefined && { pointer: cleanPointer })
          }
        ]
      })
    : undefined
  const details = problems?.map(problem => problem.detail)
  const requestUrl = httpError.requestUrl
  const fragment = type === undefined ? '' : problemFragment(type)
  const baseMessage =
    typeof httpError.message === 'string'
      ? httpError.message
      : 'WAS request failed'
  // Without a server title, name the problem kind for readability.
  const message =
    title ?? (fragment === '' ? baseMessage : `${baseMessage} (${fragment})`)
  const options = {
    status,
    type,
    title,
    problems,
    details,
    requestUrl,
    cause: err
  }

  // Dispatch on the full problem-type URI when the server sent a known one,
  // falling through to the status-based switch otherwise.
  const ErrorClass =
    type === undefined ? undefined : ERROR_CLASS_BY_TYPE.get(type)
  if (ErrorClass) {
    return new ErrorClass(message, options)
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
    case 422:
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
