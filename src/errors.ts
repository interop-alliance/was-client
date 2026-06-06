/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Typed error hierarchy for the WAS client. A `WasError` base carries the
 * server's `application/problem+json` fields (`status` / `title` / `details` /
 * `requestUrl`); `mapError()` translates a thrown ky/ezcap error into the
 * appropriate subclass.
 */

/**
 * Structured fields attached to a `WasError`, sourced from the server's
 * `application/problem+json` response body.
 */
export interface WasErrorOptions {
  status?: number
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
  title?: string
  details?: string[]
  requestUrl?: string

  constructor(message: string, options: WasErrorOptions = {}) {
    const { status, title, details, requestUrl, cause } = options
    super(message, cause !== undefined ? { cause } : undefined)
    this.name = 'WasError'
    this.status = status
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
 * Authorization headers were missing or could not be verified (HTTP 401).
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
  data?: { title?: string; errors?: Array<{ detail?: string }> }
}

/**
 * Translates a thrown ky/ezcap error into the appropriate `WasError` subclass,
 * carrying through the server's `problem+json` fields.
 *
 * @param err {unknown}   the caught error
 * @returns {WasError}
 */
export function mapError(err: unknown): WasError {
  if (err instanceof WasError) {
    return err
  }

  const httpError = (err ?? {}) as HttpClientError
  const status = httpError.status ?? httpError.response?.status
  const data = httpError.data
  const title = data?.title
  const details = data?.errors
    ?.map(entry => entry.detail)
    .filter((detail): detail is string => typeof detail === 'string')
  const requestUrl = httpError.requestUrl
  const message = title ?? httpError.message ?? 'WAS request failed'
  const options = { status, title, details, requestUrl, cause: err }

  switch (status) {
    case 400:
      return new ValidationError(message, options)
    case 401:
      return new AuthRequiredError(message, options)
    case 404:
      return new NotFoundError(message, options)
    case 501:
      return new NotImplementedError(message, options)
  }

  if (typeof status === 'number' && status >= 500) {
    return new WasServerError(message, options)
  }

  return new WasError(message, options)
}
