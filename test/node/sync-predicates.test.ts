/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `./sync` subpath's error classification (`isSyncConflictError` /
 * `isSyncNotFoundError` / `isSyncAuthError` / `isUnknownEpochError` /
 * `isKeyUnwrapError`, `src/sync/predicates.ts`; the last also ships from
 * `./edv`, beside the cipher that raises it).
 *
 * All five signals are raised inside app-injected seams -- the `WasSyncPort`
 * for the three wire signals, the caller's `DocCipher` for the two no-key
 * signals --
 * and a consumer's tree can resolve a SECOND copy of this package (a `link:`
 * dev setup, a dedupe miss through a dependency tree). So every case here also
 * raises the foreign-realm shape: a value carrying only the `name` string,
 * which no `instanceof` against this copy's class can match. Each pins the
 * branch a consumer's loop takes, since the cost of a miss is silent and
 * expensive: every push 412 becomes a fatal cycle error, and a create-loss
 * re-mint rethrows instead of re-minting.
 */
import { describe, it, expect } from 'vitest'

import { isKeyUnwrapError as isKeyUnwrapErrorFromEdv } from '../../src/edv/index.js'
import {
  isKeyUnwrapError,
  isSyncAuthError,
  isSyncConflictError,
  isSyncNotFoundError,
  isUnknownEpochError,
  KeyUnwrapError,
  UnknownEpochError,
  WasSyncAuthError,
  WasSyncConflictError,
  WasSyncNotFoundError
} from '../../src/sync/index.js'

/**
 * An error as it arrives from a SECOND copy of `@interop/was-client`: the same
 * `name` contract, an unrelated constructor.
 */
function foreignRealmError(name: string): Error {
  const err = new Error(`${name} raised by another copy of the package.`)
  err.name = name
  return err
}

const PREDICATES = [
  isSyncConflictError,
  isSyncNotFoundError,
  isSyncAuthError,
  isUnknownEpochError
]

describe('the sync error predicates', () => {
  it("matches this package's own classes", () => {
    expect(isSyncConflictError(new WasSyncConflictError())).toBe(true)
    expect(isSyncNotFoundError(new WasSyncNotFoundError())).toBe(true)
    expect(isSyncAuthError(new WasSyncAuthError(403))).toBe(true)
    expect(
      isUnknownEpochError(
        new UnknownEpochError({ collectionId: 'c', kids: ['k'] })
      )
    ).toBe(true)
  })

  it("matches a foreign realm's errors, which instanceof cannot", () => {
    const conflict = foreignRealmError('WasSyncConflictError')
    const notFound = foreignRealmError('WasSyncNotFoundError')
    const auth = foreignRealmError('WasSyncAuthError')
    const unknownEpoch = foreignRealmError('UnknownEpochError')

    expect(conflict instanceof WasSyncConflictError).toBe(false)
    expect(notFound instanceof WasSyncNotFoundError).toBe(false)
    expect(auth instanceof WasSyncAuthError).toBe(false)
    expect(unknownEpoch instanceof UnknownEpochError).toBe(false)

    expect(isSyncConflictError(conflict)).toBe(true)
    expect(isSyncNotFoundError(notFound)).toBe(true)
    expect(isSyncAuthError(auth)).toBe(true)
    expect(isUnknownEpochError(unknownEpoch)).toBe(true)
  })

  it('matches a plain object carrying only the name', () => {
    // A value that lost its prototype (a structured clone, a serialized
    // rejection) still classifies, since the contract is the string.
    expect(isSyncConflictError({ name: 'WasSyncConflictError' })).toBe(true)
    expect(isSyncNotFoundError({ name: 'WasSyncNotFoundError' })).toBe(true)
    expect(isSyncAuthError({ name: 'WasSyncAuthError', status: 404 })).toBe(
      true
    )
    expect(isUnknownEpochError({ name: 'UnknownEpochError' })).toBe(true)
  })

  it('matches a locally declared class with the same name', () => {
    class WasSyncAuthError {
      name = 'WasSyncAuthError'
      status = 401
    }
    const local = new WasSyncAuthError()

    expect(isSyncAuthError(local)).toBe(true)
    // The masked-404 read a consumer needs is a property read past the match,
    // not a class identity.
    expect(local.status).toBe(401)
  })

  it('reads the status off a matched auth error', () => {
    for (const status of [401, 403, 404]) {
      const err = new WasSyncAuthError(status)
      expect(isSyncAuthError(err)).toBe(true)
      expect(err.status).toBe(status)
    }
  })

  it('keeps the four signals apart, and rejects everything else', () => {
    const conflict = foreignRealmError('WasSyncConflictError')
    expect(isSyncNotFoundError(conflict)).toBe(false)
    expect(isSyncAuthError(conflict)).toBe(false)
    expect(isUnknownEpochError(conflict)).toBe(false)

    for (const predicate of PREDICATES) {
      expect(predicate(new Error('plain'))).toBe(false)
      expect(predicate(foreignRealmError('KeyUnwrapError'))).toBe(false)
      // A nullish or non-object rejection reads as "not this signal" rather
      // than raising a TypeError of its own.
      expect(predicate(undefined)).toBe(false)
      expect(predicate(null)).toBe(false)
      expect(predicate('WasSyncConflictError')).toBe(false)
    }
  })

  it('does not match a subtype relationship the name does not state', () => {
    // `WasSyncAuthError` is an `AuthRequiredError` and `WasSyncConflictError`
    // a `PreconditionFailedError`, but the base classes carry their own names,
    // so a base-class error is not one of the port's signals.
    expect(isSyncAuthError(foreignRealmError('AuthRequiredError'))).toBe(false)
    expect(
      isSyncConflictError(foreignRealmError('PreconditionFailedError'))
    ).toBe(false)
    expect(isSyncNotFoundError(foreignRealmError('NotFoundError'))).toBe(false)
  })

  it('classifies the not-a-recipient signal, own class and foreign realm alike', () => {
    const own = new KeyUnwrapError('no key for this epoch')
    const foreign = foreignRealmError('KeyUnwrapError')

    expect(foreign instanceof KeyUnwrapError).toBe(false)
    expect(isKeyUnwrapError(own)).toBe(true)
    expect(isKeyUnwrapError(foreign)).toBe(true)
    // The `./edv` export is the same predicate, one owner per name.
    expect(isKeyUnwrapErrorFromEdv).toBe(isKeyUnwrapError)
  })

  it('keeps the two no-key signals apart, and rejects a nullish rejection', () => {
    // Re-reading the descriptor may fix an unknown epoch and cannot fix a
    // missing key, so a row scan must never conflate them.
    expect(isKeyUnwrapError(foreignRealmError('UnknownEpochError'))).toBe(false)
    expect(
      isUnknownEpochError(new KeyUnwrapError('no key for this epoch'))
    ).toBe(false)
    expect(isKeyUnwrapError(new Error('socket hang up'))).toBe(false)
    expect(isKeyUnwrapError(undefined)).toBe(false)
    expect(isKeyUnwrapError(null)).toBe(false)
  })
})
