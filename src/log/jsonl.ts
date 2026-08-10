/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Strict JSON Lines parse/serialize for resource logs (the Resource Log
 * Profile, App Connect spec `#resource-log-profile`): one log entry as one
 * JSON object per line, lines separated by U+000A LINE FEED, with a single
 * terminating LINE FEED after the last line. Strict on purpose -- a non-object
 * line is a parse failure, not a skip, so a truncated or doctored log surfaces
 * as an error instead of a silently shorter history.
 *
 * Wire level only: the parse guarantees each line is one JSON object and
 * nothing deeper. The profile's verifier-side rules (the five-member entry
 * shape, `parameters` per position, SCID and chain-hash recomputation, proofs,
 * authorization) belong to the consuming verifier, which runs over the parsed
 * entries.
 */
import type { ResourceLogEntry } from '@interop/storage-core'
import { ValidationError } from '../errors.js'

/**
 * Parses a resource-log body into its entries, strictly: the text must be one
 * JSON object per line, with an optional single trailing newline. Any empty
 * line, non-JSON line, or line holding a non-object JSON value (an array, a
 * string, a number, `null`) fails the whole parse. An empty body fails too --
 * a log has at least its genesis entry (an absent resource is the store
 * seam's `null`, not an empty body).
 *
 * @param text {string}   the log resource's body
 * @returns {ResourceLogEntry[]}   the parsed entries, first line first
 */
export function parseResourceLog(text: string): ResourceLogEntry[] {
  const body = text.endsWith('\n') ? text.slice(0, -1) : text
  if (body === '') {
    throw new ValidationError(
      'Cannot parse resource log: the body is empty (a log carries at least ' +
        'its genesis entry).'
    )
  }
  return body.split('\n').map((line, index) => {
    let parsed: unknown
    try {
      parsed = JSON.parse(line)
    } catch (err) {
      throw new ValidationError(
        `Cannot parse resource log: line ${index + 1} is not valid JSON.`,
        { cause: err }
      )
    }
    if (
      parsed === null ||
      typeof parsed !== 'object' ||
      Array.isArray(parsed)
    ) {
      throw new ValidationError(
        `Cannot parse resource log: line ${index + 1} is not a JSON object.`
      )
    }
    return parsed as unknown as ResourceLogEntry
  })
}

/**
 * Serializes one log entry as its single JSON Lines line, without the line
 * separator. `JSON.stringify` escapes any newline inside string values, so the
 * result never contains an embedded U+000A.
 *
 * @param entry {ResourceLogEntry}
 * @returns {string}
 */
export function serializeResourceLogEntry(entry: ResourceLogEntry): string {
  return JSON.stringify(entry)
}

/**
 * Serializes a full resource log as JSON Lines: one entry per line, in order,
 * with a terminating newline. Refuses an empty log (a log carries at least
 * its genesis entry).
 *
 * @param entries {ResourceLogEntry[]}
 * @returns {string}
 */
export function serializeResourceLog(entries: ResourceLogEntry[]): string {
  if (entries.length === 0) {
    throw new ValidationError(
      'Cannot serialize resource log: a log carries at least its genesis entry.'
    )
  }
  return entries.map(serializeResourceLogEntry).join('\n') + '\n'
}
