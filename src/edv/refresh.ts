/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The unknown-epoch refresh policy: an epoch rotation emits no change-feed
 * entry, so a cipher built from a cached descriptor can meet envelopes stamped
 * with an epoch it has never seen. The remedy is one re-read of the
 * Collection Description plus a cipher rebuild and a single retry -- and the
 * policy guards that remedy to ONCE per collection per session, so a
 * genuinely foreign envelope (one no descriptor will ever route) cannot drive
 * a refetch loop, let alone a refetch per resource.
 */

/**
 * Tracks which collections have already spent their one refresh this session,
 * and runs reads under the refresh-and-retry-once rule. One instance per
 * session (it IS the session scope of the guard); the injected `refresh` does
 * the host's whole swap -- re-acquire the descriptor(s), rebuild the
 * cipher(s), and install them wherever the host keeps them.
 */
export class DescriptorRefreshPolicy {
  readonly #refresh: (options: { collectionId: string }) => Promise<void>
  // Collection ids whose one refresh this session is already spent.
  readonly #refreshed = new Set<string>()

  constructor({
    refresh
  }: {
    refresh: (options: { collectionId: string }) => Promise<void>
  }) {
    this.#refresh = refresh
  }

  /**
   * Whether a collection still has its one refresh this session.
   */
  shouldRefresh({ collectionId }: { collectionId: string }): boolean {
    return !this.#refreshed.has(collectionId)
  }

  /**
   * Runs a read that reports whether it skipped unknown-epoch rows; on the
   * first such report for a collection this session, spends the collection's
   * refresh (descriptor re-read + cipher swap, via the injected `refresh`) and
   * re-reads once. A later unknown-epoch report for the same collection
   * returns the read's value as-is.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param options.read {function}   the read, reporting `unknownEpoch`
   * @returns {Promise<T>}   the (possibly re-read) value
   */
  async readWithRefresh<T>({
    collectionId,
    read
  }: {
    collectionId: string
    read: () => Promise<{ value: T; unknownEpoch: boolean }>
  }): Promise<T> {
    const first = await read()
    if (first.unknownEpoch && this.shouldRefresh({ collectionId })) {
      this.#refreshed.add(collectionId)
      await this.#refresh({ collectionId })
      return (await read()).value
    }
    return first.value
  }

  /**
   * Re-arms the guard -- for one collection, or (with no argument) for all.
   * Call when a fresh descriptor is installed by some other path (a share,
   * unshare, or recipient rotation this session performed itself), since the
   * next unknown-epoch read is then evidence of a NEW rotation elsewhere.
   */
  reset(options?: { collectionId?: string }): void {
    if (options?.collectionId === undefined) {
      this.#refreshed.clear()
    } else {
      this.#refreshed.delete(options.collectionId)
    }
  }
}
