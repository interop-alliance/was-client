/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The shared "memoize an in-flight promise, but only cache a success" helper.
 * Several lazily-resolved singletons across the client -- a handle's codec, a
 * backend-feature probe, a lazily-unwrapped epoch key -- want the same three
 * properties: concurrent callers share one round-trip, a rejection is not
 * cached (so the next call retries rather than replaying a stale failure), and
 * a reset drops whatever is held. Written once here so the three cannot drift
 * apart, which they had.
 */

/**
 * A memo of one lazily-resolved value. Holds the in-flight promise so
 * concurrent callers share a single resolution, drops it on rejection so a
 * transient failure does not permanently poison the memo, and exposes
 * {@link Memo.reset} for when the underlying answer is known to have changed.
 */
export class Memo<T> {
  #promise?: Promise<T>
  readonly #resolve: () => Promise<T>

  /**
   * @param resolve {function}   resolves a fresh value; re-invoked after a
   *   rejection or a `reset()`, else called at most once
   */
  constructor(resolve: () => Promise<T>) {
    this.#resolve = resolve
  }

  /**
   * Returns the memoized value, resolving it on first use.
   *
   * @returns {Promise<T>}
   */
  get(): Promise<T> {
    if (this.#promise) {
      return this.#promise
    }
    const promise = this.#resolve()
    // Memoize the in-flight promise so concurrent callers share one round-trip,
    // but drop it on rejection so a transient failure does not permanently
    // poison the memo. The identity guard avoids clobbering a newer promise.
    this.#promise = promise
    promise.catch((): void => {
      if (this.#promise === promise) {
        this.#promise = undefined
      }
    })
    return promise
  }

  /**
   * Drops any memoized value so the next `get()` re-resolves.
   *
   * @returns {void}
   */
  reset(): void {
    this.#promise = undefined
  }
}
