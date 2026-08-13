/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared test helpers for the codec seam: the single-request narrowing of
 * `ResourceCodec` several suites assert against, and a stub backend-feature
 * probe for the affordance gates.
 */
import { featureProbeFrom } from '../../src/internal/features.js'
import type { FeatureProbe } from '../../src/internal/features.js'
import type { EncodedWrite, ResourceCodec } from '../../src/index.js'

/**
 * The codec seam narrowed to its single-request half. `encode` returns a
 * `CodecWrite` union: the ordinary `EncodedWrite`, or a chunked-write plan for
 * a payload too large for one request. A suite whose fixtures all write
 * payloads that fit one request narrows the codec once with this type instead
 * of discriminating the union at each assertion.
 */
export type SingleWriteCodec = Omit<ResourceCodec, 'encode'> & {
  encode(input: Parameters<ResourceCodec['encode']>[0]): Promise<EncodedWrite>
}

/**
 * A stub {@link FeatureProbe} over a fixed token list, for the tests that drive
 * an affordance gate without a server.
 *
 * @param tokens {string[]}   the feature tokens the backend advertises
 * @param [options] {object}
 * @param [options.descriptorAbsent] {boolean}   whether the probe should report
 *   that the backend descriptor could not be read at all (as opposed to one
 *   that was read and lists `tokens`)
 * @returns {FeatureProbe}
 */
export function stubFeatures(
  tokens: string[],
  { descriptorAbsent = false }: { descriptorAbsent?: boolean } = {}
): FeatureProbe {
  return featureProbeFrom(
    async () => tokens,
    async () => descriptorAbsent
  )
}
