/**
 * We don't use the BigIntegerInterface wrapper from noble-hashes because:
 * - importing the instance results in it being shared with noble-hashes, which separately calls `setImplementation()`
 *  on load, causing it to throw due to duplicate initialization.
 * - even duplicating the interface code here to keep a separate instance requires handing a race-conditions the first time
 * `getBigInteger` is called, when the code needs to check if the implementation is set, and initialize it if not.
 * Ultimately, the interface provides no advantages and it's only needed because of TS.
 */
const detectBigInt = () => typeof BigInt !== 'undefined';
export async function getBigInteger() {
  if (detectBigInt()) {
    // NativeBigInteger is small, so it's imported in isolation (it could also be imported at the top level)
    const { default: NativeBigInteger } = await import('@openpgp/noble-hashes/esm/biginteger/native.interface');
    return NativeBigInteger;
  } else {
    // FallbackBigInteger relies on large BN.js lib, which is also used by noble-hashes and noble-curves
    const { default: FallbackBigInteger } = await import('@openpgp/noble-hashes/esm/biginteger/bn.interface');
    return FallbackBigInteger;
  }
}
