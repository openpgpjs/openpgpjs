/**
 * This is a vanilla JS copy of @openpgp/noble-hashes/esm/biginteger/interface.ts .
 * We need to duplicate the file, instead of importing it, since in that case the BigIntegerInterface instance
 * would be shared with noble-hashes, which separately calls `setImplementation()` on load, causing it to throw due to
 * duplicate initialization.
 */
class BigInteger {
  static setImplementation(Implementation, replace = false) {
    if (BigInteger.Implementation && !replace) {
      throw new Error('Implementation already set');
    }
    BigInteger.Implementation = Implementation;
  }

  static new(n) {
    return new BigInteger.Implementation(n);
  }
}

const detectBigInt = () => typeof BigInt !== 'undefined';
export async function getBigInteger() {
  if (BigInteger.Implementation) {
    return BigInteger;
  }

  // TODOOOOO replace = true needed in case of concurrent class loading, how to fix without removing wrapper class?

  if (detectBigInt()) {
    // NativeBigInteger is small, so it's imported in isolation (it could also be imported at the top level)
    const { default: NativeBigInteger } = await import('@openpgp/noble-hashes/esm/biginteger/native.interface');
    BigInteger.setImplementation(NativeBigInteger, true);
  } else {
    // FallbackBigInteger relies on large BN.js lib, which is also used by noble-hashes and noble-curves
    const { default: FallbackBigInteger } = await import('@openpgp/noble-hashes/esm/biginteger/bn.interface');
    BigInteger.setImplementation(FallbackBigInteger, true);
  }

  return BigInteger;
}
