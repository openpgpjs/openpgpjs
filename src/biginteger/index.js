import BigInteger from './native.interface';

const detectBigInt = () => typeof BigInt !== 'undefined';

async function getBigInteger() {
  if (detectBigInt()) {
    return BigInteger;
  } else {
    const { default: BigInteger } = await import('./bn.interface');
    return BigInteger;
  }
}

export { getBigInteger };
