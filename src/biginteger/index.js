import util from '../util';
import BigInteger from './native.interface';

async function getBigInteger() {
  if (util.detectBigInt()) {
    return BigInteger;
  } else {
    const { default: BigInteger } = await import('./bn.interface');
    return BigInteger;
  }
}

// eslint-disable-next-line import/prefer-default-export
export { getBigInteger };
