import aes from './aes'; // can be imported dynamically once Web Crypto is used for AES-KW too
import enums from '../../enums';

export async function getCipher(algo) {
  switch (algo) {
    case enums.symmetric.aes128:
    case enums.symmetric.aes192:
    case enums.symmetric.aes256:
      return aes(getCipherKeySize(algo));
    case enums.symmetric.tripledes: {
      const { TripleDES } = await import('./des');
      return TripleDES;
    }
    case enums.symmetric.cast5: {
      const { default: CAST5 } = await import('./cast5');
      return CAST5;
    }
    case enums.symmetric.twofish: {
      const { default: TwoFish } = await import('./twofish');
      return TwoFish;
    }
    case enums.symmetric.blowfish: {
      const { default: BlowFish } = await import('./blowfish');
      return BlowFish;
    }
    default:
      throw new Error('Unsupported symmetric-key algorithm');
  }
}

/**
 * Get block size for given cipher algo
 * @param {module:enums.symmetric} algo - alrogithm identifier
 */
function getCipherBlockSize(algo) {
  switch (algo) {
    case enums.symmetric.aes128:
    case enums.symmetric.aes192:
    case enums.symmetric.aes256:
    case enums.symmetric.twofish:
      return 16;
    case enums.symmetric.blowfish:
    case enums.symmetric.cast5:
    case enums.symmetric.tripledes:
      return 8;
    default:
      throw new Error('Unsupported cipher');
  }
}

/**
 * Get key size for given cipher algo
 * @param {module:enums.symmetric} algo - alrogithm identifier
 */
function getCipherKeySize(algo) {
  switch (algo) {
    case enums.symmetric.aes128:
    case enums.symmetric.blowfish:
    case enums.symmetric.cast5:
      return 16;
    case enums.symmetric.aes192:
    case enums.symmetric.tripledes:
      return 24;
    case enums.symmetric.aes256:
    case enums.symmetric.twofish:
      return 32;
    default:
      throw new Error('Unsupported cipher');
  }
}

/**
 * Get block and key size for given cipher algo
 * @param {module:enums.symmetric} algo - alrogithm identifier
 */
export function getCipherParams(algo) {
  return { keySize: getCipherKeySize(algo), blockSize: getCipherBlockSize(algo) };
}
