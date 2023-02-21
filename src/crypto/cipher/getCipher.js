import * as cipher from '.';
import enums from '../../enums';

/**
 * Get implementation of the given cipher
 * @param {enums.symmetric} algo
 * @returns {Object}
 * @throws {Error} on invalid algo
 */
export default function getCipher(algo) {
  const algoName = enums.read(enums.symmetric, algo);
  return cipher[algoName];
}
