/**
 * @fileoverview Cipher modes
 * @module crypto/cipherMode
 * @access private
 */

export * as cfb from './cfb.js';
import eax from './eax.js';
import ocb from './ocb.js';
import gcm from './gcm.js';
import enums from '../../enums.ts';

/**
* Get implementation of the given AEAD mode
* @param {enums.aead} algo
* @param {Boolean} [acceptExperimentalGCM] - whether to allow the non-standard, legacy `experimentalGCM` algo
* @returns {Object}
* @throws {Error} on invalid algo
*/
export function getAEADMode(algo, acceptExperimentalGCM = false) {
  switch (algo) {
    case enums.aead.eax:
      return eax;
    case enums.aead.ocb:
      return ocb;
    case enums.aead.gcm:
      return gcm;
    case enums.aead.experimentalGCM:
      if (!acceptExperimentalGCM) {
        throw new Error('Unexpected non-standard `experimentalGCM` AEAD algorithm provided in `config.preferredAEADAlgorithm`: use `gcm` instead');
      }
      return gcm;
    default:
      throw new Error('Unsupported AEAD mode');
  }
}
