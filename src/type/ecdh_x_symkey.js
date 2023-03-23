/**
 * Encoded symmetric key for x25519 and x448
 * The payload format varies for v3 and v6 PKESK:
 * the former includes an algorithm byte preceeding the encrypted session key.
 *
 * @module type/x25519x448_symkey
 */

import util from '../util';

class ECDHXSymmetricKey {
  static fromObject({ wrappedKey, algorithm }) {
    const instance = new ECDHXSymmetricKey();
    instance.wrappedKey = wrappedKey;
    instance.algorithm = algorithm;
    return instance;
  }

  /**
   * - 1 octect for the length `l`
   * - `l` octects of encoded session key data (with optional leading algorithm byte)
   * @param {Uint8Array} bytes
   * @returns {Number} Number of read bytes.
   */
  read(bytes) {
    let read = 0;
    let followLength = bytes[read++];
    this.algorithm = followLength % 2 ? bytes[read++] : null; // session key size is always even
    followLength -= followLength % 2;
    this.wrappedKey = bytes.subarray(read, read + followLength); read += followLength;
  }

  /**
   * Write an MontgomerySymmetricKey as an Uint8Array
   * @returns  {Uint8Array} Serialised data
   */
  write() {
    return util.concatUint8Array([
      this.algorithm ?
        new Uint8Array([this.wrappedKey.length + 1, this.algorithm]) :
        new Uint8Array([this.wrappedKey.length]),
      this.wrappedKey
    ]);
  }
}

export default ECDHXSymmetricKey;
