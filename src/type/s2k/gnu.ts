// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the String-to-key specifier
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-3.7|RFC4880 3.7}:
 * String-to-key (S2K) specifiers are used to convert passphrase strings
 * into symmetric-key encryption/decryption keys.  They are used in two
 * places, currently: to encrypt the secret part of private keys in the
 * private keyring, and to convert passphrases to encryption keys for
 * symmetrically encrypted messages.
 * @module type/s2k
 */

import defaultConfig from '../../config';
import crypto from '../../crypto';
import enums from '../../enums';
import { UnsupportedError } from '../../packet/packet';
import util from '../../util';

class GnuS2k {
  algorithm: number;
  type: string;
  c: number;
  /**
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   */
  constructor(config = defaultConfig) {
    /**
     * Hash function identifier, or 0 for gnu-dummy keys
     * @type {module:enums.hash | 0}
     */
    this.algorithm = enums.hash.sha256;
    /**
     * enums.s2k identifier or 'gnu-dummy'
     * @type {String}
     */
    this.type = 'gnu';
    /** 
     * @type {Integer}  
     */
    this.c = config.s2kIterationCountByte;
  }

  /**
   * Parsing function for a string-to-key specifier ({@link https://tools.ietf.org/html/rfc4880#section-3.7|RFC 4880 3.7}).
   * @param {Uint8Array} bytes - Payload of string-to-key specifier
   * @returns {Integer} Actual length of the object.
   */
  read(bytes: Uint8Array): Number {
    let i = 0;
    this.algorithm = bytes[i++];
      if (util.uint8ArrayToString(bytes.subarray(i, i + 3)) === 'GNU') {
        i += 3; // GNU
        const gnuExtType = 1000 + bytes[i++];
        if (gnuExtType === 1001) {
          this.type = 'gnu-dummy';
          // GnuPG extension mode 1001 -- don't write secret key at all
        } else {
          throw new UnsupportedError('Unknown s2k gnu protection mode.');
        }
      } else {
        throw new UnsupportedError('Unknown s2k type.');
      }
    
    return i;
  }

  /**
   * Serializes s2k information
   * @returns {Uint8Array} Binary representation of s2k.
   */
  write(): Uint8Array {
    if (this.type === 'gnu-dummy') {
      return new Uint8Array([101, 0, ...util.stringToUint8Array('GNU'), 1]);
    } else {
      throw new Error('GNU s2k type not supported.');
    }
  }

  /**
   * Produces a key using the specified passphrase and the defined
   * hashAlgorithm
   * @param {String} passphrase - Passphrase containing user input
   * @returns {Promise<Uint8Array>} Produced key with a length corresponding to.
   * hashAlgorithm hash length
   * @async
   */
  async produceKey(passphrase: string, numBytes: number): Promise<Uint8Array> {
    const arr: number[] = [];
    let rlength = 0;

    while (rlength < numBytes) {
      if (this.type !== 'gnu') {
        throw new Error('Unknown s2k type.');
      } else {
        throw new Error('GNU s2k type not supported.');
      }
    }

    return util.concatUint8Array(arr).subarray(0, numBytes);
  }
}

export default GnuS2k;
