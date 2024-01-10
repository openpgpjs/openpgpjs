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

import type { Config, enums as enumsType } from '../../../openpgp';
import enums from '../../enums';

import crypto from '../../crypto';
import { UnsupportedError } from '../../packet/packet';
import util from '../../util';

class GenericS2K {
  private algorithm: number;
  type: string;
  private c: number;
  private salt: Uint8Array | null;
  /**
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   */
  constructor(s2kType: enumsType.s2k.simple | enumsType.s2k.salted | enumsType.s2k.iterated, config:Config ) {
    /**
     * Hash function identifier, or 0 for gnu-dummy keys
     * @type {module:enums.hash | 0}
     */
    this.algorithm = enums.hash.sha256;
    /**
     * enums.s2k identifier or 'gnu-dummy'
     * @type {String}
     */
    this.type = enums.read(enums.s2k, s2kType);
    /** @type {Integer} */
    this.c = config.s2kIterationCountByte;
    /** Eight bytes of salt in a binary string.
     * @type {Uint8Array}
     */
    this.salt = null;
  }

  generateSalt() {
    switch (this.type) {
      case 'salted':
      case 'iterated':
        this.salt = crypto.random.getRandomBytes(8);
    }
  }

  private getCount() {
    // Exponent bias, defined in RFC4880
    const expbias = 6;

    return (16 + (this.c & 15)) << ((this.c >> 4) + expbias);
  }

  /**
   * Parsing function for a string-to-key specifier ({@link https://tools.ietf.org/html/rfc4880#section-3.7|RFC 4880 3.7}).
   * @param {Uint8Array} bytes - Payload of string-to-key specifier
   * @returns {Integer} Actual length of the object.
   */
  read(bytes: Uint8Array): Number {
    let i = 0;
    this.algorithm = bytes[i++];

    switch (this.type) {
      case 'simple':
        break;

      case 'salted':
        this.salt = bytes.subarray(i, i + 8);
        i += 8;
        break;

      case 'iterated':
        this.salt = bytes.subarray(i, i + 8);
        i += 8;

        // Octet 10: count, a one-octet, coded value
        this.c = bytes[i++];
        break;

      default:
        
        throw new UnsupportedError('Unknown s2k type.'); // unreachable
    }

    return i;
  }

  /**
   * Serializes s2k information
   * @returns {Uint8Array} Binary representation of s2k.
   */
  write(): Uint8Array {
    const arr = [new Uint8Array([enums.write(enums.s2k, this.type), this.algorithm])];

    switch (this.type) {
      case 'simple':
        break;
      case 'salted':
        this.salt && arr.push(this.salt);
        break;
      case 'iterated':
        this.salt &&arr.push(this.salt);
        arr.push(new Uint8Array([this.c]));
        break;
      default:
        throw new Error('Unknown s2k type.');
    }

    return util.concatUint8Array(arr);
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
    const encodedPassphrase = util.encodeUTF8(passphrase);

    const arr = [];
    let rlength = 0;

    let prefixlen = 0;
    while (rlength < numBytes) {
      let toHash;
      switch (this.type) {
        case 'simple':
          toHash = util.concatUint8Array([new Uint8Array(prefixlen), encodedPassphrase]);
          break;
        case 'salted':
          toHash = util.concatUint8Array([new Uint8Array(prefixlen), this.salt, encodedPassphrase]);
          break;
        case 'iterated': {
          const data = util.concatUint8Array([this.salt, encodedPassphrase]);
          let datalen = data.length;
          const count = Math.max(this.getCount(), datalen);
          toHash = new Uint8Array(prefixlen + count);
          toHash.set(data, prefixlen);
          for (let pos = prefixlen + datalen; pos < count; pos += datalen, datalen *= 2) {
            toHash.copyWithin(pos, prefixlen, pos);
          }
          break;
        }
        default:
          throw new Error('Unknown s2k type.');
      }
      const result = await crypto.hash.digest(this.algorithm, toHash);
      arr.push(result);
      rlength += result.length;
      prefixlen++;
    }

    return util.concatUint8Array(arr).subarray(0, numBytes);
  }
}

export default GenericS2K;
