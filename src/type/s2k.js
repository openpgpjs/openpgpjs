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
 * @requires config
 * @requires crypto
 * @requires enums
 * @requires util
 * @module type/s2k
 */

import config from '../config';
import crypto from '../crypto';
import enums from '../enums.js';
import util from '../util.js';

/**
 * @constructor
 */
function S2K() {
  /** @type {module:enums.hash} */
  this.algorithm = 'sha256';
  /** @type {module:enums.s2k} */
  this.type = 'iterated';
  /** @type {Integer} */
  this.c = config.s2k_iteration_count_byte;
  /** Eight bytes of salt in a binary string.
   * @type {String}
   */
  this.salt = null;
}

S2K.prototype.get_count = function () {
  // Exponent bias, defined in RFC4880
  const expbias = 6;

  return (16 + (this.c & 15)) << ((this.c >> 4) + expbias);
};

/**
 * Parsing function for a string-to-key specifier ({@link https://tools.ietf.org/html/rfc4880#section-3.7|RFC 4880 3.7}).
 * @param {String} input Payload of string-to-key specifier
 * @returns {Integer} Actual length of the object
 */
S2K.prototype.read = function (bytes) {
  let i = 0;
  this.type = enums.read(enums.s2k, bytes[i++]);
  this.algorithm = bytes[i++];
  if (this.type !== 'gnu') {
    this.algorithm = enums.read(enums.hash, this.algorithm);
  }

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

    case 'gnu':
      if (util.Uint8Array_to_str(bytes.subarray(i, i + 3)) === "GNU") {
        i += 3; // GNU
        const gnuExtType = 1000 + bytes[i++];
        if (gnuExtType === 1001) {
          this.type = 'gnu-dummy';
          // GnuPG extension mode 1001 -- don't write secret key at all
        } else {
          throw new Error("Unknown s2k gnu protection mode.");
        }
      } else {
        throw new Error("Unknown s2k type.");
      }
      break;

    default:
      throw new Error("Unknown s2k type.");
  }

  return i;
};


/**
 * Serializes s2k information
 * @returns {Uint8Array} binary representation of s2k
 */
S2K.prototype.write = function () {
  if (this.type === 'gnu-dummy') {
    return new Uint8Array([101, 0, ...util.str_to_Uint8Array('GNU'), 1]);
  }

  const arr = [new Uint8Array([enums.write(enums.s2k, this.type), enums.write(enums.hash, this.algorithm)])];

  switch (this.type) {
    case 'simple':
      break;
    case 'salted':
      arr.push(this.salt);
      break;
    case 'iterated':
      arr.push(this.salt);
      arr.push(new Uint8Array([this.c]));
      break;
    case 'gnu':
      throw new Error("GNU s2k type not supported.");
    default:
      throw new Error("Unknown s2k type.");
  }

  return util.concatUint8Array(arr);
};

/**
 * Produces a key using the specified passphrase and the defined
 * hashAlgorithm
 * @param {String} passphrase Passphrase containing user input
 * @returns {Uint8Array} Produced key with a length corresponding to
 * hashAlgorithm hash length
 */
S2K.prototype.produce_key = async function (passphrase, numBytes) {
  passphrase = util.encode_utf8(passphrase);
  const algorithm = enums.write(enums.hash, this.algorithm);

  const arr = [];
  let rlength = 0;

  let prefixlen = 0;
  while (rlength < numBytes) {
    let toHash;
    switch (this.type) {
      case 'simple':
        toHash = util.concatUint8Array([new Uint8Array(prefixlen), passphrase]);
        break;
      case 'salted':
        toHash = util.concatUint8Array([new Uint8Array(prefixlen), this.salt, passphrase]);
        break;
      case 'iterated': {
        const data = util.concatUint8Array([this.salt, passphrase]);
        let datalen = data.length;
        const count = Math.max(this.get_count(), datalen);
        toHash = new Uint8Array(prefixlen + count);
        toHash.set(data, prefixlen);
        for (let pos = prefixlen + datalen; pos < count; pos += datalen, datalen *= 2) {
          toHash.copyWithin(pos, prefixlen, pos);
        }
        break;
      }
      case 'gnu':
        throw new Error("GNU s2k type not supported.");
      default:
        throw new Error("Unknown s2k type.");
    }
    const result = await crypto.hash.digest(algorithm, toHash);
    arr.push(result);
    rlength += result.length;
    prefixlen++;
  }

  return util.concatUint8Array(arr).subarray(0, numBytes);
};

S2K.fromClone = function (clone) {
  const s2k = new S2K();
  s2k.algorithm = clone.algorithm;
  s2k.type = clone.type;
  s2k.c = clone.c;
  s2k.salt = clone.salt;
  return s2k;
};

export default S2K;
