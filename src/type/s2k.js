// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
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
 * Implementation of the String-to-key specifier ({@link http://tools.ietf.org/html/rfc4880#section-3.7|RFC4880 3.7})<br/>
 * <br/>
 * String-to-key (S2K) specifiers are used to convert passphrase strings
 * into symmetric-key encryption/decryption keys.  They are used in two
 * places, currently: to encrypt the secret part of private keys in the
 * private keyring, and to convert passphrases to encryption keys for
 * symmetrically encrypted messages.
 * @requires crypto
 * @requires enums
 * @requires util
 * @module type/s2k
 */

module.exports = S2K;

var enums = require('../enums.js'),
  util = require('../util.js'),
  crypto = require('../crypto');

/**
 * @constructor
 */
function S2K() {
  /** @type {module:enums.hash} */
  this.algorithm = 'sha256';
  /** @type {module:enums.s2k} */
  this.type = 'iterated';
  this.c = 96;
  /** Eight bytes of salt in a binary string.
   * @type {String}
   */
  this.salt = crypto.random.getRandomBytes(8);
}

S2K.prototype.get_count = function () {
  // Exponent bias, defined in RFC4880
  var expbias = 6;

  return (16 + (this.c & 15)) << ((this.c >> 4) + expbias);
};

/**
 * Parsing function for a string-to-key specifier ({@link http://tools.ietf.org/html/rfc4880#section-3.7|RFC 4880 3.7}).
 * @param {String} input Payload of string-to-key specifier
 * @return {Integer} Actual length of the object
 */
S2K.prototype.read = function (bytes) {
  var i = 0;
  this.type = enums.read(enums.s2k, bytes.charCodeAt(i++));
  this.algorithm = enums.read(enums.hash, bytes.charCodeAt(i++));

  switch (this.type) {
    case 'simple':
      break;

    case 'salted':
      this.salt = bytes.substr(i, 8);
      i += 8;
      break;

    case 'iterated':
      this.salt = bytes.substr(i, 8);
      i += 8;

      // Octet 10: count, a one-octet, coded value
      this.c = bytes.charCodeAt(i++);
      break;

    case 'gnu':
      if (bytes.substr(i, 3) == "GNU") {
        i += 3; // GNU
        var gnuExtType = 1000 + bytes.charCodeAt(i++);
        if (gnuExtType == 1001) {
          this.type = gnuExtType;
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
 * writes an s2k hash based on the inputs.
 * @return {String} Produced key of hashAlgorithm hash length
 */
S2K.prototype.write = function () {
  var bytes = String.fromCharCode(enums.write(enums.s2k, this.type));
  bytes += String.fromCharCode(enums.write(enums.hash, this.algorithm));

  switch (this.type) {
    case 'simple':
      break;
    case 'salted':
      bytes += this.salt;
      break;
    case 'iterated':
      bytes += this.salt;
      bytes += String.fromCharCode(this.c);
      break;
  }

  return bytes;
};

/**
 * Produces a key using the specified passphrase and the defined
 * hashAlgorithm
 * @param {String} passphrase Passphrase containing user input
 * @return {String} Produced key with a length corresponding to
 * hashAlgorithm hash length
 */
S2K.prototype.produce_key = function (passphrase, numBytes) {
  passphrase = util.encode_utf8(passphrase);

  function round(prefix, s2k) {
    var algorithm = enums.write(enums.hash, s2k.algorithm);

    switch (s2k.type) {
      case 'simple':
        return crypto.hash.digest(algorithm, prefix + passphrase);

      case 'salted':
        return crypto.hash.digest(algorithm,
          prefix + s2k.salt + passphrase);

      case 'iterated':
        var isp = [],
          count = s2k.get_count();
        data = s2k.salt + passphrase;

        while (isp.length * data.length < count)
          isp.push(data);

        isp = isp.join('');

        if (isp.length > count)
          isp = isp.substr(0, count);

        return crypto.hash.digest(algorithm, prefix + isp);
    }
  }

  var result = '',
    prefix = '';

  while (result.length <= numBytes) {
    result += round(prefix, this);
    prefix += String.fromCharCode(0);
  }

  return result.substr(0, numBytes);
};

module.exports.fromClone = function (clone) {
  var s2k = new S2K();
  this.algorithm = clone.algorithm;
  this.type = clone.type;
  this.c = clone.c;
  this.salt = clone.salt;
  return s2k;
};
