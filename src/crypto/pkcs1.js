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
 * PKCS1 encoding
 * @requires crypto/crypto
 * @requires crypto/hash
 * @requires crypto/public_key/jsbn
 * @requires crypto/random
 * @requires util
 * @module crypto/pkcs1
 */

/**
 * ASN1 object identifiers for hashes (See {@link http://tools.ietf.org/html/rfc4880#section-5.2.2})
 */
hash_headers = [];
hash_headers[1] = [0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04,
    0x10
];
hash_headers[2] = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
hash_headers[3] = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14];
hash_headers[8] = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    0x04, 0x20
];
hash_headers[9] = [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00,
    0x04, 0x30
];
hash_headers[10] = [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40
];
hash_headers[11] = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
    0x00, 0x04, 0x1C
];

var crypto = require('./crypto.js'),
  random = require('./random.js'),
  util = require('../util.js'),
  BigInteger = require('./public_key/jsbn.js'),
  hash = require('./hash');

module.exports = {
  eme: {
    /**
     * create a EME-PKCS1-v1_5 padding (See {@link http://tools.ietf.org/html/rfc4880#section-13.1.1|RFC 4880 13.1.1})
     * @param {String} message message to be padded
     * @param {Integer} length Length to the resulting message
     * @return {String} EME-PKCS1 padded message
     */
    encode: function(message, length) {
      if (message.length > length - 11)
        return -1;
      var result = "";
      result += String.fromCharCode(0);
      result += String.fromCharCode(2);
      for (var i = 0; i < length - message.length - 3; i++) {
        result += String.fromCharCode(random.getPseudoRandom(1, 255));
      }
      result += String.fromCharCode(0);
      result += message;
      return result;
    },

    /**
     * decodes a EME-PKCS1-v1_5 padding (See {@link http://tools.ietf.org/html/rfc4880#section-13.1.2|RFC 4880 13.1.2})
     * @param {String} message EME-PKCS1 padded message
     * @return {String} decoded message
     */
    decode: function(message, len) {
      if (message.length < len)
        message = String.fromCharCode(0) + message;
      if (message.length < 12 || message.charCodeAt(0) !== 0 || message.charCodeAt(1) != 2)
        return -1;
      var i = 2;
      while (message.charCodeAt(i) !== 0 && message.length > i)
        i++;
      return message.substring(i + 1, message.length);
    }
  },

  emsa: {

    /**
     * create a EMSA-PKCS1-v1_5 padding (See {@link http://tools.ietf.org/html/rfc4880#section-13.1.3|RFC 4880 13.1.3})
     * @param {Integer} algo Hash algorithm type used
     * @param {String} data Data to be hashed
     * @param {Integer} keylength Key size of the public mpi in bytes
     * @returns {String} Hashcode with pkcs1padding as string
     */
    encode: function(algo, data, keylength) {
      var data2 = "";
      data2 += String.fromCharCode(0x00);
      data2 += String.fromCharCode(0x01);
      var i;
      for (i = 0; i < (keylength - hash_headers[algo].length - 3 -
        hash.getHashByteLength(algo)); i++)

        data2 += String.fromCharCode(0xff);

      data2 += String.fromCharCode(0x00);

      for (i = 0; i < hash_headers[algo].length; i++)
        data2 += String.fromCharCode(hash_headers[algo][i]);

      data2 += hash.digest(algo, data);
      return new BigInteger(util.hexstrdump(data2), 16);
    },

    /**
     * extract the hash out of an EMSA-PKCS1-v1.5 padding (See {@link http://tools.ietf.org/html/rfc4880#section-13.1.3|RFC 4880 13.1.3})
     * @param {String} data Hash in pkcs1 encoding
     * @returns {String} The hash as string
     */
    decode: function(algo, data) {
      var i = 0;
      if (data.charCodeAt(0) === 0) i++;
      else if (data.charCodeAt(0) != 1) return -1;
      else i++;

      while (data.charCodeAt(i) == 0xFF) i++;
      if (data.charCodeAt(i++) !== 0) return -1;
      var j = 0;
      for (j = 0; j < hash_headers[algo].length && j + i < data.length; j++) {
        if (data.charCodeAt(j + i) != hash_headers[algo][j]) return -1;
      }
      i += j;
      if (data.substring(i).length < hash.getHashByteLength(algo)) return -1;
      return data.substring(i);
    }
  }
};
