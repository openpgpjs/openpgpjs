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
 * @fileoverview Provides EME-PKCS1-v1_5 encoding and decoding and EMSA-PKCS1-v1_5 encoding function
 * @see module:crypto/public_key/rsa
 * @see module:crypto/public_key/elliptic/ecdh
 * @see PublicKeyEncryptedSessionKeyPacket
 * @requires crypto/random
 * @requires crypto/hash
 * @module crypto/pkcs1
 */

import random from './random';
import hash from './hash';

/** @namespace */
const eme = {};
/** @namespace */
const emsa = {};

/**
 * ASN1 object identifiers for hashes
 * @see {@link https://tools.ietf.org/html/rfc4880#section-5.2.2}
 */
const hash_headers = [];
hash_headers[1] = [0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04,
  0x10];
hash_headers[2] = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
hash_headers[3] = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14];
hash_headers[8] = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
  0x04, 0x20];
hash_headers[9] = [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00,
  0x04, 0x30];
hash_headers[10] = [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
  0x00, 0x04, 0x40];
hash_headers[11] = [0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
  0x00, 0x04, 0x1C];

/**
 * Create padding with secure random data
 * @private
 * @param  {Integer}      length Length of the padding in bytes
 * @returns {Uint8Array}  Random padding
 * @async
 */
async function getPkcs1Padding(length) {
  const result = new Uint8Array(length);
  let count = 0;
  while (count < length) {
    const randomBytes = await random.getRandomBytes(length - count);
    for (let i = 0; i < randomBytes.length; i++) {
      if (randomBytes[i] !== 0) {
        result[count++] = randomBytes[i];
      }
    }
  }
  return result;
}

/**
 * Create a EME-PKCS1-v1_5 padded message
 * @see {@link https://tools.ietf.org/html/rfc4880#section-13.1.1|RFC 4880 13.1.1}
 * @param {Uint8Array} message message to be encoded
 * @param {Integer} keyLength the length in octets of the key modulus
 * @returns {Promise<Uint8Array>} EME-PKCS1 padded message
 * @async
 */
eme.encode = async function(message, keyLength) {
  const mLength = message.length;
  // length checking
  if (mLength > keyLength - 11) {
    throw new Error('Message too long');
  }
  // Generate an octet string PS of length k - mLen - 3 consisting of
  // pseudo-randomly generated nonzero octets
  const PS = await getPkcs1Padding(keyLength - mLength - 3);
  // Concatenate PS, the message M, and other padding to form an
  // encoded message EM of length k octets as EM = 0x00 || 0x02 || PS || 0x00 || M.
  const encoded = new Uint8Array(keyLength);
  // 0x00 byte
  encoded[1] = 2;
  encoded.set(PS, 2);
  // 0x00 bytes
  encoded.set(message, keyLength - mLength);
  return encoded;
};

/**
 * Decode a EME-PKCS1-v1_5 padded message
 * @see {@link https://tools.ietf.org/html/rfc4880#section-13.1.2|RFC 4880 13.1.2}
 * @param {Uint8Array} encoded encoded message bytes
 * @returns {Uint8Array} message
 */
eme.decode = function(encoded) {
  let i = 2;
  while (encoded[i] !== 0 && i < encoded.length) {
    i++;
  }
  const psLen = i - 2;
  const separator = encoded[i++];
  if (encoded[0] === 0 && encoded[1] === 2 && psLen >= 8 && separator === 0) {
    return encoded.subarray(i);
  }
  throw new Error('Decryption error');
};

/**
 * Create a EMSA-PKCS1-v1_5 padded message
 * @see {@link https://tools.ietf.org/html/rfc4880#section-13.1.3|RFC 4880 13.1.3}
 * @param {Integer} algo Hash algorithm type used
 * @param {Uint8Array} hashed message to be encoded
 * @param {Integer} emLen intended length in octets of the encoded message
 * @returns {Uint8Array} encoded message
 */
emsa.encode = async function(algo, hashed, emLen) {
  let i;
  if (hashed.length !== hash.getHashByteLength(algo)) {
    throw new Error('Invalid hash length');
  }
  // produce an ASN.1 DER value for the hash function used.
  // Let T be the full hash prefix
  const hashPrefix = new Uint8Array(hash_headers[algo].length);
  for (i = 0; i < hash_headers[algo].length; i++) {
    hashPrefix[i] = hash_headers[algo][i];
  }
  // and let tLen be the length in octets prefix and hashed data
  const tLen = hashPrefix.length + hashed.length;
  if (emLen < tLen + 11) {
    throw new Error('Intended encoded message length too short');
  }
  // an octet string PS consisting of emLen - tLen - 3 octets with hexadecimal value 0xFF
  // The length of PS will be at least 8 octets
  const PS = new Uint8Array(emLen - tLen - 3).fill(0xff);

  // Concatenate PS, the hash prefix, hashed data, and other padding to form the
  // encoded message EM as EM = 0x00 || 0x01 || PS || 0x00 || prefix || hashed
  const EM = new Uint8Array(emLen);
  EM[1] = 0x01;
  EM.set(PS, 2);
  EM.set(hashPrefix, emLen - tLen);
  EM.set(hashed, emLen - hashed.length);
  return EM;
};

export default { eme, emsa };
