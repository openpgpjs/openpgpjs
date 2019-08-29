// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015-2016 Decentral
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
 * @fileoverview Implementation of RFC 3394 AES Key Wrap & Key Unwrap funcions
 * @see module:crypto/public_key/elliptic/ecdh
 * @requires crypto/cipher
 * @requires util
 * @module crypto/aes_kw
 */

import cipher from './cipher';
import util from '../util';

function wrap(key, data) {
  const aes = new cipher["aes" + (key.length * 8)](key);
  const IV = new Uint32Array([0xA6A6A6A6, 0xA6A6A6A6]);
  const P = unpack(data);
  let A = IV;
  const R = P;
  const n = P.length / 2;
  const t = new Uint32Array([0, 0]);
  let B = new Uint32Array(4);
  for (let j = 0; j <= 5; ++j) {
    for (let i = 0; i < n; ++i) {
      t[1] = n * j + (1 + i);
      // B = A
      B[0] = A[0];
      B[1] = A[1];
      // B = A || R[i]
      B[2] = R[2 * i];
      B[3] = R[2 * i + 1];
      // B = AES(K, B)
      B = unpack(aes.encrypt(pack(B)));
      // A = MSB(64, B) ^ t
      A = B.subarray(0, 2);
      A[0] ^= t[0];
      A[1] ^= t[1];
      // R[i] = LSB(64, B)
      R[2 * i] = B[2];
      R[2 * i + 1] = B[3];
    }
  }
  return pack(A, R);
}

function unwrap(key, data) {
  const aes = new cipher["aes" + (key.length * 8)](key);
  const IV = new Uint32Array([0xA6A6A6A6, 0xA6A6A6A6]);
  const C = unpack(data);
  let A = C.subarray(0, 2);
  const R = C.subarray(2);
  const n = C.length / 2 - 1;
  const t = new Uint32Array([0, 0]);
  let B = new Uint32Array(4);
  for (let j = 5; j >= 0; --j) {
    for (let i = n - 1; i >= 0; --i) {
      t[1] = n * j + (i + 1);
      // B = A ^ t
      B[0] = A[0] ^ t[0];
      B[1] = A[1] ^ t[1];
      // B = (A ^ t) || R[i]
      B[2] = R[2 * i];
      B[3] = R[2 * i + 1];
      // B = AES-1(B)
      B = unpack(aes.decrypt(pack(B)));
      // A = MSB(64, B)
      A = B.subarray(0, 2);
      // R[i] = LSB(64, B)
      R[2 * i] = B[2];
      R[2 * i + 1] = B[3];
    }
  }
  if (A[0] === IV[0] && A[1] === IV[1]) {
    return pack(R);
  }
  throw new Error("Key Data Integrity failed");
}

function createArrayBuffer(data) {
  if (util.isString(data)) {
    const { length } = data;
    const buffer = new ArrayBuffer(length);
    const view = new Uint8Array(buffer);
    for (let j = 0; j < length; ++j) {
      view[j] = data.charCodeAt(j);
    }
    return buffer;
  }
  return new Uint8Array(data).buffer;
}

function unpack(data) {
  const { length } = data;
  const buffer = createArrayBuffer(data);
  const view = new DataView(buffer);
  const arr = new Uint32Array(length / 4);
  for (let i = 0; i < length / 4; ++i) {
    arr[i] = view.getUint32(4 * i);
  }
  return arr;
}

function pack() {
  let length = 0;
  for (let k = 0; k < arguments.length; ++k) {
    length += 4 * arguments[k].length;
  }
  const buffer = new ArrayBuffer(length);
  const view = new DataView(buffer);
  let offset = 0;
  for (let i = 0; i < arguments.length; ++i) {
    for (let j = 0; j < arguments[i].length; ++j) {
      view.setUint32(offset + 4 * j, arguments[i][j]);
    }
    offset += 4 * arguments[i].length;
  }
  return new Uint8Array(buffer);
}

export default {
  /**
   * AES key wrap
   * @function
   * @param {String} key
   * @param {String} data
   * @returns {Uint8Array}
   */
  wrap,
  /**
   * AES key unwrap
   * @function
   * @param {String} key
   * @param {String} data
   * @returns {Uint8Array}
   * @throws {Error}
   */
  unwrap
};
