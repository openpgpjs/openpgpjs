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
 * @module crypto/aes_kw
 */

import { AES_CBC } from '@openpgp/asmcrypto.js/aes/cbc.js';
import { getCipherParams } from './cipher';
import util from '../util';

const webCrypto = util.getWebCrypto();
/**
 * AES key wrap
 * @param {enums.symmetric.aes128|enums.symmetric.aes256|enums.symmetric.aes192} algo - AES algo
 * @param {Uint8Array} key - wrapping key
 * @param {Uint8Array} dataToWrap
 * @returns {Uint8Array} wrapped key
 */
export async function wrap(algo, key, dataToWrap) {
  const { keySize } = getCipherParams(algo);
  // sanity checks, since WebCrypto does not use the `algo` input
  if (!util.isAES(algo) || key.length !== keySize) {
    throw new Error('Unexpected algorithm or key size');
  }

  try {
    const wrappingKey = await webCrypto.importKey('raw', key, { name: 'AES-KW' }, false, ['wrapKey']);
    // Import data as HMAC key, as it has no key length requirements
    const keyToWrap = await webCrypto.importKey('raw', dataToWrap, { name: 'HMAC', hash: 'SHA-256' }, true, ['sign']);
    const wrapped = await webCrypto.wrapKey('raw', keyToWrap, wrappingKey, { name: 'AES-KW' });
    return new Uint8Array(wrapped);
  } catch (err) {
    // no 192 bit support in Chromium, which throws `OperationError`, see: https://www.chromium.org/blink/webcrypto#TOC-AES-support
    if (err.name !== 'NotSupportedError' &&
      !(key.length === 24 && err.name === 'OperationError')) {
      throw err;
    }
    util.printDebugError('Browser did not support operation: ' + err.message);
  }

  return asmcryptoWrap(algo, key, dataToWrap);
}

/**
 * AES key unwrap
 * @param {enums.symmetric.aes128|enums.symmetric.aes256|enums.symmetric.aes192} algo - AES algo
 * @param {Uint8Array} key - wrapping key
 * @param {Uint8Array} wrappedData
 * @returns {Uint8Array} unwrapped data
 */
export async function unwrap(algo, key, wrappedData) {
  const { keySize } = getCipherParams(algo);
  // sanity checks, since WebCrypto does not use the `algo` input
  if (!util.isAES(algo) || key.length !== keySize) {
    throw new Error('Unexpected algorithm or key size');
  }

  let wrappingKey;
  try {
    wrappingKey = await webCrypto.importKey('raw', key, { name: 'AES-KW' }, false, ['unwrapKey']);
  } catch (err) {
    // no 192 bit support in Chromium, which throws `OperationError`, see: https://www.chromium.org/blink/webcrypto#TOC-AES-support
    if (err.name !== 'NotSupportedError' &&
      !(key.length === 24 && err.name === 'OperationError')) {
      throw err;
    }
    util.printDebugError('Browser did not support operation: ' + err.message);
    return asmcryptoUnwrap(algo, key, wrappedData);
  }

  try {
    const unwrapped = await webCrypto.unwrapKey('raw', wrappedData, wrappingKey, { name: 'AES-KW' }, { name: 'HMAC', hash: 'SHA-256' }, true, ['sign']);
    return new Uint8Array(await webCrypto.exportKey('raw', unwrapped));
  } catch (err) {
    if (err.name === 'OperationError') {
      throw new Error('Key Data Integrity failed');
    }
    throw err;
  }
}

function asmcryptoWrap(aesAlgo, key, data) {
  const aesInstance = new AES_CBC(key, new Uint8Array(16), false);
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
      B = unpack(aesInstance.encrypt(pack(B)));
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

function asmcryptoUnwrap(aesAlgo, key, data) {
  const aesInstance = new AES_CBC(key, new Uint8Array(16), false);
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
      B = unpack(aesInstance.decrypt(pack(B)));
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
  throw new Error('Key Data Integrity failed');
}

function unpack(data) {
  const buffer = data.buffer;
  const view = new DataView(buffer);
  const arr = new Uint32Array(data.length / 4);
  for (let i = 0; i < data.length / 4; ++i) {
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
