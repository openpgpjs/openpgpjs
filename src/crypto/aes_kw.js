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
 * @access private
 */

import { aeskw as nobleAesKW } from '@noble/ciphers/aes';
import { getCipherParams } from './cipher';
import util from '../util';

const webCrypto = util.getWebCrypto();
/**
 * AES key wrap
 * @param {enums.symmetric.aes128|enums.symmetric.aes256|enums.symmetric.aes192} algo - AES algo
 * @param {Uint8Array} key - wrapping key
 * @param {Uint8Array} dataToWrap
 * @returns {Promise<Uint8Array>} wrapped key
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

  return nobleAesKW(key).encrypt(dataToWrap);
}

/**
 * AES key unwrap
 * @param {enums.symmetric.aes128|enums.symmetric.aes256|enums.symmetric.aes192} algo - AES algo
 * @param {Uint8Array} key - wrapping key
 * @param {Uint8Array} wrappedData
 * @returns {Promise<Uint8Array>} unwrapped data
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
    return nobleAesKW(key).decrypt(wrappedData);
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
