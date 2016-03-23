// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2016 Tankred Hase
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
 * @fileoverview This module wraps native AES-GCM en/decryption for both
 * the WebCrypto api as well as node.js' crypto api.
 */

'use strict';

import util from '../util.js';
import config from '../config';
import asmCrypto from 'asmcrypto-lite';
const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();
const Buffer = util.getNodeBuffer();

export const ivLength = 12; // size of the IV in bytes
const TAG_LEN = 16; // size of the tag in bytes
const ALGO = 'AES-GCM';

/**
 * Encrypt plaintext input.
 * @param  {String}     cipher      The symmetric cipher algorithm to use e.g. 'aes128'
 * @param  {Uint8Array} plaintext   The cleartext input to be encrypted
 * @param  {Uint8Array} key         The encryption key
 * @param  {Uint8Array} iv          The initialization vector (12 bytes)
 * @return {Promise<Uint8Array>}    The ciphertext output
 */
export function encrypt(cipher, plaintext, key, iv) {
  if (cipher.substr(0,3) !== 'aes') {
    return Promise.reject(new Error('GCM mode supports only AES cipher'));
  }

  const keySize = key.length * 8;
  if (webCrypto && config.useNative && keySize !== 192) { // WebCrypto (no 192 bit support) see: https://www.chromium.org/blink/webcrypto#TOC-AES-support
    return webCrypto.importKey('raw', key, { name: ALGO }, false, ['encrypt'])
      .then(keyObj => webCrypto.encrypt({ name: ALGO, iv }, keyObj, plaintext))
      .then(ciphertext => new Uint8Array(ciphertext));

  } else if (nodeCrypto && config.useNative) { // Node crypto library
    const en = new nodeCrypto.createCipheriv('aes-' + keySize + '-gcm', new Buffer(key.buffer), new Buffer(iv.buffer));
    const encrypted = Buffer.concat([en.update(new Buffer(plaintext.buffer)), en.final()]);
    return Promise.resolve(new Uint8Array(Buffer.concat([encrypted, en.getAuthTag()])));

  } else { // asm.js fallback
    return Promise.resolve(asmCrypto.AES_GCM.encrypt(plaintext, key, iv));
  }
}

/**
 * Decrypt ciphertext input
 * @param  {String}     cipher       The symmetric cipher algorithm to use e.g. 'aes128'
 * @param  {Uint8Array} ciphertext   The ciphertext input to be decrypted
 * @param  {Uint8Array} key          The encryption key
 * @param  {Uint8Array} iv           The initialization vector (12 bytes)
 * @return {Promise<Uint8Array>}     The plaintext output
 */
export function decrypt(cipher, ciphertext, key, iv) {
  if (cipher.substr(0,3) !== 'aes') {
    return Promise.reject(new Error('GCM mode supports only AES cipher'));
  }

  const keySize = key.length * 8;
  if (webCrypto && config.useNative && keySize !== 192) { // WebCrypto (no 192 bit support) see: https://www.chromium.org/blink/webcrypto#TOC-AES-support
    return webCrypto.importKey('raw', key, { name: ALGO }, false, ['decrypt'])
      .then(keyObj => webCrypto.decrypt({ name: ALGO, iv }, keyObj, ciphertext))
      .then(plaintext => new Uint8Array(plaintext));

  } else if (nodeCrypto && config.useNative) { // Node crypto library
    const ctBuf = new Buffer(ciphertext.buffer);
    const de = new nodeCrypto.createDecipheriv('aes-' + keySize + '-gcm', new Buffer(key.buffer), new Buffer(iv.buffer));
    de.setAuthTag(ctBuf.slice(ctBuf.length - TAG_LEN, ctBuf.length));
    const encrypted = ctBuf.slice(0, ctBuf.length - TAG_LEN);
    return Promise.resolve(new Uint8Array(Buffer.concat([de.update(encrypted), de.final()])));

  } else { // asm.js fallback
    return Promise.resolve(asmCrypto.AES_GCM.decrypt(ciphertext, key, iv));
  }
}