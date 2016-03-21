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
import asmCrypto from 'asmcrypto-lite';
const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();
const Buffer = util.getNodeBuffer();

export const ivLength = 12;

/**
 * Encrypt plaintext input.
 * @param  {String}     cipher      The symmetric cipher algorithm to use
 * @param  {Uint8Array} plaintext   The cleartext input to be encrypted
 * @param  {Uint8Array} key         The encryption key
 * @param  {Uint8Array} iv          The initialization vector (12 bytes)
 * @return {Promise<Uint8Array>}    The ciphertext output
 */
export function encrypt(cipher, plaintext, key, iv) {
  if (cipher.substr(0,3) !== 'aes') {
    return Promise.reject(new Error('Invalid cipher for GCM mode'));
  }

  if (webCrypto) { // native WebCrypto api
    const keyOptions = {
      name: 'AES-GCM'
    },
    encryptOptions = {
      name: 'AES-GCM',
      iv: iv
    };
    return webCrypto.importKey('raw', key, keyOptions, false, ['encrypt']).then(keyObj => {
      return webCrypto.encrypt(encryptOptions, keyObj, plaintext);
    }).then(ciphertext => {
      return new Uint8Array(ciphertext);
    });

  } else if(nodeCrypto) { // native node crypto library
    let cipherObj = new nodeCrypto.createCipheriv('aes-' + cipher.substr(3,3) + '-gcm', new Buffer(key), new Buffer(iv));
    let encrypted = Buffer.concat([cipherObj.update(new Buffer(plaintext)), cipherObj.final()]);
    return Promise.resolve(new Uint8Array(encrypted));

  } else { // asm.js fallback
    return Promise.resolve(asmCrypto.AES_GCM.encrypt(plaintext, key, iv));
  }
}

/**
 * Decrypt ciphertext input
 * @param  {String}     cipher       The symmetric cipher algorithm to use
 * @param  {Uint8Array} ciphertext   The ciphertext input to be decrypted
 * @param  {Uint8Array} key          The encryption key
 * @param  {Uint8Array} iv           The initialization vector (12 bytes)
 * @return {Promise<Uint8Array>}     The plaintext output
 */
export function decrypt(cipher, ciphertext, key, iv) {
  if (cipher.substr(0,3) !== 'aes') {
    return Promise.reject(new Error('Invalid cipher for GCM mode'));
  }

  if (webCrypto) { // native WebCrypto api
    const keyOptions = {
      name: 'AES-GCM'
    },
    decryptOptions = {
      name: 'AES-GCM',
      iv: iv
    };
    return webCrypto.importKey('raw', key, keyOptions, false, ['decrypt']).then(keyObj => {
      return webCrypto.decrypt(decryptOptions, keyObj, ciphertext);
    }).then(plaintext => {
      return new Uint8Array(plaintext);
    });

  } else if(nodeCrypto) { // native node crypto library
    let decipherObj = new nodeCrypto.createDecipheriv('aes-' + cipher.substr(3,3) + '-gcm', new Buffer(key), new Buffer(iv));
    let decrypted = Buffer.concat([decipherObj.update(new Buffer(ciphertext)), decipherObj.final()]);
    return Promise.resolve(new Uint8Array(decrypted));

  } else { // asm.js fallback
    return Promise.resolve(asmCrypto.AES_GCM.decrypt(ciphertext, key, iv));
  }
}