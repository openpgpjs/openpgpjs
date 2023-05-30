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
 * @module crypto/mode/gcm
 */

import { AES_GCM } from '@openpgp/asmcrypto.js/aes/gcm.js';
import util from '../../util';
import enums from '../../enums';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();
const Buffer = util.getNodeBuffer();

const blockLength = 16;
const ivLength = 12; // size of the IV in bytes
const tagLength = 16; // size of the tag in bytes
const ALGO = 'AES-GCM';

/**
 * Class to en/decrypt using GCM mode.
 * @param {enums.symmetric} cipher - The symmetric cipher algorithm to use
 * @param {Uint8Array} key - The encryption key
 */
async function GCM(cipher, key) {
  if (cipher !== enums.symmetric.aes128 &&
    cipher !== enums.symmetric.aes192 &&
    cipher !== enums.symmetric.aes256) {
    throw new Error('GCM mode supports only AES cipher');
  }

  if (util.getNodeCrypto()) { // Node crypto library
    return {
      encrypt: async function(pt, iv, adata = new Uint8Array()) {
        const en = new nodeCrypto.createCipheriv('aes-' + (key.length * 8) + '-gcm', key, iv);
        en.setAAD(adata);
        const ct = Buffer.concat([en.update(pt), en.final(), en.getAuthTag()]); // append auth tag to ciphertext
        return new Uint8Array(ct);
      },

      decrypt: async function(ct, iv, adata = new Uint8Array()) {
        const de = new nodeCrypto.createDecipheriv('aes-' + (key.length * 8) + '-gcm', key, iv);
        de.setAAD(adata);
        de.setAuthTag(ct.slice(ct.length - tagLength, ct.length)); // read auth tag at end of ciphertext
        const pt = Buffer.concat([de.update(ct.slice(0, ct.length - tagLength)), de.final()]);
        return new Uint8Array(pt);
      }
    };
  }

  if (util.getWebCrypto()) {
    try {
      const _key = await webCrypto.importKey('raw', key, { name: ALGO }, false, ['encrypt', 'decrypt']);
      // Safari 13 and Safari iOS 14 does not support GCM-en/decrypting empty messages
      const webcryptoEmptyMessagesUnsupported = navigator.userAgent.match(/Version\/13\.\d(\.\d)* Safari/) ||
        navigator.userAgent.match(/Version\/(13|14)\.\d(\.\d)* Mobile\/\S* Safari/);
      return {
        encrypt: async function(pt, iv, adata = new Uint8Array()) {
          if (webcryptoEmptyMessagesUnsupported && !pt.length) {
            return AES_GCM.encrypt(pt, key, iv, adata);
          }
          const ct = await webCrypto.encrypt({ name: ALGO, iv, additionalData: adata, tagLength: tagLength * 8 }, _key, pt);
          return new Uint8Array(ct);
        },

        decrypt: async function(ct, iv, adata = new Uint8Array()) {
          if (webcryptoEmptyMessagesUnsupported && ct.length === tagLength) {
            return AES_GCM.decrypt(ct, key, iv, adata);
          }
          const pt = await webCrypto.decrypt({ name: ALGO, iv, additionalData: adata, tagLength: tagLength * 8 }, _key, ct);
          return new Uint8Array(pt);
        }
      };
    } catch (err) {
      // no 192 bit support in Chromium, which throws `OperationError`, see: https://www.chromium.org/blink/webcrypto#TOC-AES-support
      if (err.name !== 'NotSupportedError' &&
        !(key.length === 24 && err.name === 'OperationError')) {
        throw err;
      }
      util.printDebugError('Browser did not support operation: ' + err.message);
    }
  }

  return {
    encrypt: async function(pt, iv, adata) {
      return AES_GCM.encrypt(pt, key, iv, adata);
    },

    decrypt: async function(ct, iv, adata) {
      return AES_GCM.decrypt(ct, key, iv, adata);
    }
  };
}


/**
 * Get GCM nonce. Note: this operation is not defined by the standard.
 * A future version of the standard may define GCM mode differently,
 * hopefully under a different ID (we use Private/Experimental algorithm
 * ID 100) so that we can maintain backwards compatibility.
 * @param {Uint8Array} iv - The initialization vector (12 bytes)
 * @param {Uint8Array} chunkIndex - The chunk index (8 bytes)
 */
GCM.getNonce = function(iv, chunkIndex) {
  const nonce = iv.slice();
  for (let i = 0; i < chunkIndex.length; i++) {
    nonce[4 + i] ^= chunkIndex[i];
  }
  return nonce;
};

GCM.blockLength = blockLength;
GCM.ivLength = ivLength;
GCM.tagLength = tagLength;

export default GCM;
