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
 * @requires asmcrypto.js
 * @requires util
 * @module crypto/gcm
 */

import { AES_GCM } from 'asmcrypto.js/dist_es5/aes/gcm';
import util from '../util';

const webCrypto = util.getWebCrypto(); // no GCM support in IE11, Safari 9
const nodeCrypto = util.getNodeCrypto();
const Buffer = util.getNodeBuffer();

const blockLength = 16;
const ivLength = 12; // size of the IV in bytes
const tagLength = 16; // size of the tag in bytes
const ALGO = 'AES-GCM';

/**
 * Class to en/decrypt using GCM mode.
 * @param  {String}     cipher      The symmetric cipher algorithm to use e.g. 'aes128'
 * @param  {Uint8Array} key         The encryption key
 */
async function GCM(cipher, key) {
  if (cipher.substr(0, 3) !== 'aes') {
    throw new Error('GCM mode supports only AES cipher');
  }

  if (util.getWebCrypto() && key.length !== 24) { // WebCrypto (no 192 bit support) see: https://www.chromium.org/blink/webcrypto#TOC-AES-support
    const _key = await webCrypto.importKey('raw', key, { name: ALGO }, false, ['encrypt', 'decrypt']);

    return {
      encrypt: async function(pt, iv, adata = new Uint8Array()) {
        if (
          !pt.length ||
          // iOS does not support GCM-en/decrypting empty messages
          // Also, synchronous en/decryption might be faster in this case.
          (!adata.length && navigator.userAgent.indexOf('Edge') !== -1)
          // Edge does not support GCM-en/decrypting without ADATA
        ) {
          return AES_GCM.encrypt(pt, key, iv, adata);
        }
        const ct = await webCrypto.encrypt({ name: ALGO, iv, additionalData: adata, tagLength: tagLength * 8 }, _key, pt);
        return new Uint8Array(ct);
      },

      decrypt: async function(ct, iv, adata = new Uint8Array()) {
        if (
          ct.length === tagLength ||
          // iOS does not support GCM-en/decrypting empty messages
          // Also, synchronous en/decryption might be faster in this case.
          (!adata.length && navigator.userAgent.indexOf('Edge') !== -1)
          // Edge does not support GCM-en/decrypting without ADATA
        ) {
          return AES_GCM.decrypt(ct, key, iv, adata);
        }
        const pt = await webCrypto.decrypt({ name: ALGO, iv, additionalData: adata, tagLength: tagLength * 8 }, _key, ct);
        return new Uint8Array(pt);
      }
    };
  }

  if (util.getNodeCrypto()) { // Node crypto library
    key = Buffer.from(key);

    return {
      encrypt: async function(pt, iv, adata = new Uint8Array()) {
        pt = Buffer.from(pt);
        iv = Buffer.from(iv);
        adata = Buffer.from(adata);
        const en = new nodeCrypto.createCipheriv('aes-' + (key.length * 8) + '-gcm', key, iv);
        en.setAAD(adata);
        const ct = Buffer.concat([en.update(pt), en.final(), en.getAuthTag()]); // append auth tag to ciphertext
        return new Uint8Array(ct);
      },

      decrypt: async function(ct, iv, adata = new Uint8Array()) {
        ct = Buffer.from(ct);
        iv = Buffer.from(iv);
        adata = Buffer.from(adata);
        const de = new nodeCrypto.createDecipheriv('aes-' + (key.length * 8) + '-gcm', key, iv);
        de.setAAD(adata);
        de.setAuthTag(ct.slice(ct.length - tagLength, ct.length)); // read auth tag at end of ciphertext
        const pt = Buffer.concat([de.update(ct.slice(0, ct.length - tagLength)), de.final()]);
        return new Uint8Array(pt);
      }
    };
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
 * @param  {Uint8Array} iv           The initialization vector (12 bytes)
 * @param  {Uint8Array} chunkIndex   The chunk index (8 bytes)
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
