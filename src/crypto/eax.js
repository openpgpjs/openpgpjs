// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2018 ProtonTech AG
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
 * @fileoverview This module implements AES-EAX en/decryption on top of
 * native AES-CTR using either the WebCrypto API or Node.js' crypto API.
 * @requires asmcrypto.js
 * @requires crypto/cmac
 * @requires util
 * @module crypto/eax
 */

import { AES_CTR } from 'asmcrypto.js/dist_es5/aes/ctr';
import CMAC from './cmac';
import util from '../util';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();
const Buffer = util.getNodeBuffer();


const blockLength = 16;
const ivLength = blockLength;
const tagLength = blockLength;

const zero = new Uint8Array(blockLength);
const one = new Uint8Array(blockLength); one[blockLength - 1] = 1;
const two = new Uint8Array(blockLength); two[blockLength - 1] = 2;

async function OMAC(key) {
  const cmac = await CMAC(key);
  return function(t, message) {
    return cmac(util.concatUint8Array([t, message]));
  };
}

async function CTR(key) {
  if (
    util.getWebCrypto() &&
    key.length !== 24 && // WebCrypto (no 192 bit support) see: https://www.chromium.org/blink/webcrypto#TOC-AES-support
    navigator.userAgent.indexOf('Edge') === -1
  ) {
    key = await webCrypto.importKey('raw', key, { name: 'AES-CTR', length: key.length * 8 }, false, ['encrypt']);
    return async function(pt, iv) {
      const ct = await webCrypto.encrypt({ name: 'AES-CTR', counter: iv, length: blockLength * 8 }, key, pt);
      return new Uint8Array(ct);
    };
  }
  if (util.getNodeCrypto()) { // Node crypto library
    key = Buffer.from(key);
    return async function(pt, iv) {
      pt = Buffer.from(pt);
      iv = Buffer.from(iv);
      const en = new nodeCrypto.createCipheriv('aes-' + (key.length * 8) + '-ctr', key, iv);
      const ct = Buffer.concat([en.update(pt), en.final()]);
      return new Uint8Array(ct);
    };
  }
  // asm.js fallback
  return async function(pt, iv) {
    return AES_CTR.encrypt(pt, key, iv);
  };
}


/**
 * Class to en/decrypt using EAX mode.
 * @param  {String}     cipher      The symmetric cipher algorithm to use e.g. 'aes128'
 * @param  {Uint8Array} key         The encryption key
 */
async function EAX(cipher, key) {
  if (cipher.substr(0, 3) !== 'aes') {
    throw new Error('EAX mode supports only AES cipher');
  }

  const [
    omac,
    ctr
  ] = await Promise.all([
    OMAC(key),
    CTR(key)
  ]);

  return {
    /**
     * Encrypt plaintext input.
     * @param  {Uint8Array} plaintext   The cleartext input to be encrypted
     * @param  {Uint8Array} nonce       The nonce (16 bytes)
     * @param  {Uint8Array} adata       Associated data to sign
     * @returns {Promise<Uint8Array>}    The ciphertext output
     */
    encrypt: async function(plaintext, nonce, adata) {
      const [
        omacNonce,
        omacAdata
      ] = await Promise.all([
        omac(zero, nonce),
        omac(one, adata)
      ]);
      const ciphered = await ctr(plaintext, omacNonce);
      const omacCiphered = await omac(two, ciphered);
      const tag = omacCiphered; // Assumes that omac(*).length === tagLength.
      for (let i = 0; i < tagLength; i++) {
        tag[i] ^= omacAdata[i] ^ omacNonce[i];
      }
      return util.concatUint8Array([ciphered, tag]);
    },

    /**
     * Decrypt ciphertext input.
     * @param  {Uint8Array} ciphertext   The ciphertext input to be decrypted
     * @param  {Uint8Array} nonce        The nonce (16 bytes)
     * @param  {Uint8Array} adata        Associated data to verify
     * @returns {Promise<Uint8Array>}     The plaintext output
     */
    decrypt: async function(ciphertext, nonce, adata) {
      if (ciphertext.length < tagLength) throw new Error('Invalid EAX ciphertext');
      const ciphered = ciphertext.subarray(0, -tagLength);
      const ctTag = ciphertext.subarray(-tagLength);
      const [
        omacNonce,
        omacAdata,
        omacCiphered
      ] = await Promise.all([
        omac(zero, nonce),
        omac(one, adata),
        omac(two, ciphered)
      ]);
      const tag = omacCiphered; // Assumes that omac(*).length === tagLength.
      for (let i = 0; i < tagLength; i++) {
        tag[i] ^= omacAdata[i] ^ omacNonce[i];
      }
      if (!util.equalsUint8Array(ctTag, tag)) throw new Error('Authentication tag mismatch');
      const plaintext = await ctr(ciphered, omacNonce);
      return plaintext;
    }
  };
}


/**
 * Get EAX nonce as defined by {@link https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-04#section-5.16.1|RFC4880bis-04, section 5.16.1}.
 * @param  {Uint8Array} iv           The initialization vector (16 bytes)
 * @param  {Uint8Array} chunkIndex   The chunk index (8 bytes)
 */
EAX.getNonce = function(iv, chunkIndex) {
  const nonce = iv.slice();
  for (let i = 0; i < chunkIndex.length; i++) {
    nonce[8 + i] ^= chunkIndex[i];
  }
  return nonce;
};

EAX.blockLength = blockLength;
EAX.ivLength = ivLength;
EAX.tagLength = tagLength;

export default EAX;
