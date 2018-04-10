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

import { AES_CTR } from 'asmcrypto.js/src/aes/ctr/exports';
import CMAC from './cmac';
import util from '../util';

const webCrypto = util.getWebCryptoAll();
const nodeCrypto = util.getNodeCrypto();
const Buffer = util.getNodeBuffer();


const blockLength = 16;
const ivLength = blockLength;
const tagLength = blockLength;

const zero = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
const one = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const two = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

class OMAC extends CMAC {
  mac(t, message) {
    return super.mac(concat(t, message));
  }
}


/**
 * Encrypt plaintext input.
 * @param  {String}     cipher      The symmetric cipher algorithm to use e.g. 'aes128'
 * @param  {Uint8Array} plaintext   The cleartext input to be encrypted
 * @param  {Uint8Array} key         The encryption key
 * @param  {Uint8Array} nonce       The nonce (16 bytes)
 * @param  {Uint8Array} adata       Associated data to sign
 * @returns {Promise<Uint8Array>}    The ciphertext output
 */
async function encrypt(cipher, plaintext, key, nonce, adata) {
  if (cipher.substr(0, 3) !== 'aes') {
    throw new Error('EAX mode supports only AES cipher');
  }

  const omac = new OMAC(key);
  const _nonce = omac.mac(zero, nonce);
  const _adata = omac.mac(one, adata);
  const ciphered = await CTR(plaintext, key, _nonce);
  const _ciphered = omac.mac(two, ciphered);
  const tag = xor3(_nonce, _ciphered, _adata); // Assumes that omac.mac(*).length === tagLength.
  return concat(ciphered, tag);
}

/**
 * Decrypt ciphertext input.
 * @param  {String}     cipher       The symmetric cipher algorithm to use e.g. 'aes128'
 * @param  {Uint8Array} ciphertext   The ciphertext input to be decrypted
 * @param  {Uint8Array} key          The encryption key
 * @param  {Uint8Array} nonce        The nonce (16 bytes)
 * @param  {Uint8Array} adata        Associated data to verify
 * @returns {Promise<Uint8Array>}     The plaintext output
 */
async function decrypt(cipher, ciphertext, key, nonce, adata) {
  if (cipher.substr(0, 3) !== 'aes') {
    throw new Error('EAX mode supports only AES cipher');
  }

  if (ciphertext.length < tagLength) throw new Error('Invalid EAX ciphertext');
  const ciphered = ciphertext.subarray(0, ciphertext.length - tagLength);
  const tag = ciphertext.subarray(ciphertext.length - tagLength);
  const omac = new OMAC(key);
  const _nonce = omac.mac(zero, nonce);
  const _adata = omac.mac(one, adata);
  const _ciphered = omac.mac(two, ciphered);
  const _tag = xor3(_nonce, _ciphered, _adata); // Assumes that omac.mac(*).length === tagLength.
  if (!util.equalsUint8Array(tag, _tag)) throw new Error('Authentication tag mismatch in EAX ciphertext');
  const plaintext = await CTR(ciphered, key, _nonce);
  return plaintext;
}

/**
 * Get EAX nonce as defined by {@link https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-04#section-5.16.1|RFC4880bis-04, section 5.16.1}.
 * @param  {Uint8Array} iv           The initialization vector (16 bytes)
 * @param  {Uint8Array} chunkIndex   The chunk index (8 bytes)
 */
function getNonce(iv, chunkIndex) {
  const nonce = iv.slice();
  for (let i = 0; i < chunkIndex.length; i++) {
    nonce[8 + i] ^= chunkIndex[i];
  }
  return nonce;
}


export default {
  blockLength,
  ivLength,
  encrypt,
  decrypt,
  getNonce
};


//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////


function xor3(a, b, c) {
  return a.map((n, i) => n ^ b[i] ^ c[i]);
}

function concat(...arrays) {
  return util.concatUint8Array(arrays);
}

function CTR(plaintext, key, iv) {
  if (util.getWebCryptoAll() && key.length !== 24) { // WebCrypto (no 192 bit support) see: https://www.chromium.org/blink/webcrypto#TOC-AES-support
    return webCtr(plaintext, key, iv);
  } else if (util.getNodeCrypto()) { // Node crypto library
    return nodeCtr(plaintext, key, iv);
  } // asm.js fallback
  return Promise.resolve(AES_CTR.encrypt(plaintext, key, iv));
}

function webCtr(pt, key, iv) {
  return webCrypto.importKey('raw', key, { name: 'AES-CTR', length: key.length * 8 }, false, ['encrypt'])
    .then(keyObj => webCrypto.encrypt({ name: 'AES-CTR', counter: iv, length: blockLength * 8 }, keyObj, pt))
    .then(ct => new Uint8Array(ct));
}

function nodeCtr(pt, key, iv) {
  pt = new Buffer(pt);
  key = new Buffer(key);
  iv = new Buffer(iv);
  const en = new nodeCrypto.createCipheriv('aes-' + (key.length * 8) + '-ctr', key, iv);
  const ct = Buffer.concat([en.update(pt), en.final()]);
  return Promise.resolve(new Uint8Array(ct));
}
