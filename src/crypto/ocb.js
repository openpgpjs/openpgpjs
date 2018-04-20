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
 * @fileoverview This module implements AES-OCB en/decryption.
 * @requires crypto/cipher
 * @requires util
 * @module crypto/ocb
 */

import ciphers from './cipher';
import util from '../util';


const blockLength = 16;
const ivLength = 15;

// https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-04#section-5.16.2:
// While OCB [RFC7253] allows the authentication tag length to be of any
// number up to 128 bits long, this document requires a fixed
// authentication tag length of 128 bits (16 octets) for simplicity.
const tagLength = 16;


function ntz(n) {
  let ntz = 0;
  for(let i = 1; (n & i) === 0; i <<= 1) {
    ntz++;
  }
  return ntz;
}

function xorMut(S, T) {
  for (let i = 0; i < S.length; i++) {
    S[i] ^= T[i];
  }
  return S;
}

function xor(S, T) {
  return xorMut(S.slice(), T);
}

const zeroBlock = new Uint8Array(blockLength);
const one = new Uint8Array([1]);

/**
 * Class to en/decrypt using OCB mode.
 * @param  {String}     cipher      The symmetric cipher algorithm to use e.g. 'aes128'
 * @param  {Uint8Array} key         The encryption key
 */
async function OCB(cipher, key) {

  let maxNtz = 0;
  let kv;

  constructKeyVariables(cipher, key);

  function constructKeyVariables(cipher, key) {
    const aes = new ciphers[cipher](key);
    const encipher = aes.encrypt.bind(aes);
    const decipher = aes.decrypt.bind(aes);

    const mask_x = encipher(zeroBlock);
    const mask_$ = util.double(mask_x);
    const mask = [];
    mask[0] = util.double(mask_$);


    mask.x = mask_x;
    mask.$ = mask_$;

    kv = { encipher, decipher, mask };
  }

  function extendKeyVariables(text, adata) {
    const { mask } = kv;
    const newMaxNtz = util.nbits(Math.max(text.length, adata.length) >> 4) - 1;
    for (let i = maxNtz + 1; i <= newMaxNtz; i++) {
      mask[i] = util.double(mask[i - 1]);
    }
    maxNtz = newMaxNtz;
  }

  function hash(adata) {
    if (!adata.length) {
      // Fast path
      return zeroBlock;
    }

    const { encipher, mask } = kv;

    //
    // Consider A as a sequence of 128-bit blocks
    //
    const m = adata.length >> 4;

    const offset = new Uint8Array(16);
    const sum = new Uint8Array(16);
    for (let i = 0; i < m; i++) {
      xorMut(offset, mask[ntz(i + 1)]);
      xorMut(sum, encipher(xor(offset, adata)));
      adata = adata.subarray(16);
    }

    //
    // Process any final partial block; compute final hash value
    //
    if (adata.length) {
      xorMut(offset, mask.x);

      const cipherInput = new Uint8Array(16);
      cipherInput.set(adata, 0);
      cipherInput[adata.length] = 0b10000000;
      xorMut(cipherInput, offset);

      xorMut(sum, encipher(cipherInput));
    }

    return sum;
  }


  return {
    /**
     * Encrypt plaintext input.
     * @param  {Uint8Array} plaintext   The cleartext input to be encrypted
     * @param  {Uint8Array} nonce       The nonce (15 bytes)
     * @param  {Uint8Array} adata       Associated data to sign
     * @returns {Promise<Uint8Array>}    The ciphertext output
     */
    encrypt: async function(plaintext, nonce, adata) {
      //
      // Consider P as a sequence of 128-bit blocks
      //
      const m = plaintext.length >> 4;

      //
      // Key-dependent variables
      //
      extendKeyVariables(plaintext, adata);
      const { encipher, mask } = kv;

      //
      // Nonce-dependent and per-encryption variables
      //
      // We assume here that tagLength mod 16 == 0.
      const paddedNonce = util.concatUint8Array([zeroBlock.subarray(0, 15 - nonce.length), one, nonce]);
      const bottom = paddedNonce[15] & 0b111111;
      paddedNonce[15] &= 0b11000000;
      const kTop = encipher(paddedNonce);
      const stretched = util.concatUint8Array([kTop, xor(kTop.subarray(0, 8), kTop.subarray(1, 9))]);
      //    Offset_0 = Stretch[1+bottom..128+bottom]
      const offset = util.shiftRight(stretched.subarray(0 + (bottom >> 3), 17 + (bottom >> 3)), 8 - (bottom & 7)).subarray(1);
      const checksum = new Uint8Array(16);

      const ct = new Uint8Array(plaintext.length + tagLength);

      //
      // Process any whole blocks
      //
      let i;
      let pos = 0;
      for (i = 0; i < m; i++) {
        xorMut(offset, mask[ntz(i + 1)]);
        ct.set(xorMut(encipher(xor(offset, plaintext)), offset), pos);
        xorMut(checksum, plaintext);

        plaintext = plaintext.subarray(16);
        pos += 16;
      }

      //
      // Process any final partial block and compute raw tag
      //
      if (plaintext.length) {
        xorMut(offset, mask.x);
        const padding = encipher(offset);
        ct.set(xor(plaintext, padding), pos);

        // Checksum_* = Checksum_m xor (P_* || 1 || new Uint8Array(127-bitlen(P_*)))
        const xorInput = new Uint8Array(16);
        xorInput.set(plaintext, 0);
        xorInput[plaintext.length] = 0b10000000;
        xorMut(checksum, xorInput);
        pos += plaintext.length;
      }
      const tag = xorMut(encipher(xorMut(xorMut(checksum, offset), mask.$)), hash(adata));

      //
      // Assemble ciphertext
      //
      ct.set(tag, pos);
      return ct;
    },


    /**
     * Decrypt ciphertext input.
     * @param  {Uint8Array} ciphertext   The ciphertext input to be decrypted
     * @param  {Uint8Array} nonce        The nonce (15 bytes)
     * @param  {Uint8Array} adata        Associated data to verify
     * @returns {Promise<Uint8Array>}     The plaintext output
     */
    decrypt: async function(ciphertext, nonce, adata) {
      //
      // Consider C as a sequence of 128-bit blocks
      //
      const ctTag = ciphertext.subarray(ciphertext.length - tagLength);
      ciphertext = ciphertext.subarray(0, ciphertext.length - tagLength);
      const m = ciphertext.length >> 4;

      //
      // Key-dependent variables
      //
      extendKeyVariables(ciphertext, adata);
      const { encipher, decipher, mask } = kv;

      //
      // Nonce-dependent and per-encryption variables
      //
      // We assume here that tagLength mod 16 == 0.
      const paddedNonce = util.concatUint8Array([zeroBlock.subarray(0, 15 - nonce.length), one, nonce]);
      const bottom = paddedNonce[15] & 0b111111;
      paddedNonce[15] &= 0b11000000;
      const kTop = encipher(paddedNonce);
      const stretched = util.concatUint8Array([kTop, xor(kTop.subarray(0, 8), kTop.subarray(1, 9))]);
      //    Offset_0 = Stretch[1+bottom..128+bottom]
      const offset = util.shiftRight(stretched.subarray(0 + (bottom >> 3), 17 + (bottom >> 3)), 8 - (bottom & 7)).subarray(1);
      const checksum = new Uint8Array(16);

      const pt = new Uint8Array(ciphertext.length);

      //
      // Process any whole blocks
      //
      let i;
      let pos = 0;
      for (i = 0; i < m; i++) {
        xorMut(offset, mask[ntz(i + 1)]);
        pt.set(xorMut(decipher(xor(offset, ciphertext)), offset), pos);
        xorMut(checksum, pt.subarray(pos));

        ciphertext = ciphertext.subarray(16);
        pos += 16;
      }

      //
      // Process any final partial block and compute raw tag
      //
      if (ciphertext.length) {
        xorMut(offset, mask.x);
        const padding = encipher(offset);
        pt.set(xor(ciphertext, padding), pos);

        // Checksum_* = Checksum_m xor (P_* || 1 || new Uint8Array(127-bitlen(P_*)))
        const xorInput = new Uint8Array(16);
        xorInput.set(pt.subarray(pos), 0);
        xorInput[ciphertext.length] = 0b10000000;
        xorMut(checksum, xorInput);
        pos += ciphertext.length;
      }
      const tag = xorMut(encipher(xorMut(xorMut(checksum, offset), mask.$)), hash(adata));

      //
      // Check for validity and assemble plaintext
      //
      if (!util.equalsUint8Array(ctTag, tag)) {
        throw new Error('Authentication tag mismatch in OCB ciphertext');
      }
      return pt;
    }
  };
}


/**
 * Get OCB nonce as defined by {@link https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-04#section-5.16.2|RFC4880bis-04, section 5.16.2}.
 * @param  {Uint8Array} iv           The initialization vector (15 bytes)
 * @param  {Uint8Array} chunkIndex   The chunk index (8 bytes)
 */
OCB.getNonce = function(iv, chunkIndex) {
  const nonce = iv.slice();
  for (let i = 0; i < chunkIndex.length; i++) {
    nonce[7 + i] ^= chunkIndex[i];
  }
  return nonce;
};

OCB.blockLength = blockLength;
OCB.ivLength = ivLength;
OCB.tagLength = tagLength;

export default OCB;
