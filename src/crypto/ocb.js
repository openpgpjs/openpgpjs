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
  for (let i = 1; (n & i) === 0; i <<= 1) {
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
  let encipher;
  let decipher;
  let mask;

  constructKeyVariables(cipher, key);

  function constructKeyVariables(cipher, key) {
    const aes = new ciphers[cipher](key);
    encipher = aes.encrypt.bind(aes);
    decipher = aes.decrypt.bind(aes);

    const mask_x = encipher(zeroBlock);
    const mask_$ = util.double(mask_x);
    mask = [];
    mask[0] = util.double(mask_$);


    mask.x = mask_x;
    mask.$ = mask_$;
  }

  function extendKeyVariables(text, adata) {
    const newMaxNtz = util.nbits(Math.max(text.length, adata.length) / blockLength | 0) - 1;
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

    //
    // Consider A as a sequence of 128-bit blocks
    //
    const m = adata.length / blockLength | 0;

    const offset = new Uint8Array(blockLength);
    const sum = new Uint8Array(blockLength);
    for (let i = 0; i < m; i++) {
      xorMut(offset, mask[ntz(i + 1)]);
      xorMut(sum, encipher(xor(offset, adata)));
      adata = adata.subarray(blockLength);
    }

    //
    // Process any final partial block; compute final hash value
    //
    if (adata.length) {
      xorMut(offset, mask.x);

      const cipherInput = new Uint8Array(blockLength);
      cipherInput.set(adata, 0);
      cipherInput[adata.length] = 0b10000000;
      xorMut(cipherInput, offset);

      xorMut(sum, encipher(cipherInput));
    }

    return sum;
  }

  /**
   * Encrypt/decrypt data.
   * @param  {encipher|decipher} fn   Encryption/decryption block cipher function
   * @param  {Uint8Array} text        The cleartext or ciphertext (without tag) input
   * @param  {Uint8Array} nonce       The nonce (15 bytes)
   * @param  {Uint8Array} adata       Associated data to sign
   * @returns {Promise<Uint8Array>}    The ciphertext or plaintext output, with tag appended in both cases
   */
  function crypt(fn, text, nonce, adata) {
    //
    // Consider P as a sequence of 128-bit blocks
    //
    const m = text.length / blockLength | 0;

    //
    // Key-dependent variables
    //
    extendKeyVariables(text, adata);

    //
    // Nonce-dependent and per-encryption variables
    //
    //    Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N
    // Note: We assume here that tagLength mod 16 == 0.
    const paddedNonce = util.concatUint8Array([zeroBlock.subarray(0, ivLength - nonce.length), one, nonce]);
    //    bottom = str2num(Nonce[123..128])
    const bottom = paddedNonce[blockLength - 1] & 0b111111;
    //    Ktop = ENCIPHER(K, Nonce[1..122] || zeros(6))
    paddedNonce[blockLength - 1] &= 0b11000000;
    const kTop = encipher(paddedNonce);
    //    Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72])
    const stretched = util.concatUint8Array([kTop, xor(kTop.subarray(0, 8), kTop.subarray(1, 9))]);
    //    Offset_0 = Stretch[1+bottom..128+bottom]
    const offset = util.shiftRight(stretched.subarray(0 + (bottom >> 3), 17 + (bottom >> 3)), 8 - (bottom & 7)).subarray(1);
    //    Checksum_0 = zeros(128)
    const checksum = new Uint8Array(blockLength);

    const ct = new Uint8Array(text.length + tagLength);

    //
    // Process any whole blocks
    //
    let i;
    let pos = 0;
    for (i = 0; i < m; i++) {
      // Offset_i = Offset_{i-1} xor L_{ntz(i)}
      xorMut(offset, mask[ntz(i + 1)]);
      // C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)
      // P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i)
      ct.set(xorMut(fn(xor(offset, text)), offset), pos);
      // Checksum_i = Checksum_{i-1} xor P_i
      xorMut(checksum, fn === encipher ? text : ct.subarray(pos));

      text = text.subarray(blockLength);
      pos += blockLength;
    }

    //
    // Process any final partial block and compute raw tag
    //
    if (text.length) {
      // Offset_* = Offset_m xor L_*
      xorMut(offset, mask.x);
      // Pad = ENCIPHER(K, Offset_*)
      const padding = encipher(offset);
      // C_* = P_* xor Pad[1..bitlen(P_*)]
      ct.set(xor(text, padding), pos);

      // Checksum_* = Checksum_m xor (P_* || 1 || new Uint8Array(127-bitlen(P_*)))
      const xorInput = new Uint8Array(blockLength);
      xorInput.set(fn === encipher ? text : ct.subarray(pos, -tagLength), 0);
      xorInput[text.length] = 0b10000000;
      xorMut(checksum, xorInput);
      pos += text.length;
    }
    // Tag = ENCIPHER(K, Checksum_* xor Offset_* xor L_$) xor HASH(K,A)
    const tag = xorMut(encipher(xorMut(xorMut(checksum, offset), mask.$)), hash(adata));

    //
    // Assemble ciphertext
    //
    // C = C_1 || C_2 || ... || C_m || C_* || Tag[1..TAGLEN]
    ct.set(tag, pos);
    return ct;
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
      return crypt(encipher, plaintext, nonce, adata);
    },

    /**
     * Decrypt ciphertext input.
     * @param  {Uint8Array} ciphertext  The ciphertext input to be decrypted
     * @param  {Uint8Array} nonce       The nonce (15 bytes)
     * @param  {Uint8Array} adata       Associated data to sign
     * @returns {Promise<Uint8Array>}    The ciphertext output
     */
    decrypt: async function(ciphertext, nonce, adata) {
      if (ciphertext.length < tagLength) throw new Error('Invalid OCB ciphertext');

      const tag = ciphertext.subarray(-tagLength);
      ciphertext = ciphertext.subarray(0, -tagLength);

      const crypted = crypt(decipher, ciphertext, nonce, adata);
      // if (Tag[1..TAGLEN] == T)
      if (util.equalsUint8Array(tag, crypted.subarray(-tagLength))) {
        return crypted.subarray(0, -tagLength);
      }
      throw new Error('Authentication tag mismatch');
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
