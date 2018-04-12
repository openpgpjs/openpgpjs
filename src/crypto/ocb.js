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


const { shiftLeft, shiftRight } = util;


function zeros(bytes) {
  return new Uint8Array(bytes);
}

function ntz(n) {
  let ntz = 0;
  for(let i = 1; (n & i) === 0; i <<= 1) {
    ntz++;
  }
  return ntz;
}

function set_xor(S, T) {
  for (let i = 0; i < S.length; i++) {
    S[i] ^= T[i];
  }
  return S;
}

function xor(S, T) {
  return set_xor(S.slice(), T);
}

function concat(...arrays) {
  return util.concatUint8Array(arrays);
}

function double(S) {
  const double = S.slice();
  shiftLeft(double, 1);
  if (S[0] & 0b10000000) {
    double[15] ^= 0b10000111;
  }
  return double;
}


const zeros_16 = zeros(16);
const one = new Uint8Array([1]);

class OCB {
  /**
   * Class to en/decrypt using OCB mode.
   * @param  {String}     cipher      The symmetric cipher algorithm to use e.g. 'aes128'
   * @param  {Uint8Array} key         The encryption key
   */
  constructor(cipher, key) {
    this.max_ntz = 0;
    this.constructKeyVariables(cipher, key);
  }

  constructKeyVariables(cipher, key) {
    const aes = new ciphers[cipher](key);
    const encipher = aes.encrypt.bind(aes);
    const decipher = aes.decrypt.bind(aes);

    const L_x = encipher(zeros_16);
    const L_$ = double(L_x);
    const L = [];
    L[0] = double(L_$);


    L.x = L_x;
    L.$ = L_$;

    this.kv = { encipher, decipher, L };
  }

  extendKeyVariables(text, adata) {
    const { L } = this.kv;
    const max_ntz = util.nbits(Math.max(text.length, adata.length) >> 4) - 1;
    for (let i = this.max_ntz + 1; i <= max_ntz; i++) {
      L[i] = double(L[i - 1]);
    }
    this.max_ntz = max_ntz;
  }

  hash(adata) {
    if (!adata.length) {
      // Fast path
      return zeros_16;
    }

    const { encipher, L } = this.kv;

    //
    // Consider A as a sequence of 128-bit blocks
    //
    const m = adata.length >> 4;

    const offset = zeros(16);
    const sum = zeros(16);
    for (let i = 0; i < m; i++) {
      set_xor(offset, L[ntz(i + 1)]);
      set_xor(sum, encipher(xor(offset, adata)));
      adata = adata.subarray(16);
    }

    //
    // Process any final partial block; compute final hash value
    //
    if (adata.length) {
      set_xor(offset, L.x);

      const cipherInput = zeros(16);
      cipherInput.set(adata, 0);
      cipherInput[adata.length] = 0b10000000;
      set_xor(cipherInput, offset);

      set_xor(sum, encipher(cipherInput));
    }

    return sum;
  }


  /**
   * Encrypt plaintext input.
   * @param  {Uint8Array} plaintext   The cleartext input to be encrypted
   * @param  {Uint8Array} nonce       The nonce (15 bytes)
   * @param  {Uint8Array} adata       Associated data to sign
   * @returns {Promise<Uint8Array>}    The ciphertext output
   */
  async encrypt(plaintext, nonce, adata) {
    //
    // Consider P as a sequence of 128-bit blocks
    //
    const m = plaintext.length >> 4;

    //
    // Key-dependent variables
    //
    this.extendKeyVariables(plaintext, adata);
    const { encipher, L } = this.kv;

    //
    // Nonce-dependent and per-encryption variables
    //
    // We assume here that TAGLEN mod 128 == 0 (tagLength === 16).
    const Nonce = concat(zeros_16.subarray(0, 15 - nonce.length), one, nonce);
    const bottom = Nonce[15] & 0b111111;
    Nonce[15] &= 0b11000000;
    const Ktop = encipher(Nonce);
    const Stretch = concat(Ktop, xor(Ktop.subarray(0, 8), Ktop.subarray(1, 9)));
    //    Offset_0 = Stretch[1+bottom..128+bottom]
    const offset = shiftRight(Stretch.subarray(0 + (bottom >> 3), 17 + (bottom >> 3)), 8 - (bottom & 7)).subarray(1);
    const checksum = zeros(16);

    const C = new Uint8Array(plaintext.length + tagLength);

    //
    // Process any whole blocks
    //
    let i;
    let pos = 0;
    for (i = 0; i < m; i++) {
      set_xor(offset, L[ntz(i + 1)]);
      C.set(set_xor(encipher(xor(offset, plaintext)), offset), pos);
      set_xor(checksum, plaintext);

      plaintext = plaintext.subarray(16);
      pos += 16;
    }

    //
    // Process any final partial block and compute raw tag
    //
    if (plaintext.length) {
      set_xor(offset, L.x);
      const Pad = encipher(offset);
      C.set(xor(plaintext, Pad), pos);

      // Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*)))
      const xorInput = zeros(16);
      xorInput.set(plaintext, 0);
      xorInput[plaintext.length] = 0b10000000;
      set_xor(checksum, xorInput);
      pos += plaintext.length;
    }
    const Tag = set_xor(encipher(set_xor(set_xor(checksum, offset), L.$)), this.hash(adata));

    //
    // Assemble ciphertext
    //
    C.set(Tag, pos);
    return C;
  }


  /**
   * Decrypt ciphertext input.
   * @param  {Uint8Array} ciphertext   The ciphertext input to be decrypted
   * @param  {Uint8Array} nonce        The nonce (15 bytes)
   * @param  {Uint8Array} adata        Associated data to verify
   * @returns {Promise<Uint8Array>}     The plaintext output
   */
  async decrypt(ciphertext, nonce, adata) {
    //
    // Consider C as a sequence of 128-bit blocks
    //
    const T = ciphertext.subarray(ciphertext.length - tagLength);
    ciphertext = ciphertext.subarray(0, ciphertext.length - tagLength);
    const m = ciphertext.length >> 4;

    //
    // Key-dependent variables
    //
    this.extendKeyVariables(ciphertext, adata);
    const { encipher, decipher, L } = this.kv;

    //
    // Nonce-dependent and per-encryption variables
    //
    // We assume here that TAGLEN mod 128 == 0 (tagLength === 16).
    const Nonce = concat(zeros_16.subarray(0, 15 - nonce.length), one, nonce);
    const bottom = Nonce[15] & 0b111111;
    Nonce[15] &= 0b11000000;
    const Ktop = encipher(Nonce);
    const Stretch = concat(Ktop, xor(Ktop.subarray(0, 8), Ktop.subarray(1, 9)));
    //    Offset_0 = Stretch[1+bottom..128+bottom]
    const offset = shiftRight(Stretch.subarray(0 + (bottom >> 3), 17 + (bottom >> 3)), 8 - (bottom & 7)).subarray(1);
    const checksum = zeros(16);

    const P = new Uint8Array(ciphertext.length);

    //
    // Process any whole blocks
    //
    let i;
    let pos = 0;
    for (i = 0; i < m; i++) {
      set_xor(offset, L[ntz(i + 1)]);
      P.set(set_xor(decipher(xor(offset, ciphertext)), offset), pos);
      set_xor(checksum, P.subarray(pos));

      ciphertext = ciphertext.subarray(16);
      pos += 16;
    }

    //
    // Process any final partial block and compute raw tag
    //
    if (ciphertext.length) {
      set_xor(offset, L.x);
      const Pad = encipher(offset);
      P.set(xor(ciphertext, Pad), pos);

      // Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*)))
      const xorInput = zeros(16);
      xorInput.set(P.subarray(pos), 0);
      xorInput[ciphertext.length] = 0b10000000;
      set_xor(checksum, xorInput);
      pos += ciphertext.length;
    }
    const Tag = set_xor(encipher(set_xor(set_xor(checksum, offset), L.$)), this.hash(adata));

    //
    // Check for validity and assemble plaintext
    //
    if (!util.equalsUint8Array(Tag, T)) {
      throw new Error('Authentication tag mismatch in OCB ciphertext');
    }
    return P;
  }
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

export default OCB;
