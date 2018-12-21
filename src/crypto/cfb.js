// Modified by ProtonTech AG

// Modified by Recurity Labs GmbH

// modified version of https://www.hanewin.net/encrypt/PGdecode.js:

/* OpenPGP encryption using RSA/AES
 * Copyright 2005-2006 Herbert Hanewinkel, www.haneWIN.de
 * version 2.0, check www.haneWIN.de for the latest version

 * This software is provided as-is, without express or implied warranty.
 * Permission to use, copy, modify, distribute or sell this software, with or
 * without fee, for any purpose and by any individual or organization, is hereby
 * granted, provided that the above copyright notice and this paragraph appear
 * in all copies. Distribution as a part of an application or binary must
 * include the above copyright notice in the documentation and/or other
 * materials provided with the application or distribution.
 */

/**
 * @requires web-stream-tools
 * @requires crypto/cipher
 * @requires util
 * @module crypto/cfb
 */

import { AES_CFB } from 'asmcrypto.js/dist_es5/aes/cfb';

import stream from 'web-stream-tools';
import cipher from './cipher';
import config from '../config';
import util from '../util';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();
const Buffer = util.getNodeBuffer();

export default {
  encrypt: function(algo, key, plaintext, iv) {
    if (algo.substr(0, 3) === 'aes') {
      return aesEncrypt(algo, key, plaintext, iv);
    }

    const cipherfn = new cipher[algo](key);
    const block_size = cipherfn.blockSize;

    let blocki = new Uint8Array(block_size);
    const blockc = iv;
    let pos = 0;
    const ciphertext = new Uint8Array(plaintext.length);
    let i;
    let j = 0;

    while (plaintext.length > block_size * pos) {
      const encblock = cipherfn.encrypt(blockc);
      blocki = plaintext.subarray((pos * block_size), (pos * block_size) + block_size);
      for (i = 0; i < blocki.length; i++) {
        blockc[i] = blocki[i] ^ encblock[i];
        ciphertext[j++] = blockc[i];
      }
      pos++;
    }
    return ciphertext;
  },

  decrypt: async function(algo, key, ciphertext, iv) {
    if (algo.substr(0, 3) === 'aes') {
      return aesDecrypt(algo, key, ciphertext, iv);
    }

    ciphertext = await stream.readToEnd(ciphertext);

    const cipherfn = new cipher[algo](key);
    const block_size = cipherfn.blockSize;

    let blockp = iv;
    let pos = 0;
    const plaintext = new Uint8Array(ciphertext.length);
    const offset = 0;
    let i;
    let j = 0;

    while (ciphertext.length > (block_size * pos)) {
      const decblock = cipherfn.encrypt(blockp);
      blockp = ciphertext.subarray((pos * (block_size)) + offset, (pos * (block_size)) + (block_size) + offset);
      for (i = 0; i < blockp.length; i++) {
        plaintext[j++] = blockp[i] ^ decblock[i];
      }
      pos++;
    }

    return plaintext;
  }
};

function aesEncrypt(algo, key, pt, iv) {
  if (
    util.getWebCrypto() &&
    key.length !== 24 && // Chrome doesn't support 192 bit keys, see https://www.chromium.org/blink/webcrypto#TOC-AES-support
    !util.isStream(pt) &&
    pt.length >= 3000 * config.min_bytes_for_web_crypto // Default to a 3MB minimum. Chrome is pretty slow for small messages, see: https://bugs.chromium.org/p/chromium/issues/detail?id=701188#c2
  ) { // Web Crypto
    return webEncrypt(algo, key, pt, iv);
  }
  if (nodeCrypto) { // Node crypto library.
    return nodeEncrypt(algo, key, pt, iv);
  } // asm.js fallback
  const cfb = new AES_CFB(key, iv);
  return stream.transform(pt, value => cfb.AES_Encrypt_process(value), () => cfb.AES_Encrypt_finish());
}

function aesDecrypt(algo, key, ct, iv) {
  if (nodeCrypto) { // Node crypto library.
    return nodeDecrypt(algo, key, ct, iv);
  }
  if (util.isStream(ct)) {
    const cfb = new AES_CFB(key, iv);
    return stream.transform(ct, value => cfb.AES_Decrypt_process(value), () => cfb.AES_Decrypt_finish());
  }
  return AES_CFB.decrypt(ct, key, iv);
}

function xorMut(a, b) {
  for (let i = 0; i < a.length; i++) {
    a[i] = a[i] ^ b[i];
  }
}

async function webEncrypt(algo, key, pt, iv) {
  const ALGO = 'AES-CBC';
  const _key = await webCrypto.importKey('raw', key, { name: ALGO }, false, ['encrypt']);
  const { blockSize } = cipher[algo];
  const cbc_pt = util.concatUint8Array([new Uint8Array(blockSize), pt]);
  const ct = new Uint8Array(await webCrypto.encrypt({ name: ALGO, iv }, _key, cbc_pt)).subarray(0, pt.length);
  xorMut(ct, pt);
  return ct;
}

function nodeEncrypt(algo, key, pt, iv) {
  key = new Buffer(key);
  iv = new Buffer(iv);
  const cipherObj = new nodeCrypto.createCipheriv('aes-' + algo.substr(3, 3) + '-cfb', key, iv);
  return stream.transform(pt, value => new Uint8Array(cipherObj.update(new Buffer(value))));
}

function nodeDecrypt(algo, key, ct, iv) {
  key = new Buffer(key);
  iv = new Buffer(iv);
  const decipherObj = new nodeCrypto.createDecipheriv('aes-' + algo.substr(3, 3) + '-cfb', key, iv);
  return stream.transform(ct, value => new Uint8Array(decipherObj.update(new Buffer(value))));
}
