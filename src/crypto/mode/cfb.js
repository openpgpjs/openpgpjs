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
 * @module crypto/mode/cfb
 * @private
 */

import { AES_CFB } from '@openpgp/asmcrypto.js/dist_es8/aes/cfb';
import * as stream from '@openpgp/web-stream-tools';
import getCipher from '../cipher/getCipher';
import util from '../../util';
import enums from '../../enums';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();

const knownAlgos = nodeCrypto ? nodeCrypto.getCiphers() : [];
const nodeAlgos = {
  idea: knownAlgos.includes('idea-cfb') ? 'idea-cfb' : undefined, /* Unused, not implemented */
  tripledes: knownAlgos.includes('des-ede3-cfb') ? 'des-ede3-cfb' : undefined,
  cast5: knownAlgos.includes('cast5-cfb') ? 'cast5-cfb' : undefined,
  blowfish: knownAlgos.includes('bf-cfb') ? 'bf-cfb' : undefined,
  aes128: knownAlgos.includes('aes-128-cfb') ? 'aes-128-cfb' : undefined,
  aes192: knownAlgos.includes('aes-192-cfb') ? 'aes-192-cfb' : undefined,
  aes256: knownAlgos.includes('aes-256-cfb') ? 'aes-256-cfb' : undefined
  /* twofish is not implemented in OpenSSL */
};

/**
 * CFB encryption
 * @param {enums.symmetric} algo - block cipher algorithm
 * @param {Uint8Array} key
 * @param {MaybeStream<Uint8Array>} plaintext
 * @param {Uint8Array} iv
 * @param {Object} config - full configuration, defaults to openpgp.config
 * @returns MaybeStream<Uint8Array>
 */
export async function encrypt(algo, key, plaintext, iv, config) {
  const algoName = enums.read(enums.symmetric, algo);
  if (util.getNodeCrypto() && nodeAlgos[algoName]) { // Node crypto library.
    return nodeEncrypt(algo, key, plaintext, iv);
  }
  if (util.isAES(algo)) {
    return aesEncrypt(algo, key, plaintext, iv, config);
  }

  const Cipher = getCipher(algo);
  const cipherfn = new Cipher(key);
  const block_size = cipherfn.blockSize;

  const blockc = iv.slice();
  let pt = new Uint8Array();
  const process = chunk => {
    if (chunk) {
      pt = util.concatUint8Array([pt, chunk]);
    }
    const ciphertext = new Uint8Array(pt.length);
    let i;
    let j = 0;
    while (chunk ? pt.length >= block_size : pt.length) {
      const encblock = cipherfn.encrypt(blockc);
      for (i = 0; i < block_size; i++) {
        blockc[i] = pt[i] ^ encblock[i];
        ciphertext[j++] = blockc[i];
      }
      pt = pt.subarray(block_size);
    }
    return ciphertext.subarray(0, j);
  };
  return stream.transform(plaintext, process, process);
}

/**
 * CFB decryption
 * @param {enums.symmetric} algo - block cipher algorithm
 * @param {Uint8Array} key
 * @param {MaybeStream<Uint8Array>} ciphertext
 * @param {Uint8Array} iv
 * @returns MaybeStream<Uint8Array>
 */
export async function decrypt(algo, key, ciphertext, iv) {
  const algoName = enums.read(enums.symmetric, algo);
  if (util.getNodeCrypto() && nodeAlgos[algoName]) { // Node crypto library.
    return nodeDecrypt(algo, key, ciphertext, iv);
  }
  if (util.isAES(algo)) {
    return aesDecrypt(algo, key, ciphertext, iv);
  }

  const Cipher = getCipher(algo);
  const cipherfn = new Cipher(key);
  const block_size = cipherfn.blockSize;

  let blockp = iv;
  let ct = new Uint8Array();
  const process = chunk => {
    if (chunk) {
      ct = util.concatUint8Array([ct, chunk]);
    }
    const plaintext = new Uint8Array(ct.length);
    let i;
    let j = 0;
    while (chunk ? ct.length >= block_size : ct.length) {
      const decblock = cipherfn.encrypt(blockp);
      blockp = ct;
      for (i = 0; i < block_size; i++) {
        plaintext[j++] = blockp[i] ^ decblock[i];
      }
      ct = ct.subarray(block_size);
    }
    return plaintext.subarray(0, j);
  };
  return stream.transform(ciphertext, process, process);
}

function aesEncrypt(algo, key, pt, iv, config) {
  if (
    util.getWebCrypto() &&
    key.length !== 24 && // Chrome doesn't support 192 bit keys, see https://www.chromium.org/blink/webcrypto#TOC-AES-support
    !util.isStream(pt) &&
    pt.length >= 3000 * config.minBytesForWebCrypto // Default to a 3MB minimum. Chrome is pretty slow for small messages, see: https://bugs.chromium.org/p/chromium/issues/detail?id=701188#c2
  ) { // Web Crypto
    return webEncrypt(algo, key, pt, iv);
  }
  // asm.js fallback
  const cfb = new AES_CFB(key, iv);
  return stream.transform(pt, value => cfb.aes.AES_Encrypt_process(value), () => cfb.aes.AES_Encrypt_finish());
}

function aesDecrypt(algo, key, ct, iv) {
  if (util.isStream(ct)) {
    const cfb = new AES_CFB(key, iv);
    return stream.transform(ct, value => cfb.aes.AES_Decrypt_process(value), () => cfb.aes.AES_Decrypt_finish());
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
  const { blockSize } = getCipher(algo);
  const cbc_pt = util.concatUint8Array([new Uint8Array(blockSize), pt]);
  const ct = new Uint8Array(await webCrypto.encrypt({ name: ALGO, iv }, _key, cbc_pt)).subarray(0, pt.length);
  xorMut(ct, pt);
  return ct;
}

function nodeEncrypt(algo, key, pt, iv) {
  const algoName = enums.read(enums.symmetric, algo);
  const cipherObj = new nodeCrypto.createCipheriv(nodeAlgos[algoName], key, iv);
  return stream.transform(pt, value => new Uint8Array(cipherObj.update(value)));
}

function nodeDecrypt(algo, key, ct, iv) {
  const algoName = enums.read(enums.symmetric, algo);
  const decipherObj = new nodeCrypto.createDecipheriv(nodeAlgos[algoName], key, iv);
  return stream.transform(ct, value => new Uint8Array(decipherObj.update(value)));
}
