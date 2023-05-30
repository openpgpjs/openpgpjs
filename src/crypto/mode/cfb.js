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
 */

import { AES_CFB } from '@openpgp/asmcrypto.js/aes/cfb.js';
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
  if (algoName.substr(0, 3) === 'aes') {
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
  if (nodeCrypto && nodeAlgos[algoName]) { // Node crypto library.
    return nodeDecrypt(algo, key, ciphertext, iv);
  }
  if (algoName.substr(0, 3) === 'aes') {
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

class WebCryptoEncryptor {
  constructor(algo, key, iv) {
    const { blockSize } = getCipher(algo);
    this.key = key;
    this.prevBlock = iv;
    this.nextBlock = new Uint8Array(blockSize);
    this.i = 0; // pointer inside next block
    this.blockSize = blockSize;
    this.zeroBlock = new Uint8Array(this.blockSize);
  }

  static async isSupported(algo) {
    const { keySize } = getCipher(algo);
    return webCrypto.importKey('raw', new Uint8Array(keySize), 'aes-cbc', false, ['encrypt'])
      .then(() => true, () => false);
  }

  async _runCBC(plaintext, nonZeroIV) {
    const mode = 'AES-CBC';
    this.keyRef = this.keyRef || await webCrypto.importKey('raw', this.key, mode, false, ['encrypt']);
    const ciphertext = await webCrypto.encrypt(
      { name: mode, iv: nonZeroIV || this.zeroBlock },
      this.keyRef,
      plaintext
    );
    return new Uint8Array(ciphertext).subarray(0, plaintext.length);
  }

  async encryptChunk(value) {
    const missing = this.nextBlock.length - this.i;
    const added = value.subarray(0, missing);
    this.nextBlock.set(added, this.i);
    if ((this.i + value.length) >= (2 * this.blockSize)) {
      const leftover = (value.length - missing) % this.blockSize;
      const plaintext = util.concatUint8Array([
        this.nextBlock,
        value.subarray(missing, value.length - leftover)
      ]);
      const toEncrypt = util.concatUint8Array([
        this.prevBlock,
        plaintext.subarray(0, plaintext.length - this.blockSize) // stop one block "early", since we only need to xor the plaintext and pass it over as prevBlock
      ]);

      const encryptedBlocks = await this._runCBC(toEncrypt);
      xorMut(encryptedBlocks, plaintext);
      this.prevBlock = encryptedBlocks.subarray(-this.blockSize).slice();

      // take care of leftover data
      if (leftover > 0) this.nextBlock.set(value.subarray(-leftover).slice());
      this.i = leftover;

      return encryptedBlocks;
    }

    this.i += added.length;
    let encryptedBlock = new Uint8Array();
    if (this.i === this.nextBlock.length) { // block ready to be encrypted
      const curBlock = this.nextBlock;
      encryptedBlock = await this._runCBC(this.prevBlock);
      xorMut(encryptedBlock, curBlock);
      this.prevBlock = encryptedBlock.slice();
      this.i = 0;

      const remaining = value.subarray(added.length);
      this.nextBlock.set(remaining, this.i);
      this.i += remaining.length;
    }

    return encryptedBlock;
  }

  async finish() {
    let result;
    if (this.i === 0) { // nothing more to encrypt
      result = new Uint8Array();
    } else {
      this.nextBlock = this.nextBlock.subarray(0, this.i);
      const curBlock = this.nextBlock;
      const encryptedBlock = await this._runCBC(this.prevBlock);
      xorMut(encryptedBlock, curBlock);
      result = encryptedBlock.subarray(0, curBlock.length);
    }

    this.clearSensitiveData();
    return result;
  }

  clearSensitiveData() {
    this.nextBlock.fill(0);
    this.prevBlock.fill(0);
    this.keyRef = null;
    this.key = null;
  }

  async encrypt(plaintext) {
    // plaintext is internally padded to block length before encryption
    const encryptedWithPadding = await this._runCBC(
      util.concatUint8Array([new Uint8Array(this.blockSize), plaintext]),
      this.iv
    );
    // drop encrypted padding
    const ct = encryptedWithPadding.subarray(0, plaintext.length);
    xorMut(ct, plaintext);
    this.clearSensitiveData();
    return ct;
  }
}

async function aesEncrypt(algo, key, pt, iv) {
  if (webCrypto && await WebCryptoEncryptor.isSupported(algo)) { // Chromium does not implement AES with 192-bit keys
    const cfb = new WebCryptoEncryptor(algo, key, iv);
    return util.isStream(pt) ? stream.transform(pt, value => cfb.encryptChunk(value), () => cfb.finish()) : cfb.encrypt(pt);
  } else {
    const cfb = new AES_CFB(key, iv);
    return stream.transform(pt, value => cfb.aes.AES_Encrypt_process(value), () => cfb.aes.AES_Encrypt_finish());
  }
}

function aesDecrypt(algo, key, ct, iv) {
  if (util.isStream(ct)) {
    const cfb = new AES_CFB(key, iv);
    return stream.transform(ct, value => cfb.aes.AES_Decrypt_process(value), () => cfb.aes.AES_Decrypt_finish());
  }
  return AES_CFB.decrypt(ct, key, iv);
}

function xorMut(a, b) {
  const aLength = Math.min(a.length, b.length);
  for (let i = 0; i < aLength; i++) {
    a[i] = a[i] ^ b[i];
  }
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
