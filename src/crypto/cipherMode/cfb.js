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

import { cfb as nobleAesCfb, unsafe as nobleAesHelpers } from '@noble/ciphers/aes.js';

import { transform as streamTransform } from '@openpgp/web-stream-tools';
import util from '../../util';
import enums from '../../enums';
import { getLegacyCipher, getCipherParams } from '../cipher';
import { getRandomBytes } from '../random';

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
 * Generates a random byte prefix for the specified algorithm
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
 * @param {module:enums.symmetric} algo - Symmetric encryption algorithm
 * @returns {Promise<Uint8Array>} Random bytes with length equal to the block size of the cipher, plus the last two bytes repeated.
 */
export function getPrefixRandom(algo) {
  const { blockSize } = getCipherParams(algo);
  const prefixrandom = getRandomBytes(blockSize);
  const repeat = new Uint8Array([prefixrandom[prefixrandom.length - 2], prefixrandom[prefixrandom.length - 1]]);
  return util.concat([prefixrandom, repeat]);
}

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

  const LegacyCipher = await getLegacyCipher(algo);
  const cipherfn = new LegacyCipher(key);
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
  return streamTransform(plaintext, process, process);
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
  if (util.isAES(algo)) {
    return aesDecrypt(algo, key, ciphertext, iv);
  }

  const LegacyCipher = await getLegacyCipher(algo);
  const cipherfn = new LegacyCipher(key);
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
      blockp = ct.subarray(0, block_size);
      for (i = 0; i < block_size; i++) {
        plaintext[j++] = blockp[i] ^ decblock[i];
      }
      ct = ct.subarray(block_size);
    }
    return plaintext.subarray(0, j);
  };
  return streamTransform(ciphertext, process, process);
}

class WebCryptoEncryptor {
  constructor(algo, key, iv) {
    const { blockSize } = getCipherParams(algo);
    this.key = key;
    this.prevBlock = iv;
    this.nextBlock = new Uint8Array(blockSize);
    this.i = 0; // pointer inside next block
    this.blockSize = blockSize;
    this.zeroBlock = new Uint8Array(this.blockSize);
  }

  /**
   * @returns {Promise<boolean>}
   */
  static isSupported(algo) {
    const { keySize } = getCipherParams(algo);
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
      this.prevBlock = encryptedBlocks.slice(-this.blockSize);

      // take care of leftover data
      if (leftover > 0) this.nextBlock.set(value.subarray(-leftover));
      this.i = leftover;

      return encryptedBlocks;
    }

    this.i += added.length;
    let encryptedBlock;
    if (this.i === this.nextBlock.length) { // block ready to be encrypted
      const curBlock = this.nextBlock;
      encryptedBlock = await this._runCBC(this.prevBlock);
      xorMut(encryptedBlock, curBlock);
      this.prevBlock = encryptedBlock.slice();
      this.i = 0;

      const remaining = value.subarray(added.length);
      this.nextBlock.set(remaining, this.i);
      this.i += remaining.length;
    } else {
      encryptedBlock = new Uint8Array();
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

class NobleStreamProcessor {
  constructor(forEncryption, algo, key, iv) {
    this.forEncryption = forEncryption;
    const { blockSize } = getCipherParams(algo);
    this.key = nobleAesHelpers.expandKeyLE(key);

    if (iv.byteOffset % 4 !== 0) iv = iv.slice(); // aligned arrays required by noble-ciphers
    this.prevBlock = getUint32Array(iv);
    this.nextBlock = new Uint8Array(blockSize);
    this.i = 0; // pointer inside next block
    this.blockSize = blockSize;
  }

  _runCFB(src) {
    const src32 = getUint32Array(src);
    const dst = new Uint8Array(src.length);
    const dst32 = getUint32Array(dst);
    for (let i = 0; i + 4 <= dst32.length; i += 4) {
      const { s0: e0, s1: e1, s2: e2, s3: e3 } = nobleAesHelpers.encrypt(this.key, this.prevBlock[0], this.prevBlock[1], this.prevBlock[2], this.prevBlock[3]);
      dst32[i + 0] = src32[i + 0] ^ e0;
      dst32[i + 1] = src32[i + 1] ^ e1;
      dst32[i + 2] = src32[i + 2] ^ e2;
      dst32[i + 3] = src32[i + 3] ^ e3;
      this.prevBlock = (this.forEncryption ? dst32 : src32).slice(i, i + 4);
    }
    return dst;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async processChunk(value) {
    const missing = this.nextBlock.length - this.i;
    const added = value.subarray(0, missing);
    this.nextBlock.set(added, this.i);

    if ((this.i + value.length) >= (2 * this.blockSize)) {
      const leftover = (value.length - missing) % this.blockSize;
      const toProcess = util.concatUint8Array([
        this.nextBlock,
        value.subarray(missing, value.length - leftover)
      ]);

      const processedBlocks = this._runCFB(toProcess);

      // take care of leftover data
      if (leftover > 0) this.nextBlock.set(value.subarray(-leftover));
      this.i = leftover;

      return processedBlocks;
    }

    this.i += added.length;

    let processedBlock;
    if (this.i === this.nextBlock.length) { // block ready to be encrypted
      processedBlock = this._runCFB(this.nextBlock);
      this.i = 0;

      const remaining = value.subarray(added.length);
      this.nextBlock.set(remaining, this.i);
      this.i += remaining.length;
    } else {
      processedBlock = new Uint8Array();
    }

    return processedBlock;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async finish() {
    let result;
    if (this.i === 0) { // nothing more to encrypt
      result = new Uint8Array();
    } else {
      const processedBlock = this._runCFB(this.nextBlock);

      result = processedBlock.subarray(0, this.i);
    }

    this.clearSensitiveData();
    return result;
  }

  clearSensitiveData() {
    this.nextBlock.fill(0);
    this.prevBlock.fill(0);
    this.key.fill(0);
  }
}


async function aesEncrypt(algo, key, pt, iv) {
  if (webCrypto && await WebCryptoEncryptor.isSupported(algo)) { // Chromium does not implement AES with 192-bit keys
    const cfb = new WebCryptoEncryptor(algo, key, iv);
    return util.isStream(pt) ? streamTransform(pt, value => cfb.encryptChunk(value), () => cfb.finish()) : cfb.encrypt(pt);
  } else if (util.isStream(pt)) { // async callbacks are not accepted by streamTransform unless the input is a stream
    const cfb = new NobleStreamProcessor(true, algo, key, iv);
    return streamTransform(pt, value => cfb.processChunk(value), () => cfb.finish());
  }
  return nobleAesCfb(key, iv).encrypt(pt);
}

function aesDecrypt(algo, key, ct, iv) {
  if (util.isStream(ct)) {
    const cfb = new NobleStreamProcessor(false, algo, key, iv);
    return streamTransform(ct, value => cfb.processChunk(value), () => cfb.finish());
  }
  return nobleAesCfb(key, iv).decrypt(ct);
}

function xorMut(a, b) {
  const aLength = Math.min(a.length, b.length);
  for (let i = 0; i < aLength; i++) {
    a[i] = a[i] ^ b[i];
  }
}

const getUint32Array = arr => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));

function nodeEncrypt(algo, key, pt, iv) {
  const algoName = enums.read(enums.symmetric, algo);
  const cipherObj = new nodeCrypto.createCipheriv(nodeAlgos[algoName], key, iv);
  return streamTransform(pt, value => new Uint8Array(cipherObj.update(value)));
}

function nodeDecrypt(algo, key, ct, iv) {
  const algoName = enums.read(enums.symmetric, algo);
  const decipherObj = new nodeCrypto.createDecipheriv(nodeAlgos[algoName], key, iv);
  return streamTransform(ct, value => new Uint8Array(decipherObj.update(value)));
}
