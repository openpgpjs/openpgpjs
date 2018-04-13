/**
 * @fileoverview This module implements AES-CMAC on top of
 * native AES-CBC using either the WebCrypto API or Node.js' crypto API.
 * @requires asmcrypto.js
 * @requires util
 * @module crypto/cmac
 */

import { AES_CBC } from 'asmcrypto.js/src/aes/cbc/exports';
import util from '../util';

const webCrypto = util.getWebCryptoAll();
const nodeCrypto = util.getNodeCrypto();
const Buffer = util.getNodeBuffer();


const blockLength = 16;


function set_xor_r(S, T) {
  const offset = S.length - blockLength;
  for (let i = 0; i < blockLength; i++) {
    S[i + offset] ^= T[i];
  }
  return S;
}

function mul2(data) {
  const t = data[0] & 0x80;
  for (let i = 0; i < 15; i++) {
    data[i] = (data[i] << 1) ^ ((data[i + 1] & 0x80) ? 1 : 0);
  }
  data[15] = (data[15] << 1) ^ (t ? 0x87 : 0);
  return data;
}

const zeros_16 = new Uint8Array(16);

export default async function CMAC(key) {
  const cbc = await CBC(key);
  const padding = mul2(await cbc(zeros_16));
  const padding2 = mul2(padding.slice());

  return async function(data) {
    return (await cbc(pad(data, padding, padding2))).subarray(-blockLength);
  };
}

function pad(data, padding, padding2) {
  if (data.length % blockLength === 0) {
    return set_xor_r(data, padding);
  }
  const padded = new Uint8Array(data.length + (blockLength - data.length % blockLength));
  padded.set(data);
  padded[data.length] = 0b10000000;
  return set_xor_r(padded, padding2);
}

async function CBC(key) {
  if (util.getWebCryptoAll() && key.length !== 24) { // WebCrypto (no 192 bit support) see: https://www.chromium.org/blink/webcrypto#TOC-AES-support
    key = await webCrypto.importKey('raw', key, { name: 'AES-CBC', length: key.length * 8 }, false, ['encrypt']);
    return async function(pt) {
      const ct = await webCrypto.encrypt({ name: 'AES-CBC', iv: zeros_16, length: blockLength * 8 }, key, pt);
      return new Uint8Array(ct).subarray(0, ct.byteLength - blockLength);
    };
  }
  if (util.getNodeCrypto()) { // Node crypto library
    key = new Buffer(key);
    return async function(pt) {
      pt = new Buffer(pt);
      const en = new nodeCrypto.createCipheriv('aes-' + (key.length * 8) + '-cbc', key, zeros_16);
      const ct = en.update(pt);
      return new Uint8Array(ct);
    };
  }
  // asm.js fallback
  return async function(pt) {
    return AES_CBC.encrypt(pt, key, false, zeros_16);
  };
}
