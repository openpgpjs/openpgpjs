/**
 * @fileoverview Provides access to all cryptographic primitives used in OpenPGP.js
 * @see module:crypto/crypto
 * @see module:crypto/signature
 * @see module:crypto/public_key
 * @see module:crypto/cipher
 * @see module:crypto/random
 * @see module:crypto/hash
 * @module crypto
 */

import cipher from './cipher';
import hash from './hash';
import cfb from './cfb';
import gcm from './gcm';
import eax from './eax';
import ocb from './ocb';
import publicKey from './public_key';
import signature from './signature';
import random from './random';
import pkcs1 from './pkcs1';
import pkcs5 from './pkcs5';
import crypto from './crypto';
import aes_kw from './aes_kw';

// TODO move cfb and gcm to cipher
const mod = {
  /** @see module:crypto/cipher */
  cipher: cipher,
  /** @see module:crypto/hash */
  hash: hash,
  /** @see module:crypto/cfb */
  cfb: cfb,
  /** @see module:crypto/gcm */
  gcm: gcm,
  experimental_gcm: gcm,
  /** @see module:crypto/eax */
  eax: eax,
  /** @see module:crypto/ocb */
  ocb: ocb,
  /** @see module:crypto/public_key */
  publicKey: publicKey,
  /** @see module:crypto/signature */
  signature: signature,
  /** @see module:crypto/random */
  random: random,
  /** @see module:crypto/pkcs1 */
  pkcs1: pkcs1,
  /** @see module:crypto/pkcs5 */
  pkcs5: pkcs5,
  /** @see module:crypto/aes_kw */
  aes_kw: aes_kw
};

Object.assign(mod, crypto);

export default mod;
