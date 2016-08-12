/**
 * @see module:crypto/crypto
 * @module crypto
 */

'use strict';

import cipher from './cipher';
import hash from './hash';
import cfb from './cfb';
import * as gcm from './gcm';
import publicKey from './public_key';
import signature from './signature';
import random from './random';
import pkcs1 from './pkcs1';
import crypto from './crypto.js';
import rfc3394 from './rfc3394.js';

const mod = {
  /** @see module:crypto/cipher */
  cipher: cipher,
  /** @see module:crypto/hash */
  hash: hash,
  /** @see module:crypto/cfb */
  cfb: cfb,
  /** @see module:crypto/gcm */
  gcm: gcm,
  /** @see module:crypto/public_key */
  publicKey: publicKey,
  /** @see module:crypto/signature */
  signature: signature,
  /** @see module:crypto/random */
  random: random,
  /** @see module:crypto/pkcs1 */
  pkcs1: pkcs1,
  /** @see module:crypto/rfc3394 */
  rfc3394: rfc3394,
};

for (var i in crypto) {
  mod[i] = crypto[i];
}

export default mod;
