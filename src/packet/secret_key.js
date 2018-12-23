// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
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
 * @requires packet/public_key
 * @requires type/keyid
 * @requires type/s2k
 * @requires crypto
 * @requires enums
 * @requires util
 */

import publicKey from './public_key';
import type_keyid from '../type/keyid.js';
import type_s2k from '../type/s2k';
import crypto from '../crypto';
import enums from '../enums';
import util from '../util';

/**
 * A Secret-Key packet contains all the information that is found in a
 * Public-Key packet, including the public-key material, but also
 * includes the secret-key material after all the public-key fields.
 * @memberof module:packet
 * @constructor
 * @extends module:packet.PublicKey
 */
function SecretKey(date=new Date()) {
  publicKey.call(this, date);
  /**
   * Packet type
   * @type {module:enums.packet}
   */
  this.tag = enums.packet.secretKey;
  /**
   * Encrypted secret-key data
   */
  this.encrypted = null;
  /**
   * Indicator if secret-key data is encrypted. `this.isEncrypted === false` means data is available in decrypted form.
   */
  this.isEncrypted = null;
}

SecretKey.prototype = new publicKey();
SecretKey.prototype.constructor = SecretKey;

// Helper function

function parse_cleartext_params(cleartext, algorithm) {
  const algo = enums.write(enums.publicKey, algorithm);
  const types = crypto.getPrivKeyParamTypes(algo);
  const params = crypto.constructParams(types);
  let p = 0;

  for (let i = 0; i < types.length && p < cleartext.length; i++) {
    p += params[i].read(cleartext.subarray(p, cleartext.length));
    if (p > cleartext.length) {
      throw new Error('Error reading param @:' + p);
    }
  }

  return params;
}

function write_cleartext_params(params, algorithm) {
  const arr = [];
  const algo = enums.write(enums.publicKey, algorithm);
  const numPublicParams = crypto.getPubKeyParamTypes(algo).length;

  for (let i = numPublicParams; i < params.length; i++) {
    arr.push(params[i].write());
  }

  return util.concatUint8Array(arr);
}


// 5.5.3.  Secret-Key Packet Formats

/**
 * Internal parser for private keys as specified in
 * {@link https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-04#section-5.5.3|RFC4880bis-04 section 5.5.3}
 * @param {String} bytes Input string to read the packet from
 */
SecretKey.prototype.read = function (bytes) {
  // - A Public-Key or Public-Subkey packet, as described above.
  const len = this.readPublicKey(bytes);

  bytes = bytes.subarray(len, bytes.length);


  // - One octet indicating string-to-key usage conventions.  Zero
  //   indicates that the secret-key data is not encrypted.  255 or 254
  //   indicates that a string-to-key specifier is being given.  Any
  //   other value is a symmetric-key encryption algorithm identifier.
  const isEncrypted = bytes[0];

  if (isEncrypted) {
    this.encrypted = bytes;
    this.isEncrypted = true;
  } else {
    // - Plain or encrypted multiprecision integers comprising the secret
    //   key data.  These algorithm-specific fields are as described
    //   below.
    const cleartext = bytes.subarray(1, -2);
    if (!util.equalsUint8Array(util.write_checksum(cleartext), bytes.subarray(-2))) {
      throw new Error('Key checksum mismatch');
    }
    const privParams = parse_cleartext_params(cleartext, this.algorithm);
    this.params = this.params.concat(privParams);
    this.isEncrypted = false;
  }
};

/**
 * Creates an OpenPGP key packet for the given key.
 * @returns {String} A string of bytes containing the secret key OpenPGP packet
 */
SecretKey.prototype.write = function () {
  const arr = [this.writePublicKey()];

  if (!this.encrypted) {
    arr.push(new Uint8Array([0]));
    const cleartextParams = write_cleartext_params(this.params, this.algorithm);
    arr.push(cleartextParams);
    arr.push(util.write_checksum(cleartextParams));
  } else {
    arr.push(this.encrypted);
  }

  return util.concatUint8Array(arr);
};

/**
 * Check whether secret-key data is available in decrypted form. Returns null for public keys.
 * @returns {Boolean|null}
 */
SecretKey.prototype.isDecrypted = function() {
  return this.isEncrypted === false;
};

/**
 * Encrypt the payload. By default, we use aes256 and iterated, salted string
 * to key specifier. If the key is in a decrypted state (isEncrypted === false)
 * and the passphrase is empty or undefined, the key will be set as not encrypted.
 * This can be used to remove passphrase protection after calling decrypt().
 * @param {String} passphrase
 * @returns {Promise<Boolean>}
 * @async
 */
SecretKey.prototype.encrypt = async function (passphrase) {
  if (this.isDecrypted() && !passphrase) {
    this.encrypted = null;
    return false;
  } else if (!passphrase) {
    throw new Error('The key must be decrypted before removing passphrase protection.');
  }

  const s2k = new type_s2k();
  s2k.salt = await crypto.random.getRandomBytes(8);
  const symmetric = 'aes256';
  const cleartext = write_cleartext_params(this.params, this.algorithm);
  const key = await produceEncryptionKey(s2k, passphrase, symmetric);
  const blockLen = crypto.cipher[symmetric].blockSize;
  const iv = await crypto.random.getRandomBytes(blockLen);

  let arr;

  if (this.version === 5) {
    const aead = 'eax';
    const optionalFields = util.concatUint8Array([new Uint8Array([enums.write(enums.symmetric, symmetric), enums.write(enums.aead, aead)]), s2k.write(), iv]);
    arr = [new Uint8Array([253, optionalFields.length])];
    arr.push(optionalFields);
    const mode = crypto[aead];
    const modeInstance = await mode(symmetric, key);
    const encrypted = await modeInstance.encrypt(cleartext, iv.subarray(0, mode.ivLength), new Uint8Array());
    arr.push(util.writeNumber(encrypted.length, 4));
    arr.push(encrypted);
  } else {
    arr = [new Uint8Array([254, enums.write(enums.symmetric, symmetric)])];
    arr.push(s2k.write());
    arr.push(iv);
    arr.push(crypto.cfb.encrypt(symmetric, key, util.concatUint8Array([
      cleartext,
      await crypto.hash.sha1(cleartext)
    ]), iv));
  }

  this.encrypted = util.concatUint8Array(arr);
  return true;
};

async function produceEncryptionKey(s2k, passphrase, algorithm) {
  return s2k.produce_key(
    passphrase,
    crypto.cipher[algorithm].keySize
  );
}

/**
 * Decrypts the private key params which are needed to use the key.
 * {@link module:packet.SecretKey.isDecrypted} should be false, as
 * otherwise calls to this function will throw an error.
 * @param {String} passphrase The passphrase for this private key as string
 * @returns {Promise<Boolean>}
 * @async
 */
SecretKey.prototype.decrypt = async function (passphrase) {
  if (this.isDecrypted()) {
    throw new Error('Key packet is already decrypted.');
  }

  let i = 0;
  let symmetric;
  let aead;
  let key;

  const s2k_usage = this.encrypted[i++];

  // - Only for a version 5 packet, a one-octet scalar octet count of
  //   the next 4 optional fields.
  if (this.version === 5) {
    i++;
  }

  // - [Optional] If string-to-key usage octet was 255, 254, or 253, a
  //   one-octet symmetric encryption algorithm.
  if (s2k_usage === 255 || s2k_usage === 254 || s2k_usage === 253) {
    symmetric = this.encrypted[i++];
    symmetric = enums.read(enums.symmetric, symmetric);

    // - [Optional] If string-to-key usage octet was 253, a one-octet
    //   AEAD algorithm.
    if (s2k_usage === 253) {
      aead = this.encrypted[i++];
      aead = enums.read(enums.aead, aead);
    }

    // - [Optional] If string-to-key usage octet was 255, 254, or 253, a
    //   string-to-key specifier.  The length of the string-to-key
    //   specifier is implied by its type, as described above.
    const s2k = new type_s2k();
    i += s2k.read(this.encrypted.subarray(i, this.encrypted.length));

    key = await produceEncryptionKey(s2k, passphrase, symmetric);
  } else {
    symmetric = s2k_usage;
    symmetric = enums.read(enums.symmetric, symmetric);
    key = await crypto.hash.md5(passphrase);
  }

  // - [Optional] If secret data is encrypted (string-to-key usage octet
  //   not zero), an Initial Vector (IV) of the same length as the
  //   cipher's block size.
  const iv = this.encrypted.subarray(
    i,
    i + crypto.cipher[symmetric].blockSize
  );

  i += iv.length;

  // - Only for a version 5 packet, a four-octet scalar octet count for
  //   the following key material.
  if (this.version === 5) {
    i += 4;
  }

  const ciphertext = this.encrypted.subarray(i, this.encrypted.length);
  let cleartext;
  if (aead) {
    const mode = crypto[aead];
    try {
      const modeInstance = await mode(symmetric, key);
      cleartext = await modeInstance.decrypt(ciphertext, iv.subarray(0, mode.ivLength), new Uint8Array());
    } catch(err) {
      if (err.message === 'Authentication tag mismatch') {
        throw new Error('Incorrect key passphrase: ' + err.message);
      }
    }
  } else {
    const cleartextWithHash = await crypto.cfb.decrypt(symmetric, key, ciphertext, iv);

    let hash;
    let hashlen;
    if (s2k_usage === 255) {
      hashlen = 2;
      cleartext = cleartextWithHash.subarray(0, -hashlen);
      hash = util.write_checksum(cleartext);
    } else {
      hashlen = 20;
      cleartext = cleartextWithHash.subarray(0, -hashlen);
      hash = await crypto.hash.sha1(cleartext);
    }

    if (!util.equalsUint8Array(hash, cleartextWithHash.subarray(-hashlen))) {
      throw new Error('Incorrect key passphrase');
    }
  }

  const privParams = parse_cleartext_params(cleartext, this.algorithm);
  this.params = this.params.concat(privParams);
  this.isEncrypted = false;
  this.encrypted = null;

  return true;
};

SecretKey.prototype.generate = async function (bits, curve) {
  const algo = enums.write(enums.publicKey, this.algorithm);
  this.params = await crypto.generateParams(algo, bits, curve);
  this.isEncrypted = false;
};

/**
 * Clear private params, return to initial state
 */
SecretKey.prototype.clearPrivateParams = function () {
  if (!this.encrypted) {
    throw new Error('If secret key is not encrypted, clearing private params is irreversible.');
  }
  const algo = enums.write(enums.publicKey, this.algorithm);
  this.params = this.params.slice(0, crypto.getPubKeyParamTypes(algo).length);
  this.isEncrypted = true;
};

/**
 * Fix custom types after cloning
 */
SecretKey.prototype.postCloneTypeFix = function() {
  const algo = enums.write(enums.publicKey, this.algorithm);
  const types = [].concat(crypto.getPubKeyParamTypes(algo), crypto.getPrivKeyParamTypes(algo));
  for (let i = 0; i < this.params.length; i++) {
    const param = this.params[i];
    this.params[i] = types[i].fromClone(param);
  }
  if (this.keyid) {
    this.keyid = type_keyid.fromClone(this.keyid);
  }
};

export default SecretKey;
