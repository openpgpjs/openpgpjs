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
   * Indicator if secret-key data is available in decrypted form
   */
  this.isDecrypted = false;
}

SecretKey.prototype = new publicKey();
SecretKey.prototype.constructor = SecretKey;

function get_hash_len(hash) {
  if (hash === 'sha1') {
    return 20;
  }
  return 2;
}

function get_hash_fn(hash) {
  if (hash === 'sha1') {
    return crypto.hash.sha1;
  }
  return function(c) {
    return util.writeNumber(util.calc_checksum(c), 2);
  };
}

// Helper function

function parse_cleartext_params(hash_algorithm, cleartext, algorithm) {
  const hashlen = get_hash_len(hash_algorithm);
  const hashfn = get_hash_fn(hash_algorithm);

  const hashtext = util.Uint8Array_to_str(cleartext.subarray(cleartext.length - hashlen, cleartext.length));
  cleartext = cleartext.subarray(0, cleartext.length - hashlen);
  const hash = util.Uint8Array_to_str(hashfn(cleartext));

  if (hash !== hashtext) {
    return new Error("Incorrect key passphrase");
  }

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

function write_cleartext_params(hash_algorithm, algorithm, params) {
  const arr = [];
  const algo = enums.write(enums.publicKey, algorithm);
  const numPublicParams = crypto.getPubKeyParamTypes(algo).length;

  for (let i = numPublicParams; i < params.length; i++) {
    arr.push(params[i].write());
  }

  const bytes = util.concatUint8Array(arr);

  const hash = get_hash_fn(hash_algorithm)(bytes);

  return util.concatUint8Array([bytes, hash]);
}


// 5.5.3.  Secret-Key Packet Formats

/**
 * Internal parser for private keys as specified in
 * {@link https://tools.ietf.org/html/rfc4880#section-5.5.3|RFC 4880 section 5.5.3}
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
  } else {
    // - Plain or encrypted multiprecision integers comprising the secret
    //   key data.  These algorithm-specific fields are as described
    //   below.
    const privParams = parse_cleartext_params('mod', bytes.subarray(1, bytes.length), this.algorithm);
    if (privParams instanceof Error) {
      throw privParams;
    }
    this.params = this.params.concat(privParams);
    this.isDecrypted = true;
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
    arr.push(write_cleartext_params('mod', this.algorithm, this.params));
  } else {
    arr.push(this.encrypted);
  }

  return util.concatUint8Array(arr);
};


/**
 * Encrypt the payload. By default, we use aes256 and iterated, salted string
 * to key specifier. If the key is in a decrypted state (isDecrypted === true)
 * and the passphrase is empty or undefined, the key will be set as not encrypted.
 * This can be used to remove passphrase protection after calling decrypt().
 * @param {String} passphrase
 * @returns {Promise<Boolean>}
 * @async
 */
SecretKey.prototype.encrypt = async function (passphrase) {
  if (this.isDecrypted && !passphrase) {
    this.encrypted = null;
    return false;
  } else if (!passphrase) {
    throw new Error('The key must be decrypted before removing passphrase protection.');
  }

  const s2k = new type_s2k();
  s2k.salt = await crypto.random.getRandomBytes(8);
  const symmetric = 'aes256';
  const cleartext = write_cleartext_params('sha1', this.algorithm, this.params);
  const key = produceEncryptionKey(s2k, passphrase, symmetric);
  const blockLen = crypto.cipher[symmetric].blockSize;
  const iv = await crypto.random.getRandomBytes(blockLen);

  const arr = [new Uint8Array([254, enums.write(enums.symmetric, symmetric)])];
  arr.push(s2k.write());
  arr.push(iv);
  arr.push(crypto.cfb.normalEncrypt(symmetric, key, cleartext, iv));

  this.encrypted = util.concatUint8Array(arr);
  return true;
};

function produceEncryptionKey(s2k, passphrase, algorithm) {
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
  if (this.isDecrypted) {
    throw new Error('Key packet is already decrypted.');
  }

  let i = 0;
  let symmetric;
  let key;

  const s2k_usage = this.encrypted[i++];

  // - [Optional] If string-to-key usage octet was 255 or 254, a one-
  //   octet symmetric encryption algorithm.
  if (s2k_usage === 255 || s2k_usage === 254) {
    symmetric = this.encrypted[i++];
    symmetric = enums.read(enums.symmetric, symmetric);

    // - [Optional] If string-to-key usage octet was 255 or 254, a
    //   string-to-key specifier.  The length of the string-to-key
    //   specifier is implied by its type, as described above.
    const s2k = new type_s2k();
    i += s2k.read(this.encrypted.subarray(i, this.encrypted.length));

    key = produceEncryptionKey(s2k, passphrase, symmetric);
  } else {
    symmetric = s2k_usage;
    symmetric = enums.read(enums.symmetric, symmetric);
    key = crypto.hash.md5(passphrase);
  }

  // - [Optional] If secret data is encrypted (string-to-key usage octet
  //   not zero), an Initial Vector (IV) of the same length as the
  //   cipher's block size.
  const iv = this.encrypted.subarray(
    i,
    i + crypto.cipher[symmetric].blockSize
  );

  i += iv.length;

  const ciphertext = this.encrypted.subarray(i, this.encrypted.length);
  const cleartext = crypto.cfb.normalDecrypt(symmetric, key, ciphertext, iv);
  const hash = s2k_usage === 254 ?
    'sha1' :
    'mod';

  const privParams = parse_cleartext_params(hash, cleartext, this.algorithm);
  if (privParams instanceof Error) {
    throw privParams;
  }
  this.params = this.params.concat(privParams);
  this.isDecrypted = true;
  this.encrypted = null;

  return true;
};

SecretKey.prototype.generate = function (bits, curve) {
  const that = this;
  const algo = enums.write(enums.publicKey, that.algorithm);
  return crypto.generateParams(algo, bits, curve).then(function(params) {
    that.params = params;
    that.isDecrypted = true;
  });
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
  this.isDecrypted = false;
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
