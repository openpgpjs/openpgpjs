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
 * @requires type/keyid
 * @requires type/mpi
 * @requires config
 * @requires crypto
 * @requires enums
 * @requires util
 */

import { Sha1 } from 'asmcrypto.js/dist_es5/hash/sha1/sha1';
import { Sha256 } from 'asmcrypto.js/dist_es5/hash/sha256/sha256';
import type_keyid from '../type/keyid';
import type_mpi from '../type/mpi';
import config from '../config';
import crypto from '../crypto';
import enums from '../enums';
import util from '../util';

/**
 * Implementation of the Key Material Packet (Tag 5,6,7,14)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.5|RFC4480 5.5}:
 * A key material packet contains all the information about a public or
 * private key.  There are four variants of this packet type, and two
 * major versions.
 *
 * A Public-Key packet starts a series of packets that forms an OpenPGP
 * key (sometimes called an OpenPGP certificate).
 * @memberof module:packet
 * @constructor
 */
function PublicKey(date = new Date()) {
  /**
   * Packet type
   * @type {module:enums.packet}
   */
  this.tag = enums.packet.publicKey;
  /**
   * Packet version
   * @type {Integer}
   */
  this.version = config.v5_keys ? 5 : 4;
  /**
   * Key creation date.
   * @type {Date}
   */
  this.created = util.normalizeDate(date);
  /**
   * Public key algorithm.
   * @type {String}
   */
  this.algorithm = null;
  /**
   * Algorithm specific params
   * @type {Array<Object>}
   */
  this.params = [];
  /**
   * Time until expiration in days (V3 only)
   * @type {Integer}
   */
  this.expirationTimeV3 = 0;
  /**
   * Fingerprint in lowercase hex
   * @type {String}
   */
  this.fingerprint = null;
  /**
   * Keyid
   * @type {module:type/keyid}
   */
  this.keyid = null;
}

/**
 * Internal Parser for public keys as specified in {@link https://tools.ietf.org/html/rfc4880#section-5.5.2|RFC 4880 section 5.5.2 Public-Key Packet Formats}
 * called by read_tag&lt;num&gt;
 * @param {Uint8Array} bytes Input array to read the packet from
 * @returns {Object} This object with attributes set by the parser
 */
PublicKey.prototype.read = function (bytes) {
  let pos = 0;
  // A one-octet version number (3, 4 or 5).
  this.version = bytes[pos++];

  if (this.version === 4 || this.version === 5) {
    // - A four-octet number denoting the time that the key was created.
    this.created = util.readDate(bytes.subarray(pos, pos + 4));
    pos += 4;

    // - A one-octet number denoting the public-key algorithm of this key.
    this.algorithm = enums.read(enums.publicKey, bytes[pos++]);
    const algo = enums.write(enums.publicKey, this.algorithm);

    if (this.version === 5) {
      // - A four-octet scalar octet count for the following key material.
      pos += 4;
    }

    // - A series of values comprising the key material.  This is
    //   algorithm-specific and described in section XXXX.
    const types = crypto.getPubKeyParamTypes(algo);
    this.params = crypto.constructParams(types);

    for (let i = 0; i < types.length && pos < bytes.length; i++) {
      pos += this.params[i].read(bytes.subarray(pos, bytes.length));
      if (pos > bytes.length) {
        throw new Error('Error reading MPI @:' + pos);
      }
    }

    return pos;
  }
  throw new Error('Version ' + this.version + ' of the key packet is unsupported.');
};

/**
 * Alias of read()
 * @see module:packet.PublicKey#read
 */
PublicKey.prototype.readPublicKey = PublicKey.prototype.read;

/**
 * Same as write_private_key, but has less information because of
 * public key.
 * @returns {Uint8Array} OpenPGP packet body contents,
 */
PublicKey.prototype.write = function () {
  const arr = [];
  // Version
  arr.push(new Uint8Array([this.version]));
  arr.push(util.writeDate(this.created));
  // A one-octet number denoting the public-key algorithm of this key
  const algo = enums.write(enums.publicKey, this.algorithm);
  arr.push(new Uint8Array([algo]));

  const paramCount = crypto.getPubKeyParamTypes(algo).length;
  const params = util.concatUint8Array(this.params.slice(0, paramCount).map(param => param.write()));
  if (this.version === 5) {
    // A four-octet scalar octet count for the following key material
    arr.push(util.writeNumber(params.length, 4));
  }
  // Algorithm-specific params
  arr.push(params);
  return util.concatUint8Array(arr);
};

/**
 * Alias of write()
 * @see module:packet.PublicKey#write
 */
PublicKey.prototype.writePublicKey = PublicKey.prototype.write;

/**
 * Write packet in order to be hashed; either for a signature or a fingerprint.
 */
PublicKey.prototype.writeForHash = function (version) {
  const bytes = this.writePublicKey();

  if (version === 5) {
    return util.concatUint8Array([new Uint8Array([0x9A]), util.writeNumber(bytes.length, 4), bytes]);
  }
  return util.concatUint8Array([new Uint8Array([0x99]), util.writeNumber(bytes.length, 2), bytes]);
};

/**
 * Check whether secret-key data is available in decrypted form. Returns null for public keys.
 * @returns {Boolean|null}
 */
PublicKey.prototype.isDecrypted = function() {
  return null;
};

/**
 * Returns the creation time of the key
 * @returns {Date}
 */
PublicKey.prototype.getCreationTime = function() {
  return this.created;
};

/**
 * Calculates the key id of the key
 * @returns {module:type/keyid} A 8 byte key id
 */
PublicKey.prototype.getKeyId = function () {
  if (this.keyid) {
    return this.keyid;
  }
  this.keyid = new type_keyid();
  if (this.version === 5) {
    this.keyid.read(util.hex_to_Uint8Array(this.getFingerprint()).subarray(0, 8));
  } else if (this.version === 4) {
    this.keyid.read(util.hex_to_Uint8Array(this.getFingerprint()).subarray(12, 20));
  }
  return this.keyid;
};

/**
 * Calculates the fingerprint of the key
 * @returns {Uint8Array} A Uint8Array containing the fingerprint
 */
PublicKey.prototype.getFingerprintBytes = function () {
  if (this.fingerprint) {
    return this.fingerprint;
  }
  const toHash = this.writeForHash(this.version);
  if (this.version === 5) {
    this.fingerprint = Sha256.bytes(toHash);
  } else if (this.version === 4) {
    this.fingerprint = Sha1.bytes(toHash);
  }
  return this.fingerprint;
};

/**
 * Calculates the fingerprint of the key
 * @returns {String} A string containing the fingerprint in lowercase hex
 */
PublicKey.prototype.getFingerprint = function() {
  return util.Uint8Array_to_hex(this.getFingerprintBytes());
};

/**
 * Calculates whether two keys have the same fingerprint without actually calculating the fingerprint
 * @returns {Boolean} Whether the two keys have the same version and public key data
 */
PublicKey.prototype.hasSameFingerprintAs = function(other) {
  return this.version === other.version && util.equalsUint8Array(this.writePublicKey(), other.writePublicKey());
};

/**
 * Returns algorithm information
 * @returns {Object} An object of the form {algorithm: String, rsaBits:int, curve:String}
 */
PublicKey.prototype.getAlgorithmInfo = function () {
  const result = {};
  result.algorithm = this.algorithm;
  if (this.params[0] instanceof type_mpi) {
    result.rsaBits = this.params[0].byteLength() * 8;
    result.bits = result.rsaBits; // Deprecated.
  } else {
    result.curve = this.params[0].getName();
  }
  return result;
};

/**
 * Fix custom types after cloning
 */
PublicKey.prototype.postCloneTypeFix = function() {
  const algo = enums.write(enums.publicKey, this.algorithm);
  const types = crypto.getPubKeyParamTypes(algo);
  for (let i = 0; i < types.length; i++) {
    const param = this.params[i];
    this.params[i] = types[i].fromClone(param);
  }
  if (this.keyid) {
    this.keyid = type_keyid.fromClone(this.keyid);
  }
};

export default PublicKey;
