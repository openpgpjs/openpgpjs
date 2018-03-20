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
 * @requires crypto
 * @requires enums
 * @requires util
 */

import type_keyid from '../type/keyid';
import type_mpi from '../type/mpi';
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
function PublicKey(date=new Date()) {
  /**
   * Packet type
   * @type {module:enums.packet}
   */
  this.tag = enums.packet.publicKey;
  /**
   * Packet version
   * @type {Integer}
   */
  this.version = 4;
  /**
   * Key creation date.
   * @type {Date}
   */
  this.created = util.normalizeDate(date);
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
  // A one-octet version number (3 or 4).
  this.version = bytes[pos++];

  if (this.version === 3 || this.version === 4) {
    // - A four-octet number denoting the time that the key was created.
    this.created = util.readDate(bytes.subarray(pos, pos + 4));
    pos += 4;

    if (this.version === 3) {
      // - A two-octet number denoting the time in days that this key is
      //   valid.  If this number is zero, then it does not expire.
      this.expirationTimeV3 = util.readNumber(bytes.subarray(pos, pos + 2));
      pos += 2;
    }

    // - A one-octet number denoting the public-key algorithm of this key.
    this.algorithm = enums.read(enums.publicKey, bytes[pos++]);
    const algo = enums.write(enums.publicKey, this.algorithm);
    const types = crypto.getPubKeyParamTypes(algo);
    this.params = crypto.constructParams(types);

    const b = bytes.subarray(pos, bytes.length);
    let p = 0;

    for (let i = 0; i < types.length && p < b.length; i++) {
      p += this.params[i].read(b.subarray(p, b.length));
      if (p > b.length) {
        throw new Error('Error reading MPI @:' + p);
      }
    }

    return p + 6;
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
  if (this.version === 3) {
    arr.push(util.writeNumber(this.expirationTimeV3, 2));
  }
  // Algorithm-specific params
  const algo = enums.write(enums.publicKey, this.algorithm);
  const paramCount = crypto.getPubKeyParamTypes(algo).length;
  arr.push(new Uint8Array([algo]));
  for (let i = 0; i < paramCount; i++) {
    arr.push(this.params[i].write());
  }

  return util.concatUint8Array(arr);
};

/**
 * Alias of write()
 * @see module:packet.PublicKey#write
 */
PublicKey.prototype.writePublicKey = PublicKey.prototype.write;

/**
 * Write an old version packet - it's used by some of the internal routines.
 */
PublicKey.prototype.writeOld = function () {
  const bytes = this.writePublicKey();

  return util.concatUint8Array([new Uint8Array([0x99]), util.writeNumber(bytes.length, 2), bytes]);
};

/**
 * Calculates the key id of the key
 * @returns {String} A 8 byte key id
 */
PublicKey.prototype.getKeyId = function () {
  if (this.keyid) {
    return this.keyid;
  }
  this.keyid = new type_keyid();
  if (this.version === 4) {
    this.keyid.read(util.hex_to_Uint8Array(this.getFingerprint()).subarray(12, 20));
  } else if (this.version === 3) {
    const arr = this.params[0].write();
    this.keyid.read(arr.subarray(arr.length - 8, arr.length));
  }
  return this.keyid;
};

/**
 * Calculates the fingerprint of the key
 * @returns {String} A string containing the fingerprint in lowercase hex
 */
PublicKey.prototype.getFingerprint = function () {
  if (this.fingerprint) {
    return this.fingerprint;
  }
  let toHash = '';
  if (this.version === 4) {
    toHash = this.writeOld();
    this.fingerprint = util.Uint8Array_to_str(crypto.hash.sha1(toHash));
  } else if (this.version === 3) {
    const algo = enums.write(enums.publicKey, this.algorithm);
    const paramCount = crypto.getPubKeyParamTypes(algo).length;
    for (let i = 0; i < paramCount; i++) {
      toHash += this.params[i].toString();
    }
    this.fingerprint = util.Uint8Array_to_str(crypto.hash.md5(util.str_to_Uint8Array(toHash)));
  }
  this.fingerprint = util.str_to_hex(this.fingerprint);
  return this.fingerprint;
};

/**
 * Returns algorithm information
 * @returns {Promise<Object>} An object of the form {algorithm: String, bits:int, curve:String}
 */
PublicKey.prototype.getAlgorithmInfo = function () {
  const result = {};
  result.algorithm = this.algorithm;
  if (this.params[0] instanceof type_mpi) {
    result.bits = this.params[0].byteLength() * 8;
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
