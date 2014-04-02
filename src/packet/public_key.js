// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
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
 * Implementation of the Key Material Packet (Tag 5,6,7,14)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.5|RFC4480 5.5}:
 * A key material packet contains all the information about a public or
 * private key.  There are four variants of this packet type, and two
 * major versions.  Consequently, this section is complex.
 * @requires crypto
 * @requires enums
 * @requires type/keyid
 * @requires type/mpi
 * @requires util
 * @module packet/public_key
 */

module.exports = PublicKey;

var util = require('../util.js'),
  type_mpi = require('../type/mpi.js'),
  type_keyid = require('../type/keyid.js'),
  enums = require('../enums.js'),
  crypto = require('../crypto');

/**
 * @constructor
 */
function PublicKey() {
  this.tag = enums.packet.publicKey;
  this.version = 4;
  /** Key creation date.
   * @type {Date} */
  this.created = new Date();
  /** A list of multiprecision integers
   * @type {module:type/mpi} */
  this.mpi = [];
  /** Public key algorithm
   * @type {module:enums.publicKey} */
  this.algorithm = 'rsa_sign';
  // time in days (V3 only)
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
 * Internal Parser for public keys as specified in {@link http://tools.ietf.org/html/rfc4880#section-5.5.2|RFC 4880 section 5.5.2 Public-Key Packet Formats}
 * called by read_tag&lt;num&gt;
 * @param {String} input Input string to read the packet from
 * @return {Object} This object with attributes set by the parser
 */
PublicKey.prototype.read = function (bytes) {
  var pos = 0;
  // A one-octet version number (3 or 4).
  this.version = bytes.charCodeAt(pos++);

  if (this.version == 3 || this.version == 4) {
    // - A four-octet number denoting the time that the key was created.
    this.created = util.readDate(bytes.substr(pos, 4));
    pos += 4;

    if (this.version == 3) {
      // - A two-octet number denoting the time in days that this key is
      //   valid.  If this number is zero, then it does not expire.
      this.expirationTimeV3 = util.readNumber(bytes.substr(pos, 2));
      pos += 2;
    }

    // - A one-octet number denoting the public-key algorithm of this key.
    this.algorithm = enums.read(enums.publicKey, bytes.charCodeAt(pos++));

    var mpicount = crypto.getPublicMpiCount(this.algorithm);
    this.mpi = [];

    var bmpi = bytes.substr(pos);
    var p = 0;

    for (var i = 0; i < mpicount && p < bmpi.length; i++) {

      this.mpi[i] = new type_mpi();

      p += this.mpi[i].read(bmpi.substr(p));

      if (p > bmpi.length) {
        throw new Error('Error reading MPI @:' + p);
      }
    }

    return p + 6;
  } else {
    throw new Error('Version ' + this.version + ' of the key packet is unsupported.');
  }
};

/**
 * Alias of read()
 * @see module:packet/public_key~PublicKey#read
 */
PublicKey.prototype.readPublicKey = PublicKey.prototype.read;

/**
 * Same as write_private_key, but has less information because of
 * public key.
 * @return {Object} {body: [string]OpenPGP packet body contents,
 * header: [string] OpenPGP packet header, string: [string] header+body}
 */
PublicKey.prototype.write = function () {
  // Version
  var result = String.fromCharCode(this.version);
  result += util.writeDate(this.created);
  if (this.version == 3) {
    result += util.writeNumber(this.expirationTimeV3, 2);
  }
  result += String.fromCharCode(enums.write(enums.publicKey, this.algorithm));

  var mpicount = crypto.getPublicMpiCount(this.algorithm);

  for (var i = 0; i < mpicount; i++) {
    result += this.mpi[i].write();
  }

  return result;
};

/**
 * Alias of write()
 * @see module:packet/public_key~PublicKey#write
 */
PublicKey.prototype.writePublicKey = PublicKey.prototype.write;

/**
 * Write an old version packet - it's used by some of the internal routines.
 */
PublicKey.prototype.writeOld = function () {
  var bytes = this.writePublicKey();

  return String.fromCharCode(0x99) +
    util.writeNumber(bytes.length, 2) +
    bytes;
};

/**
 * Calculates the key id of the key
 * @return {String} A 8 byte key id
 */
PublicKey.prototype.getKeyId = function () {
  if (this.keyid) {
    return this.keyid;
  }
  this.keyid = new type_keyid();
  if (this.version == 4) {
    this.keyid.read(util.hex2bin(this.getFingerprint()).substr(12, 8));
  } else if (this.version == 3) {
    this.keyid.read(this.mpi[0].write().substr(-8));
  }
  return this.keyid;
};

/**
 * Calculates the fingerprint of the key
 * @return {String} A string containing the fingerprint in lowercase hex
 */
PublicKey.prototype.getFingerprint = function () {
  if (this.fingerprint) {
    return this.fingerprint;
  }
  var toHash = '';
  if (this.version == 4) {
    toHash = this.writeOld();
    this.fingerprint = crypto.hash.sha1(toHash);
  } else if (this.version == 3) {
    var mpicount = crypto.getPublicMpiCount(this.algorithm);
    for (var i = 0; i < mpicount; i++) {
      toHash += this.mpi[i].toBytes();
    }
    this.fingerprint = crypto.hash.md5(toHash);
  }
  this.fingerprint = util.hexstrdump(this.fingerprint);
  return this.fingerprint;
};

/**
 * Returns bit size of key
 * @return {int} Number of bits
 */
PublicKey.prototype.getBitSize = function () {
  return this.mpi[0].byteLength() * 8;
};

/**
 * Fix custom types after cloning
 */
PublicKey.prototype.postCloneTypeFix = function() {
  for (var i = 0; i < this.mpi.length; i++) {
    this.mpi[i] = type_mpi.fromClone(this.mpi[i]);
  }
  if (this.keyid) {
    this.keyid = type_keyid.fromClone(this.keyid);
  }
};
