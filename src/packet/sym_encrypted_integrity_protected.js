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
 * Implementation of the Sym. Encrypted Integrity Protected Data
 * Packet (Tag 18)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.13|RFC4880 5.13}:
 * The Symmetrically Encrypted Integrity Protected Data packet is
 * a variant of the Symmetrically Encrypted Data packet. It is a new feature
 * created for OpenPGP that addresses the problem of detecting a modification to
 * encrypted data. It is used in combination with a Modification Detection Code
 * packet.
 * @requires crypto
 * @requires util
 * @requires enums
 * @module packet/sym_encrypted_integrity_protected
 */

module.exports = SymEncryptedIntegrityProtected;

var util = require('../util.js'),
  crypto = require('../crypto'),
  enums = require('../enums.js');

/**
 * @constructor
 */
function SymEncryptedIntegrityProtected() {
  this.tag = enums.packet.symEncryptedIntegrityProtected;
  /** The encrypted payload. */
  this.encrypted = null; // string
  /**
   * If after decrypting the packet this is set to true,
   * a modification has been detected and thus the contents
   * should be discarded.
   * @type {Boolean}
   */
  this.modification = false;
  this.packets = null;
}

SymEncryptedIntegrityProtected.prototype.read = function (bytes) {
  // - A one-octet version number. The only currently defined value is 1.
  var version = bytes.charCodeAt(0);

  if (version != 1) {
    throw new Error('Invalid packet version.');
  }

  // - Encrypted data, the output of the selected symmetric-key cipher
  //   operating in Cipher Feedback mode with shift amount equal to the
  //   block size of the cipher (CFB-n where n is the block size).
  this.encrypted = bytes.substr(1);
};

SymEncryptedIntegrityProtected.prototype.write = function () {

  // 1 = Version
  return String.fromCharCode(1) + this.encrypted;
};

SymEncryptedIntegrityProtected.prototype.encrypt = function (sessionKeyAlgorithm, key) {
  var bytes = this.packets.write();

  var prefixrandom = crypto.getPrefixRandom(sessionKeyAlgorithm);
  var prefix = prefixrandom + prefixrandom.charAt(prefixrandom.length - 2) + prefixrandom.charAt(prefixrandom.length -
    1);

  var tohash = bytes;


  // Modification detection code packet.
  tohash += String.fromCharCode(0xD3);
  tohash += String.fromCharCode(0x14);


  tohash += crypto.hash.sha1(prefix + tohash);


  this.encrypted = crypto.cfb.encrypt(prefixrandom,
    sessionKeyAlgorithm, tohash, key, false).substring(0,
    prefix.length + tohash.length);
};

/**
 * Decrypts the encrypted data contained in this object read_packet must
 * have been called before
 *
 * @param {module:enums.symmetric} sessionKeyAlgorithm
 *            The selected symmetric encryption algorithm to be used
 * @param {String} key The key of cipher blocksize length to be used
 * @return {String} The decrypted data of this packet
 */
SymEncryptedIntegrityProtected.prototype.decrypt = function (sessionKeyAlgorithm, key) {
  var decrypted = crypto.cfb.decrypt(
    sessionKeyAlgorithm, key, this.encrypted, false);


  // there must be a modification detection code packet as the
  // last packet and everything gets hashed except the hash itself
  this.hash = crypto.hash.sha1(
    crypto.cfb.mdc(sessionKeyAlgorithm, key, this.encrypted) + decrypted.substring(0, decrypted.length - 20));


  var mdc = decrypted.substr(decrypted.length - 20, 20);

  if (this.hash != mdc) {
    throw new Error('Modification detected.');
  } else
    this.packets.read(decrypted.substr(0, decrypted.length - 22));
};
