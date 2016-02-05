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
 * @requires config
 * @module packet/sym_encrypted_integrity_protected
 */

'use strict';

import util from '../util.js';
import crypto from '../crypto';
import enums from '../enums.js';
import asmCrypto from 'asmcrypto-lite';
const nodeCrypto = util.getNodeCrypto();
const Buffer = util.getNodeBuffer();

/**
 * @constructor
 */
export default function SymEncryptedIntegrityProtected() {
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
  var version = bytes[0];

  if (version !== 1) {
    throw new Error('Invalid packet version.');
  }

  // - Encrypted data, the output of the selected symmetric-key cipher
  //   operating in Cipher Feedback mode with shift amount equal to the
  //   block size of the cipher (CFB-n where n is the block size).
  this.encrypted = bytes.subarray(1, bytes.length);
};

SymEncryptedIntegrityProtected.prototype.write = function () {
  // 1 = Version
  return util.concatUint8Array([new Uint8Array([1]), this.encrypted]);
};

SymEncryptedIntegrityProtected.prototype.encrypt = function (sessionKeyAlgorithm, key) {
  var bytes = this.packets.write();

  var prefixrandom = crypto.getPrefixRandom(sessionKeyAlgorithm);
  var repeat = new Uint8Array([prefixrandom[prefixrandom.length - 2], prefixrandom[prefixrandom.length - 1]]);
  var prefix = util.concatUint8Array([prefixrandom, repeat]);

  // Modification detection code packet.
  var mdc = new Uint8Array([0xD3, 0x14]);

  // This could probably be cleaned up to use less memory
  var tohash = util.concatUint8Array([bytes, mdc]);
  var hash = crypto.hash.sha1(util.concatUint8Array([prefix, tohash]));
  tohash = util.concatUint8Array([tohash, hash]);

  if(sessionKeyAlgorithm.substr(0,3) === 'aes') { // AES optimizations. Native code for node, asmCrypto for browser.
    var blockSize = crypto.cipher[sessionKeyAlgorithm].blockSize;

    if(nodeCrypto) { // Node crypto library. Only loaded if config.useNative === true
      var cipherObj = new nodeCrypto.createCipheriv('aes-' + sessionKeyAlgorithm.substr(3,3) + '-cfb',
        new Buffer(key), new Buffer(new Uint8Array(blockSize)));
      this.encrypted = new Uint8Array(cipherObj.update(new Buffer(util.concatUint8Array([prefix, tohash]))));

    } else { // asm.js fallback
      this.encrypted = asmCrypto.AES_CFB.encrypt(util.concatUint8Array([prefix, tohash]), key);
    }

  } else {
    this.encrypted = crypto.cfb.encrypt(prefixrandom, sessionKeyAlgorithm, tohash, key, false)
      .subarray(0, prefix.length + tohash.length);
  }
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
  var decrypted;

  if(sessionKeyAlgorithm.substr(0,3) === 'aes') {  // AES optimizations. Native code for node, asmCrypto for browser.
    var blockSize = crypto.cipher[sessionKeyAlgorithm].blockSize;

    if(nodeCrypto) { // Node crypto library. Only loaded if config.useNative === true
      var decipherObj = new nodeCrypto.createDecipheriv('aes-' + sessionKeyAlgorithm.substr(3,3) + '-cfb',
        new Buffer(key), new Buffer(new Uint8Array(blockSize)));
      decrypted = new Uint8Array(decipherObj.update(new Buffer(this.encrypted)));

    } else { // asm.js fallback
      decrypted = asmCrypto.AES_CFB.decrypt(this.encrypted, key);
    }

    // Remove random prefix
    decrypted = decrypted.subarray(blockSize + 2, decrypted.length);

  } else {
    decrypted = crypto.cfb.decrypt(sessionKeyAlgorithm, key, this.encrypted, false);
  }

  // there must be a modification detection code packet as the
  // last packet and everything gets hashed except the hash itself
  this.hash = util.Uint8Array2str(crypto.hash.sha1(util.concatUint8Array([crypto.cfb.mdc(sessionKeyAlgorithm, key, this.encrypted),
    decrypted.subarray(0, decrypted.length - 20)])));

  var mdc = util.Uint8Array2str(decrypted.subarray(decrypted.length - 20, decrypted.length));

  if (this.hash !== mdc) {
    throw new Error('Modification detected.');
  } else {
    this.packets.read(decrypted.subarray(0, decrypted.length - 22));
  }
};
