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
 * @requires asmcrypto.js
 * @requires crypto
 * @requires enums
 * @requires util
 */

import { AES_CFB_Decrypt, AES_CFB_Encrypt } from 'asmcrypto.js/src/aes/cfb/exports';

import crypto from '../crypto';
import enums from '../enums';
import util from '../util';

const nodeCrypto = util.getNodeCrypto();
const Buffer = util.getNodeBuffer();

const VERSION = 1; // A one-octet version number of the data packet.

/**
 * Implementation of the Sym. Encrypted Integrity Protected Data Packet (Tag 18)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.13|RFC4880 5.13}:
 * The Symmetrically Encrypted Integrity Protected Data packet is
 * a variant of the Symmetrically Encrypted Data packet. It is a new feature
 * created for OpenPGP that addresses the problem of detecting a modification to
 * encrypted data. It is used in combination with a Modification Detection Code
 * packet.
 * @memberof module:packet
 * @constructor
 */
function SymEncryptedIntegrityProtected() {
  this.tag = enums.packet.symEncryptedIntegrityProtected;
  this.version = VERSION;
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

SymEncryptedIntegrityProtected.prototype.read = async function (bytes) {
  const reader = bytes.getReader();

  // - A one-octet version number. The only currently defined value is 1.
  if (await reader.readByte() !== VERSION) {
    throw new Error('Invalid packet version.');
  }

  // - Encrypted data, the output of the selected symmetric-key cipher
  //   operating in Cipher Feedback mode with shift amount equal to the
  //   block size of the cipher (CFB-n where n is the block size).
  this.encrypted = reader.substream();
};

SymEncryptedIntegrityProtected.prototype.write = function () {
  return util.concatUint8Array([new Uint8Array([VERSION]), this.encrypted]);
};

/**
 * Encrypt the payload in the packet.
 * @param  {String} sessionKeyAlgorithm   The selected symmetric encryption algorithm to be used e.g. 'aes128'
 * @param  {Uint8Array} key               The key of cipher blocksize length to be used
 * @returns {Promise<Boolean>}
 * @async
 */
SymEncryptedIntegrityProtected.prototype.encrypt = async function (sessionKeyAlgorithm, key) {
  const bytes = this.packets.write();
  const prefixrandom = await crypto.getPrefixRandom(sessionKeyAlgorithm);
  const repeat = new Uint8Array([prefixrandom[prefixrandom.length - 2], prefixrandom[prefixrandom.length - 1]]);
  const prefix = util.concatUint8Array([prefixrandom, repeat]);
  const mdc = new Uint8Array([0xD3, 0x14]); // modification detection code packet

  let [tohash, tohashClone] = util.concatUint8Array([bytes, mdc]).tee();
  const hash = crypto.hash.sha1(util.concatUint8Array([prefix, tohashClone]));
  tohash = util.concatUint8Array([tohash, hash]);

  if (sessionKeyAlgorithm.substr(0, 3) === 'aes') { // AES optimizations. Native code for node, asmCrypto for browser.
    this.encrypted = aesEncrypt(sessionKeyAlgorithm, util.concatUint8Array([prefix, tohash]), key);
  } else {
    this.encrypted = crypto.cfb.encrypt(prefixrandom, sessionKeyAlgorithm, tohash, key, false);
    this.encrypted = this.encrypted.subarray(0, prefix.length + tohash.length);
  }
  return true;
};

/**
 * Decrypts the encrypted data contained in the packet.
 * @param  {String} sessionKeyAlgorithm   The selected symmetric encryption algorithm to be used e.g. 'aes128'
 * @param  {Uint8Array} key               The key of cipher blocksize length to be used
 * @returns {Promise<Boolean>}
 * @async
 */
SymEncryptedIntegrityProtected.prototype.decrypt = async function (sessionKeyAlgorithm, key) {
  const [encrypted, encryptedClone] = this.encrypted.tee();
  let decrypted;
  if (sessionKeyAlgorithm.substr(0, 3) === 'aes') { // AES optimizations. Native code for node, asmCrypto for browser.
    decrypted = aesDecrypt(sessionKeyAlgorithm, encrypted, key);
  } else {
    decrypted = crypto.cfb.decrypt(sessionKeyAlgorithm, key, encrypted, false);
  }

  let decryptedClone;
  [decrypted, decryptedClone] = decrypted.tee();
  // there must be a modification detection code packet as the
  // last packet and everything gets hashed except the hash itself
  const encryptedPrefix = await encryptedClone.subarray(0, crypto.cipher[sessionKeyAlgorithm].blockSize + 2).readToEnd();
  const prefix = crypto.cfb.mdc(sessionKeyAlgorithm, key, encryptedPrefix);
  let [bytes, bytesClone] = decrypted.subarray(0, -20).tee();
  const tohash = util.concatUint8Array([prefix, bytes]);
  this.hash = util.Uint8Array_to_str(await crypto.hash.sha1(tohash).readToEnd());
  const mdc = util.Uint8Array_to_str(await decryptedClone.subarray(-20).readToEnd());

  if (this.hash !== mdc) {
    throw new Error('Modification detected.');
  } else {
    await this.packets.read(bytesClone.subarray(0, -2));
  }

  return true;
};

export default SymEncryptedIntegrityProtected;


//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////


function aesEncrypt(algo, pt, key) {
  if (nodeCrypto) { // Node crypto library.
    return nodeEncrypt(algo, pt, key);
  } // asm.js fallback
  const cfb = new AES_CFB_Encrypt(key);
  return pt.transform((done, value) => {
    if (!done) {
      return cfb.process(value).result;
    }
    return cfb.finish().result;
  });
}

function aesDecrypt(algo, ct, key) {
  let pt;
  if (nodeCrypto) { // Node crypto library.
    pt = nodeDecrypt(algo, ct, key);
  } else { // asm.js fallback
    const cfb = new AES_CFB_Decrypt(key);
    pt = ct.transform((done, value) => {
      if (!done) {
        return cfb.process(value).result;
      }
      return cfb.finish().result;
    });
  }
  return pt.subarray(crypto.cipher[algo].blockSize + 2); // Remove random prefix
}

function nodeEncrypt(algo, prefix, pt, key) {
  key = new Buffer(key);
  const iv = new Buffer(new Uint8Array(crypto.cipher[algo].blockSize));
  const cipherObj = new nodeCrypto.createCipheriv('aes-' + algo.substr(3, 3) + '-cfb', key, iv);
  const ct = cipherObj.update(new Buffer(util.concatUint8Array([prefix, pt])));
  return new Uint8Array(ct);
}

function nodeDecrypt(algo, ct, key) {
  ct = new Buffer(ct);
  key = new Buffer(key);
  const iv = new Buffer(new Uint8Array(crypto.cipher[algo].blockSize));
  const decipherObj = new nodeCrypto.createDecipheriv('aes-' + algo.substr(3, 3) + '-cfb', key, iv);
  const pt = decipherObj.update(ct);
  return new Uint8Array(pt);
}
