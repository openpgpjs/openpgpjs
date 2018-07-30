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
 * @requires web-stream-tools
 * @requires config
 * @requires crypto
 * @requires enums
 * @requires util
 */

import { AES_CFB } from 'asmcrypto.js/dist_es5/aes/cfb';

import stream from 'web-stream-tools';
import config from '../config';
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
  await stream.parse(bytes, async reader => {

    // - A one-octet version number. The only currently defined value is 1.
    if (await reader.readByte() !== VERSION) {
      throw new Error('Invalid packet version.');
    }

    // - Encrypted data, the output of the selected symmetric-key cipher
    //   operating in Cipher Feedback mode with shift amount equal to the
    //   block size of the cipher (CFB-n where n is the block size).
    this.encrypted = reader.remainder();
  });
};

SymEncryptedIntegrityProtected.prototype.write = function () {
  return util.concat([new Uint8Array([VERSION]), this.encrypted]);
};

/**
 * Encrypt the payload in the packet.
 * @param  {String} sessionKeyAlgorithm   The selected symmetric encryption algorithm to be used e.g. 'aes128'
 * @param  {Uint8Array} key               The key of cipher blocksize length to be used
 * @param  {Boolean} streaming            Whether to set this.encrypted to a stream
 * @returns {Promise<Boolean>}
 * @async
 */
SymEncryptedIntegrityProtected.prototype.encrypt = async function (sessionKeyAlgorithm, key, streaming) {
  let bytes = this.packets.write();
  if (!streaming) bytes = await stream.readToEnd(bytes);
  const prefixrandom = await crypto.getPrefixRandom(sessionKeyAlgorithm);
  const repeat = new Uint8Array([prefixrandom[prefixrandom.length - 2], prefixrandom[prefixrandom.length - 1]]);
  const prefix = util.concat([prefixrandom, repeat]);
  const mdc = new Uint8Array([0xD3, 0x14]); // modification detection code packet

  let tohash = util.concat([bytes, mdc]);
  const hash = crypto.hash.sha1(util.concat([prefix, stream.passiveClone(tohash)]));
  tohash = util.concat([tohash, hash]);

  if (sessionKeyAlgorithm.substr(0, 3) === 'aes') { // AES optimizations. Native code for node, asmCrypto for browser.
    this.encrypted = aesEncrypt(sessionKeyAlgorithm, util.concat([prefix, tohash]), key);
  } else {
    tohash = await stream.readToEnd(tohash);
    this.encrypted = crypto.cfb.encrypt(prefixrandom, sessionKeyAlgorithm, tohash, key, false);
    this.encrypted = stream.slice(this.encrypted, 0, prefix.length + tohash.length);
  }
  return true;
};

/**
 * Decrypts the encrypted data contained in the packet.
 * @param  {String} sessionKeyAlgorithm   The selected symmetric encryption algorithm to be used e.g. 'aes128'
 * @param  {Uint8Array} key               The key of cipher blocksize length to be used
 * @param  {Boolean} streaming            Whether to read this.encrypted as a stream
 * @returns {Promise<Boolean>}
 * @async
 */
SymEncryptedIntegrityProtected.prototype.decrypt = async function (sessionKeyAlgorithm, key, streaming) {
  if (!streaming) this.encrypted = await stream.readToEnd(this.encrypted);
  const encrypted = stream.clone(this.encrypted);
  const encryptedClone = stream.passiveClone(encrypted);
  let decrypted;
  if (sessionKeyAlgorithm.substr(0, 3) === 'aes') { // AES optimizations. Native code for node, asmCrypto for browser.
    decrypted = aesDecrypt(sessionKeyAlgorithm, encrypted, key, streaming);
  } else {
    decrypted = crypto.cfb.decrypt(sessionKeyAlgorithm, key, await stream.readToEnd(encrypted), false);
  }

  // there must be a modification detection code packet as the
  // last packet and everything gets hashed except the hash itself
  const encryptedPrefix = await stream.readToEnd(stream.slice(encryptedClone, 0, crypto.cipher[sessionKeyAlgorithm].blockSize + 2));
  const prefix = crypto.cfb.mdc(sessionKeyAlgorithm, key, encryptedPrefix);
  const realHash = stream.slice(stream.passiveClone(decrypted), -20);
  const bytes = stream.slice(decrypted, 0, -20);
  const tohash = util.concat([prefix, stream.passiveClone(bytes)]);
  const verifyHash = Promise.all([
    stream.readToEnd(crypto.hash.sha1(tohash)),
    stream.readToEnd(realHash)
  ]).then(([hash, mdc]) => {
    if (!util.equalsUint8Array(hash, mdc)) {
      throw new Error('Modification detected.');
    }
    return new Uint8Array();
  });
  let packetbytes = stream.slice(bytes, 0, -2);
  packetbytes = stream.concat([packetbytes, stream.fromAsync(() => verifyHash)]);
  if (!util.isStream(encrypted) || !config.allow_unauthenticated_stream) {
    packetbytes = await stream.readToEnd(packetbytes);
  }
  await this.packets.read(packetbytes);
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
  const cfb = new AES_CFB(key);
  return stream.transform(pt, value => cfb.AES_Encrypt_process(value), () => cfb.AES_Encrypt_finish());
}

function aesDecrypt(algo, ct, key) {
  let pt;
  if (nodeCrypto) { // Node crypto library.
    pt = nodeDecrypt(algo, ct, key);
  } else { // asm.js fallback
    if (util.isStream(ct)) {
      const cfb = new AES_CFB(key);
      pt = stream.transform(ct, value => cfb.AES_Decrypt_process(value), () => cfb.AES_Decrypt_finish());
    } else {
      pt = AES_CFB.decrypt(ct, key);
    }
  }
  return stream.slice(pt, crypto.cipher[algo].blockSize + 2); // Remove random prefix
}

function nodeEncrypt(algo, pt, key) {
  key = new Buffer(key);
  const iv = new Buffer(new Uint8Array(crypto.cipher[algo].blockSize));
  const cipherObj = new nodeCrypto.createCipheriv('aes-' + algo.substr(3, 3) + '-cfb', key, iv);
  return stream.transform(pt, value => new Uint8Array(cipherObj.update(new Buffer(value))));
}

function nodeDecrypt(algo, ct, key) {
  key = new Buffer(key);
  const iv = new Buffer(new Uint8Array(crypto.cipher[algo].blockSize));
  const decipherObj = new nodeCrypto.createDecipheriv('aes-' + algo.substr(3, 3) + '-cfb', key, iv);
  return stream.transform(ct, value => new Uint8Array(decipherObj.update(new Buffer(value))));
}
