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

import stream from 'web-stream-tools';
import config from '../config';
import crypto from '../crypto';
import enums from '../enums';
import util from '../util';

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
  const prefix = await crypto.getPrefixRandom(sessionKeyAlgorithm);
  const mdc = new Uint8Array([0xD3, 0x14]); // modification detection code packet

  const tohash = util.concat([prefix, bytes, mdc]);
  const hash = await crypto.hash.sha1(stream.passiveClone(tohash));
  const plaintext = util.concat([tohash, hash]);

  this.encrypted = await crypto.cfb.encrypt(sessionKeyAlgorithm, key, plaintext, new Uint8Array(crypto.cipher[sessionKeyAlgorithm].blockSize));
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
  let encrypted = stream.clone(this.encrypted);
  if (!streaming) encrypted = await stream.readToEnd(encrypted);
  const decrypted = await crypto.cfb.decrypt(sessionKeyAlgorithm, key, encrypted, new Uint8Array(crypto.cipher[sessionKeyAlgorithm].blockSize));

  // there must be a modification detection code packet as the
  // last packet and everything gets hashed except the hash itself
  const realHash = stream.slice(stream.passiveClone(decrypted), -20);
  const tohash = stream.slice(decrypted, 0, -20);
  const verifyHash = Promise.all([
    stream.readToEnd(await crypto.hash.sha1(stream.passiveClone(tohash))),
    stream.readToEnd(realHash)
  ]).then(([hash, mdc]) => {
    if (!util.equalsUint8Array(hash, mdc)) {
      throw new Error('Modification detected.');
    }
    return new Uint8Array();
  });
  const bytes = stream.slice(tohash, crypto.cipher[sessionKeyAlgorithm].blockSize + 2); // Remove random prefix
  let packetbytes = stream.slice(bytes, 0, -2); // Remove MDC packet
  packetbytes = stream.concat([packetbytes, stream.fromAsync(() => verifyHash)]);
  if (!util.isStream(encrypted) || !config.allow_unauthenticated_stream) {
    packetbytes = await stream.readToEnd(packetbytes);
  }
  await this.packets.read(packetbytes, streaming);
  return true;
};

export default SymEncryptedIntegrityProtected;
