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

import * as stream from '@openpgp/web-stream-tools';
import crypto from '../crypto';
import enums from '../enums';
import util from '../util';
import defaultConfig from '../config';

import LiteralDataPacket from './literal_data';
import CompressedDataPacket from './compressed_data';
import OnePassSignaturePacket from './one_pass_signature';
import SignaturePacket from './signature';
import PacketList from './packetlist';

// A SEIP packet can contain the following packet types
const allowedPackets = /*#__PURE__*/ util.constructAllowedPackets([
  LiteralDataPacket,
  CompressedDataPacket,
  OnePassSignaturePacket,
  SignaturePacket
]);

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
 */
class SymEncryptedIntegrityProtectedDataPacket {
  static get tag() {
    return enums.packet.symEncryptedIntegrityProtectedData;
  }

  constructor() {
    this.version = VERSION;
    this.encrypted = null;
    this.packets = null;
  }

  async read(bytes) {
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
  }

  write() {
    return util.concat([new Uint8Array([VERSION]), this.encrypted]);
  }

  /**
   * Encrypt the payload in the packet.
   * @param {String} sessionKeyAlgorithm - The selected symmetric encryption algorithm to be used e.g. 'aes128'
   * @param {Uint8Array} key - The key of cipher blocksize length to be used
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Boolean>}
   * @async
   */
  async encrypt(sessionKeyAlgorithm, key, config = defaultConfig) {
    let bytes = this.packets.write();
    if (stream.isArrayStream(bytes)) bytes = await stream.readToEnd(bytes);
    const prefix = await crypto.getPrefixRandom(sessionKeyAlgorithm);
    const mdc = new Uint8Array([0xD3, 0x14]); // modification detection code packet

    const tohash = util.concat([prefix, bytes, mdc]);
    const hash = await crypto.hash.sha1(stream.passiveClone(tohash));
    const plaintext = util.concat([tohash, hash]);

    this.encrypted = await crypto.mode.cfb.encrypt(sessionKeyAlgorithm, key, plaintext, new Uint8Array(crypto.cipher[sessionKeyAlgorithm].blockSize), config);
    return true;
  }

  /**
   * Decrypts the encrypted data contained in the packet.
   * @param {String} sessionKeyAlgorithm - The selected symmetric encryption algorithm to be used e.g. 'aes128'
   * @param {Uint8Array} key - The key of cipher blocksize length to be used
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Boolean>}
   * @async
   */
  async decrypt(sessionKeyAlgorithm, key, config = defaultConfig) {
    let encrypted = stream.clone(this.encrypted);
    if (stream.isArrayStream(encrypted)) encrypted = await stream.readToEnd(encrypted);
    const decrypted = await crypto.mode.cfb.decrypt(sessionKeyAlgorithm, key, encrypted, new Uint8Array(crypto.cipher[sessionKeyAlgorithm].blockSize));

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
    if (!util.isStream(encrypted) || !config.allowUnauthenticatedStream) {
      packetbytes = await stream.readToEnd(packetbytes);
    }
    this.packets = new PacketList();
    await this.packets.read(packetbytes, allowedPackets);
    return true;
  }
}

export default SymEncryptedIntegrityProtectedDataPacket;
