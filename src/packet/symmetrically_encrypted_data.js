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
 * @requires web-stream-tools
 * @requires config
 * @requires crypto
 * @requires enums
 * @requires util
 * @requires packet
 */

import stream from 'web-stream-tools';
import config from '../config';
import crypto from '../crypto';
import enums from '../enums';
import util from '../util';
import {
  LiteralDataPacket,
  CompressedDataPacket,
  OnePassSignaturePacket,
  SignaturePacket
} from '../packet';

/**
 * Implementation of the Symmetrically Encrypted Data Packet (Tag 9)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.7|RFC4880 5.7}:
 * The Symmetrically Encrypted Data packet contains data encrypted with a
 * symmetric-key algorithm. When it has been decrypted, it contains other
 * packets (usually a literal data packet or compressed data packet, but in
 * theory other Symmetrically Encrypted Data packets or sequences of packets
 * that form whole OpenPGP messages).
 * @memberof module:packet
 */
class SymmetricallyEncryptedDataPacket {
  constructor() {
    /**
     * Packet type
     * @type {module:enums.packet}
     */
    this.tag = enums.packet.symmetricallyEncryptedData;
    /**
     * Encrypted secret-key data
     */
    this.encrypted = null;
    /**
     * Decrypted packets contained within.
     * @type {PacketList}
     */
    this.packets = null;
    /**
     * When true, decrypt fails if message is not integrity protected
     * @see module:config.ignoreMdcError
     */
    this.ignoreMdcError = config.ignoreMdcError;
  }

  read(bytes) {
    this.encrypted = bytes;
  }

  write() {
    return this.encrypted;
  }

  /**
   * Decrypt the symmetrically-encrypted packet data
   * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
   * @param {module:enums.symmetric} sessionKeyAlgorithm Symmetric key algorithm to use
   * @param {Uint8Array} key    The key of cipher blocksize length to be used
   * @returns {Promise<Boolean>}
   * @async
   */
  async decrypt(sessionKeyAlgorithm, key, streaming) {
    // If MDC errors are not being ignored, all missing MDC packets in symmetrically encrypted data should throw an error
    if (!this.ignoreMdcError) {
      throw new Error('Decryption failed due to missing MDC.');
    }

    this.encrypted = await stream.readToEnd(this.encrypted);
    const decrypted = await crypto.cfb.decrypt(sessionKeyAlgorithm, key,
      this.encrypted.subarray(crypto.cipher[sessionKeyAlgorithm].blockSize + 2),
      this.encrypted.subarray(2, crypto.cipher[sessionKeyAlgorithm].blockSize + 2)
    );

    await this.packets.read(decrypted, {
      LiteralDataPacket,
      CompressedDataPacket,
      OnePassSignaturePacket,
      SignaturePacket
    }, streaming);

    return true;
  }

  /**
   * Encrypt the symmetrically-encrypted packet data
   * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
   * @param {module:enums.symmetric} sessionKeyAlgorithm Symmetric key algorithm to use
   * @param {Uint8Array} key    The key of cipher blocksize length to be used
   * @returns {Promise<Boolean>}
   * @async
   */
  async encrypt(algo, key) {
    const data = this.packets.write();

    const prefix = await crypto.getPrefixRandom(algo);
    const FRE = await crypto.cfb.encrypt(algo, key, prefix, new Uint8Array(crypto.cipher[algo].blockSize));
    const ciphertext = await crypto.cfb.encrypt(algo, key, data, FRE.subarray(2));
    this.encrypted = util.concat([FRE, ciphertext]);

    return true;
  }
}

export default SymmetricallyEncryptedDataPacket;
