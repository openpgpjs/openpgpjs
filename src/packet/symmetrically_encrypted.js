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
 */

import stream from 'web-stream-tools';
import config from '../config';
import crypto from '../crypto';
import enums from '../enums';
import util from '../util';

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
 * @constructor
 */
function SymmetricallyEncrypted() {
  /**
   * Packet type
   * @type {module:enums.packet}
   */
  this.tag = enums.packet.symmetricallyEncrypted;
  /**
   * Encrypted secret-key data
   */
  this.encrypted = null;
  /**
   * Decrypted packets contained within.
   * @type {module:packet.List}
   */
  this.packets = null;
  /**
   * When true, decrypt fails if message is not integrity protected
   * @see module:config.ignore_mdc_error
   */
  this.ignore_mdc_error = config.ignore_mdc_error;
}

SymmetricallyEncrypted.prototype.read = function (bytes) {
  this.encrypted = bytes;
};

SymmetricallyEncrypted.prototype.write = function () {
  return this.encrypted;
};

/**
 * Decrypt the symmetrically-encrypted packet data
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
 * @param {module:enums.symmetric} sessionKeyAlgorithm Symmetric key algorithm to use
 * @param {Uint8Array} key    The key of cipher blocksize length to be used
 * @returns {Promise<Boolean>}
 * @async
 */
SymmetricallyEncrypted.prototype.decrypt = async function (sessionKeyAlgorithm, key) {
  // If MDC errors are not being ignored, all missing MDC packets in symmetrically encrypted data should throw an error
  if (!this.ignore_mdc_error) {
    throw new Error('Decryption failed due to missing MDC.');
  }

  this.encrypted = await stream.readToEnd(this.encrypted);
  const decrypted = await crypto.cfb.decrypt(sessionKeyAlgorithm, key,
    this.encrypted.subarray(crypto.cipher[sessionKeyAlgorithm].blockSize + 2),
    this.encrypted.subarray(2, crypto.cipher[sessionKeyAlgorithm].blockSize + 2)
  );

  await this.packets.read(decrypted);

  return true;
};

/**
 * Encrypt the symmetrically-encrypted packet data
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
 * @param {module:enums.symmetric} sessionKeyAlgorithm Symmetric key algorithm to use
 * @param {Uint8Array} key    The key of cipher blocksize length to be used
 * @returns {Promise<Boolean>}
 * @async
 */
SymmetricallyEncrypted.prototype.encrypt = async function (algo, key) {
  const data = this.packets.write();

  const prefix = await crypto.getPrefixRandom(algo);
  const FRE = await crypto.cfb.encrypt(algo, key, prefix, new Uint8Array(crypto.cipher[algo].blockSize));
  const ciphertext = await crypto.cfb.encrypt(algo, key, data, FRE.subarray(2));
  this.encrypted = util.concat([FRE, ciphertext]);

  return true;
};

export default SymmetricallyEncrypted;
