// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2022 Proton AG
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

import crypto from '../crypto';
import enums from '../enums';

/**
 * Implementation of the Padding Packet
 *
 * {@link https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#name-padding-packet-tag-21}:
 * Padding Packet
 */
class PaddingPacket {
  static get tag() {
    return enums.packet.padding;
  }

  constructor() {
    this.padding = null;
  }

  /**
   * Read a padding packet
   * @param {Uint8Array | ReadableStream<Uint8Array>} bytes
   */
  read(bytes) { // eslint-disable-line no-unused-vars
    // Padding packets are ignored, so this function is never called.
  }

  /**
   * Write the padding packet
   * @returns {Uint8Array} The padding packet.
   */
  write() {
    return this.padding;
  }

  /**
   * Create random padding.
   * @param {Number} length - The length of padding to be generated.
   * @throws {Error} if padding generation was not successful
   * @async
   */
  async createPadding(length) {
    this.padding = await crypto.random.getRandomBytes(length);
  }
}

export default PaddingPacket;
