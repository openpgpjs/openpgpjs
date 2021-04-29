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

/* eslint class-methods-use-this: ["error", { "exceptMethods": ["read"] }] */

import enums from '../enums';

/**
 * Implementation of the strange "Marker packet" (Tag 10)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.8|RFC4880 5.8}:
 * An experimental version of PGP used this packet as the Literal
 * packet, but no released version of PGP generated Literal packets with this
 * tag. With PGP 5.x, this packet has been reassigned and is reserved for use as
 * the Marker packet.
 *
 * The body of this packet consists of:
 *   The three octets 0x50, 0x47, 0x50 (which spell "PGP" in UTF-8).
 *
 * Such a packet MUST be ignored when received. It may be placed at the
 * beginning of a message that uses features not available in PGP
 * version 2.6 in order to cause that version to report that newer
 * software is necessary to process the message.
 */
class MarkerPacket {
  static get tag() {
    return enums.packet.marker;
  }

  /**
   * Parsing function for a marker data packet (tag 10).
   * @param {Uint8Array} bytes - Payload of a tag 10 packet
   * @returns {Boolean} whether the packet payload contains "PGP"
   */
  read(bytes) {
    if (bytes[0] === 0x50 && // P
        bytes[1] === 0x47 && // G
        bytes[2] === 0x50) { // P
      return true;
    }
    return false;
  }

  // eslint-disable-next-line class-methods-use-this
  write() {
    return new Uint8Array([0x50, 0x47, 0x50]);
  }
}

export default MarkerPacket;
