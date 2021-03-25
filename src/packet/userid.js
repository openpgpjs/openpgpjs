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

import emailAddresses from 'email-addresses';

import enums from '../enums';
import util from '../util';
import defaultConfig from '../config';

/**
 * Implementation of the User ID Packet (Tag 13)
 *
 * A User ID packet consists of UTF-8 text that is intended to represent
 * the name and email address of the key holder.  By convention, it
 * includes an RFC 2822 [RFC2822] mail name-addr, but there are no
 * restrictions on its content.  The packet length in the header
 * specifies the length of the User ID.
 */
class UserIDPacket {
  static get tag() {
    return enums.packet.userID;
  }

  constructor() {
    /** A string containing the user id. Usually in the form
     * John Doe <john@example.com>
     * @type {String}
     */
    this.userID = '';

    this.name = '';
    this.email = '';
    this.comment = '';
  }

  /**
   * Create UserIDPacket instance from object
   * @param {Object} userID - Object specifying userID name, email and comment
   * @returns {UserIDPacket}
   * @static
   */
  static fromObject(userID) {
    if (util.isString(userID) ||
      (userID.name && !util.isString(userID.name)) ||
      (userID.email && !util.isEmailAddress(userID.email)) ||
      (userID.comment && !util.isString(userID.comment))) {
      throw new Error('Invalid user ID format');
    }
    const packet = new UserIDPacket();
    Object.assign(packet, userID);
    const components = [];
    if (packet.name) components.push(packet.name);
    if (packet.comment) components.push(`(${packet.comment})`);
    if (packet.email) components.push(`<${packet.email}>`);
    packet.userID = components.join(' ');
    return packet;
  }

  /**
   * Parsing function for a user id packet (tag 13).
   * @param {Uint8Array} input - Payload of a tag 13 packet
   */
  read(bytes, config = defaultConfig) {
    const userID = util.decodeUTF8(bytes);
    if (userID.length > config.maxUserIDLength) {
      throw new Error('User ID string is too long');
    }
    try {
      const { name, address: email, comments } = emailAddresses.parseOneAddress({ input: userID, atInDisplayName: true });
      this.comment = comments.replace(/^\(|\)$/g, '');
      this.name = name;
      this.email = email;
    } catch (e) {}
    this.userID = userID;
  }

  /**
   * Creates a binary representation of the user id packet
   * @returns {Uint8Array} Binary representation.
   */
  write() {
    return util.encodeUTF8(this.userID);
  }
}

export default UserIDPacket;
