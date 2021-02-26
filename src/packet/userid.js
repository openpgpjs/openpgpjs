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
 * @requires enums
 * @requires util
 */
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
 * @memberof module:packet
 */
class UserIDPacket {
  constructor() {
    this.tag = enums.packet.userID;
    /** A string containing the user id. Usually in the form
     * John Doe <john@example.com>
     * @type {String}
     */
    this.userid = '';

    this.name = '';
    this.email = '';
    this.comment = '';
  }

  /**
   * Create UserIDPacket instance from object
   * @param {Object} userId  object specifying userId name, email and comment
   * @returns {module:userid.UserIDPacket}
   * @static
   */
  static fromObject(userId) {
    if (util.isString(userId) ||
      (userId.name && !util.isString(userId.name)) ||
      (userId.email && !util.isEmailAddress(userId.email)) ||
      (userId.comment && !util.isString(userId.comment))) {
      throw new Error('Invalid user ID format');
    }
    const packet = new UserIDPacket();
    Object.assign(packet, userId);
    const components = [];
    if (packet.name) components.push(packet.name);
    if (packet.comment) components.push(`(${packet.comment})`);
    if (packet.email) components.push(`<${packet.email}>`);
    packet.userid = components.join(' ');
    return packet;
  }

  /**
   * Parsing function for a user id packet (tag 13).
   * @param {Uint8Array} input payload of a tag 13 packet
   */
  read(bytes, config = defaultConfig) {
    const userid = util.decodeUtf8(bytes);
    if (userid.length > config.maxUseridLength) {
      throw new Error('User ID string is too long');
    }
    try {
      const { name, address: email, comments } = emailAddresses.parseOneAddress({ input: userid, atInDisplayName: true });
      this.comment = comments.replace(/^\(|\)$/g, '');
      this.name = name;
      this.email = email;
    } catch (e) {}
    this.userid = userid;
  }

  /**
   * Creates a binary representation of the user id packet
   * @returns {Uint8Array} binary representation
   */
  write() {
    return util.encodeUtf8(this.userid);
  }
}

export default UserIDPacket;
