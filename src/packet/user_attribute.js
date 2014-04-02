// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
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
 * Implementation of the User Attribute Packet (Tag 17)<br/>
 * <br/>
 * The User Attribute packet is a variation of the User ID packet.  It
 * is capable of storing more types of data than the User ID packet,
 * which is limited to text.  Like the User ID packet, a User Attribute
 * packet may be certified by the key owner ("self-signed") or any other
 * key owner who cares to certify it.  Except as noted, a User Attribute
 * packet may be used anywhere that a User ID packet may be used.
 * <br/>
 * While User Attribute packets are not a required part of the OpenPGP
 * standard, implementations SHOULD provide at least enough
 * compatibility to properly handle a certification signature on the
 * User Attribute packet.  A simple way to do this is by treating the
 * User Attribute packet as a User ID packet with opaque contents, but
 * an implementation may use any method desired.
 * module packet/user_attribute
 * @requires enums
 * @module packet/user_attribute
 */

var util = require('../util.js'),
  packet = require('./packet.js'),
  enums = require('../enums.js');

module.exports = UserAttribute;

/**
 * @constructor
 */
function UserAttribute() {
  this.tag = enums.packet.userAttribute;
  this.attributes = [];
}

/**
 * parsing function for a user attribute packet (tag 17).
 * @param {String} input payload of a tag 17 packet
 */
UserAttribute.prototype.read = function(bytes) {
  var i = 0;
  while (i < bytes.length) {
    var len = packet.readSimpleLength(bytes.substr(i));
    i += len.offset;

    this.attributes.push(bytes.substr(i, len.len));
    i += len.len;
  }
};

/**
 * Creates a string representation of the user attribute packet
 * @return {String} string representation
 */
UserAttribute.prototype.write = function() {
  var result = '';
  for (var i = 0; i < this.attributes.length; i++) {
    result += packet.writeSimpleLength(this.attributes[i].length);
    result += this.attributes[i];
  }
  return result;
};

/**
 * Compare for equality
 * @param  {module:user_attribute~UserAttribute} usrAttr
 * @return {Boolean}         true if equal
 */
UserAttribute.prototype.equals = function(usrAttr) {
  if (!usrAttr || !(usrAttr instanceof UserAttribute)) {
    return false;
  }
  return this.attributes.every(function(attr, index) {
    return attr === usrAttr.attributes[index];
  });
};
