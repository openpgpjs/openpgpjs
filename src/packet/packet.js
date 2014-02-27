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
 * @requires enums
 * @requires util
 * @module packet/packet
 */

var enums = require('../enums.js'),
  util = require('../util.js');

module.exports = {
  readSimpleLength: function(bytes) {
    var len = 0,
      offset,
      type = bytes.charCodeAt(0);


    if (type < 192) {
      len = bytes.charCodeAt(0);
      offset = 1;
    } else if (type < 255) {
      len = ((bytes.charCodeAt(0) - 192) << 8) + (bytes.charCodeAt(1)) + 192;
      offset = 2;
    } else if (type == 255) {
      len = util.readNumber(bytes.substr(1, 4));
      offset = 5;
    }

    return {
      len: len,
      offset: offset
    };
  },

  /**
   * Encodes a given integer of length to the openpgp length specifier to a
   * string
   * 
   * @param {Integer} length The length to encode
   * @return {String} String with openpgp length representation
   */
  writeSimpleLength: function(length) {
    var result = "";
    if (length < 192) {
      result += String.fromCharCode(length);
    } else if (length > 191 && length < 8384) {
      /*
       * let a = (total data packet length) - 192 let bc = two octet
       * representation of a let d = b + 192
       */
      result += String.fromCharCode(((length - 192) >> 8) + 192);
      result += String.fromCharCode((length - 192) & 0xFF);
    } else {
      result += String.fromCharCode(255);
      result += util.writeNumber(length, 4);
    }
    return result;
  },

  /**
   * Writes a packet header version 4 with the given tag_type and length to a
   * string
   * 
   * @param {Integer} tag_type Tag type
   * @param {Integer} length Length of the payload
   * @return {String} String of the header
   */
  writeHeader: function(tag_type, length) {
    /* we're only generating v4 packet headers here */
    var result = "";
    result += String.fromCharCode(0xC0 | tag_type);
    result += this.writeSimpleLength(length);
    return result;
  },

  /**
   * Writes a packet header Version 3 with the given tag_type and length to a
   * string
   * 
   * @param {Integer} tag_type Tag type
   * @param {Integer} length Length of the payload
   * @return {String} String of the header
   */
  writeOldHeader: function(tag_type, length) {
    var result = "";
    if (length < 256) {
      result += String.fromCharCode(0x80 | (tag_type << 2));
      result += String.fromCharCode(length);
    } else if (length < 65536) {
      result += String.fromCharCode(0x80 | (tag_type << 2) | 1);
      result += util.writeNumber(length, 2);
    } else {
      result += String.fromCharCode(0x80 | (tag_type << 2) | 2);
      result += util.writeNumber(length, 4);
    }
    return result;
  },

  /**
   * Generic static Packet Parser function
   * 
   * @param {String} input Input stream as string
   * @param {integer} position Position to start parsing
   * @param {integer} len Length of the input from position on
   * @return {Object} Returns a parsed module:packet/packet
   */
  read: function(input, position, len) {
    // some sanity checks
    if (input === null || input.length <= position || input.substring(position).length < 2 || (input.charCodeAt(position) &
      0x80) === 0) {
      throw new Error("Error during parsing. This message / key is probably not containing a valid OpenPGP format.");
    }
    var mypos = position;
    var tag = -1;
    var format = -1;
    var packet_length;

    format = 0; // 0 = old format; 1 = new format
    if ((input.charCodeAt(mypos) & 0x40) !== 0) {
      format = 1;
    }

    var packet_length_type;
    if (format) {
      // new format header
      tag = input.charCodeAt(mypos) & 0x3F; // bit 5-0
    } else {
      // old format header
      tag = (input.charCodeAt(mypos) & 0x3F) >> 2; // bit 5-2
      packet_length_type = input.charCodeAt(mypos) & 0x03; // bit 1-0
    }

    // header octet parsing done
    mypos++;

    // parsed length from length field
    var bodydata = null;

    // used for partial body lengths
    var real_packet_length = -1;
    if (!format) {
      // 4.2.1. Old Format Packet Lengths
      switch (packet_length_type) {
        case 0:
          // The packet has a one-octet length. The header is 2 octets
          // long.
          packet_length = input.charCodeAt(mypos++);
          break;
        case 1:
          // The packet has a two-octet length. The header is 3 octets
          // long.
          packet_length = (input.charCodeAt(mypos++) << 8) | input.charCodeAt(mypos++);
          break;
        case 2:
          // The packet has a four-octet length. The header is 5
          // octets long.
          packet_length = (input.charCodeAt(mypos++) << 24) | (input.charCodeAt(mypos++) << 16) | (input.charCodeAt(mypos++) <<
            8) | input.charCodeAt(mypos++);
          break;
        default:
          // 3 - The packet is of indeterminate length. The header is 1
          // octet long, and the implementation must determine how long
          // the packet is. If the packet is in a file, this means that
          // the packet extends until the end of the file. In general, 
          // an implementation SHOULD NOT use indeterminate-length 
          // packets except where the end of the data will be clear 
          // from the context, and even then it is better to use a 
          // definite length, or a new format header. The new format 
          // headers described below have a mechanism for precisely
          // encoding data of indeterminate length.
          packet_length = len;
          break;
      }

    } else // 4.2.2. New Format Packet Lengths
    {

      // 4.2.2.1. One-Octet Lengths
      if (input.charCodeAt(mypos) < 192) {
        packet_length = input.charCodeAt(mypos++);
        util.print_debug("1 byte length:" + packet_length);
        // 4.2.2.2. Two-Octet Lengths
      } else if (input.charCodeAt(mypos) >= 192 && input.charCodeAt(mypos) < 224) {
        packet_length = ((input.charCodeAt(mypos++) - 192) << 8) + (input.charCodeAt(mypos++)) + 192;
        util.print_debug("2 byte length:" + packet_length);
        // 4.2.2.4. Partial Body Lengths
      } else if (input.charCodeAt(mypos) > 223 && input.charCodeAt(mypos) < 255) {
        packet_length = 1 << (input.charCodeAt(mypos++) & 0x1F);
        util.print_debug("4 byte length:" + packet_length);
        // EEEK, we're reading the full data here...
        var mypos2 = mypos + packet_length;
        bodydata = input.substring(mypos, mypos + packet_length);
        var tmplen;
        while (true) {
          if (input.charCodeAt(mypos2) < 192) {
            tmplen = input.charCodeAt(mypos2++);
            packet_length += tmplen;
            bodydata += input.substring(mypos2, mypos2 + tmplen);
            mypos2 += tmplen;
            break;
          } else if (input.charCodeAt(mypos2) >= 192 && input.charCodeAt(mypos2) < 224) {
            tmplen = ((input.charCodeAt(mypos2++) - 192) << 8) + (input.charCodeAt(mypos2++)) + 192;
            packet_length += tmplen;
            bodydata += input.substring(mypos2, mypos2 + tmplen);
            mypos2 += tmplen;
            break;
          } else if (input.charCodeAt(mypos2) > 223 && input.charCodeAt(mypos2) < 255) {
            tmplen = 1 << (input.charCodeAt(mypos2++) & 0x1F);
            packet_length += tmplen;
            bodydata += input.substring(mypos2, mypos2 + tmplen);
            mypos2 += tmplen;
          } else {
            mypos2++;
            tmplen = (input.charCodeAt(mypos2++) << 24) | (input.charCodeAt(mypos2++) << 16) | (input[mypos2++]
              .charCodeAt() << 8) | input.charCodeAt(mypos2++);
            bodydata += input.substring(mypos2, mypos2 + tmplen);
            packet_length += tmplen;
            mypos2 += tmplen;
            break;
          }
        }
        real_packet_length = mypos2 - mypos;
        // 4.2.2.3. Five-Octet Lengths
      } else {
        mypos++;
        packet_length = (input.charCodeAt(mypos++) << 24) | (input.charCodeAt(mypos++) << 16) | (input.charCodeAt(mypos++) <<
          8) | input.charCodeAt(mypos++);
      }
    }

    // if there was'nt a partial body length: use the specified
    // packet_length
    if (real_packet_length == -1) {
      real_packet_length = packet_length;
    }

    if (bodydata === null) {
      bodydata = input.substring(mypos, mypos + real_packet_length);
    }

    return {
      tag: tag,
      packet: bodydata,
      offset: mypos + real_packet_length
    };
  }
};
