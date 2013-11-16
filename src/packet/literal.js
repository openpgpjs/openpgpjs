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

var util = require('../util'),
  enums = require('../enums.js');

/**
 * @class
 * @classdesc Implementation of the Literal Data Packet (Tag 11)
 * 
 * RFC4880 5.9: A Literal Data packet contains the body of a message; data that
 * is not to be further interpreted.
 */
module.exports = function packet_literal() {
  this.format = 'utf8'; // default format for literal data packets
  this.data = ''; // literal data representation as native JavaScript string or bytes
  this.date = new Date();


  /**
   * Set the packet data to a javascript native string or a squence of 
   * bytes. Conversion to the provided format takes place when the 
   * packet is written.
   * @param {String} str Any native javascript string
   * @param {'utf8|'binary'|'text'} format The format the packet data will be written to,
   *                                defaults to 'utf8'
   */
  this.set = function(str, format) {
    this.format = format || this.format;
    this.data = str;
  }

  /**
   * Set the packet data to value represented by the provided string of bytes.
   * @param {String} bytes The string of bytes
   * @param {'utf8|'binary'|'text'} format The format of the string of bytes
   */
  this.setBytes = function(bytes, format) {
    this.format = format;
    switch (format) {
      case 'utf8':
        bytes = util.decode_utf8(bytes);
        bytes = bytes.replace(/\r\n/g, '\n');
        break;
      case 'text':
        bytes = bytes.replace(/\r\n/g, '\n');
        break;
    }
    this.data = bytes;
  }

  /**
   * Get the byte sequence representing the literal packet data
   * @returns {String} A sequence of bytes
   */
  this.getBytes = function() {
    var bytes = this.data;
    switch (this.format) {
      case 'utf8':
        bytes = bytes.replace(/\n/g, '\r\n');
        bytes = util.encode_utf8(bytes);
        break;
      case 'text':
        bytes = bytes.replace(/\n/g, '\r\n');
        break;
    }
    return bytes;
  }



  /**
   * Parsing function for a literal data packet (tag 11).
   * 
   * @param {String} input Payload of a tag 11 packet
   * @param {Integer} position
   *            Position to start reading from the input string
   * @param {Integer} len
   *            Length of the packet or the remaining length of
   *            input at position
   * @return {openpgp_packet_encrypteddata} object representation
   */
  this.read = function(bytes) {
    // - A one-octet field that describes how the data is formatted.

    var format = enums.read(enums.literal, bytes[0].charCodeAt());

    var filename_len = bytes.charCodeAt(1);
    this.filename = util.decode_utf8(bytes.substr(2, filename_len));

    this.date = util.readDate(bytes.substr(2 + filename_len, 4));

    var data = bytes.substring(6 + filename_len);

    this.setBytes(data, format);
  }

  /**
   * Creates a string representation of the packet
   * 
   * @param {String} data The data to be inserted as body
   * @return {String} string-representation of the packet
   */
  this.write = function() {
    var filename = util.encode_utf8("msg.txt");

    var data = this.getBytes();

    var result = '';
    result += String.fromCharCode(enums.write(enums.literal, this.format));
    result += String.fromCharCode(filename.length);
    result += filename;
    result += util.writeDate(this.date);
    result += data;
    return result;
  }
}
