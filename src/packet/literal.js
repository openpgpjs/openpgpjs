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
 * Implementation of the Literal Data Packet (Tag 11)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.9|RFC4880 5.9}: A Literal Data packet contains the body of a message; data that
 * is not to be further interpreted.
 * @requires enums
 * @requires util
 * @module packet/literal
 */

module.exports = Literal;

var util = require('../util.js'),
  enums = require('../enums.js');

/**
 * @constructor
 */
function Literal() {
  this.tag = enums.packet.literal;
  this.format = 'utf8'; // default format for literal data packets
  this.data = ''; // literal data representation as native JavaScript string or bytes
  this.date = new Date();
  this.filename = 'msg.txt';
}

/**
 * Set the packet data to a javascript native string, end of line
 * will be normalized to \r\n and by default text is converted to UTF8
 * @param {String} text Any native javascript string
 */
Literal.prototype.setText = function (text) {
  // normalize EOL to \r\n
  text = text.replace(/\r/g, '').replace(/\n/g, '\r\n');
  // encode UTF8
  this.data = this.format == 'utf8' ? util.encode_utf8(text) : text;
};

/**
 * Returns literal data packets as native JavaScript string
 * with normalized end of line to \n
 * @return {String} literal data as text
 */
Literal.prototype.getText = function () {
  // decode UTF8
  var text = util.decode_utf8(this.data);
  // normalize EOL to \n
  return text.replace(/\r\n/g, '\n');
};

/**
 * Set the packet data to value represented by the provided string of bytes.
 * @param {String} bytes The string of bytes
 * @param {utf8|binary|text} format The format of the string of bytes
 */
Literal.prototype.setBytes = function (bytes, format) {
  this.format = format;
  this.data = bytes;
};


/**
 * Get the byte sequence representing the literal packet data
 * @returns {String} A sequence of bytes
 */
Literal.prototype.getBytes = function () {
  return this.data;
};


/**
 * Sets the filename of the literal packet data
 * @param {String} filename Any native javascript string
 */
Literal.prototype.setFilename = function (filename) {
  this.filename = filename;
};


/**
 * Get the filename of the literal packet data
 * @returns {String} filename 
 */
Literal.prototype.getFilename = function() {
  return this.filename;
};


/**
 * Parsing function for a literal data packet (tag 11).
 *
 * @param {String} input Payload of a tag 11 packet
 * @param {Integer} position
 *            Position to start reading from the input string
 * @param {Integer} len
 *            Length of the packet or the remaining length of
 *            input at position
 * @return {module:packet/literal} object representation
 */
Literal.prototype.read = function (bytes) {
  // - A one-octet field that describes how the data is formatted.

  var format = enums.read(enums.literal, bytes.charCodeAt(0));

  var filename_len = bytes.charCodeAt(1);
  this.filename = util.decode_utf8(bytes.substr(2, filename_len));

  this.date = util.readDate(bytes.substr(2 + filename_len, 4));

  var data = bytes.substring(6 + filename_len);

  this.setBytes(data, format);
};

/**
 * Creates a string representation of the packet
 *
 * @param {String} data The data to be inserted as body
 * @return {String} string-representation of the packet
 */
Literal.prototype.write = function () {
  var filename = util.encode_utf8(this.filename);

  var data = this.getBytes();

  var result = '';
  result += String.fromCharCode(enums.write(enums.literal, this.format));
  result += String.fromCharCode(filename.length);
  result += filename;
  result += util.writeDate(this.date);
  result += data;
  return result;
};
