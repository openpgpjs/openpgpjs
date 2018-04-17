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

import enums from '../enums';
import util from '../util';

/**
 * Implementation of the Literal Data Packet (Tag 11)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.9|RFC4880 5.9}:
 * A Literal Data packet contains the body of a message; data that is not to be
 * further interpreted.
 * @param {Date} date the creation date of the literal package
 * @memberof module:packet
 * @constructor
 */
function Literal(date=new Date()) {
  this.tag = enums.packet.literal;
  this.format = 'utf8'; // default format for literal data packets
  this.date = util.normalizeDate(date);
  this.data = new Uint8Array(0); // literal data representation
  this.filename = 'msg.txt';
}

/**
 * Set the packet data to a javascript native string, end of line
 * will be normalized to \r\n and by default text is converted to UTF8
 * @param {String} text Any native javascript string
 */
Literal.prototype.setText = function(text) {
  // normalize EOL to \r\n
  text = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").replace(/[ \t]+\n/g, "\n").replace(/\n/g, "\r\n");
  this.format = 'utf8';
  // encode UTF8
  this.data = util.str_to_Uint8Array(util.encode_utf8(text));
};

/**
 * Returns literal data packets as native JavaScript string
 * with normalized end of line to \n
 * @returns {String} literal data as text
 */
Literal.prototype.getText = function() {
  // decode UTF8
  const text = util.decode_utf8(util.Uint8Array_to_str(this.data));
  // normalize EOL to \n
  return text.replace(/\r\n/g, '\n');
};

/**
 * Set the packet data to value represented by the provided string of bytes.
 * @param {Uint8Array} bytes The string of bytes
 * @param {utf8|binary|text} format The format of the string of bytes
 */
Literal.prototype.setBytes = function(bytes, format) {
  this.format = format;
  this.data = bytes;
};


/**
 * Get the byte sequence representing the literal packet data
 * @returns {Uint8Array} A sequence of bytes
 */
Literal.prototype.getBytes = function() {
  return this.data;
};


/**
 * Sets the filename of the literal packet data
 * @param {String} filename Any native javascript string
 */
Literal.prototype.setFilename = function(filename) {
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
 * @param {Uint8Array} input Payload of a tag 11 packet
 * @returns {module:packet.Literal} object representation
 */
Literal.prototype.read = function(bytes) {
  // - A one-octet field that describes how the data is formatted.
  const format = enums.read(enums.literal, bytes[0]);

  const filename_len = bytes[1];
  this.filename = util.decode_utf8(util.Uint8Array_to_str(bytes.subarray(2, 2 + filename_len)));

  this.date = util.readDate(bytes.subarray(2 + filename_len, 2 + filename_len + 4));

  const data = bytes.subarray(6 + filename_len, bytes.length);

  this.setBytes(data, format);
};

/**
 * Creates a string representation of the packet
 *
 * @returns {Uint8Array} Uint8Array representation of the packet
 */
Literal.prototype.write = function() {
  const filename = util.str_to_Uint8Array(util.encode_utf8(this.filename));
  const filename_length = new Uint8Array([filename.length]);

  const format = new Uint8Array([enums.write(enums.literal, this.format)]);
  const date = util.writeDate(this.date);
  const data = this.getBytes();

  return util.concatUint8Array([format, filename_length, filename, date, data]);
};

export default Literal;
