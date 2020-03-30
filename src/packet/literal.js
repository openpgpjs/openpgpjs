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
 * @requires enums
 * @requires util
 */

import stream from 'web-stream-tools';
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
function Literal(date = new Date()) {
  this.tag = enums.packet.literal;
  this.format = 'utf8'; // default format for literal data packets
  this.date = util.normalizeDate(date);
  this.text = null; // textual data representation
  this.data = null; // literal data representation
  this.filename = 'msg.txt';
}

/**
 * Set the packet data to a javascript native string, end of line
 * will be normalized to \r\n and by default text is converted to UTF8
 * @param {String | ReadableStream<String>} text Any native javascript string
 * @param {utf8|binary|text|mime} format (optional) The format of the string of bytes
 */
Literal.prototype.setText = function(text, format = 'utf8') {
  this.format = format;
  this.text = text;
  this.data = null;
};

/**
 * Returns literal data packets as native JavaScript string
 * with normalized end of line to \n
 * @param {Boolean} clone (optional) Whether to return a clone so that getBytes/getText can be called again
 * @returns {String | ReadableStream<String>} literal data as text
 */
Literal.prototype.getText = function(clone = false) {
  if (this.text === null || util.isStream(this.text)) { // Assume that this.text has been read
    this.text = util.decode_utf8(util.nativeEOL(this.getBytes(clone)));
  }
  return this.text;
};

/**
 * Set the packet data to value represented by the provided string of bytes.
 * @param {Uint8Array | ReadableStream<Uint8Array>} bytes The string of bytes
 * @param {utf8|binary|text|mime} format The format of the string of bytes
 */
Literal.prototype.setBytes = function(bytes, format) {
  this.format = format;
  this.data = bytes;
  this.text = null;
};


/**
 * Get the byte sequence representing the literal packet data
 * @param {Boolean} clone (optional) Whether to return a clone so that getBytes/getText can be called again
 * @returns {Uint8Array | ReadableStream<Uint8Array>} A sequence of bytes
 */
Literal.prototype.getBytes = function(clone = false) {
  if (this.data === null) {
    // encode UTF8 and normalize EOL to \r\n
    this.data = util.canonicalizeEOL(util.encode_utf8(this.text));
  }
  if (clone) {
    return stream.passiveClone(this.data);
  }
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
 * @param {Uint8Array | ReadableStream<Uint8Array>} input Payload of a tag 11 packet
 * @returns {module:packet.Literal} object representation
 */
Literal.prototype.read = async function(bytes) {
  await stream.parse(bytes, async reader => {
    // - A one-octet field that describes how the data is formatted.
    const format = enums.read(enums.literal, await reader.readByte());

    const filename_len = await reader.readByte();
    this.filename = util.decode_utf8(await reader.readBytes(filename_len));

    this.date = util.readDate(await reader.readBytes(4));

    const data = reader.remainder();

    this.setBytes(data, format);
  });
};

/**
 * Creates a Uint8Array representation of the packet, excluding the data
 *
 * @returns {Uint8Array} Uint8Array representation of the packet
 */
Literal.prototype.writeHeader = function() {
  const filename = util.encode_utf8(this.filename);
  const filename_length = new Uint8Array([filename.length]);

  const format = new Uint8Array([enums.write(enums.literal, this.format)]);
  const date = util.writeDate(this.date);

  return util.concatUint8Array([format, filename_length, filename, date]);
};

/**
 * Creates a Uint8Array representation of the packet
 *
 * @returns {Uint8Array | ReadableStream<Uint8Array>} Uint8Array representation of the packet
 */
Literal.prototype.write = function() {
  const header = this.writeHeader();
  const data = this.getBytes();

  return util.concat([header, data]);
};

export default Literal;
