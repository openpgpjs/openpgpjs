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
 * Implementation of the Compressed Data Packet (Tag 8)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.6|RFC4880 5.6}: The Compressed Data packet contains compressed data.  Typically,
 * this packet is found as the contents of an encrypted packet, or following
 * a Signature or One-Pass Signature packet, and contains a literal data packet.
 * @requires compression/zlib
 * @requires compression/rawinflate
 * @requires compression/rawdeflate
 * @requires enums
 * @requires util
 * @module packet/compressed
 */

module.exports = Compressed;

var enums = require('../enums.js'),
  util = require('../util.js'),
  Zlib = require('../compression/zlib.min.js'),
  RawInflate = require('../compression/rawinflate.min.js'),
  RawDeflate = require('../compression/rawdeflate.min.js');

/**
 * @constructor
 */
function Compressed() {
  /**
   * Packet type
   * @type {module:enums.packet}
   */
  this.tag = enums.packet.compressed;
  /**
   * List of packets
   * @type {module:packet/packetlist}
   */
  this.packets = null;
  /**
   * Compression algorithm
   * @type {compression}
   */
  this.algorithm = 'zip';

  /**
   * Compressed packet data
   * @type {String}
   */
  this.compressed = null;
}

/**
 * Parsing function for the packet.
 * @param {String} bytes Payload of a tag 8 packet
 */
Compressed.prototype.read = function (bytes) {
  // One octet that gives the algorithm used to compress the packet.
  this.algorithm = enums.read(enums.compression, bytes.charCodeAt(0));

  // Compressed data, which makes up the remainder of the packet.
  this.compressed = bytes.substr(1);

  this.decompress();
};



/**
 * Return the compressed packet.
 * @return {String} binary compressed packet
 */
Compressed.prototype.write = function () {
  if (this.compressed === null)
    this.compress();

  return String.fromCharCode(enums.write(enums.compression, this.algorithm)) + this.compressed;
};


/**
 * Decompression method for decompressing the compressed data
 * read by read_packet
 */
Compressed.prototype.decompress = function () {
  var decompressed;

  switch (this.algorithm) {
    case 'uncompressed':
      decompressed = this.compressed;
      break;

    case 'zip':
      var inflate = new RawInflate.Zlib.RawInflate(util.str2Uint8Array(this.compressed));
      decompressed = util.Uint8Array2str(inflate.decompress());
      break;

    case 'zlib':
      var inflate = new Zlib.Zlib.Inflate(util.str2Uint8Array(this.compressed));
      decompressed = util.Uint8Array2str(inflate.decompress());
      break;

    case 'bzip2':
      // TODO: need to implement this
      throw new Error('Compression algorithm BZip2 [BZ2] is not implemented.');

    default:
      throw new Error("Compression algorithm unknown :" + this.alogrithm);
  }

  this.packets.read(decompressed);
};

/**
 * Compress the packet data (member decompressedData)
 */
Compressed.prototype.compress = function () {
  var uncompressed, deflate;
  uncompressed = this.packets.write();

  switch (this.algorithm) {

    case 'uncompressed':
      // - Uncompressed
      this.compressed = uncompressed;
      break;

    case 'zip':
      // - ZIP [RFC1951]
      deflate = new RawDeflate.Zlib.RawDeflate(util.str2Uint8Array(uncompressed));
      this.compressed = util.Uint8Array2str(deflate.compress());
      break;

    case 'zlib':
      // - ZLIB [RFC1950]
      deflate = new Zlib.Zlib.Deflate(util.str2Uint8Array(uncompressed));
      this.compressed = util.Uint8Array2str(deflate.compress());
      break;

    case 'bzip2':
      //  - BZip2 [BZ2]
      // TODO: need to implement this
      throw new Error("Compression algorithm BZip2 [BZ2] is not implemented.");

    default:
      throw new Error("Compression algorithm unknown :" + this.type);
  }
};
