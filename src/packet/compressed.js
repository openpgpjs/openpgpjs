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
 * Implementation of the Compressed Data Packet (Tag 8)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.6|RFC4880 5.6}: The Compressed Data packet contains compressed data.  Typically,
 * this packet is found as the contents of an encrypted packet, or following
 * a Signature or One-Pass Signature packet, and contains a literal data packet.
 * @requires compression/jxg
 * @requires encoding/base64
 * @requires enums
 * @module packet/compressed
 */

module.exports = Compressed;

var enums = require('../enums.js'),
  JXG = require('../compression/jxg.js'),
  base64 = require('../encoding/base64.js');

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
  this.algorithm = 'uncompressed';

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
  var decompressed, compdata, radix;

  switch (this.algorithm) {
    case 'uncompressed':
      decompressed = this.compressed;
      break;

    case 'zip':
      compData = this.compressed;

      radix = base64.encode(compData).replace(/\n/g, "");
      // no header in this case, directly call deflate
      var jxg_obj = new JXG.Util.Unzip(JXG.Util.Base64.decodeAsArray(radix));

      decompressed = unescape(jxg_obj.deflate()[0][0]);
      break;

    case 'zlib':
      //RFC 1950. Bits 0-3 Compression Method
      var compressionMethod = this.compressed.charCodeAt(0) % 0x10;

      //Bits 4-7 RFC 1950 are LZ77 Window. Generally this value is 7 == 32k window size.
      // 2nd Byte in RFC 1950 is for "FLAGs" Allows for a Dictionary
      // (how is this defined). Basic checksum, and compression level.

      if (compressionMethod == 8) { //CM 8 is for DEFLATE, RFC 1951
        // remove 4 bytes ADLER32 checksum from the end
        compData = this.compressed.substring(0, this.compressed.length - 4);
        radix = base64.encode(compData).replace(/\n/g, "");
        //TODO check ADLER32 checksum
        decompressed = JXG.decompress(radix);
        break;

      } else {
        throw new Error("Compression algorithm ZLIB only supports " +
          "DEFLATE compression method.");
      }
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
  switch (this.algorithm) {

    case 'uncompressed':
      // - Uncompressed
      this.compressed = this.packets.write();
      break;

    case 'zip':
      // - ZIP [RFC1951]
      throw new Error("Compression algorithm ZIP [RFC1951] is not implemented.");

    case 'zlib':
      // - ZLIB [RFC1950]
      // TODO: need to implement this
      throw new Error("Compression algorithm ZLIB [RFC1950] is not implemented.");

    case 'bzip2':
      //  - BZip2 [BZ2]
      // TODO: need to implement this
      throw new Error("Compression algorithm BZip2 [BZ2] is not implemented.");

    default:
      throw new Error("Compression algorithm unknown :" + this.type);
  }
};
