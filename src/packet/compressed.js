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
 * @requires pako
 * @requires config
 * @requires enums
 * @requires util
 * @requires compression/bzip2
 */

import pako from 'pako';
import Bunzip from 'seek-bzip';
import stream from 'web-stream-tools';
import config from '../config';
import enums from '../enums';
import util from '../util';

/**
 * Implementation of the Compressed Data Packet (Tag 8)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.6|RFC4880 5.6}:
 * The Compressed Data packet contains compressed data.  Typically,
 * this packet is found as the contents of an encrypted packet, or following
 * a Signature or One-Pass Signature packet, and contains a literal data packet.
 * @memberof module:packet
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
   * @type {module:packet.List}
   */
  this.packets = null;
  /**
   * Compression algorithm
   * @type {compression}
   */
  this.algorithm = 'zip';

  /**
   * Compressed packet data
   * @type {Uint8Array | ReadableStream<Uint8Array>}
   */
  this.compressed = null;
}

/**
 * Parsing function for the packet.
 * @param {Uint8Array | ReadableStream<Uint8Array>} bytes Payload of a tag 8 packet
 */
Compressed.prototype.read = async function (bytes, streaming) {
  await stream.parse(bytes, async reader => {

    // One octet that gives the algorithm used to compress the packet.
    this.algorithm = enums.read(enums.compression, await reader.readByte());

    // Compressed data, which makes up the remainder of the packet.
    this.compressed = reader.remainder();

    await this.decompress(streaming);
  });
};


/**
 * Return the compressed packet.
 * @returns {Uint8Array | ReadableStream<Uint8Array>} binary compressed packet
 */
Compressed.prototype.write = function () {
  if (this.compressed === null) {
    this.compress();
  }

  return util.concat([new Uint8Array([enums.write(enums.compression, this.algorithm)]), this.compressed]);
};


/**
 * Decompression method for decompressing the compressed data
 * read by read_packet
 */
Compressed.prototype.decompress = async function (streaming) {

  if (!decompress_fns[this.algorithm]) {
    throw new Error(this.algorithm + ' decompression not supported');
  }

  await this.packets.read(decompress_fns[this.algorithm](this.compressed), streaming);
};

/**
 * Compress the packet data (member decompressedData)
 */
Compressed.prototype.compress = function () {

  if (!compress_fns[this.algorithm]) {
    throw new Error(this.algorithm + ' compression not supported');
  }

  this.compressed = compress_fns[this.algorithm](this.packets.write());
};

export default Compressed;

//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////


const nodeZlib = util.getNodeZlib();

function uncompressed(data) {
  return data;
}

function node_zlib(func, options = {}) {
  return function (data) {
    return stream.nodeToWeb(stream.webToNode(data).pipe(func(options)));
  };
}

function pako_zlib(constructor, options = {}) {
  return function(data) {
    const obj = new constructor(options);
    return stream.transform(data, value => {
      if (value.length) {
        obj.push(value, pako.Z_SYNC_FLUSH);
        return obj.result;
      }
    }, () => {
      if (constructor === pako.Deflate) {
        obj.push([], pako.Z_FINISH);
        return obj.result;
      }
    });
  };
}

function bzip2(func) {
  return function(data) {
    return stream.fromAsync(async () => func(await stream.readToEnd(data)));
  };
}

let compress_fns;
let decompress_fns;
if (nodeZlib) { // Use Node native zlib for DEFLATE compression/decompression
  compress_fns = {
    zip: node_zlib(nodeZlib.createDeflateRaw, { level: config.deflate_level }),
    zlib: node_zlib(nodeZlib.createDeflate, { level: config.deflate_level })
  };

  decompress_fns = {
    uncompressed: uncompressed,
    zip: node_zlib(nodeZlib.createInflateRaw),
    zlib: node_zlib(nodeZlib.createInflate),
    bzip2: bzip2(Bunzip.decode)
  };
} else { // Use JS fallbacks
  compress_fns = {
    zip: pako_zlib(pako.Deflate, { raw: true, level: config.deflate_level }),
    zlib: pako_zlib(pako.Deflate, { level: config.deflate_level })
  };

  decompress_fns = {
    uncompressed: uncompressed,
    zip: pako_zlib(pako.Inflate, { raw: true }),
    zlib: pako_zlib(pako.Inflate),
    bzip2: bzip2(Bunzip.decode)
  };
}
