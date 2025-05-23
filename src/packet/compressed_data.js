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

import { Inflate, Deflate, Zlib, Unzlib } from 'fflate';
import { isArrayStream, fromAsync as streamFromAsync, parse as streamParse, readToEnd as streamReadToEnd } from '@openpgp/web-stream-tools';
import enums from '../enums';
import util from '../util';
import defaultConfig from '../config';

import LiteralDataPacket from './literal_data';
import OnePassSignaturePacket from './one_pass_signature';
import SignaturePacket from './signature';
import PacketList from './packetlist';
import { MessageGrammarValidator } from './grammar';

// A Compressed Data packet can contain the following packet types
const allowedPackets = /*#__PURE__*/ util.constructAllowedPackets([
  LiteralDataPacket,
  OnePassSignaturePacket,
  SignaturePacket
]);

/**
 * Implementation of the Compressed Data Packet (Tag 8)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.6|RFC4880 5.6}:
 * The Compressed Data packet contains compressed data.  Typically,
 * this packet is found as the contents of an encrypted packet, or following
 * a Signature or One-Pass Signature packet, and contains a literal data packet.
 */
class CompressedDataPacket {
  static get tag() {
    return enums.packet.compressedData;
  }

  /**
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   */
  constructor(config = defaultConfig) {
    /**
     * List of packets
     * @type {PacketList}
     */
    this.packets = null;
    /**
     * Compression algorithm
     * @type {enums.compression}
     */
    this.algorithm = config.preferredCompressionAlgorithm;

    /**
     * Compressed packet data
     * @type {Uint8Array | ReadableStream<Uint8Array>}
     */
    this.compressed = null;
  }

  /**
   * Parsing function for the packet.
   * @param {Uint8Array | ReadableStream<Uint8Array>} bytes - Payload of a tag 8 packet
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   */
  async read(bytes, config = defaultConfig) {
    await streamParse(bytes, async reader => {

      // One octet that gives the algorithm used to compress the packet.
      this.algorithm = await reader.readByte();

      // Compressed data, which makes up the remainder of the packet.
      this.compressed = reader.remainder();

      await this.decompress(config);
    });
  }


  /**
   * Return the compressed packet.
   * @returns {Uint8Array | ReadableStream<Uint8Array>} Binary compressed packet.
   */
  write() {
    if (this.compressed === null) {
      this.compress();
    }

    return util.concat([new Uint8Array([this.algorithm]), this.compressed]);
  }


  /**
   * Decompression method for decompressing the compressed data
   * read by read_packet
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   */
  async decompress(config = defaultConfig) {
    const compressionName = enums.read(enums.compression, this.algorithm);
    const decompressionFn = decompress_fns[compressionName]; // bzip decompression is async
    if (!decompressionFn) {
      throw new Error(`${compressionName} decompression not supported`);
    }

    // Decompressing a Compressed Data packet MUST also yield a valid OpenPGP Message
    this.packets = await PacketList.fromBinary(await decompressionFn(this.compressed), allowedPackets, config, new MessageGrammarValidator());
  }

  /**
   * Compress the packet data (member decompressedData)
   */
  compress() {
    const compressionName = enums.read(enums.compression, this.algorithm);
    const compressionFn = compress_fns[compressionName];
    if (!compressionFn) {
      throw new Error(`${compressionName} compression not supported`);
    }

    this.compressed = compressionFn(this.packets.write());
  }
}

export default CompressedDataPacket;

//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////

/**
 * Zlib processor relying on Compression Stream API if available, or falling back to fflate otherwise.
 * @param {function(): CompressionStream|function(): DecompressionStream} compressionStreamInstantiator
 * @param {FunctionConstructor} ZlibStreamedConstructor - fflate constructor
 * @returns {ReadableStream<Uint8Array>} compressed or decompressed data
 */
function zlib(compressionStreamInstantiator, ZlibStreamedConstructor) {
  return data => {
    if (!util.isStream(data) || isArrayStream(data)) {
      return streamFromAsync(() => streamReadToEnd(data).then(inputData => {
        return new Promise((resolve, reject) => {
          const zlibStream = new ZlibStreamedConstructor();
          zlibStream.ondata = processedData => {
            resolve(processedData);
          };
          try {
            zlibStream.push(inputData, true); // only one chunk to push
          } catch (err) {
            reject(err);
          }
        });
      }));
    }

    // Use Compression Streams API if available (see https://developer.mozilla.org/en-US/docs/Web/API/Compression_Streams_API)
    if (compressionStreamInstantiator) {
      try {
        const compressorOrDecompressor = compressionStreamInstantiator();
        return data.pipeThrough(compressorOrDecompressor);
      } catch (err) {
        // If format is unsupported in Compression/DecompressionStream, then a TypeError in thrown, and we fallback to fflate.
        if (err.name !== 'TypeError') {
          throw err;
        }
      }
    }

    // JS fallback
    const inputReader = data.getReader();
    const zlibStream = new ZlibStreamedConstructor();

    return new ReadableStream({
      async start(controller) {
        zlibStream.ondata = async (value, isLast) => {
          controller.enqueue(value);
          if (isLast) {
            controller.close();
          }
        };

        while (true) {
          const { done, value } = await inputReader.read();
          if (done) {
            zlibStream.push(new Uint8Array(), true);
            return;
          } else if (value.length) {
            zlibStream.push(value);
          }
        }
      }
    });
  };
}

function bzip2Decompress() {
  return async function(data) {
    const { decode: bunzipDecode } = await import('@openpgp/seek-bzip');
    return streamFromAsync(async () => bunzipDecode(await streamReadToEnd(data)));
  };
}

/**
 * Get Compression Stream API instatiators if the constructors are implemented.
 * NB: the return instatiator functions will throw when called if the provided `compressionFormat` is not supported
 * (supported formats cannot be determined in advance).
 * @param {'deflate-raw'|'deflate'|'gzip'|string} compressionFormat
 * @returns {{ compressor: function(): CompressionStream | false, decompressor: function(): DecompressionStream | false }}
 */
const getCompressionStreamInstantiators = compressionFormat => ({
  compressor: typeof CompressionStream !== 'undefined' && (() => new CompressionStream(compressionFormat)),
  decompressor: typeof DecompressionStream !== 'undefined' && (() => new DecompressionStream(compressionFormat))
});

const compress_fns = {
  zip: /*#__PURE__*/ zlib(getCompressionStreamInstantiators('deflate-raw').compressor, Deflate),
  zlib: /*#__PURE__*/ zlib(getCompressionStreamInstantiators('deflate').compressor, Zlib)
};

const decompress_fns = {
  uncompressed: data => data,
  zip: /*#__PURE__*/ zlib(getCompressionStreamInstantiators('deflate-raw').decompressor, Inflate),
  zlib: /*#__PURE__*/ zlib(getCompressionStreamInstantiators('deflate').decompressor, Unzlib),
  bzip2: /*#__PURE__*/ bzip2Decompress() // NB: async due to dynamic lib import
};

