/** @access public */

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
import { isStream, isArrayStream, toStream, fromAsync as streamFromAsync, transform as streamTransform, parse as streamParse, getReader as streamGetReader, readToEnd as streamReadToEnd } from '@openpgp/web-stream-tools';
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

    let decompressed = await decompressionFn(this.compressed);
    if (config.maxDecompressedMessageSize !== Infinity) {
      let decompressedSize = 0;
      decompressed = streamTransform(decompressed, chunk => {
        decompressedSize += chunk.length;
        if (decompressedSize > config.maxDecompressedMessageSize) {
          throw new Error('Maximum decompressed message size exceeded');
        }
        return chunk;
      });
    }
    if (!isStream(this.compressed) || isArrayStream(this.compressed)) {
      decompressed = await streamReadToEnd(decompressed);
    }
    // Decompressing a Compressed Data packet MUST also yield a valid OpenPGP Message
    this.packets = await PacketList.fromBinary(decompressed, allowedPackets, config, new MessageGrammarValidator());
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

    const data = this.packets.write();
    let compressed = compressionFn(data);
    if (!isStream(data) || isArrayStream(data)) {
      // Convert back to an ArrayStream when we weren't streaming before,
      // even if web streams were used internally while compressing,
      // so that we don't return a stream from the high-level function.
      compressed = streamFromAsync(() => streamReadToEnd(compressed));
    }
    this.compressed = compressed;
  }
}

export default CompressedDataPacket;

//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////

function splitStream(data) {
  const chunkSize = 65536;
  const reader = streamGetReader(data);
  return new ReadableStream({
    async pull(controller) {
      try {
        const { value, done } = await reader.read();
        if (done) {
          controller.close();
          return;
        }
        for (let i = 0; i <= value.length; i += chunkSize) {
          if (!i || i < value.length) {
            controller.enqueue(value.subarray(i, i + chunkSize));
          }
        }
      } catch (e) {
        controller.error(e);
      }
    }
  }, { highWaterMark: 0 });
}

/**
 * Zlib processor relying on Compression Stream API if available, or falling back to fflate otherwise.
 * @param {function(): CompressionStream|function(): DecompressionStream} compressionStreamInstantiator
 * @param {FunctionConstructor} ZlibStreamedConstructor - fflate constructor
 * @returns {ReadableStream<Uint8Array>} compressed or decompressed data
 * @private
 */
function zlib(compressionStreamInstantiator, ZlibStreamedConstructor) {
  return data => {
    let stream;
    if (isArrayStream(data)) {
      stream = new ReadableStream({
        async start(controller) {
          try {
            controller.enqueue(await streamReadToEnd(data));
            controller.close();
          } catch (e) {
            controller.error(e);
          }
        }
      });
    } else if (isStream(data)) {
      stream = data;
    } else {
      stream = toStream(data);
    }

    // Split the input stream into chunks of 64KiB.
    // This is only necessary for the fflate fallback decompressor, and
    // the native Compression API in WebKit, as they decompress the
    // entire input chunk and emit one output chunk, rather than
    // outputting chunks incrementally as it decompresses the input.
    // Therefore, for backpressure to work properly, we need to split
    // the input chunks.
    // We do it unconditionally here (regardless of the platform and
    // API used) for simplicity and because it doesn't hurt much.
    // (This only does anything if the input chunks aren't already 64KiB
    // or smaller, e.g. when a large message is passed all at once.)
    stream = splitStream(stream);

    // Use Compression Streams API if available (see https://developer.mozilla.org/en-US/docs/Web/API/Compression_Streams_API)
    if (compressionStreamInstantiator) {
      try {
        const compressorOrDecompressor = compressionStreamInstantiator();
        return stream.pipeThrough(compressorOrDecompressor);
      } catch (err) {
        // If format is unsupported in Compression/DecompressionStream, then a TypeError is thrown, and we fallback to fflate.
        if (err.name !== 'TypeError') {
          throw err;
        }
      }
    }

    // JS fallback
    const inputReader = streamGetReader(stream);
    const zlibStream = new ZlibStreamedConstructor();
    let providedData = false;
    let allDone = false;

    return new ReadableStream({
      start(controller) {
        zlibStream.ondata = (value, isLast) => {
          controller.enqueue(value);
          providedData = true;
          if (isLast) {
            controller.close();
            allDone = true;
          }
        };
      },

      async pull() {
        providedData = false;
        while (!providedData && !allDone) {
          const { done, value } = await inputReader.read();
          if (done) {
            zlibStream.push(new Uint8Array(), true);
            return;
          } else if (value.length) {
            zlibStream.push(value);
          }
        }
      }
    }, { highWaterMark: 0 });
  };
}

function bzip2Decompress() {
  return async function(data) {
    const { default: unbzip2Stream } = await import('@openpgp/unbzip2-stream');
    return unbzip2Stream(toStream(data));
  };
}

/**
 * Get Compression Stream API instantiators if the constructors are implemented.
 * NB: the return instantiator functions will throw when called if the provided `compressionFormat` is not supported
 * (supported formats cannot be determined in advance).
 * @param {'deflate-raw'|'deflate'|'gzip'|string} compressionFormat
 * @returns {{ compressor: function(): CompressionStream | false, decompressor: function(): DecompressionStream | false }}
 * @private
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

