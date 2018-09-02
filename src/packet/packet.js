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

/* eslint-disable callback-return */

/**
 * @fileoverview Functions for reading and writing packets
 * @requires web-stream-tools
 * @requires enums
 * @requires util
 * @module packet/packet
 */

import stream from 'web-stream-tools';
import enums from '../enums';
import util from '../util';

export default {
  readSimpleLength: function(bytes) {
    let len = 0;
    let offset;
    const type = bytes[0];


    if (type < 192) {
      [len] = bytes;
      offset = 1;
    } else if (type < 255) {
      len = ((bytes[0] - 192) << 8) + (bytes[1]) + 192;
      offset = 2;
    } else if (type === 255) {
      len = util.readNumber(bytes.subarray(1, 1 + 4));
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
   * @returns {Uint8Array} String with openpgp length representation
   */
  writeSimpleLength: function(length) {
    if (length < 192) {
      return new Uint8Array([length]);
    } else if (length > 191 && length < 8384) {
      /*
       * let a = (total data packet length) - 192 let bc = two octet
       * representation of a let d = b + 192
       */
      return new Uint8Array([((length - 192) >> 8) + 192, (length - 192) & 0xFF]);
    }
    return util.concatUint8Array([new Uint8Array([255]), util.writeNumber(length, 4)]);
  },

  writePartialLength: function(power) {
    if (power < 0 || power > 30) {
      throw new Error('Partial Length power must be between 1 and 30');
    }
    return new Uint8Array([224 + power]);
  },

  writeTag: function(tag_type) {
    /* we're only generating v4 packet headers here */
    return new Uint8Array([0xC0 | tag_type]);
  },

  /**
   * Writes a packet header version 4 with the given tag_type and length to a
   * string
   *
   * @param {Integer} tag_type Tag type
   * @param {Integer} length Length of the payload
   * @returns {String} String of the header
   */
  writeHeader: function(tag_type, length) {
    /* we're only generating v4 packet headers here */
    return util.concatUint8Array([this.writeTag(tag_type), this.writeSimpleLength(length)]);
  },

  /**
   * Writes a packet header Version 3 with the given tag_type and length to a
   * string
   *
   * @param {Integer} tag_type Tag type
   * @param {Integer} length Length of the payload
   * @returns {String} String of the header
   */
  writeOldHeader: function(tag_type, length) {
    if (length < 256) {
      return new Uint8Array([0x80 | (tag_type << 2), length]);
    } else if (length < 65536) {
      return util.concatUint8Array([new Uint8Array([0x80 | (tag_type << 2) | 1]), util.writeNumber(length, 2)]);
    }
    return util.concatUint8Array([new Uint8Array([0x80 | (tag_type << 2) | 2]), util.writeNumber(length, 4)]);
  },

  /**
   * Whether the packet type supports partial lengths per RFC4880
   * @param {Integer} tag_type Tag type
   * @returns {Boolean} String of the header
   */
  supportsStreaming: function(tag_type) {
    return [
      enums.packet.literal,
      enums.packet.compressed,
      enums.packet.symmetricallyEncrypted,
      enums.packet.symEncryptedIntegrityProtected,
      enums.packet.symEncryptedAEADProtected
    ].includes(tag_type);
  },

  /**
   * Generic static Packet Parser function
   *
   * @param {Uint8Array | ReadableStream<Uint8Array>} input Input stream as string
   * @param {Function} callback Function to call with the parsed packet
   * @returns {Boolean} Returns false if the stream was empty and parsing is done, and true otherwise.
   */
  read: async function(input, callback) {
    const reader = stream.getReader(input);
    let writer;
    try {
      const peekedBytes = await reader.peekBytes(2);
      // some sanity checks
      if (!peekedBytes || peekedBytes.length < 2 || (peekedBytes[0] & 0x80) === 0) {
        throw new Error("Error during parsing. This message / key probably does not conform to a valid OpenPGP format.");
      }
      const headerByte = await reader.readByte();
      let tag = -1;
      let format = -1;
      let packet_length;

      format = 0; // 0 = old format; 1 = new format
      if ((headerByte & 0x40) !== 0) {
        format = 1;
      }

      let packet_length_type;
      if (format) {
        // new format header
        tag = headerByte & 0x3F; // bit 5-0
      } else {
        // old format header
        tag = (headerByte & 0x3F) >> 2; // bit 5-2
        packet_length_type = headerByte & 0x03; // bit 1-0
      }

      const streaming = this.supportsStreaming(tag);
      let packet = null;
      let callbackReturned;
      if (streaming) {
        const transform = new TransformStream();
        writer = stream.getWriter(transform.writable);
        packet = transform.readable;
        callbackReturned = callback({ tag, packet });
      }

      let wasPartialLength;
      do {
        if (!format) {
          // 4.2.1. Old Format Packet Lengths
          switch (packet_length_type) {
            case 0:
              // The packet has a one-octet length. The header is 2 octets
              // long.
              packet_length = await reader.readByte();
              break;
            case 1:
              // The packet has a two-octet length. The header is 3 octets
              // long.
              packet_length = (await reader.readByte() << 8) | await reader.readByte();
              break;
            case 2:
              // The packet has a four-octet length. The header is 5
              // octets long.
              packet_length = (await reader.readByte() << 24) | (await reader.readByte() << 16) | (await reader.readByte() <<
                8) | await reader.readByte();
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
              packet_length = Infinity;
              break;
          }
        } else { // 4.2.2. New Format Packet Lengths
          // 4.2.2.1. One-Octet Lengths
          const lengthByte = await reader.readByte();
          wasPartialLength = false;
          if (lengthByte < 192) {
            packet_length = lengthByte;
            // 4.2.2.2. Two-Octet Lengths
          } else if (lengthByte >= 192 && lengthByte < 224) {
            packet_length = ((lengthByte - 192) << 8) + (await reader.readByte()) + 192;
            // 4.2.2.4. Partial Body Lengths
          } else if (lengthByte > 223 && lengthByte < 255) {
            packet_length = 1 << (lengthByte & 0x1F);
            wasPartialLength = true;
            if (!streaming) {
              throw new TypeError('This packet type does not support partial lengths.');
            }
            // 4.2.2.3. Five-Octet Lengths
          } else {
            packet_length = (await reader.readByte() << 24) | (await reader.readByte() << 16) | (await reader.readByte() <<
              8) | await reader.readByte();
          }
        }
        if (writer && packet_length > 0) {
          let bytesRead = 0;
          while (true) {
            await writer.ready;
            const { done, value } = await reader.read();
            if (done) {
              if (packet_length === Infinity) break;
              throw new Error('Unexpected end of packet');
            }
            await writer.write(value.slice(0, packet_length - bytesRead));
            bytesRead += value.length;
            if (bytesRead >= packet_length) {
              reader.unshift(value.slice(packet_length - bytesRead + value.length));
              break;
            }
          }
        }
      } while(wasPartialLength);

      if (!streaming) {
        packet = await reader.readBytes(packet_length);
        await callback({ tag, packet });
      }
      const nextPacket = await reader.peekBytes(2);
      if (writer) {
        await writer.ready;
        await writer.close();
      }
      if (streaming) await callbackReturned;
      return !nextPacket || !nextPacket.length;
    } catch(e) {
      if (writer) {
        await writer.abort(e);
        return true;
      } else {
        throw e;
      }
    } finally {
      reader.releaseLock();
    }
  }
};
