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
  read: async function(input, streaming, callback) {
    const reader = stream.getReader(input);
    let writer;
    let callbackReturned;
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

      const supportsStreaming = this.supportsStreaming(tag);
      let packet = null;
      if (streaming && supportsStreaming) {
        const transform = new TransformStream();
        writer = stream.getWriter(transform.writable);
        packet = transform.readable;
        callbackReturned = callback({ tag, packet });
      } else {
        packet = [];
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
            if (!supportsStreaming) {
              throw new TypeError('This packet type does not support partial lengths.');
            }
            // 4.2.2.3. Five-Octet Lengths
          } else {
            packet_length = (await reader.readByte() << 24) | (await reader.readByte() << 16) | (await reader.readByte() <<
              8) | await reader.readByte();
          }
        }
        if (packet_length > 0) {
          let bytesRead = 0;
          while (true) {
            if (writer) await writer.ready;
            const { done, value } = await reader.read();
            if (done) {
              if (packet_length === Infinity) break;
              throw new Error('Unexpected end of packet');
            }
            const chunk = packet_length === Infinity ? value : value.subarray(0, packet_length - bytesRead);
            if (writer) await writer.write(chunk);
            else packet.push(chunk);
            bytesRead += value.length;
            if (bytesRead >= packet_length) {
              reader.unshift(value.subarray(packet_length - bytesRead + value.length));
              break;
            }
          }
        }
      } while (wasPartialLength);

      // If this was not a packet that "supports streaming", we peek to check
      // whether it is the last packet in the message. We peek 2 bytes instead
      // of 1 because the beginning of this function also peeks 2 bytes, and we
      // want to cut a `subarray` of the correct length into `web-stream-tools`'
      // `externalBuffer` as a tiny optimization here.
      //
      // If it *was* a streaming packet (i.e. the data packets), we peek at the
      // entire remainder of the stream, in order to forward errors in the
      // remainder of the stream to the packet data. (Note that this means we
      // read/peek at all signature packets before closing the literal data
      // packet, for example.) This forwards armor checksum errors to the
      // encrypted data stream, for example, so that they don't get lost /
      // forgotten on encryptedMessage.packets.stream, which we never look at.
      //
      // Note that subsequent packet parsing errors could still end up there if
      // `config.tolerant` is set to false, or on malformed messages with
      // multiple data packets, but usually it shouldn't happen.
      //
      // An example of what we do when stream-parsing a message containing
      // [ one-pass signature packet, literal data packet, signature packet ]:
      // 1. Read the one-pass signature packet
      // 2. Peek 2 bytes of the literal data packet
      // 3. Parse the one-pass signature packet
      //
      // 4. Read the literal data packet, simultaneously stream-parsing it
      // 5. Peek until the end of the message
      // 6. Finish parsing the literal data packet
      //
      // 7. Read the signature packet again (we already peeked at it in step 5)
      // 8. Peek at the end of the stream again (`peekBytes` returns undefined)
      // 9. Parse the signature packet
      //
      // Note that this means that if there's an error in the very end of the
      // stream, such as an MDC error, we throw in step 5 instead of in step 8
      // (or never), which is the point of this exercise.
      const nextPacket = await reader.peekBytes(supportsStreaming ? Infinity : 2);
      if (writer) {
        await writer.ready;
        await writer.close();
      } else {
        packet = util.concatUint8Array(packet);
        await callback({ tag, packet });
      }
      return !nextPacket || !nextPacket.length;
    } catch (e) {
      if (writer) {
        await writer.abort(e);
        return true;
      } else {
        throw e;
      }
    } finally {
      if (writer) {
        await callbackReturned;
      }
      reader.releaseLock();
    }
  }
};
