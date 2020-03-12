/* eslint-disable callback-return */
/**
 * @requires web-stream-tools
 * @requires packet/all_packets
 * @requires packet/packet
 * @requires config
 * @requires enums
 * @requires util
 */

import stream from 'web-stream-tools';
import * as packets from './all_packets';
import packetParser from './packet';
import config from '../config';
import enums from '../enums';
import util from '../util';

/**
 * This class represents a list of openpgp packets.
 * Take care when iterating over it - the packets themselves
 * are stored as numerical indices.
 * @memberof module:packet
 * @constructor
 * @extends Array
 */
function List() {
  /**
   * The number of packets contained within the list.
   * @readonly
   * @type {Integer}
   */
  this.length = 0;
}

List.prototype = [];

/**
 * Reads a stream of binary data and interprents it as a list of packets.
 * @param {Uint8Array | ReadableStream<Uint8Array>} A Uint8Array of bytes.
 */
List.prototype.read = async function (bytes, streaming) {
  this.stream = stream.transformPair(bytes, async (readable, writable) => {
    const writer = stream.getWriter(writable);
    try {
      while (true) {
        await writer.ready;
        const done = await packetParser.read(readable, streaming, async parsed => {
          try {
            const tag = enums.read(enums.packet, parsed.tag);
            const packet = packets.newPacketFromTag(tag);
            packet.packets = new List();
            packet.fromStream = util.isStream(parsed.packet);
            await packet.read(parsed.packet, streaming);
            await writer.write(packet);
          } catch (e) {
            if (!config.tolerant || packetParser.supportsStreaming(parsed.tag)) {
              // The packets that support streaming are the ones that contain
              // message data. Those are also the ones we want to be more strict
              // about and throw on parse errors for.
              await writer.abort(e);
            }
            util.print_debug_error(e);
          }
        });
        if (done) {
          await writer.ready;
          await writer.close();
          return;
        }
      }
    } catch (e) {
      await writer.abort(e);
    }
  });

  // Wait until first few packets have been read
  const reader = stream.getReader(this.stream);
  while (true) {
    const { done, value } = await reader.read();
    if (!done) {
      this.push(value);
    } else {
      this.stream = null;
    }
    if (done || packetParser.supportsStreaming(value.tag)) {
      break;
    }
  }
  reader.releaseLock();
};

/**
 * Creates a binary representation of openpgp objects contained within the
 * class instance.
 * @returns {Uint8Array} A Uint8Array containing valid openpgp packets.
 */
List.prototype.write = function () {
  const arr = [];

  for (let i = 0; i < this.length; i++) {
    const packetbytes = this[i].write();
    if (util.isStream(packetbytes) && packetParser.supportsStreaming(this[i].tag)) {
      let buffer = [];
      let bufferLength = 0;
      const minLength = 512;
      arr.push(packetParser.writeTag(this[i].tag));
      arr.push(stream.transform(packetbytes, value => {
        buffer.push(value);
        bufferLength += value.length;
        if (bufferLength >= minLength) {
          const powerOf2 = Math.min(Math.log(bufferLength) / Math.LN2 | 0, 30);
          const chunkSize = 2 ** powerOf2;
          const bufferConcat = util.concat([packetParser.writePartialLength(powerOf2)].concat(buffer));
          buffer = [bufferConcat.subarray(1 + chunkSize)];
          bufferLength = buffer[0].length;
          return bufferConcat.subarray(0, 1 + chunkSize);
        }
      }, () => util.concat([packetParser.writeSimpleLength(bufferLength)].concat(buffer))));
    } else {
      if (util.isStream(packetbytes)) {
        let length = 0;
        arr.push(stream.transform(stream.clone(packetbytes), value => {
          length += value.length;
        }, () => packetParser.writeHeader(this[i].tag, length)));
      } else {
        arr.push(packetParser.writeHeader(this[i].tag, packetbytes.length));
      }
      arr.push(packetbytes);
    }
  }

  return util.concat(arr);
};

/**
 * Adds a packet to the list. This is the only supported method of doing so;
 * writing to packetlist[i] directly will result in an error.
 * @param {Object} packet Packet to push
 */
List.prototype.push = function (packet) {
  if (!packet) {
    return;
  }

  packet.packets = packet.packets || new List();

  this[this.length] = packet;
  this.length++;
};

/**
 * Creates a new PacketList with all packets from the given types
 */
List.prototype.filterByTag = function (...args) {
  const filtered = new List();

  const handle = tag => packetType => tag === packetType;

  for (let i = 0; i < this.length; i++) {
    if (args.some(handle(this[i].tag))) {
      filtered.push(this[i]);
    }
  }

  return filtered;
};

/**
 * Traverses packet tree and returns first matching packet
 * @param  {module:enums.packet} type The packet type
 * @returns {module:packet/packet|undefined}
 */
List.prototype.findPacket = function (type) {
  return this.find(packet => packet.tag === type);
};

/**
 * Returns array of found indices by tag
 */
List.prototype.indexOfTag = function (...args) {
  const tagIndex = [];
  const that = this;

  const handle = tag => packetType => tag === packetType;

  for (let i = 0; i < this.length; i++) {
    if (args.some(handle(that[i].tag))) {
      tagIndex.push(i);
    }
  }
  return tagIndex;
};

/**
 * Concatenates packetlist or array of packets
 */
List.prototype.concat = function (packetlist) {
  if (packetlist) {
    for (let i = 0; i < packetlist.length; i++) {
      this.push(packetlist[i]);
    }
  }
  return this;
};

/**
 * Allocate a new packetlist from structured packetlist clone
 * See {@link https://w3c.github.io/html/infrastructure.html#safe-passing-of-structured-data}
 * @param {Object} packetClone packetlist clone
 * @returns {Object} new packetlist object with data from packetlist clone
 */
List.fromStructuredClone = function(packetlistClone) {
  const packetlist = new List();
  for (let i = 0; i < packetlistClone.length; i++) {
    const packet = packets.fromStructuredClone(packetlistClone[i]);
    packetlist.push(packet);
    if (packet.embeddedSignature) {
      packet.embeddedSignature = packets.fromStructuredClone(packet.embeddedSignature);
    }
    if (packet.packets.length !== 0) {
      packet.packets = this.fromStructuredClone(packet.packets);
    } else {
      packet.packets = new List();
    }
  }
  if (packetlistClone.stream) {
    packetlist.stream = stream.transform(packetlistClone.stream, packet => packets.fromStructuredClone(packet));
  }
  return packetlist;
};

export default List;
