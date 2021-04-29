import * as stream from '@openpgp/web-stream-tools';
import {
  readPackets, supportsStreaming,
  writeTag, writeHeader,
  writePartialLength, writeSimpleLength
} from './packet';
import util from '../util';
import enums from '../enums';
import defaultConfig from '../config';

/**
 * Instantiate a new packet given its tag
 * @function newPacketFromTag
 * @param {module:enums.packet} tag - Property value from {@link module:enums.packet}
 * @param {Object} allowedPackets - mapping where keys are allowed packet tags, pointing to their Packet class
 * @returns {Object} New packet object with type based on tag
 */
export function newPacketFromTag(tag, allowedPackets) {
  if (!allowedPackets[tag]) {
    throw new Error(`Packet not allowed in this context: ${enums.read(enums.packets, tag)}`);
  }
  return new allowedPackets[tag]();
}

/**
 * This class represents a list of openpgp packets.
 * Take care when iterating over it - the packets themselves
 * are stored as numerical indices.
 * @extends Array
 */
class PacketList extends Array {
  /**
   * Reads a stream of binary data and interprets it as a list of packets.
   * @param {Uint8Array | ReadableStream<Uint8Array>} bytes - A Uint8Array of bytes.
   */
  async read(bytes, allowedPackets, config = defaultConfig) {
    this.stream = stream.transformPair(bytes, async (readable, writable) => {
      const writer = stream.getWriter(writable);
      try {
        while (true) {
          await writer.ready;
          const done = await readPackets(readable, async parsed => {
            try {
              const packet = newPacketFromTag(parsed.tag, allowedPackets);
              packet.packets = new PacketList();
              packet.fromStream = util.isStream(parsed.packet);
              await packet.read(parsed.packet, config);
              await writer.write(packet);
            } catch (e) {
              if (!config.tolerant || supportsStreaming(parsed.tag)) {
                // The packets that support streaming are the ones that contain
                // message data. Those are also the ones we want to be more strict
                // about and throw on parse errors for.
                await writer.abort(e);
              }
              util.printDebugError(e);
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
      if (done || supportsStreaming(value.constructor.tag)) {
        break;
      }
    }
    reader.releaseLock();
  }

  /**
   * Creates a binary representation of openpgp objects contained within the
   * class instance.
   * @returns {Uint8Array} A Uint8Array containing valid openpgp packets.
   */
  write() {
    const arr = [];

    for (let i = 0; i < this.length; i++) {
      const packetbytes = this[i].write();
      if (util.isStream(packetbytes) && supportsStreaming(this[i].constructor.tag)) {
        let buffer = [];
        let bufferLength = 0;
        const minLength = 512;
        arr.push(writeTag(this[i].constructor.tag));
        arr.push(stream.transform(packetbytes, value => {
          buffer.push(value);
          bufferLength += value.length;
          if (bufferLength >= minLength) {
            const powerOf2 = Math.min(Math.log(bufferLength) / Math.LN2 | 0, 30);
            const chunkSize = 2 ** powerOf2;
            const bufferConcat = util.concat([writePartialLength(powerOf2)].concat(buffer));
            buffer = [bufferConcat.subarray(1 + chunkSize)];
            bufferLength = buffer[0].length;
            return bufferConcat.subarray(0, 1 + chunkSize);
          }
        }, () => util.concat([writeSimpleLength(bufferLength)].concat(buffer))));
      } else {
        if (util.isStream(packetbytes)) {
          let length = 0;
          arr.push(stream.transform(stream.clone(packetbytes), value => {
            length += value.length;
          }, () => writeHeader(this[i].constructor.tag, length)));
        } else {
          arr.push(writeHeader(this[i].constructor.tag, packetbytes.length));
        }
        arr.push(packetbytes);
      }
    }

    return util.concat(arr);
  }

  /**
   * Creates a new PacketList with all packets matching the given tag(s)
   * @param {...module:enums.packet} tags - packet tags to look for
   * @returns {PacketList}
   */
  filterByTag(...tags) {
    const filtered = new PacketList();

    const handle = tag => packetType => tag === packetType;

    for (let i = 0; i < this.length; i++) {
      if (tags.some(handle(this[i].constructor.tag))) {
        filtered.push(this[i]);
      }
    }

    return filtered;
  }

  /**
   * Traverses packet list and returns first packet with matching tag
   * @param {module:enums.packet} tag - The packet tag
   * @returns {Packet|undefined}
   */
  findPacket(tag) {
    return this.find(packet => packet.constructor.tag === tag);
  }

  /**
   * Find indices of packets with the given tag(s)
   * @param {...module:enums.packet} tags - packet tags to look for
   * @returns {Integer[]} packet indices
   */
  indexOfTag(...tags) {
    const tagIndex = [];
    const that = this;

    const handle = tag => packetType => tag === packetType;

    for (let i = 0; i < this.length; i++) {
      if (tags.some(handle(that[i].constructor.tag))) {
        tagIndex.push(i);
      }
    }
    return tagIndex;
  }
}

export default PacketList;
