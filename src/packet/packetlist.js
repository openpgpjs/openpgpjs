import { transformPair as streamTransformPair, transform as streamTransform, getWriter as streamGetWriter, getReader as streamGetReader, clone as streamClone } from '@openpgp/web-stream-tools';
import {
  readPacket, supportsStreaming,
  writeTag, writeHeader,
  writePartialLength, writeSimpleLength,
  UnparseablePacket,
  UnsupportedError,
  UnknownPacketError,
  MalformedPacketError
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
 * @throws {Error|UnsupportedError} for disallowed or unknown packets
 */
export function newPacketFromTag(tag, allowedPackets) {
  if (!allowedPackets[tag]) {
    // distinguish between disallowed packets and unknown ones
    let packetType;
    try {
      packetType = enums.read(enums.packet, tag);
    } catch (e) {
      throw new UnknownPacketError(`Unknown packet type with tag: ${tag}`);
    }
    throw new Error(`Packet not allowed in this context: ${packetType}`);
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
   * Parses the given binary data and returns a list of packets.
   * Equivalent to calling `read` on an empty PacketList instance.
   * @param {Uint8Array | ReadableStream<Uint8Array>} bytes - binary data to parse
   * @param {Object} allowedPackets - mapping where keys are allowed packet tags, pointing to their Packet class
   * @param {Object} [config] - full configuration, defaults to openpgp.config
   * @param {function(enums.packet[], boolean, Object): void} [grammarValidator]
   * @param {Boolean} [delayErrors] - delay errors until the input stream has been read completely
   * @returns {PacketList} parsed list of packets
   * @throws on parsing errors
   * @async
   */
  static async fromBinary(bytes, allowedPackets, config = defaultConfig, grammarValidator = null, delayErrors = false) {
    const packets = new PacketList();
    await packets.read(bytes, allowedPackets, config, grammarValidator, delayErrors);
    return packets;
  }

  /**
   * Reads a stream of binary data and interprets it as a list of packets.
   * @param {Uint8Array | ReadableStream<Uint8Array>} bytes - binary data to parse
   * @param {Object} allowedPackets - mapping where keys are allowed packet tags, pointing to their Packet class
   * @param {Object} [config] - full configuration, defaults to openpgp.config
   * @param {function(enums.packet[], boolean, Object): void} [grammarValidator]
   * @param {Boolean} [delayErrors] - delay errors until the input stream has been read completely
   * @throws on parsing errors
   * @async
   */
  async read(bytes, allowedPackets, config = defaultConfig, grammarValidator = null, delayErrors = false) {
    if (config.additionalAllowedPackets.length) {
      allowedPackets = { ...allowedPackets, ...util.constructAllowedPackets(config.additionalAllowedPackets) };
    }
    this.stream = streamTransformPair(bytes, async (readable, writable) => {
      const reader = streamGetReader(readable);
      const writer = streamGetWriter(writable);
      try {
        let useStreamType = util.isStream(readable);
        while (true) {
          await writer.ready;
          let unauthenticatedError;
          let wasStream;
          await readPacket(reader, useStreamType, async parsed => {
            try {
              if (parsed.tag === enums.packet.marker || parsed.tag === enums.packet.trust || parsed.tag === enums.packet.padding) {
                // According to the spec, these packet types should be ignored and not cause parsing errors, even if not explicitly allowed:
                // - Marker packets MUST be ignored when received: https://github.com/openpgpjs/openpgpjs/issues/1145
                // - Trust packets SHOULD be ignored outside of keyrings (unsupported): https://datatracker.ietf.org/doc/html/rfc4880#section-5.10
                // - [Padding Packets] MUST be ignored when received: https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#name-padding-packet-tag-21
                return;
              }
              const packet = newPacketFromTag(parsed.tag, allowedPackets);
              // Unknown packets throw in the call above, we ignore them
              // in the grammar checker.
              try {
                grammarValidator?.recordPacket(parsed.tag);
              } catch (e) {
                if (config.enforceGrammar) {
                  throw e;
                } else {
                  util.printDebugError(e);
                }
              }
              packet.packets = new PacketList();
              packet.fromStream = util.isStream(parsed.packet);
              wasStream = packet.fromStream;
              try {
                await packet.read(parsed.packet, config);
              } catch (e) {
                if (!(e instanceof UnsupportedError)) {
                  throw util.wrapError(new MalformedPacketError(`Parsing ${packet.constructor.name} failed`), e);
                }
                throw e;
              }
              await writer.write(packet);
            } catch (e) {
              // If an implementation encounters a critical packet where the packet type is unknown in a packet sequence,
              // it MUST reject the whole packet sequence. On the other hand, an unknown non-critical packet MUST be ignored.
              // Packet Tags from 0 to 39 are critical. Packet Tags from 40 to 63 are non-critical.
              const throwUnknownPacketError =
                e instanceof UnknownPacketError &&
                parsed.tag <= 39;
              // In case of unsupported packet versions/algorithms/etc, we ignore the error by default
              // (unless the packet is a data packet, see below).
              const throwUnsupportedError =
                e instanceof UnsupportedError &&
                !(e instanceof UnknownPacketError) &&
                !config.ignoreUnsupportedPackets;
              // In case of packet parsing errors, e.name was set to 'MalformedPacketError' above.
              // By default, we throw for these errors.
              const throwMalformedPacketError =
                e instanceof MalformedPacketError &&
                !config.ignoreMalformedPackets;
              // The packets that support streaming are the ones that contain message data.
              // Those are also the ones we want to be more strict about and throw on all errors
              // (since we likely cannot process the message without these packets anyway).
              const throwDataPacketError = supportsStreaming(parsed.tag);
              // Throw all other errors, including `GrammarError`s, disallowed packet errors, and unexpected errors.
              const throwOtherError = !(
                e instanceof UnknownPacketError ||
                e instanceof UnsupportedError ||
                e instanceof MalformedPacketError
              );
              if (
                throwUnknownPacketError ||
                throwUnsupportedError ||
                throwMalformedPacketError ||
                throwDataPacketError ||
                throwOtherError
              ) {
                if (delayErrors) {
                  unauthenticatedError = e;
                } else {
                  await writer.abort(e);
                }
              } else {
                const unparsedPacket = new UnparseablePacket(parsed.tag, parsed.packet);
                await writer.write(unparsedPacket);
              }
              util.printDebugError(e);
            }
          });
          if (wasStream) {
            // Don't allow more than one streaming packet, as read errors
            // may get lost in the second packet's data stream.
            useStreamType = null;
          }

          // If there was a parse error, read the entire input first
          // in case there's an MDC error, which should take precedence.
          if (unauthenticatedError) {
            await reader.readToEnd();
            // eslint-disable-next-line @typescript-eslint/no-throw-literal
            throw unauthenticatedError;
          }

          // We peek to check whether this was the last packet.
          // We peek 2 bytes instead of 1 because `readPacket` also
          // peeks 2 bytes, and we want to cut a `subarray` of the
          // correct length into `web-stream-tools`' `externalBuffer`
          // as a tiny optimization here.
          const nextPacket = await reader.peekBytes(2);
          const done = !nextPacket || !nextPacket.length;
          if (done) {
            // Here we are past the MDC check for SEIPDv1 data, hence
            // the data is always authenticated at this point.
            try {
              grammarValidator?.recordEnd();
            } catch (e) {
              if (config.enforceGrammar) {
                throw e;
              } else {
                util.printDebugError(e);
              }
            }
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
    const reader = streamGetReader(this.stream);
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
      const tag = this[i] instanceof UnparseablePacket ? this[i].tag : this[i].constructor.tag;
      const packetbytes = this[i].write();
      if (util.isStream(packetbytes) && supportsStreaming(this[i].constructor.tag)) {
        let buffer = [];
        let bufferLength = 0;
        const minLength = 512;
        arr.push(writeTag(tag));
        arr.push(streamTransform(packetbytes, value => {
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
          arr.push(streamTransform(streamClone(packetbytes), value => {
            length += value.length;
          }, () => writeHeader(tag, length)));
        } else {
          arr.push(writeHeader(tag, packetbytes.length));
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
