/* eslint-disable callback-return */
/**
 * @requires packet/all_packets
 * @requires packet/packet
 * @requires config
 * @requires enums
 * @requires util
 */

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
 */
function List() {
  /**
   * The number of packets contained within the list.
   * @readonly
   * @type {Integer}
   */
  this.length = 0;
}

/**
 * Reads a stream of binary data and interprents it as a list of packets.
 * @param {Uint8Array} A Uint8Array of bytes.
 */
List.prototype.read = function (bytes) {
  let i = 0;

  while (i < bytes.length) {
    const parsed = packetParser.read(bytes, i, bytes.length - i);
    i = parsed.offset;

    let pushed = false;
    try {
      const tag = enums.read(enums.packet, parsed.tag);
      const packet = packets.newPacketFromTag(tag);
      this.push(packet);
      pushed = true;
      packet.read(parsed.packet);
    } catch (e) {
      if (!config.tolerant ||
          parsed.tag === enums.packet.symmetricallyEncrypted ||
          parsed.tag === enums.packet.literal ||
          parsed.tag === enums.packet.compressed) {
        throw e;
      }
      if (pushed) {
        this.pop(); // drop unsupported packet
      }
    }
  }
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
    arr.push(packetParser.writeHeader(this[i].tag, packetbytes.length));
    arr.push(packetbytes);
  }

  return util.concatUint8Array(arr);
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
 * Remove a packet from the list and return it.
 * @returns {Object}   The packet that was removed
 */
List.prototype.pop = function() {
  if (this.length === 0) {
    return;
  }

  const packet = this[this.length - 1];
  delete this[this.length - 1];
  this.length--;

  return packet;
};

/**
 * Creates a new PacketList with all packets that pass the test implemented by the provided function.
 */
List.prototype.filter = function (callback) {
  const filtered = new List();

  for (let i = 0; i < this.length; i++) {
    if (callback(this[i], i, this)) {
      filtered.push(this[i]);
    }
  }

  return filtered;
};

/**
 * Creates a new PacketList with all packets from the given types
 */
List.prototype.filterByTag = function (...args) {
  const filtered = new List();
  const that = this;

  const handle = tag => packetType => tag === packetType;

  for (let i = 0; i < this.length; i++) {
    if (args.some(handle(that[i].tag))) {
      filtered.push(this[i]);
    }
  }

  return filtered;
};

/**
 * Executes the provided callback once for each element
 */
List.prototype.forEach = function (callback) {
  for (let i = 0; i < this.length; i++) {
    callback(this[i], i, this);
  }
};

/**
 * Returns an array containing return values of callback
 * on each element
 */
List.prototype.map = function (callback) {
  const packetArray = [];

  for (let i = 0; i < this.length; i++) {
    packetArray.push(callback(this[i], i, this));
  }

  return packetArray;
};

/**
 * Executes the callback function once for each element
 * until it finds one where callback returns a truthy value
 * @param  {Function} callback
 * @returns {Promise<Boolean>}
 * @async
 */
List.prototype.some = async function (callback) {
  for (let i = 0; i < this.length; i++) {
    // eslint-disable-next-line no-await-in-loop
    if (await callback(this[i], i, this)) {
      return true;
    }
  }
  return false;
};

/**
 * Executes the callback function once for each element,
 * returns true if all callbacks returns a truthy value
 */
List.prototype.every = function (callback) {
  for (let i = 0; i < this.length; i++) {
    if (!callback(this[i], i, this)) {
      return false;
    }
  }
  return true;
};

/**
 * Traverses packet tree and returns first matching packet
 * @param  {module:enums.packet} type The packet type
 * @returns {module:packet/packet|null}
 */
List.prototype.findPacket = function (type) {
  const packetlist = this.filterByTag(type);
  if (packetlist.length) {
    return packetlist[0];
  }
  let found = null;
  for (let i = 0; i < this.length; i++) {
    if (this[i].packets.length) {
      found = this[i].packets.findPacket(type);
      if (found) {
        return found;
      }
    }
  }

  return null;
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
 * Returns slice of packetlist
 */
List.prototype.slice = function (begin, end) {
  if (!end) {
    end = this.length;
  }
  const part = new List();
  for (let i = begin; i < end; i++) {
    part.push(this[i]);
  }
  return part;
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
    packetlist.push(packets.fromStructuredClone(packetlistClone[i]));
    if (packetlist[i].packets.length !== 0) {
      packetlist[i].packets = this.fromStructuredClone(packetlist[i].packets);
    } else {
      packetlist[i].packets = new List();
    }
  }
  return packetlist;
};

export default List;
