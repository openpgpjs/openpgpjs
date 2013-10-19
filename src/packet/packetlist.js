var packetParser = require('./packet.js'),
  packets = require('./all_packets.js'),
  enums = require('../enums.js');

/**
 * @class
 * @classdesc This class represents a list of openpgp packets.
 * Take care when iterating over it - the packets themselves
 * are stored as numerical indices.
 */
module.exports = function packetlist() {
  /** The number of packets contained within the list.
   * @readonly
   * @type {Integer} */
  this.length = 0;

  /**
   * Reads a stream of binary data and interprents it as a list of packets.
   * @param {openpgp_bytearray} An array of bytes.
   */
  this.read = function(bytes) {
    var i = 0;

    while (i < bytes.length) {
      var parsed = packetParser.read(bytes, i, bytes.length - i);
      i = parsed.offset;

      var tag = enums.read(enums.packet, parsed.tag);
      var packet = new packets[tag]();

      this.push(packet);

      packet.read(parsed.packet);
    }
  }

  /**
   * Creates a binary representation of openpgp objects contained within the
   * class instance.
   * @returns {openpgp_bytearray} An array of bytes containing valid openpgp packets.
   */
  this.write = function() {
    var bytes = '';

    for (var i = 0; i < this.length; i++) {
      var packetbytes = this[i].write();
      bytes += packetParser.writeHeader(this[i].tag, packetbytes.length);
      bytes += packetbytes;
    }

    return bytes;
  }

  /**
   * Adds a packet to the list. This is the only supported method of doing so;
   * writing to packetlist[i] directly will result in an error.
   */
  this.push = function(packet) {
    packet.packets = new packetlist();

    this[this.length] = packet;
    this.length++;
  }

}
