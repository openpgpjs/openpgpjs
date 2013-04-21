

/**
 * @class
 * @classdesc This class represents a list of openpgp packets.
 */
function openpgp_packetlist(bytes) {

	/** @type {openpgp_packet_[]} A list of packets */
	this.list = []


	/**
	 * Reads a stream of binary data and interprents it as a list of packets.
	 * @param {openpgp_bytearray} An array of bytes.
	 */
	this.read = function(bytes) {
		var i = 0;

		while(i < bytes.length) {
			var packet = openpgp_packet.read_packet(bytes, i, bytes.length - i);
			i += packet.headerLength + packet.packetLength;

			list.push(packet);
		}
	}

	/**
	 * Creates a binary representation of openpgp objects contained within the
	 * class instance.
	 * @returns {openpgp_bytearray} An array of bytes containing valid openpgp packets.
	 */
	this.write = function() {
		var bytes = '';

		for(var i in this.list) {
			bytes += openpgp_packet.write_header
	}

}
