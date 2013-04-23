

/**
 * @class
 * @classdesc This class represents a list of openpgp packets.
 */
function openpgp_packetlist() {

	/** @type {openpgp_packet_[]} A list of packets */
	this.packets = []



	/**
	 * Reads a stream of binary data and interprents it as a list of packets.
	 * @param {openpgp_bytearray} An array of bytes.
	 */
	this.read = function(bytes) {
		this.packets = [];
		var i = 0;

		while(i < bytes.length) {
			var parsed = openpgp_packet.read_packet(bytes, i, bytes.length - i);
			i = parsed.offset;

			this.push(parsed.packet);
		}
	}

	/**
	 * Creates a binary representation of openpgp objects contained within the
	 * class instance.
	 * @returns {openpgp_bytearray} An array of bytes containing valid openpgp packets.
	 */
	this.write = function() {
		var bytes = '';

		for(var i in this.packets) {
			var packetbytes = this.packets[i].write();
			bytes += openpgp_packet.write_packet_header(this.packets[i].tag, packetbytes.length);
			bytes += packetbytes;
		}
		
		return bytes;
	}

	this.push = function(packet) {
		this.packets.push(packet);
	}

}
