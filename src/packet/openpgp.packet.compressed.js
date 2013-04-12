// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @class
 * @classdesc Implementation of the Compressed Data Packet (Tag 8)
 * 
 * RFC4880 5.6:
 * The Compressed Data packet contains compressed data.  Typically, this
 * packet is found as the contents of an encrypted packet, or following
 * a Signature or One-Pass Signature packet, and contains a literal data
 * packet.
 */   
function openpgp_packet_compressed() {
	this.tagType = 8;
	this.decompressedData = null;
	
	/**
	 * Parsing function for the packet.
	 * @param {String} input Payload of a tag 8 packet
	 * @param {Integer} position Position to start reading from the input string
	 * @param {Integer} len Length of the packet or the remaining length of 
	 * input at position
	 * @return {openpgp_packet_compressed} Object representation
	 */
	function read_packet (input, position, len) {
		this.packetLength = len;
		var mypos = position;
		// One octet that gives the algorithm used to compress the packet.
		this.type = input.charCodeAt(mypos++);
		// Compressed data, which makes up the remainder of the packet.
		this.compressedData = input.substring(position+1, position+len);
		return this;
	}
	/**
	 * Decompression method for decompressing the compressed data
	 * read by read_packet
	 * @return {String} The decompressed data
	 */
	function decompress() {
		if (this.decompressedData != null)
			return this.decompressedData;

		if (this.type == null)
			return null;

		switch (this.type) {
		case 0: // - Uncompressed
			this.decompressedData = this.compressedData;
			break;
		case 1: // - ZIP [RFC1951]
			util.print_info('Decompressed packet [Type 1-ZIP]: ' + this.toString());
			var compData = this.compressedData;
			var radix = s2r(compData).replace(/\n/g,"");
			// no header in this case, directly call deflate
			var jxg_obj = new JXG.Util.Unzip(JXG.Util.Base64.decodeAsArray(radix));
			this.decompressedData = unescape(jxg_obj.deflate()[0][0]);
			break;
		case 2: // - ZLIB [RFC1950]
			util.print_info('Decompressed packet [Type 2-ZLIB]: ' + this.toString());
			var compressionMethod = this.compressedData.charCodeAt(0) % 0x10; //RFC 1950. Bits 0-3 Compression Method
			//Bits 4-7 RFC 1950 are LZ77 Window. Generally this value is 7 == 32k window size.
			//2nd Byte in RFC 1950 is for "FLAGs" Allows for a Dictionary (how is this defined). Basic checksum, and compression level.
			if (compressionMethod == 8) { //CM 8 is for DEFLATE, RFC 1951
				// remove 4 bytes ADLER32 checksum from the end
				var compData = this.compressedData.substring(0, this.compressedData.length - 4);
				var radix = s2r(compData).replace(/\n/g,"");
				//TODO check ADLER32 checksum
				this.decompressedData = JXG.decompress(radix);
				break;
			} else {
				util.print_error("Compression algorithm ZLIB only supports DEFLATE compression method.");
			}
			break;
		case 3: //  - BZip2 [BZ2]
			// TODO: need to implement this
			util.print_error("Compression algorithm BZip2 [BZ2] is not implemented.");
			break;
		default:
			util.print_error("Compression algorithm unknown :"+this.type);
			break;
		}
		util.print_debug("decompressed:"+util.hexstrdump(this.decompressedData));
		return this.decompressedData; 
	}

	/**
	 * Compress the packet data (member decompressedData)
	 * @param {Integer} type Algorithm to be used // See RFC 4880 9.3
	 * @param {String} data Data to be compressed
	 * @return {String} The compressed data stored in attribute compressedData
	 */
	function compress(type, data) {
		this.type = type;
		this.decompressedData = data;
		switch (this.type) {
		case 0: // - Uncompressed
			this.compressedData = this.decompressedData;
			break;
		case 1: // - ZIP [RFC1951]
			util.print_error("Compression algorithm ZIP [RFC1951] is not implemented.");
			break;
		case 2: // - ZLIB [RFC1950]
			// TODO: need to implement this
			util.print_error("Compression algorithm ZLIB [RFC1950] is not implemented.");
			break;
		case 3: //  - BZip2 [BZ2]
			// TODO: need to implement this
			util.print_error("Compression algorithm BZip2 [BZ2] is not implemented.");
			break;
		default:
			util.print_error("Compression algorithm unknown :"+this.type);
			break;
		}
		this.packetLength = this.compressedData.length +1;
		return this.compressedData; 
	}
	
	/**
	 * Creates a string representation of the packet
	 * @param {Integer} algorithm Algorithm to be used // See RFC 4880 9.3
	 * @param {String} data Data to be compressed
	 * @return {String} String-representation of the packet
	 */
	function write_packet(algorithm, data) {
		this.decompressedData = data;
		if (algorithm == null) {
			this.type = 1;
		}
		var result = String.fromCharCode(this.type)+this.compress(this.type);
		return openpgp_packet.write_packet_header(8, result.length)+result;
	}
	
	/**
	 * Pretty printing the packet (useful for debug purposes)
	 * @return {String}
	 */
	function toString() {
		return '5.6.  Compressed Data Packet (Tag 8)\n'+
		   '    length:  '+this.packetLength+'\n'+
			   '    Compression Algorithm = '+this.type+'\n'+
		       '    Compressed Data: Byte ['+util.hexstrdump(this.compressedData)+']\n';
	}
	
	this.read_packet = read_packet;
	this.toString = toString;
	this.compress = compress;
	this.decompress = decompress;
	this.write_packet = write_packet;
};
