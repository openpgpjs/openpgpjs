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
 * Implementation of the Compressed Data Packet (Tag 8)
 * 
 * RFC4880 5.6:
 * The Compressed Data packet contains compressed data.  Typically, this
 * packet is found as the contents of an encrypted packet, or following
 * a Signature or One-Pass Signature packet, and contains a literal data
 * packet.
 */   
function openpgp_packet_compressed() {
	this.tagType = 8;
	
	/**
	 * parsing function for the packet.
	 * @param input [string] payload of a tag 8 packet
	 * @param position [integer] position to start reading from the input string
	 * @param len [integer] length of the packet or the remaining length of input at position
	 * @return [openpgp_packet_compressed] object representation
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
	 * decompression method for decompressing the compressed data
	 * read by read_packet
	 * @return [String] the decompressed data
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
            var inflater = new zip.Inflater();
            var output = inflater.append(util.str2Uint8Array(this.compressedData));
            var outputString = util.Uint8Array2str(output);
            var packet = openpgp_packet.read_packet(outputString,0,outputString.length);
            util.print_info('Decompressed packet [Type 1-ZIP]: ' + packet);
            this.decompressedData = packet.data;
			break;
		case 2: // - ZLIB [RFC1950]
			// TODO: This is pretty hacky. Not fully utilizing ZLIB (ADLER-32). No real JS implementations out there for this?
            var compressionMethod = this.compressedData.charCodeAt(0)%0x10; //RFC 1950. Bits 0-3 Compression Method
            //Bits 4-7 RFC 1950 are LZ77 Window. Generally this value is 7 == 32k window size.
            //2nd Byte in RFC 1950 is for "FLAGs" Allows for a Dictionary (how is this defined). Basic checksum, and compression level.
            if(compressionMethod == 8) { //CM 8 is for DEFLATE, RFC 1951
                var inflater = new zip.Inflater();
			    var output = inflater.append(util.str2Uint8Array(this.compressedData.substring(2,this.compressedData.length-4)));
                var outputString = util.Uint8Array2str(output);
                //TODO check ADLER32 checksum
                var packet = openpgp_packet.read_packet(outputString,0,outputString.length);
                util.print_info('Decompressed packet [Type 2-ZLIB]: ' + packet);
                this.decompressedData = packet.data;
            }
            else{
			        util.print_error("Compression algorithm ZLIB is not fully implemented.");
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
	 * @param type [integer] algorithm to be used // See RFC 4880 9.3
	 * @param data [String] data to be compressed
	 * @return [String] The compressed data stored in attribute compressedData
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
	 * creates a string representation of the packet
	 * @param algorithm [integer] algorithm to be used // See RFC 4880 9.3
	 * @param data [String] data to be compressed
	 * @return [String] string-representation of the packet
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
	 * pretty printing the packet (useful for debug purposes)
	 * @return [String]
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
