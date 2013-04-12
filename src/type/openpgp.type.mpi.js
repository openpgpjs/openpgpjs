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

// Hint: We hold our MPIs as an array of octets in big endian format preceeding a two
// octet scalar: MPI: [a,b,c,d,e,f]
// - MPI size: (a << 8) | b 
// - MPI = c | d << 8 | e << ((MPI.length -2)*8) | f ((MPI.length -2)*8)

/**
 * @class
 * @classdescImplementation of type MPI (RFC4880 3.2)
 * Multiprecision integers (also called MPIs) are unsigned integers used
 * to hold large integers such as the ones used in cryptographic
 * calculations.
 * An MPI consists of two pieces: a two-octet scalar that is the length
 * of the MPI in bits followed by a string of octets that contain the
 * actual integer.
 */
function openpgp_type_mpi() {
	this.MPI = null;
	this.mpiBitLength = null;
	this.mpiByteLength = null;
	this.data = null;
	/**
	 * Parsing function for a mpi (RFC 4880 3.2).
	 * @param {String} input Payload of mpi data
	 * @param {Integer} position Position to start reading from the input 
	 * string
	 * @param {Integer} len Length of the packet or the remaining length of 
	 * input at position
	 * @return {openpgp_type_mpi} Object representation
	 */
	function read(input, position, len) {
		var mypos = position;
		
		this.mpiBitLength = (input[mypos++].charCodeAt() << 8) | input[mypos++].charCodeAt();
		
		// Additional rules:
		//
		//    The size of an MPI is ((MPI.length + 7) / 8) + 2 octets.
		//
		//    The length field of an MPI describes the length starting from its
		//	  most significant non-zero bit.  Thus, the MPI [00 02 01] is not
		//    formed correctly.  It should be [00 01 01].

		// TODO: Verification of this size method! This size calculation as
		// 		 specified above is not applicable in JavaScript
		this.mpiByteLength = (this.mpiBitLength - (this.mpiBitLength % 8)) / 8;
		if (this.mpiBitLength % 8 != 0)
			this.mpiByteLength++;
		
		this.MPI = input.substring(mypos,mypos+this.mpiByteLength);
		this.data = input.substring(position, position+2+this.mpiByteLength);
		this.packetLength = this.mpiByteLength +2;
		return this;
	}
	
	/**
	 * Generates debug output (pretty print)
	 * @return {String} String which gives some information about the mpi
	 */
	function toString() {
		var r = "    MPI("+this.mpiBitLength+"b/"+this.mpiByteLength+"B) : 0x";
		r+=util.hexstrdump(this.MPI);
		return r+'\n';
	}
	
	/**
	 * Converts the mpi to an BigInteger object
	 * @return {BigInteger}
	 */
	function getBigInteger() {
		return new BigInteger(util.hexstrdump(this.MPI),16); 
	}

	
	function getBits(num) {
		for (var i = 0; i < 9; i++)
		if (num >> i == 0)
		return i;
	}
	
	/**
	 * Gets the length of the mpi in bytes
	 * @return {Integer} Mpi byte length
	 */
	function getByteLength() {
		return this.mpiByteLength;
	}
	
	/**
	 * Creates an mpi from the specified string
	 * @param {String} data Data to read the mpi from
	 * @return {openpgp_type_mpi} 
	 */
	function create(data) {
		this.MPI = data;
		this.mpiBitLength = (data.length -1) *8 + getBits(data.charCodeAt(0));
		this.mpiByteLength = data.length;
		return this;
	}
	
	/**
	 * Converts the mpi object to a string as specified in RFC4880 3.2
	 * @return {String} mpi Byte representation
	 */
	function toBin() {
		var result = String.fromCharCode((this.mpiBitLength >> 8) & 0xFF);
		result += String.fromCharCode(this.mpiBitLength & 0xFF);
		result += this.MPI;
		return result;
	}
	
	this.read = read;
	this.toBigInteger = getBigInteger;
	this.toString = toString;
	this.create = create;
	this.toBin = toBin;
	this.getByteLength = getByteLength;
}

