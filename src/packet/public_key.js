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
 * @classdesc Implementation of the Key Material Packet (Tag 5,6,7,14)
 *   
 * RFC4480 5.5:
 * A key material packet contains all the information about a public or
 * private key.  There are four variants of this packet type, and two
 * major versions.  Consequently, this section is complex.
 */
function openpgp_packet_public_key() {
	this.tag = 6;
	this.version = 4;
	this.created = new Date();
	this.mpi = [];
	this.algorithm = openpgp.publickey.rsa_sign;

	
	var public_mpis = function(algorithm) {
		// - A series of multiprecision integers comprising the key material:
		//   Algorithm-Specific Fields for RSA public keys:
		//       - a multiprecision integer (MPI) of RSA public modulus n;
		//       - an MPI of RSA public encryption exponent e.
		if (algorithm > 0 && algorithm < 4)
			return 2;
		//   Algorithm-Specific Fields for Elgamal public keys:
		//     - MPI of Elgamal prime p;
		//     - MPI of Elgamal group generator g;
		//     - MPI of Elgamal public key value y (= g**x mod p where x  is secret).
		else if (algorithm == 16)
			return 3;

		//   Algorithm-Specific Fields for DSA public keys:
		//       - MPI of DSA prime p;
		//       - MPI of DSA group order q (q is a prime divisor of p-1);
		//       - MPI of DSA group generator g;
		//       - MPI of DSA public-key value y (= g**x mod p where x  is secret).
		else if (algorithm == 17)
			return 4;
		else
			return 0;
	};


	/**
	 * Internal Parser for public keys as specified in RFC 4880 section 
	 * 5.5.2 Public-Key Packet Formats
	 * called by read_tag&lt;num&gt;
	 * @param {String} input Input string to read the packet from
	 * @param {Integer} position Start position for the parser
	 * @param {Integer} len Length of the packet or remaining length of input
	 * @return {Object} This object with attributes set by the parser
	 */  
	this.read = function(bytes) {
		// A one-octet version number (3 or 4).
		this.version = bytes[0].charCodeAt();

		if (this.version == 3) {
		/*	
			// A four-octet number denoting the time that the key was created.
			this.creationTime = new Date(((input[mypos++].charCodeAt() << 24) |
				(input[mypos++].charCodeAt() << 16) |
				(input[mypos++].charCodeAt() <<  8) |
				(input[mypos++].charCodeAt()))*1000);
			
		    // - A two-octet number denoting the time in days that this key is
		    //   valid.  If this number is zero, then it does not expire.
			this.expiration = (input[mypos++].charCodeAt() << 8) & input[mypos++].charCodeAt();
	
		    // - A one-octet number denoting the public-key algorithm of this key.
			this.publicKeyAlgorithm = input[mypos++].charCodeAt();
			var mpicount = 0;
		    // - A series of multiprecision integers comprising the key material:
			//   Algorithm-Specific Fields for RSA public keys:
		    //       - a multiprecision integer (MPI) of RSA public modulus n;
		    //       - an MPI of RSA public encryption exponent e.
			if (this.publicKeyAlgorithm > 0 && this.publicKeyAlgorithm < 4)
				mpicount = 2;
			//   Algorithm-Specific Fields for Elgamal public keys:
			//     - MPI of Elgamal prime p;
			//     - MPI of Elgamal group generator g;
			//     - MPI of Elgamal public key value y (= g**x mod p where x  is secret).

			else if (this.publicKeyAlgorithm == 16)
				mpicount = 3;
			//   Algorithm-Specific Fields for DSA public keys:
			//       - MPI of DSA prime p;
			//       - MPI of DSA group order q (q is a prime divisor of p-1);
			//       - MPI of DSA group generator g;
			//       - MPI of DSA public-key value y (= g**x mod p where x  is secret).
			else if (this.publicKeyAlgorithm == 17)
				mpicount = 4;

			this.MPIs = new Array();
			for (var i = 0; i < mpicount; i++) {
				this.MPIs[i] = new openpgp_type_mpi();
				if (this.MPIs[i].read(input, mypos, (mypos-position)) != null && 
						!this.packetLength < (mypos-position)) {
					mypos += this.MPIs[i].packetLength;
				} else {
					util.print_error("openpgp.packet.keymaterial.js\n"+
						'error reading MPI @:'+mypos);
				}
			}
			this.packetLength = mypos-position;
			*/
		} else if (this.version == 4) {
			// - A four-octet number denoting the time that the key was created.
			this.created = openpgp_packet_time_read(bytes.substr(1, 4));
			
			// - A one-octet number denoting the public-key algorithm of this key.
			this.algorithm = bytes[5].charCodeAt();

			var mpicount = public_mpis(this.algorithm);
			this.mpi = [];

			var bmpi = bytes.substr(6);
			var p = 0;

			for (var i = 0; 
				i < mpicount && p < bmpi.length; 
				i++) {

				this.mpi[i] = new openpgp_type_mpi();

				p += this.mpi[i].read(bmpi.substr(p))

				if(p > bmpi.length)
					util.print_error("openpgp.packet.keymaterial.js\n"
						+'error reading MPI @:'+p);
			}

			return p + 6;
		} else {
			util.print_error('Unknown packet version');
		}
	}

	/*
     * Same as write_private_key, but has less information because of 
	 * public key.
     * @param {Integer} keyType Follows the OpenPGP algorithm standard, 
	 * IE 1 corresponds to RSA.
     * @param {RSA.keyObject} key
     * @param timePacket
     * @return {Object} {body: [string]OpenPGP packet body contents, 
	 * header: [string] OpenPGP packet header, string: [string] header+body}
     */
    this.write = function() {
		var result = String.fromCharCode(4);
        result += openpgp_packet_time_write(this.created);
		result += String.fromCharCode(this.algorithm);

		for(var i in this.mpi) {
			result += this.mpi[i].write();
		}

		return result;
	}
}

function openpgp_packet_public_subkey() {
	openpgp_packet_public_key.call(this);
	this.tag = 14;
}
