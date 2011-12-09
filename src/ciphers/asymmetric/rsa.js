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
//
// RSA implementation

function RSA() {
	/**
	 * This function uses jsbn Big Num library to decrypt RSA
	 * @param m
	 *            message
	 * @param d
	 *            RSA d as BigInteger
	 * @param p
	 *            RSA p as BigInteger
	 * @param q
	 *            RSA q as BigInteger
	 * @param u
	 *            RSA u as BigInteger
	 * @return
	 */
	function decrypt(m, d, p, q, u) {
		var xp = m.mod(p).modPow(d.mod(p.subtract(BigInteger.ONE)), p);
		var xq = m.mod(q).modPow(d.mod(q.subtract(BigInteger.ONE)), q);
		util.print_debug("rsa.js decrypt\nxpn:"+util.hexstrdump(xp.toMPI())+"\nxqn:"+util.hexstrdump(xq.toMPI()));

		var t = xq.subtract(xp);
		if (t[0] == 0) {
			t = xp.subtract(xq);
			t = t.multiply(u).mod(q);
			t = q.subtract(t);
		} else {
			t = t.multiply(u).mod(q);
		}
		return t.multiply(p).add(xp);
	}
	
	/**
	 * encrypt message
	 * @param m message as BigInteger
	 * @param e public MPI part as BigInteger
	 * @param n public MPI part as BigInteger
	 * @return BigInteger
	 */
	function encrypt(m,e,n) {
		return m.modPowInt(e, n);
	}
	
	/* Sign and Verify */
	function sign(m,d,n) {
		return m.modPow(d, n);
	}
		
	function verify(x,e,n) {
		return x.modPowInt(e, n);
	}
		
	this.encrypt = encrypt;
	this.decrypt = decrypt;
	this.verify = verify;
	this.sign = sign;
}