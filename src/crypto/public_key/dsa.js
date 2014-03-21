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
// A Digital signature algorithm implementation

/**
 * @requires crypto/hash
 * @requires crypto/public_key/jsbn
 * @requires crypto/random
 * @requires util
 * @module crypto/public_key/dsa
 */

var BigInteger = require('./jsbn.js'),
  random = require('../random.js'),
  hashModule = require('../hash'),
  util = require('../../util.js'),
  config = require('../../config');

function DSA() {
  // s1 = ((g**s) mod p) mod q
  // s1 = ((s**-1)*(sha-1(m)+(s1*x) mod q)
  function sign(hashalgo, m, g, p, q, x) {
    // If the output size of the chosen hash is larger than the number of
    // bits of q, the hash result is truncated to fit by taking the number
    // of leftmost bits equal to the number of bits of q.  This (possibly
    // truncated) hash function result is treated as a number and used
    // directly in the DSA signature algorithm.
    var hashed_data = util.getLeftNBits(hashModule.digest(hashalgo, m), q.bitLength());
    var hash = new BigInteger(util.hexstrdump(hashed_data), 16);
    // FIPS-186-4, section 4.6:
    // The values of r and s shall be checked to determine if r = 0 or s = 0.
    // If either r = 0 or s = 0, a new value of k shall be generated, and the
    // signature shall be recalculated. It is extremely unlikely that r = 0 
    // or s = 0 if signatures are generated properly.
    var k, s1, s2;
    while (true) {
      k = random.getRandomBigIntegerInRange(BigInteger.ONE, q.subtract(BigInteger.ONE));
      s1 = (g.modPow(k, p)).mod(q);
      s2 = (k.modInverse(q).multiply(hash.add(x.multiply(s1)))).mod(q);
      if (s1 != 0 && s2 != 0) {
        break;
      }
    }
    var result = [];
    result[0] = s1.toMPI();
    result[1] = s2.toMPI();
    return result;
  }

  function select_hash_algorithm(q) {
    var usersetting = config.prefer_hash_algorithm;
    /*
     * 1024-bit key, 160-bit q, SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512 hash
     * 2048-bit key, 224-bit q, SHA-224, SHA-256, SHA-384, or SHA-512 hash
     * 2048-bit key, 256-bit q, SHA-256, SHA-384, or SHA-512 hash
     * 3072-bit key, 256-bit q, SHA-256, SHA-384, or SHA-512 hash
     */
    switch (Math.round(q.bitLength() / 8)) {
      case 20:
        // 1024 bit
        if (usersetting != 2 &&
          usersetting > 11 &&
          usersetting != 10 &&
          usersetting < 8)
          return 2; // prefer sha1
        return usersetting;
      case 28:
        // 2048 bit
        if (usersetting > 11 &&
          usersetting < 8)
          return 11;
        return usersetting;
      case 32:
        // 4096 bit // prefer sha224
        if (usersetting > 10 &&
          usersetting < 8)
          return 8; // prefer sha256
        return usersetting;
      default:
        util.print_debug("DSA select hash algorithm: returning null for an unknown length of q");
        return null;

    }
  }
  this.select_hash_algorithm = select_hash_algorithm;

  function verify(hashalgo, s1, s2, m, p, q, g, y) {
    var hashed_data = util.getLeftNBits(hashModule.digest(hashalgo, m), q.bitLength());
    var hash = new BigInteger(util.hexstrdump(hashed_data), 16);
    if (BigInteger.ZERO.compareTo(s1) > 0 ||
      s1.compareTo(q) > 0 ||
      BigInteger.ZERO.compareTo(s2) > 0 ||
      s2.compareTo(q) > 0) {
      util.print_debug("invalid DSA Signature");
      return null;
    }
    var w = s2.modInverse(q);
    var u1 = hash.multiply(w).mod(q);
    var u2 = s1.multiply(w).mod(q);
    return g.modPow(u1, p).multiply(y.modPow(u2, p)).mod(p).mod(q);
  }

  /*
	 * unused code. This can be used as a start to write a key generator
	 * function.
	
  function generateKey(bitcount) {
    var qi = new BigInteger(bitcount, primeCenterie);
    var pi = generateP(q, 512);
    var gi = generateG(p, q, bitcount);
    var xi;
    do {
      xi = new BigInteger(q.bitCount(), rand);
    } while (x.compareTo(BigInteger.ZERO) != 1 && x.compareTo(q) != -1);
    var yi = g.modPow(x, p);
    return {x: xi, q: qi, p: pi, g: gi, y: yi};
  }

  function generateP(q, bitlength, randomfn) {
    if (bitlength % 64 != 0) {
      return false;
    }
    var pTemp;
    var pTemp2;
    do {
      pTemp = randomfn(bitcount, true);
      pTemp2 = pTemp.subtract(BigInteger.ONE);
      pTemp = pTemp.subtract(pTemp2.remainder(q));
    } while (!pTemp.isProbablePrime(primeCenterie) || pTemp.bitLength() != l);
    return pTemp;
  }
	
  function generateG(p, q, bitlength, randomfn) {
    var aux = p.subtract(BigInteger.ONE);
    var pow = aux.divide(q);
    var gTemp;
    do {
      gTemp = randomfn(bitlength);
    } while (gTemp.compareTo(aux) != -1 && gTemp.compareTo(BigInteger.ONE) != 1);
    return gTemp.modPow(pow, p);
  }

  function generateK(q, bitlength, randomfn) {
    var tempK;
    do {
      tempK = randomfn(bitlength, false);
    } while (tempK.compareTo(q) != -1 && tempK.compareTo(BigInteger.ZERO) != 1);
    return tempK;
  }

  function generateR(q,p) {
    k = generateK(q);
    var r = g.modPow(k, p).mod(q);
    return r;
  }

  function generateS(hashfn,k,r,m,q,x) {
    var hash = hashfn(m);
    s = (k.modInverse(q).multiply(hash.add(x.multiply(r)))).mod(q);
    return s;
  } */
  this.sign = sign;
  this.verify = verify;
  // this.generate = generateKey;
}

module.exports = DSA;
