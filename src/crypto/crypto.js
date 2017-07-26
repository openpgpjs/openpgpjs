// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

// The GPG4Browsers crypto interface

/**
 * @requires crypto/cipher
 * @requires crypto/public_key
 * @requires crypto/random
 * @requires type/ecdh_symkey
 * @requires type/kdf_params
 * @requires type/mpi
 * @requires type/oid
 * @module crypto/crypto
 */

'use strict';

import random from './random.js';
import cipher from './cipher';
import publicKey from './public_key';
import type_ecdh_symkey from '../type/ecdh_symkey.js';
import type_kdf_params from '../type/kdf_params.js';
import type_mpi from '../type/mpi.js';
import type_oid from '../type/oid.js';

function createType(data, type) {
  switch(type) {
    case 'mpi':
      return new type_mpi(data);
    case 'oid':
      return new type_oid(data);
    case 'kdf':
      return new type_kdf_params(data);
    case 'ecdh_symkey':
      return new type_ecdh_symkey(data);
    default:
      return null;
  }
}

function constructParams(result, types) {
  for (var i=0; i < types.length; i++) {
    result[i] = createType(result[i], types[i]);
  }
  return result;
}

export default {
  /**
   * Encrypts data using the specified public key multiprecision integers
   * and the specified algorithm.
   * @param {module:enums.publicKey} algo Algorithm to be used (See {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1})
   * @param {Array<module:type/mpi>} publicParams Algorithm dependent multiprecision integers
   * @param {module:type/mpi} data Data to be encrypted as MPI
   * @return {Array<module:type/mpi>} if RSA an module:type/mpi;
   * if elgamal encryption an array of two module:type/mpi is returned; otherwise null
   */
  publicKeyEncrypt: function(algo, publicParams, data, fingerprint) {
    var types  = this.getEncSessionKeyParamTypes(algo);
    var result = (function() {
      var m;
      switch (algo) {
        case 'rsa_encrypt':
        case 'rsa_encrypt_sign':
          var rsa = new publicKey.rsa();
          var n = publicParams[0].toBigInteger();
          var e = publicParams[1].toBigInteger();
          m = data.toBigInteger();
          return constructParams([rsa.encrypt(m, e, n)], types);

        case 'elgamal':
          var elgamal = new publicKey.elgamal();
          var p = publicParams[0].toBigInteger();
          var g = publicParams[1].toBigInteger();
          var y = publicParams[2].toBigInteger();
          m = data.toBigInteger();
          return constructParams(elgamal.encrypt(m, g, p, y), types);

        case 'ecdh':
          var ecdh = publicKey.elliptic.ecdh;
          var curve = publicParams[0];
          var kdf_params = publicParams[2];
          var R = publicParams[1].toBigInteger();
          var res = ecdh.encrypt(curve.oid, kdf_params.cipher, kdf_params.hash, data, R, fingerprint);
          return constructParams([res.V, res.C], types);

        default:
          return [];
      }
    })();

    return result;
  },

  /**
   * Decrypts data using the specified public key multiprecision integers of the private key,
   * the specified secretMPIs of the private key and the specified algorithm.
   * @param {module:enums.publicKey} algo Algorithm to be used (See {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1})
   * @param {Array<module:type/mpi>} publicParams Algorithm dependent multiprecision integers
   * of the public key part of the private key
   * @param {Array<module:type/mpi>} secretMPIs Algorithm dependent multiprecision integers
   * of the private key used
   * @param {module:type/mpi} data Data to be encrypted as MPI
   * @return {module:type/mpi} returns a big integer containing the decrypted data; otherwise null
   */

  publicKeyDecrypt: function(algo, keyIntegers, dataIntegers, fingerprint) {
    var p;

    var bn = (function() {
      switch (algo) {
        case 'rsa_encrypt_sign':
        case 'rsa_encrypt':
          var rsa = new publicKey.rsa();
          // 0 and 1 are the public key.
          var n = keyIntegers[0].toBigInteger();
          var e = keyIntegers[1].toBigInteger();
          // 2 to 5 are the private key.
          var d = keyIntegers[2].toBigInteger();
          p = keyIntegers[3].toBigInteger();
          var q = keyIntegers[4].toBigInteger();
          var u = keyIntegers[5].toBigInteger();
          var m = dataIntegers[0].toBigInteger();
          return rsa.decrypt(m, n, e, d, p, q, u);
        case 'elgamal':
          var elgamal = new publicKey.elgamal();
          var x = keyIntegers[3].toBigInteger();
          var c1 = dataIntegers[0].toBigInteger();
          var c2 = dataIntegers[1].toBigInteger();
          p = keyIntegers[0].toBigInteger();
          return elgamal.decrypt(c1, c2, p, x);

        case 'ecdh':
          var ecdh = publicKey.elliptic.ecdh;
          var curve = keyIntegers[0];
          var kdf_params = keyIntegers[2];
          var V = dataIntegers[0].toBigInteger();
          var C = dataIntegers[1].data;
          var r = keyIntegers[3].toBigInteger();
          return ecdh.decrypt(curve.oid, kdf_params.cipher, kdf_params.hash, V, C, r, fingerprint);

        default:
          return null;
      }
    })();

    var result = new type_mpi(bn);
    return result;
  },

  /** Returns the number of integers comprising the private key of an algorithm
   * @param {String} algo The public key algorithm
   * @return {Integer} The number of integers.
   */
  getPrivKeyParamTypes: function(algo) {
    switch (algo) {
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
      case 'rsa_sign':
        //   Algorithm-Specific Fields for RSA secret keys:
        //   - multiprecision integer (MPI) of RSA secret exponent d.
        //   - MPI of RSA secret prime value p.
        //   - MPI of RSA secret prime value q (p < q).
        //   - MPI of u, the multiplicative inverse of p, mod q.
        return ['mpi', 'mpi', 'mpi', 'mpi'];
      case 'elgamal':
        // Algorithm-Specific Fields for Elgamal secret keys:
        //   - MPI of Elgamal secret exponent x.
        return ['mpi'];
      case 'dsa':
        // Algorithm-Specific Fields for DSA secret keys:
        //   - MPI of DSA secret exponent x.
        return ['mpi'];
      case 'ecdh':
      case 'ecdsa':
        // Algorithm-Specific Fields for ECDSA or ECDH secret keys:
        //   - MPI of an integer representing the secret key.
        return ['mpi'];
      default:
        throw new Error('Unknown algorithm');
    }
  },

  getPrivKeyParamCount: function(algo) {
    return this.getPrivKeyParamTypes(algo).length;
  },

  getPubKeyParamTypes: function(algo) {
    //   Algorithm-Specific Fields for RSA public keys:
    //       - a multiprecision integer (MPI) of RSA public modulus n;
    //       - an MPI of RSA public encryption exponent e.
    switch (algo) {
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
      case 'rsa_sign':
        return ['mpi', 'mpi'];
        //   Algorithm-Specific Fields for Elgamal public keys:
        //     - MPI of Elgamal prime p;
        //     - MPI of Elgamal group generator g;
        //     - MPI of Elgamal public key value y (= g**x mod p where x  is secret).
      case 'elgamal':
        return ['mpi', 'mpi', 'mpi'];
        //   Algorithm-Specific Fields for DSA public keys:
        //       - MPI of DSA prime p;
        //       - MPI of DSA group order q (q is a prime divisor of p-1);
        //       - MPI of DSA group generator g;
        //       - MPI of DSA public-key value y (= g**x mod p where x  is secret).
      case 'dsa':
        return ['mpi', 'mpi', 'mpi', 'mpi'];
        //   Algorithm-Specific Fields for ECDSA public keys:
        //       - OID of curve;
        //       - MPI of EC point representing public key.
      case 'ecdsa':
        return ['oid', 'mpi'];
        //   Algorithm-Specific Fields for ECDH public keys:
        //       - OID of curve;
        //       - MPI of EC point representing public key.
        //       - variable-length field containing KDF parameters.
      case 'ecdh':
        return ['oid', 'mpi', 'kdf'];
      default:
        throw new Error('Unknown algorithm.');
    }
  },

  getPubKeyParamCount: function(algo) {
    return this.getPubKeyParamTypes(algo).length;
  },

  getEncSessionKeyParamTypes: function(algo) {
    switch (algo) {
      //    Algorithm-Specific Fields for RSA encrypted session keys:
      //        - MPI of RSA encrypted value m**e mod n.
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
        return ['mpi'];

      //    Algorithm-Specific Fields for Elgamal encrypted session keys:
      //        - MPI of Elgamal value g**k mod p
      //        - MPI of Elgamal value m * y**k mod p
      case 'elgamal':
        return ['mpi', 'mpi'];

      //    Algorithm-Specific Fields for ECDH encrypted session keys:
      //        - MPI containing the ephemeral key used to establish the shared secret
      //        - ECDHSymmetricKey
      case 'ecdh':
        return ['mpi', 'ecdh_symkey'];

      default:
        throw new Error('Unknown algorithm.');
    }
  },

  getEncSessionKeyParamCount: function(algo) {
    return this.getEncSessionKeyParamTypes(algo).length;
  },

  generateParams: function(algo, bits, curve) {
    var types  = this.getPubKeyParamTypes(algo).concat(this.getPrivKeyParamTypes(algo));
    switch (algo) {
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
      case 'rsa_sign':
        //remember "publicKey" refers to the crypto/public_key dir
        var rsa = new publicKey.rsa();
        return rsa.generate(bits, "10001").then(function(keyObject) {
          return constructParams([keyObject.n, keyObject.ee, keyObject.d, keyObject.p, keyObject.q, keyObject.u], types);
        });

      case 'ecdsa':
        return publicKey.elliptic.generate(curve).then(function (keyObject) {
          return constructParams([keyObject.oid, keyObject.R, keyObject.r], types);
        });

      case 'ecdh':
        return publicKey.elliptic.generate(curve).then(function (keyObject) {
          return constructParams([keyObject.oid, keyObject.R, [keyObject.hash, keyObject.cipher], keyObject.r], types);
        });

      default:
        throw new Error('Unsupported algorithm for key generation.');
    }
  },


  /**
   * generate random byte prefix as string for the specified algorithm
   * @param {module:enums.symmetric} algo Algorithm to use (see {@link http://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2})
   * @return {Uint8Array} Random bytes with length equal to the block
   * size of the cipher
   */
  getPrefixRandom: function(algo) {
    return random.getRandomBytes(cipher[algo].blockSize);
  },

  /**
   * Generating a session key for the specified symmetric algorithm
   * @param {module:enums.symmetric} algo Algorithm to use (see {@link http://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2})
   * @return {Uint8Array} Random bytes as a string to be used as a key
   */
  generateSessionKey: function(algo) {
    return random.getRandomBytes(cipher[algo].keySize);
  },

  constructParams: constructParams
};
