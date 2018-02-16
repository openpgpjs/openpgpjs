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
 * @requires bn.js
 * @requires asmcrypto.js
 * @requires crypto/public_key
 * @requires crypto/cipher
 * @requires crypto/random
 * @requires type/ecdh_symkey
 * @requires type/kdf_params
 * @requires type/mpi
 * @requires type/oid
 * @requires util
 * @module crypto/crypto
 */

import BN from 'bn.js';
import { RSA_RAW } from 'asmcrypto.js';
import publicKey from './public_key';
import cipher from './cipher';
import random from './random';
import type_ecdh_symkey from '../type/ecdh_symkey';
import type_kdf_params from '../type/kdf_params';
import type_mpi from '../type/mpi';
import type_oid from '../type/oid';
import util from '../util';

function constructParams(types, data) {
  return types.map(function(type, i) {
    if (data && data[i]) {
      return new type(data[i]);
    }
    return new type();
  });
}

export default {
  /**
   * Encrypts data using the specified public key multiprecision integers
   * and the specified algorithm.
   * @param {module:enums.publicKey} algo Algorithm to be used (See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1})
   * @param {Array<module:type/mpi|module:type/oid|module:type/kdf_params|module:type/ecdh_symkey>} publicParams Algorithm dependent params
   * @param {module:type/mpi} data Data to be encrypted as MPI
   * @param {String} fingerprint Recipient fingerprint
   * @return {Array<module:type/mpi|module:type/oid|module:type/kdf_params|module:type/ecdh_symkey>} encrypted session key parameters
   */
  publicKeyEncrypt: async function(algo, publicParams, data, fingerprint) {
    // TODO change algo to return enums
    const types = this.getEncSessionKeyParamTypes(algo);
    return (async function() {
      switch (algo) {
        case 'rsa_encrypt':
        case 'rsa_encrypt_sign': {
          const n = publicParams[0].toUint8Array();
          const e = publicParams[1].toUint8Array();
          const m = data.toUint8Array();
          return constructParams(types, [new BN(RSA_RAW.encrypt(m, [n, e]))]);
        }
        case 'elgamal': {
          const elgamal = new publicKey.elgamal();
          const p = publicParams[0].toBigInteger();
          const g = publicParams[1].toBigInteger();
          const y = publicParams[2].toBigInteger();
          const m = data.toBigInteger();
          return constructParams(types, elgamal.encrypt(m, g, p, y));
        }
        case 'ecdh': {
          const oid = publicParams[0];
          const kdf_params = publicParams[2];
          const Q = publicParams[1].toUint8Array();
          const res = await publicKey.elliptic.ecdh.encrypt(
            oid, kdf_params.cipher, kdf_params.hash, data, Q, fingerprint);
          return constructParams(types, [res.V, res.C]);
        }
        default:
          return [];
      }
    }());
  },

  /**
   * Decrypts data using the specified public key multiprecision integers of the private key,
   * the specified secretMPIs of the private key and the specified algorithm.
   * @param {module:enums.publicKey} algo Algorithm to be used (See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1})
   * @param {Array<module:type/mpi|module:type/oid|module:type/kdf_params>} keyIntegers Algorithm dependent params
   * @param {Array<module:type/mpi|module:type/ecdh_symkey>} dataIntegers encrypted session key parameters
   * @param {String} fingerprint Recipient fingerprint
   * @return {module:type/mpi} returns a big integer containing the decrypted data; otherwise null
   */
  publicKeyDecrypt: async function(algo, keyIntegers, dataIntegers, fingerprint) {
    // TODO change algo to return enums
    return new type_mpi(await (async function() {
      switch (algo) {
        case 'rsa_encrypt_sign':
        case 'rsa_encrypt': {
          const c = dataIntegers[0].toUint8Array();
          const n = keyIntegers[0].toUint8Array(); // pq
          const e = keyIntegers[1].toUint8Array();
          const d = keyIntegers[2].toUint8Array(); // de = 1 mod (p-1)(q-1)
          const p = keyIntegers[3].toUint8Array();
          const q = keyIntegers[4].toUint8Array();
          const u = keyIntegers[5].toUint8Array(); // q^-1 mod p
          const dd = new BN(d);
          const dp = dd.mod(new BN(p).subn(1)).toArrayLike(Uint8Array); // d mod (p-1)
          const dq = dd.mod(new BN(q).subn(1)).toArrayLike(Uint8Array); // d mod (q-1)
          return new BN(RSA_RAW.decrypt(c, [n, e, d, q, p, dq, dp, u]).slice(1)); // FIXME remove slice
        }
        case 'elgamal': {
          const elgamal = new publicKey.elgamal();
          const x = keyIntegers[3].toBigInteger();
          const c1 = dataIntegers[0].toBigInteger();
          const c2 = dataIntegers[1].toBigInteger();
          const p = keyIntegers[0].toBigInteger();
          return elgamal.decrypt(c1, c2, p, x);
        }
        case 'ecdh': {
          const oid = keyIntegers[0];
          const kdf_params = keyIntegers[2];
          const V = dataIntegers[0].toUint8Array();
          const C = dataIntegers[1].data;
          const d = keyIntegers[3].toUint8Array();
          return publicKey.elliptic.ecdh.decrypt(
            oid, kdf_params.cipher, kdf_params.hash, V, C, d, fingerprint);
        }
        default:
          return null;
      }
    }()));
  },

  /** Returns the types comprising the private key of an algorithm
   * @param {String} algo The public key algorithm
   * @return {Array<String>} The array of types
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
        return [type_mpi, type_mpi, type_mpi, type_mpi];
      case 'elgamal':
        // Algorithm-Specific Fields for Elgamal secret keys:
        //   - MPI of Elgamal secret exponent x.
        return [type_mpi];
      case 'dsa':
        // Algorithm-Specific Fields for DSA secret keys:
        //   - MPI of DSA secret exponent x.
        return [type_mpi];
      case 'ecdh':
      case 'ecdsa':
      case 'eddsa':
        // Algorithm-Specific Fields for ECDSA or ECDH secret keys:
        //   - MPI of an integer representing the secret key.
        return [type_mpi];
      default:
        throw new Error('Unknown algorithm');
    }
  },

  /** Returns the types comprising the public key of an algorithm
   * @param {String} algo The public key algorithm
   * @return {Array<String>} The array of types
   */
  getPubKeyParamTypes: function(algo) {
    //   Algorithm-Specific Fields for RSA public keys:
    //       - a multiprecision integer (MPI) of RSA public modulus n;
    //       - an MPI of RSA public encryption exponent e.
    switch (algo) {
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
      case 'rsa_sign':
        return [type_mpi, type_mpi];
        //   Algorithm-Specific Fields for Elgamal public keys:
        //     - MPI of Elgamal prime p;
        //     - MPI of Elgamal group generator g;
        //     - MPI of Elgamal public key value y (= g**x mod p where x  is secret).
      case 'elgamal':
        return [type_mpi, type_mpi, type_mpi];
        //   Algorithm-Specific Fields for DSA public keys:
        //       - MPI of DSA prime p;
        //       - MPI of DSA group order q (q is a prime divisor of p-1);
        //       - MPI of DSA group generator g;
        //       - MPI of DSA public-key value y (= g**x mod p where x  is secret).
      case 'dsa':
        return [type_mpi, type_mpi, type_mpi, type_mpi];
        //   Algorithm-Specific Fields for ECDSA/EdDSA public keys:
        //       - OID of curve;
        //       - MPI of EC point representing public key.
      case 'ecdsa':
      case 'eddsa':
        return [type_oid, type_mpi];
        //   Algorithm-Specific Fields for ECDH public keys:
        //       - OID of curve;
        //       - MPI of EC point representing public key.
        //       - KDF: variable-length field containing KDF parameters.
      case 'ecdh':
        return [type_oid, type_mpi, type_kdf_params];
      default:
        throw new Error('Unknown algorithm.');
    }
  },

  /** Returns the types comprising the encrypted session key of an algorithm
   * @param {String} algo The public key algorithm
   * @return {Array<String>} The array of types
   */
  getEncSessionKeyParamTypes: function(algo) {
    switch (algo) {
      //    Algorithm-Specific Fields for RSA encrypted session keys:
      //        - MPI of RSA encrypted value m**e mod n.
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
        return [type_mpi];

      //    Algorithm-Specific Fields for Elgamal encrypted session keys:
      //        - MPI of Elgamal value g**k mod p
      //        - MPI of Elgamal value m * y**k mod p
      case 'elgamal':
        return [type_mpi, type_mpi];

      //    Algorithm-Specific Fields for ECDH encrypted session keys:
      //        - MPI containing the ephemeral key used to establish the shared secret
      //        - ECDH Symmetric Key
      case 'ecdh':
        return [type_mpi, type_ecdh_symkey];

      default:
        throw new Error('Unknown algorithm.');
    }
  },

  /** Generate algorithm-specific key parameters
   * @param {String}          algo The public key algorithm
   * @param {Integer}         bits Bit length for RSA keys
   * @param {module:type/oid} oid  Object identifier for ECC keys
   * @return {Array}               The array of parameters
   */
  generateParams: function(algo, bits, oid) {
    const types = this.getPubKeyParamTypes(algo).concat(this.getPrivKeyParamTypes(algo));
    switch (algo) {
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
      case 'rsa_sign': {
        const rsa = new publicKey.rsa();
        return rsa.generate(bits, "10001").then(function(keyObject) {
          return constructParams(
            types, [keyObject.n, keyObject.ee, keyObject.d, keyObject.p, keyObject.q, keyObject.u]
          );
        });
      }
      case 'ecdsa':
      case 'eddsa':
        return publicKey.elliptic.generate(oid).then(function (keyObject) {
          return constructParams(types, [keyObject.oid, keyObject.Q, keyObject.d]);
        });
      case 'ecdh':
        return publicKey.elliptic.generate(oid).then(function (keyObject) {
          return constructParams(types, [keyObject.oid, keyObject.Q, [keyObject.hash, keyObject.cipher], keyObject.d]);
        });
      default:
        throw new Error('Unsupported algorithm for key generation.');
    }
  },

  /**
   * generate random byte prefix as string for the specified algorithm
   * @param {module:enums.symmetric} algo Algorithm to use (see {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2})
   * @return {Uint8Array} Random bytes with length equal to the block
   * size of the cipher
   */
  getPrefixRandom: function(algo) {
    return random.getRandomBytes(cipher[algo].blockSize);
  },

  /**
   * Generating a session key for the specified symmetric algorithm
   * @param {module:enums.symmetric} algo Algorithm to use (see {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2})
   * @return {Uint8Array} Random bytes as a string to be used as a key
   */
  generateSessionKey: function(algo) {
    return random.getRandomBytes(cipher[algo].keySize);
  },

  constructParams: constructParams
};
