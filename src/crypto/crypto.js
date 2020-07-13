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
 * @fileoverview Provides functions for asymmetric encryption and decryption as
 * well as key generation and parameter handling for all public-key cryptosystems.
 * @requires crypto/public_key
 * @requires crypto/cipher
 * @requires crypto/random
 * @requires type/ecdh_symkey
 * @requires type/kdf_params
 * @requires type/mpi
 * @requires type/oid
 * @requires enums
 * @requires util
 * @module crypto/crypto
 */

import publicKey from './public_key';
import cipher from './cipher';
import random from './random';
import type_ecdh_symkey from '../type/ecdh_symkey';
import type_kdf_params from '../type/kdf_params';
import type_mpi from '../type/mpi';
import type_oid from '../type/oid';
import enums from '../enums';
import util from '../util';
import pkcs1 from './pkcs1';
import pkcs5 from './pkcs5';

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
   * Encrypts data using specified algorithm and public key parameters.
   * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1} for public key algorithms.
   * @param {module:enums.publicKey}        algo        Public key algorithm
   * @param {Array<module:type/mpi|
                   module:type/oid|
                   module:type/kdf_params>} pub_params  Algorithm-specific public key parameters
   * @param {String}                        data        Data to be encrypted
   * @param {String}                        fingerprint Recipient fingerprint
   * @returns {Array<module:type/mpi|
   *                 module:type/ecdh_symkey>}          encrypted session key parameters
   * @async
   */
  publicKeyEncrypt: async function(algo, pub_params, data, fingerprint) {
    const types = this.getEncSessionKeyParamTypes(algo);
    switch (algo) {
      case enums.publicKey.rsa_encrypt:
      case enums.publicKey.rsa_encrypt_sign: {
        data = util.str_to_Uint8Array(data);
        const n = pub_params[0].toUint8Array();
        const e = pub_params[1].toUint8Array();
        const res = await publicKey.rsa.encrypt(data, n, e);
        return constructParams(types, [res]);
      }
      case enums.publicKey.elgamal: {
        data = new type_mpi(await pkcs1.eme.encode(data, pub_params[0].byteLength()));
        const m = data.toBN();
        const p = pub_params[0].toBN();
        const g = pub_params[1].toBN();
        const y = pub_params[2].toBN();
        const res = await publicKey.elgamal.encrypt(m, p, g, y);
        return constructParams(types, [res.c1, res.c2]);
      }
      case enums.publicKey.ecdh: {
        data = new type_mpi(pkcs5.encode(data));
        const oid = pub_params[0];
        const Q = pub_params[1].toUint8Array();
        const kdfParams = pub_params[2];
        const { publicKey: V, wrappedKey: C } = await publicKey.elliptic.ecdh.encrypt(
          oid, kdfParams, data, Q, fingerprint);
        return constructParams(types, [V, C]);
      }
      default:
        return [];
    }
  },

  /**
   * Decrypts data using specified algorithm and private key parameters.
   * See {@link https://tools.ietf.org/html/rfc4880#section-5.5.3|RFC 4880 5.5.3}
   * @param {module:enums.publicKey}        algo        Public key algorithm
   * @param {Array<module:type/mpi|
                   module:type/oid|
                   module:type/kdf_params>} key_params  Algorithm-specific public, private key parameters
   * @param {Array<module:type/mpi|
                   module:type/ecdh_symkey>}
                                            data_params encrypted session key parameters
   * @param {String}                        fingerprint Recipient fingerprint
   * @returns {String}                          String containing the decrypted data
   * @async
   */
  publicKeyDecrypt: async function(algo, key_params, data_params, fingerprint) {
    switch (algo) {
      case enums.publicKey.rsa_encrypt_sign:
      case enums.publicKey.rsa_encrypt: {
        const c = data_params[0].toUint8Array();
        const n = key_params[0].toUint8Array(); // n = pq
        const e = key_params[1].toUint8Array();
        const d = key_params[2].toUint8Array(); // de = 1 mod (p-1)(q-1)
        const p = key_params[3].toUint8Array();
        const q = key_params[4].toUint8Array();
        const u = key_params[5].toUint8Array(); // p^-1 mod q
        return publicKey.rsa.decrypt(c, n, e, d, p, q, u);
      }
      case enums.publicKey.elgamal: {
        const c1 = data_params[0].toBN();
        const c2 = data_params[1].toBN();
        const p = key_params[0].toBN();
        const x = key_params[3].toBN();
        const result = new type_mpi(await publicKey.elgamal.decrypt(c1, c2, p, x));
        return pkcs1.eme.decode(result.toString());
      }
      case enums.publicKey.ecdh: {
        const oid = key_params[0];
        const kdfParams = key_params[2];
        const V = data_params[0].toUint8Array();
        const C = data_params[1].data;
        const Q = key_params[1].toUint8Array();
        const d = key_params[3].toUint8Array();
        const result = new type_mpi(await publicKey.elliptic.ecdh.decrypt(
          oid, kdfParams, V, C, Q, d, fingerprint));
        return pkcs5.decode(result.toString());
      }
      default:
        throw new Error('Invalid public key encryption algorithm.');
    }
  },

  /** Returns the types comprising the private key of an algorithm
   * @param {module:enums.publicKey}  algo The public key algorithm
   * @returns {Array<String>}         The array of types
   */
  getPrivKeyParamTypes: function(algo) {
    switch (algo) {
      //   Algorithm-Specific Fields for RSA secret keys:
      //       - multiprecision integer (MPI) of RSA secret exponent d.
      //       - MPI of RSA secret prime value p.
      //       - MPI of RSA secret prime value q (p < q).
      //       - MPI of u, the multiplicative inverse of p, mod q.
      case enums.publicKey.rsa_encrypt:
      case enums.publicKey.rsa_encrypt_sign:
      case enums.publicKey.rsa_sign:
        return [type_mpi, type_mpi, type_mpi, type_mpi];
      //   Algorithm-Specific Fields for Elgamal secret keys:
      //        - MPI of Elgamal secret exponent x.
      case enums.publicKey.elgamal:
        return [type_mpi];
      //   Algorithm-Specific Fields for DSA secret keys:
      //      - MPI of DSA secret exponent x.
      case enums.publicKey.dsa:
        return [type_mpi];
      //   Algorithm-Specific Fields for ECDSA or ECDH secret keys:
      //       - MPI of an integer representing the secret key.
      case enums.publicKey.ecdh:
      case enums.publicKey.ecdsa:
      case enums.publicKey.eddsa:
        return [type_mpi];
      default:
        throw new Error('Invalid public key encryption algorithm.');
    }
  },

  /** Returns the types comprising the public key of an algorithm
   * @param {module:enums.publicKey}  algo The public key algorithm
   * @returns {Array<String>}         The array of types
   */
  getPubKeyParamTypes: function(algo) {
    switch (algo) {
      //   Algorithm-Specific Fields for RSA public keys:
      //       - a multiprecision integer (MPI) of RSA public modulus n;
      //       - an MPI of RSA public encryption exponent e.
      case enums.publicKey.rsa_encrypt:
      case enums.publicKey.rsa_encrypt_sign:
      case enums.publicKey.rsa_sign:
        return [type_mpi, type_mpi];
      //   Algorithm-Specific Fields for Elgamal public keys:
      //       - MPI of Elgamal prime p;
      //       - MPI of Elgamal group generator g;
      //       - MPI of Elgamal public key value y (= g**x mod p where x  is secret).
      case enums.publicKey.elgamal:
        return [type_mpi, type_mpi, type_mpi];
      //   Algorithm-Specific Fields for DSA public keys:
      //       - MPI of DSA prime p;
      //       - MPI of DSA group order q (q is a prime divisor of p-1);
      //       - MPI of DSA group generator g;
      //       - MPI of DSA public-key value y (= g**x mod p where x  is secret).
      case enums.publicKey.dsa:
        return [type_mpi, type_mpi, type_mpi, type_mpi];
      //   Algorithm-Specific Fields for ECDSA/EdDSA public keys:
      //       - OID of curve;
      //       - MPI of EC point representing public key.
      case enums.publicKey.ecdsa:
      case enums.publicKey.eddsa:
        return [type_oid, type_mpi];
      //   Algorithm-Specific Fields for ECDH public keys:
      //       - OID of curve;
      //       - MPI of EC point representing public key.
      //       - KDF: variable-length field containing KDF parameters.
      case enums.publicKey.ecdh:
        return [type_oid, type_mpi, type_kdf_params];
      default:
        throw new Error('Invalid public key encryption algorithm.');
    }
  },

  /** Returns the types comprising the encrypted session key of an algorithm
   * @param {module:enums.publicKey}  algo The public key algorithm
   * @returns {Array<String>}         The array of types
   */
  getEncSessionKeyParamTypes: function(algo) {
    switch (algo) {
      //   Algorithm-Specific Fields for RSA encrypted session keys:
      //       - MPI of RSA encrypted value m**e mod n.
      case enums.publicKey.rsa_encrypt:
      case enums.publicKey.rsa_encrypt_sign:
        return [type_mpi];

      //   Algorithm-Specific Fields for Elgamal encrypted session keys:
      //       - MPI of Elgamal value g**k mod p
      //       - MPI of Elgamal value m * y**k mod p
      case enums.publicKey.elgamal:
        return [type_mpi, type_mpi];
      //   Algorithm-Specific Fields for ECDH encrypted session keys:
      //       - MPI containing the ephemeral key used to establish the shared secret
      //       - ECDH Symmetric Key
      case enums.publicKey.ecdh:
        return [type_mpi, type_ecdh_symkey];
      default:
        throw new Error('Invalid public key encryption algorithm.');
    }
  },

  /** Generate algorithm-specific key parameters
   * @param {module:enums.publicKey}  algo The public key algorithm
   * @param {Integer}                 bits Bit length for RSA keys
   * @param {module:type/oid}         oid  Object identifier for ECC keys
   * @returns {Array}                 The array of parameters
   * @async
   */
  generateParams: function(algo, bits, oid) {
    const types = [].concat(this.getPubKeyParamTypes(algo), this.getPrivKeyParamTypes(algo));
    switch (algo) {
      case enums.publicKey.rsa_encrypt:
      case enums.publicKey.rsa_encrypt_sign:
      case enums.publicKey.rsa_sign: {
        return publicKey.rsa.generate(bits, "10001").then(function(keyObject) {
          return constructParams(
            types, [keyObject.n, keyObject.e, keyObject.d, keyObject.p, keyObject.q, keyObject.u]
          );
        });
      }
      case enums.publicKey.dsa:
      case enums.publicKey.elgamal:
        throw new Error('Unsupported algorithm for key generation.');
      case enums.publicKey.ecdsa:
      case enums.publicKey.eddsa:
        return publicKey.elliptic.generate(oid).then(function (keyObject) {
          return constructParams(types, [keyObject.oid, keyObject.Q, keyObject.d]);
        });
      case enums.publicKey.ecdh:
        return publicKey.elliptic.generate(oid).then(function (keyObject) {
          return constructParams(types, [
            keyObject.oid,
            keyObject.Q,
            { hash: keyObject.hash, cipher: keyObject.cipher },
            keyObject.d
          ]);
        });
      default:
        throw new Error('Invalid public key algorithm.');
    }
  },

  /**
   * Validate algorithm-specific key parameters
   * @param {module:enums.publicKey}  algo The public key algorithm
   * @param {Array}                   params The array of parameters
   * @returns {Promise<Boolean>       whether the parameters are valid
   * @async
   */
  validateParams: async function(algo, params) {
    switch (algo) {
      case enums.publicKey.rsa_encrypt:
      case enums.publicKey.rsa_encrypt_sign:
      case enums.publicKey.rsa_sign: {
        if (params.length < 6) {
          throw new Error('Missing key parameters');
        }
        const n = params[0].toUint8Array();
        const e = params[1].toUint8Array();
        const d = params[2].toUint8Array();
        const p = params[3].toUint8Array();
        const q = params[4].toUint8Array();
        const u = params[5].toUint8Array();
        return publicKey.rsa.validateParams(n, e, d, p, q, u);
      }
      case enums.publicKey.dsa: {
        if (params.length < 5) {
          throw new Error('Missing key parameters');
        }
        const p = params[0].toUint8Array();
        const q = params[1].toUint8Array();
        const g = params[2].toUint8Array();
        const y = params[3].toUint8Array();
        const x = params[4].toUint8Array();
        return publicKey.dsa.validateParams(p, q, g, y, x);
      }
      case enums.publicKey.elgamal: {
        if (params.length < 4) {
          throw new Error('Missing key parameters');
        }
        const p = params[0].toUint8Array();
        const g = params[1].toUint8Array();
        const y = params[2].toUint8Array();
        const x = params[3].toUint8Array();
        return publicKey.elgamal.validateParams(p, g, y, x);
      }
      case enums.publicKey.ecdsa:
      case enums.publicKey.ecdh: {
        const expectedLen = algo === enums.publicKey.ecdh ? 3 : 2;
        if (params.length < expectedLen) {
          throw new Error('Missing key parameters');
        }

        const algoModule = publicKey.elliptic[enums.read(enums.publicKey, algo)];
        const { oid, Q, d } = algoModule.parseParams(params);
        return algoModule.validateParams(oid, Q, d);
      }
      case enums.publicKey.eddsa: {
        const expectedLen = 3;
        if (params.length < expectedLen) {
          throw new Error('Missing key parameters');
        }

        const { oid, Q, seed } = publicKey.elliptic.eddsa.parseParams(params);
        return publicKey.elliptic.eddsa.validateParams(oid, Q, seed);
      }
      default:
        throw new Error('Invalid public key algorithm.');
    }
  },

  /**
   * Generates a random byte prefix for the specified algorithm
   * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
   * @param {module:enums.symmetric} algo Symmetric encryption algorithm
   * @returns {Uint8Array}                Random bytes with length equal to the block size of the cipher, plus the last two bytes repeated.
   * @async
   */
  getPrefixRandom: async function(algo) {
    const prefixrandom = await random.getRandomBytes(cipher[algo].blockSize);
    const repeat = new Uint8Array([prefixrandom[prefixrandom.length - 2], prefixrandom[prefixrandom.length - 1]]);
    return util.concat([prefixrandom, repeat]);
  },

  /**
   * Generating a session key for the specified symmetric algorithm
   * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
   * @param {module:enums.symmetric} algo Symmetric encryption algorithm
   * @returns {Uint8Array}                Random bytes as a string to be used as a key
   * @async
   */
  generateSessionKey: function(algo) {
    return random.getRandomBytes(cipher[algo].keySize);
  },

  constructParams: constructParams
};
