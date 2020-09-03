/**
 * @fileoverview Provides functions for asymmetric signing and signature verification
 * @requires crypto/crypto
 * @requires crypto/public_key
 * @requires enums
 * @requires util
 * @module crypto/signature
*/

import crypto from './crypto';
import publicKey from './public_key';
import enums from '../enums';
import util from '../util';

export default {
  /**
   * Verifies the signature provided for data using specified algorithms and public key parameters.
   * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1}
   * and {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4}
   * for public key and hash algorithms.
   * @param {module:enums.publicKey} algo      Public key algorithm
   * @param {module:enums.hash}      hash_algo Hash algorithm
   * @param {Array<module:type/mpi>} msg_MPIs  Algorithm-specific signature parameters
   * @param {Array<module:type/mpi>} pub_MPIs  Algorithm-specific public key parameters
   * @param {Uint8Array}             data      Data for which the signature was created
   * @param {Uint8Array}             hashed    The hashed data
   * @returns {Boolean}                        True if signature is valid
   * @async
   */
  verify: async function(algo, hash_algo, msg_MPIs, pub_MPIs, data, hashed) {
    const types = crypto.getPubKeyParamTypes(algo);
    if (pub_MPIs.length < types.length) {
      throw new Error('Missing public key parameters');
    }
    switch (algo) {
      case enums.publicKey.rsaEncryptSign:
      case enums.publicKey.rsaEncrypt:
      case enums.publicKey.rsaSign: {
        const n = pub_MPIs[0].toUint8Array();
        const e = pub_MPIs[1].toUint8Array();
        const m = msg_MPIs[0].toUint8Array('be', n.length);
        return publicKey.rsa.verify(hash_algo, data, m, n, e, hashed);
      }
      case enums.publicKey.dsa: {
        const r = await msg_MPIs[0].toBigInteger();
        const s = await msg_MPIs[1].toBigInteger();
        const p = await pub_MPIs[0].toBigInteger();
        const q = await pub_MPIs[1].toBigInteger();
        const g = await pub_MPIs[2].toBigInteger();
        const y = await pub_MPIs[3].toBigInteger();
        return publicKey.dsa.verify(hash_algo, r, s, hashed, g, p, q, y);
      }
      case enums.publicKey.ecdsa: {
        const { oid, Q } = publicKey.elliptic.ecdsa.parseParams(pub_MPIs);
        const signature = { r: msg_MPIs[0].toUint8Array(), s: msg_MPIs[1].toUint8Array() };
        return publicKey.elliptic.ecdsa.verify(oid, hash_algo, signature, data, Q, hashed);
      }
      case enums.publicKey.eddsa: {
        const { oid, Q } = publicKey.elliptic.eddsa.parseParams(pub_MPIs);
        // EdDSA signature params are expected in little-endian format
        const signature = {
          R: msg_MPIs[0].toUint8Array('le', 32),
          S: msg_MPIs[1].toUint8Array('le', 32)
        };
        return publicKey.elliptic.eddsa.verify(oid, hash_algo, signature, data, Q, hashed);
      }
      default:
        throw new Error('Invalid signature algorithm.');
    }
  },

  /**
   * Creates a signature on data using specified algorithms and private key parameters.
   * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1}
   * and {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4}
   * for public key and hash algorithms.
   * @param {module:enums.publicKey} algo       Public key algorithm
   * @param {module:enums.hash}      hash_algo  Hash algorithm
   * @param {Array<module:type/mpi>} key_params Algorithm-specific public and private key parameters
   * @param {Uint8Array}             data       Data to be signed
   * @param {Uint8Array}             hashed     The hashed data
   * @returns {Uint8Array}                      Signature
   * @async
   */
  sign: async function(algo, hash_algo, key_params, data, hashed) {
    const types = [].concat(crypto.getPubKeyParamTypes(algo), crypto.getPrivKeyParamTypes(algo));
    if (key_params.length < types.length) {
      throw new Error('Missing private key parameters');
    }
    switch (algo) {
      case enums.publicKey.rsaEncryptSign:
      case enums.publicKey.rsaEncrypt:
      case enums.publicKey.rsaSign: {
        const n = key_params[0].toUint8Array();
        const e = key_params[1].toUint8Array();
        const d = key_params[2].toUint8Array();
        const p = key_params[3].toUint8Array();
        const q = key_params[4].toUint8Array();
        const u = key_params[5].toUint8Array();
        const signature = await publicKey.rsa.sign(hash_algo, data, n, e, d, p, q, u, hashed);
        return util.uint8ArrayToMpi(signature);
      }
      case enums.publicKey.dsa: {
        const p = await key_params[0].toBigInteger();
        const q = await key_params[1].toBigInteger();
        const g = await key_params[2].toBigInteger();
        const x = await key_params[4].toBigInteger();
        const signature = await publicKey.dsa.sign(hash_algo, hashed, g, p, q, x);
        return util.concatUint8Array([
          util.uint8ArrayToMpi(signature.r),
          util.uint8ArrayToMpi(signature.s)
        ]);
      }
      case enums.publicKey.elgamal: {
        throw new Error('Signing with Elgamal is not defined in the OpenPGP standard.');
      }
      case enums.publicKey.ecdsa: {
        const { oid, Q, d } = publicKey.elliptic.ecdsa.parseParams(key_params);
        const signature = await publicKey.elliptic.ecdsa.sign(oid, hash_algo, data, Q, d, hashed);
        return util.concatUint8Array([
          util.uint8ArrayToMpi(signature.r),
          util.uint8ArrayToMpi(signature.s)
        ]);
      }
      case enums.publicKey.eddsa: {
        const { oid, Q, seed } = publicKey.elliptic.eddsa.parseParams(key_params);
        const signature = await publicKey.elliptic.eddsa.sign(oid, hash_algo, data, Q, seed, hashed);
        return util.concatUint8Array([
          util.uint8ArrayToMpi(signature.R),
          util.uint8ArrayToMpi(signature.S)
        ]);
      }
      default:
        throw new Error('Invalid signature algorithm.');
    }
  }
};
