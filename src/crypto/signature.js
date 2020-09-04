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
   * @param {module:enums.publicKey} algo             Public key algorithm
   * @param {module:enums.hash}      hash_algo        Hash algorithm
   * @param {Array<module:type/mpi>} msg_MPIs         Algorithm-specific signature parameters
   * @param {Object}                 publicParams  Algorithm-specific public key parameters
   * @param {Uint8Array}             data             Data for which the signature was created
   * @param {Uint8Array}             hashed           The hashed data
   * @returns {Boolean}                               True if signature is valid
   * @async
   */
  verify: async function(algo, hash_algo, msg_MPIs, publicParams, data, hashed) {
    switch (algo) {
      case enums.publicKey.rsaEncryptSign:
      case enums.publicKey.rsaEncrypt:
      case enums.publicKey.rsaSign: {
        const { n, e } = publicParams;
        const m = msg_MPIs[0].toUint8Array('be', n.length);
        return publicKey.rsa.verify(hash_algo, data, m, n, e, hashed);
      }
      case enums.publicKey.dsa: {
        const r = await msg_MPIs[0].toUint8Array();
        const s = await msg_MPIs[1].toUint8Array();
        const { g, p, q, y } = publicParams;
        return publicKey.dsa.verify(hash_algo, r, s, hashed, g, p, q, y);
      }
      case enums.publicKey.ecdsa: {
        const { oid, Q } = publicParams;
        const signature = { r: msg_MPIs[0].toUint8Array(), s: msg_MPIs[1].toUint8Array() };
        return publicKey.elliptic.ecdsa.verify(oid, hash_algo, signature, data, Q, hashed);
      }
      case enums.publicKey.eddsa: {
        const { oid, Q } = publicParams;
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
   * @param {module:enums.publicKey} algo             Public key algorithm
   * @param {module:enums.hash}      hash_algo        Hash algorithm
   * @param {Object}                 publicKeyParams  Algorithm-specific public and private key parameters
   * @param {Object}                 privateKeyParams Algorithm-specific public and private key parameters
   * @param {Uint8Array}             data             Data to be signed
   * @param {Uint8Array}             hashed           The hashed data
   * @returns {Uint8Array} Signature
   * @async
   */
  sign: async function(algo, hash_algo, publicKeyParams, privateKeyParams, data, hashed) {
    if (!publicKeyParams || !privateKeyParams) {
      throw new Error('Missing key parameters');
    }
    switch (algo) {
      case enums.publicKey.rsaEncryptSign:
      case enums.publicKey.rsaEncrypt:
      case enums.publicKey.rsaSign: {
        const { n, e } = publicKeyParams;
        const { d, p, q, u } = privateKeyParams;
        const signature = await publicKey.rsa.sign(hash_algo, data, n, e, d, p, q, u, hashed);
        return util.uint8ArrayToMpi(signature);
      }
      case enums.publicKey.dsa: {
        const { g, p, q } = publicKeyParams;
        const { x } = privateKeyParams;
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
        const { oid, Q } = publicKeyParams;
        const { d } = privateKeyParams;
        const signature = await publicKey.elliptic.ecdsa.sign(oid, hash_algo, data, Q, d, hashed);
        return util.concatUint8Array([
          util.uint8ArrayToMpi(signature.r),
          util.uint8ArrayToMpi(signature.s)
        ]);
      }
      case enums.publicKey.eddsa: {
        const { oid, Q } = publicKeyParams;
        const { seed } = privateKeyParams;
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
