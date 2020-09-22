/**
 * @fileoverview Provides functions for asymmetric signing and signature verification
 * @requires crypto/public_key
 * @requires enums
 * @requires util
 * @module crypto/signature
*/

import publicKey from './public_key';
import enums from '../enums';
import util from '../util';


/**
 * Parse signature in binary form to get the parameters.
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1}
 * See {@link https://tools.ietf.org/html/rfc4880#section-5.2.2|RFC 4880 5.2.2.}
 * @param {module:enums.publicKey} algo       Public key algorithm
 * @param {Uint8Array}             signature  Data for which the signature was created
 * @returns {Object}                          True if signature is valid
 * @async
 */
export function parseSignatureParams(algo, signature) {
  let read = 0;
  switch (algo) {
    // Algorithm-Specific Fields for RSA signatures:
    // -  MPI of RSA signature value m**d mod n.
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaSign: {
      const s = util.readMPI(signature.subarray(read));
      return { s };
    }
    // Algorithm-Specific Fields for DSA or ECDSA signatures:
    // -  MPI of DSA or ECDSA value r.
    // -  MPI of DSA or ECDSA value s.
    case enums.publicKey.dsa:
    case enums.publicKey.ecdsa:
    {
      const r = util.readMPI(signature.subarray(read)); read += r.length + 2;
      const s = util.readMPI(signature.subarray(read));
      return { r, s };
    }
    // Algorithm-Specific Fields for EdDSA signatures:
    // -  MPI of an EC point r.
    // -  EdDSA value s, in MPI, in the little endian representation.
    // EdDSA signature parameters are encoded in little-endian format
    // https://tools.ietf.org/html/rfc8032#section-5.1.2
    case enums.publicKey.eddsa: {
      const r = util.padToLength(util.readMPI(signature.subarray(read)), 32, 'le'); read += r.length + 2;
      const s = util.padToLength(util.readMPI(signature.subarray(read)), 32, 'le');
      return { r, s };
    }
    default:
      throw new Error('Invalid signature algorithm.');
  }
}

/**
 * Verifies the signature provided for data using specified algorithms and public key parameters.
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1}
 * and {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4}
 * for public key and hash algorithms.
 * @param {module:enums.publicKey}  algo          Public key algorithm
 * @param {module:enums.hash}       hashAlgo      Hash algorithm
 * @param {Object}                  signature     Named algorithm-specific signature parameters
 * @param {Object}                  publicParams  Algorithm-specific public key parameters
 * @param {Uint8Array}              data          Data for which the signature was created
 * @param {Uint8Array}              hashed        The hashed data
 * @returns {Boolean}                             True if signature is valid
 * @async
 */
export async function verify(algo, hashAlgo, signature, publicParams, data, hashed) {
  switch (algo) {
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaSign: {
      const { n, e } = publicParams;
      const { s } = signature;
      return publicKey.rsa.verify(hashAlgo, data, s, n, e, hashed);
    }
    case enums.publicKey.dsa: {
      const { g, p, q, y } = publicParams;
      const { r, s } = signature;
      return publicKey.dsa.verify(hashAlgo, r, s, hashed, g, p, q, y);
    }
    case enums.publicKey.ecdsa: {
      const { oid, Q } = publicParams;
      return publicKey.elliptic.ecdsa.verify(oid, hashAlgo, signature, data, Q, hashed);
    }
    case enums.publicKey.eddsa: {
      const { oid, Q } = publicParams;
      return publicKey.elliptic.eddsa.verify(oid, hashAlgo, signature, data, Q, hashed);
    }
    default:
      throw new Error('Invalid signature algorithm.');
  }
}

/**
 * Creates a signature on data using specified algorithms and private key parameters.
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1}
 * and {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4}
 * for public key and hash algorithms.
 * @param {module:enums.publicKey} algo             Public key algorithm
 * @param {module:enums.hash}      hashAlgo         Hash algorithm
 * @param {Object}                 publicKeyParams  Algorithm-specific public and private key parameters
 * @param {Object}                 privateKeyParams Algorithm-specific public and private key parameters
 * @param {Uint8Array}             data             Data to be signed
 * @param {Uint8Array}             hashed           The hashed data
 * @returns {Object} Signature                      Object containing named signature parameters
 * @async
 */
export async function sign(algo, hashAlgo, publicKeyParams, privateKeyParams, data, hashed) {
  if (!publicKeyParams || !privateKeyParams) {
    throw new Error('Missing key parameters');
  }
  switch (algo) {
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaSign: {
      const { n, e } = publicKeyParams;
      const { d, p, q, u } = privateKeyParams;
      const s = await publicKey.rsa.sign(hashAlgo, data, n, e, d, p, q, u, hashed);
      return { s };
    }
    case enums.publicKey.dsa: {
      const { g, p, q } = publicKeyParams;
      const { x } = privateKeyParams;
      return publicKey.dsa.sign(hashAlgo, hashed, g, p, q, x);
    }
    case enums.publicKey.elgamal: {
      throw new Error('Signing with Elgamal is not defined in the OpenPGP standard.');
    }
    case enums.publicKey.ecdsa: {
      const { oid, Q } = publicKeyParams;
      const { d } = privateKeyParams;
      return publicKey.elliptic.ecdsa.sign(oid, hashAlgo, data, Q, d, hashed);
    }
    case enums.publicKey.eddsa: {
      const { oid, Q } = publicKeyParams;
      const { seed } = privateKeyParams;
      return publicKey.elliptic.eddsa.sign(oid, hashAlgo, data, Q, seed, hashed);
    }
    default:
      throw new Error('Invalid signature algorithm.');
  }
}
