/**
 * @fileoverview Provides functions for asymmetric signing and signature verification
 * @module crypto/signature
 * @private
 */

import publicKey from './public_key';
import enums from '../enums';
import util from '../util';
import { UnsupportedError } from '../packet/packet';

/**
 * Parse signature in binary form to get the parameters.
 * The returned values are only padded for EdDSA, since in the other cases their expected length
 * depends on the key params, hence we delegate the padding to the signature verification function.
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1}
 * See {@link https://tools.ietf.org/html/rfc4880#section-5.2.2|RFC 4880 5.2.2.}
 * @param {module:enums.publicKey} algo - Public key algorithm
 * @param {Uint8Array} signature - Data for which the signature was created
 * @returns {Promise<Object>} True if signature is valid.
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
      // The signature needs to be the same length as the public key modulo n.
      // We pad s on signature verification, where we have access to n.
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
    // Algorithm-Specific Fields for legacy EdDSA signatures:
    // -  MPI of an EC point r.
    // -  EdDSA value s, in MPI, in the little endian representation
    case enums.publicKey.eddsa:
    case enums.publicKey.ed25519Legacy: {
      // When parsing little-endian MPI data, we always need to left-pad it, as done with big-endian values:
      // https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#section-3.2-9
      let r = util.readMPI(signature.subarray(read)); read += r.length + 2;
      r = util.leftPad(r, 32);
      let s = util.readMPI(signature.subarray(read));
      s = util.leftPad(s, 32);
      return { r, s };
    }
    // Algorithm-Specific Fields for Ed25519 signatures:
    // - 64 octets of the native signature
    case enums.publicKey.ed25519: {
      const RS = signature.subarray(read, read + 64); read += RS.length;
      return { RS };
    }
    default:
      throw new UnsupportedError('Unknown signature algorithm.');
  }
}

/**
 * Verifies the signature provided for data using specified algorithms and public key parameters.
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1}
 * and {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4}
 * for public key and hash algorithms.
 * @param {module:enums.publicKey} algo - Public key algorithm
 * @param {module:enums.hash} hashAlgo - Hash algorithm
 * @param {Object} signature - Named algorithm-specific signature parameters
 * @param {Object} publicParams - Algorithm-specific public key parameters
 * @param {Uint8Array} data - Data for which the signature was created
 * @param {Uint8Array} hashed - The hashed data
 * @returns {Promise<Boolean>} True if signature is valid.
 * @async
 */
export async function verify(algo, hashAlgo, signature, publicParams, data, hashed) {
  switch (algo) {
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaSign: {
      const { n, e } = publicParams;
      const s = util.leftPad(signature.s, n.length); // padding needed for webcrypto and node crypto
      return publicKey.rsa.verify(hashAlgo, data, s, n, e, hashed);
    }
    case enums.publicKey.dsa: {
      const { g, p, q, y } = publicParams;
      const { r, s } = signature; // no need to pad, since we always handle them as BigIntegers
      return publicKey.dsa.verify(hashAlgo, r, s, hashed, g, p, q, y);
    }
    case enums.publicKey.ecdsa: {
      const { oid, Q } = publicParams;
      const curveSize = new publicKey.elliptic.CurveWithOID(oid).payloadSize;
      // padding needed for webcrypto
      const r = util.leftPad(signature.r, curveSize);
      const s = util.leftPad(signature.s, curveSize);
      return publicKey.elliptic.ecdsa.verify(oid, hashAlgo, { r, s }, data, Q, hashed);
    }
    case enums.publicKey.eddsa:
    case enums.publicKey.ed25519Legacy: {
      const { oid, Q } = publicParams;
      // signature already padded on parsing
      return publicKey.elliptic.eddsaLegacy.verify(oid, hashAlgo, signature, data, Q, hashed);
    }
    case enums.publicKey.ed25519: {
      const { A } = publicParams;
      return publicKey.elliptic.eddsa.verify(algo, hashAlgo, signature, data, A, hashed);
    }
    default:
      throw new Error('Unknown signature algorithm.');
  }
}

/**
 * Creates a signature on data using specified algorithms and private key parameters.
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1}
 * and {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4}
 * for public key and hash algorithms.
 * @param {module:enums.publicKey} algo - Public key algorithm
 * @param {module:enums.hash} hashAlgo - Hash algorithm
 * @param {Object} publicKeyParams - Algorithm-specific public and private key parameters
 * @param {Object} privateKeyParams - Algorithm-specific public and private key parameters
 * @param {Uint8Array} data - Data to be signed
 * @param {Uint8Array} hashed - The hashed data
 * @returns {Promise<Object>} Signature                      Object containing named signature parameters.
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
    case enums.publicKey.eddsa:
    case enums.publicKey.ed25519Legacy: {
      const { oid, Q } = publicKeyParams;
      const { seed } = privateKeyParams;
      return publicKey.elliptic.eddsaLegacy.sign(oid, hashAlgo, data, Q, seed, hashed);
    }
    case enums.publicKey.ed25519: {
      const { A } = publicKeyParams;
      const { seed } = privateKeyParams;
      return publicKey.elliptic.eddsa.sign(algo, hashAlgo, data, A, seed, hashed);
    }
    default:
      throw new Error('Unknown signature algorithm.');
  }
}
