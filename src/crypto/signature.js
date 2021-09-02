/**
 * @fileoverview Provides functions for asymmetric signing and signature verification
 * @module crypto/signature
 */

import publicKey from './public_key';
import enums from '../enums';
import util from '../util';
import ShortByteString from '../type/short_byte_string';
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
      const s = util.readMPI(signature.subarray(read)); read += s.length + 2;
      // The signature needs to be the same length as the public key modulo n.
      // We pad s on signature verification, where we have access to n.
      return { read, signatureParams: { s } };
    }
    // Algorithm-Specific Fields for DSA or ECDSA signatures:
    // -  MPI of DSA or ECDSA value r.
    // -  MPI of DSA or ECDSA value s.
    case enums.publicKey.dsa:
    case enums.publicKey.ecdsa:
    {
      // If the signature payload sizes are unexpected, we will throw on verification,
      // where we also have access to the OID curve from the key.
      const r = util.readMPI(signature.subarray(read)); read += r.length + 2;
      const s = util.readMPI(signature.subarray(read)); read += s.length + 2;
      return { read, signatureParams: { r, s } };
    }
    // Algorithm-Specific Fields for legacy EdDSA signatures:
    // -  MPI of an EC point r.
    // -  EdDSA value s, in MPI, in the little endian representation
    case enums.publicKey.eddsaLegacy: {
      // Only Curve25519Legacy is supported (no Curve448Legacy), but the relevant checks are done on key parsing and signature
      // verification: if the signature payload sizes are unexpected, we will throw on verification,
      // where we also have access to the OID curve from the key.
      const r = util.readMPI(signature.subarray(read)); read += r.length + 2;
      const s = util.readMPI(signature.subarray(read)); read += s.length + 2;
      return { read, signatureParams: { r, s } };
    }
    // Algorithm-Specific Fields for Ed25519 signatures:
    // - 64 octets of the native signature
    // Algorithm-Specific Fields for Ed448 signatures:
    // - 114 octets of the native signature
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448: {
      const rsSize = 2 * publicKey.elliptic.eddsa.getPayloadSize(algo);
      const RS = util.readExactSubarray(signature, read, read + rsSize); read += RS.length;
      return { read, signatureParams: { RS } };
    }
    case enums.publicKey.hmac: {
      const mac = new ShortByteString(); read += mac.read(signature.subarray(read));
      return { read, signatureParams: { mac } };
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
 * @param {Object} privateParams - Algorithm-specific private key parameters
 * @param {Uint8Array} data - Data for which the signature was created
 * @param {Uint8Array} hashed - The hashed data
 * @returns {Promise<Boolean>} True if signature is valid.
 * @async
 */
export async function verify(algo, hashAlgo, signature, publicParams, privateParams, data, hashed) {
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
    case enums.publicKey.eddsaLegacy: {
      const { oid, Q } = publicParams;
      const curveSize = new publicKey.elliptic.CurveWithOID(oid).payloadSize;
      // When dealing little-endian MPI data, we always need to left-pad it, as done with big-endian values:
      // https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#section-3.2-9
      const r = util.leftPad(signature.r, curveSize);
      const s = util.leftPad(signature.s, curveSize);
      return publicKey.elliptic.eddsaLegacy.verify(oid, hashAlgo, { r, s }, data, Q, hashed);
    }
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448: {
      const { A } = publicParams;
      return publicKey.elliptic.eddsa.verify(algo, hashAlgo, signature, data, A, hashed);
    }
    case enums.publicKey.hmac: {
      if (!privateParams) {
        throw new Error('Cannot verify HMAC signature with symmetric key missing private parameters');
      }
      const { cipher: algo } = publicParams;
      const { keyMaterial } = privateParams;
      return publicKey.hmac.verify(algo.getValue(), keyMaterial, signature.mac.data, hashed);
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
    case enums.publicKey.elgamal:
      throw new Error('Signing with Elgamal is not defined in the OpenPGP standard.');
    case enums.publicKey.ecdsa: {
      const { oid, Q } = publicKeyParams;
      const { d } = privateKeyParams;
      return publicKey.elliptic.ecdsa.sign(oid, hashAlgo, data, Q, d, hashed);
    }
    case enums.publicKey.eddsaLegacy: {
      const { oid, Q } = publicKeyParams;
      const { seed } = privateKeyParams;
      return publicKey.elliptic.eddsaLegacy.sign(oid, hashAlgo, data, Q, seed, hashed);
    }
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448: {
      const { A } = publicKeyParams;
      const { seed } = privateKeyParams;
      return publicKey.elliptic.eddsa.sign(algo, hashAlgo, data, A, seed, hashed);
    }
    case enums.publicKey.hmac: {
      const { cipher: algo } = publicKeyParams;
      const { keyMaterial } = privateKeyParams;
      const mac = await publicKey.hmac.sign(algo.getValue(), keyMaterial, hashed);
      return { mac: new ShortByteString(mac) };
    }
    default:
      throw new Error('Unknown signature algorithm.');
  }
}
