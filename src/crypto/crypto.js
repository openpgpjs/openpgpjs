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
 * @module crypto/crypto
 */

import publicKey from './public_key';
import mode from './mode';
import { getRandomBytes } from './random';
import { getCipherParams } from './cipher';
import ECDHSymkey from '../type/ecdh_symkey';
import hash from './hash';
import KDFParams from '../type/kdf_params';
import { SymAlgoEnum, AEADEnum, HashEnum } from '../type/enum';
import enums from '../enums';
import util from '../util';
import OID from '../type/oid';
import { UnsupportedError } from '../packet/packet';
import ECDHXSymmetricKey from '../type/ecdh_x_symkey';

/**
 * Encrypts data using specified algorithm and public key parameters.
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1} for public key algorithms.
 * @param {module:enums.publicKey} keyAlgo - Public key algorithm
 * @param {module:enums.symmetric|null} symmetricAlgo - Cipher algorithm (v3 only)
 * @param {Object} publicParams - Algorithm-specific public key parameters
 * @param {Object} privateParams - Algorithm-specific private key parameters
 * @param {Uint8Array} data - Data to be encrypted
 * @param {Uint8Array} fingerprint - Recipient fingerprint
 * @returns {Promise<Object>} Encrypted session key parameters.
 * @async
 */
export async function publicKeyEncrypt(keyAlgo, symmetricAlgo, publicParams, privateParams, data, fingerprint) {
  switch (keyAlgo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign: {
      const { n, e } = publicParams;
      const c = await publicKey.rsa.encrypt(data, n, e);
      return { c };
    }
    case enums.publicKey.elgamal: {
      const { p, g, y } = publicParams;
      return publicKey.elgamal.encrypt(data, p, g, y);
    }
    case enums.publicKey.ecdh: {
      const { oid, Q, kdfParams } = publicParams;
      const { publicKey: V, wrappedKey: C } = await publicKey.elliptic.ecdh.encrypt(
        oid, kdfParams, data, Q, fingerprint);
      return { V, C: new ECDHSymkey(C) };
    }
    case enums.publicKey.x25519:
    case enums.publicKey.x448: {
      if (symmetricAlgo && !util.isAES(symmetricAlgo)) {
        // see https://gitlab.com/openpgp-wg/rfc4880bis/-/merge_requests/276
        throw new Error('X25519 and X448 keys can only encrypt AES session keys');
      }
      const { A } = publicParams;
      const { ephemeralPublicKey, wrappedKey } = await publicKey.elliptic.ecdhX.encrypt(
        keyAlgo, data, A);
      const C = ECDHXSymmetricKey.fromObject({ algorithm: symmetricAlgo, wrappedKey });
      return { ephemeralPublicKey, C };
    }
    case enums.publicKey.aead: {
      if (!privateParams) {
        throw new Error('Cannot encrypt with symmetric key missing private parameters');
      }
      const { symAlgo, aeadMode } = publicParams;
      const { keyMaterial } = privateParams;

      const mode = getAEADMode(aeadMode.getValue());
      const { ivLength } = mode;
      const iv = getRandomBytes(ivLength);
      const modeInstance = await mode(symAlgo.getValue(), keyMaterial);
      const ciphertext = await modeInstance.encrypt(data, iv, new Uint8Array());
      const ivAndCiphertext = util.concatUint8Array([iv, ciphertext]);
      return { ivAndCiphertext };
    }
    case enums.publicKey.pqc_mlkem_x25519: {
      const { eccPublicKey, mlkemPublicKey } = publicParams;
      const { eccCipherText, mlkemCipherText, wrappedKey } = await publicKey.postQuantum.kem.encrypt(keyAlgo, eccPublicKey, mlkemPublicKey, data);
      const C = ECDHXSymmetricKey.fromObject({ algorithm: symmetricAlgo, wrappedKey });
      return { eccCipherText, mlkemCipherText, C };
    }
    default:
      return [];
  }
}

/**
 * Decrypts data using specified algorithm and private key parameters.
 * See {@link https://tools.ietf.org/html/rfc4880#section-5.5.3|RFC 4880 5.5.3}
 * @param {module:enums.publicKey} algo - Public key algorithm
 * @param {Object} publicKeyParams - Algorithm-specific public key parameters
 * @param {Object} privateKeyParams - Algorithm-specific private key parameters
 * @param {Object} sessionKeyParams - Encrypted session key parameters
 * @param {Uint8Array} fingerprint - Recipient fingerprint
 * @param {Uint8Array} [randomPayload] - Data to return on decryption error, instead of throwing
 *                                    (needed for constant-time processing in RSA and ElGamal)
 * @returns {Promise<Uint8Array>} Decrypted data.
 * @throws {Error} on sensitive decryption error, unless `randomPayload` is given
 * @async
 */
export async function publicKeyDecrypt(keyAlgo, publicKeyParams, privateKeyParams, sessionKeyParams, fingerprint, randomPayload) {
  switch (keyAlgo) {
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaEncrypt: {
      const { c } = sessionKeyParams;
      const { n, e } = publicKeyParams;
      const { d, p, q, u } = privateKeyParams;
      return publicKey.rsa.decrypt(c, n, e, d, p, q, u, randomPayload);
    }
    case enums.publicKey.elgamal: {
      const { c1, c2 } = sessionKeyParams;
      const p = publicKeyParams.p;
      const x = privateKeyParams.x;
      return publicKey.elgamal.decrypt(c1, c2, p, x, randomPayload);
    }
    case enums.publicKey.ecdh: {
      const { oid, Q, kdfParams } = publicKeyParams;
      const { d } = privateKeyParams;
      const { V, C } = sessionKeyParams;
      return publicKey.elliptic.ecdh.decrypt(
        oid, kdfParams, V, C.data, Q, d, fingerprint);
    }
    case enums.publicKey.x25519:
    case enums.publicKey.x448: {
      const { A } = publicKeyParams;
      const { k } = privateKeyParams;
      const { ephemeralPublicKey, C } = sessionKeyParams;
      if (C.algorithm !== null && !util.isAES(C.algorithm)) {
        throw new Error('AES session key expected');
      }
      return publicKey.elliptic.ecdhX.decrypt(
        keyAlgo, ephemeralPublicKey, C.wrappedKey, A, k);
    }
    case enums.publicKey.aead: {
      const { symAlgo, aeadMode } = publicKeyParams;
      const { keyMaterial } = privateKeyParams;

      const { ivAndCiphertext } = sessionKeyParams;

      const mode = getAEADMode(aeadMode.getValue());
      const { ivLength } = mode;
      const modeInstance = await mode(symAlgo.getValue(), keyMaterial);
      const iv = ivAndCiphertext.subarray(0, ivLength);
      const ciphertext = ivAndCiphertext.subarray(ivLength);
      return modeInstance.decrypt(ciphertext, iv, new Uint8Array());
    }
    case enums.publicKey.pqc_mlkem_x25519: {
      const { eccSecretKey, mlkemSecretKey } = privateKeyParams;
      const { eccPublicKey, mlkemPublicKey } = publicKeyParams;
      const { eccCipherText, mlkemCipherText, C } = sessionKeyParams;
      return publicKey.postQuantum.kem.decrypt(keyAlgo, eccCipherText, mlkemCipherText, eccSecretKey, eccPublicKey, mlkemSecretKey, mlkemPublicKey, C.wrappedKey);
    }
    default:
      throw new Error('Unknown public key encryption algorithm.');
  }
}

/**
 * Parse public key material in binary form to get the key parameters
 * @param {module:enums.publicKey} algo - The key algorithm
 * @param {Uint8Array} bytes - The key material to parse
 * @returns {{ read: Number, publicParams: Object }} Number of read bytes plus key parameters referenced by name.
 */
export function parsePublicKeyParams(algo, bytes) {
  let read = 0;
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign: {
      const n = util.readMPI(bytes.subarray(read)); read += n.length + 2;
      const e = util.readMPI(bytes.subarray(read)); read += e.length + 2;
      return { read, publicParams: { n, e } };
    }
    case enums.publicKey.dsa: {
      const p = util.readMPI(bytes.subarray(read)); read += p.length + 2;
      const q = util.readMPI(bytes.subarray(read)); read += q.length + 2;
      const g = util.readMPI(bytes.subarray(read)); read += g.length + 2;
      const y = util.readMPI(bytes.subarray(read)); read += y.length + 2;
      return { read, publicParams: { p, q, g, y } };
    }
    case enums.publicKey.elgamal: {
      const p = util.readMPI(bytes.subarray(read)); read += p.length + 2;
      const g = util.readMPI(bytes.subarray(read)); read += g.length + 2;
      const y = util.readMPI(bytes.subarray(read)); read += y.length + 2;
      return { read, publicParams: { p, g, y } };
    }
    case enums.publicKey.ecdsa: {
      const oid = new OID(); read += oid.read(bytes);
      checkSupportedCurve(oid);
      const Q = util.readMPI(bytes.subarray(read)); read += Q.length + 2;
      return { read: read, publicParams: { oid, Q } };
    }
    case enums.publicKey.eddsaLegacy: {
      const oid = new OID(); read += oid.read(bytes);
      checkSupportedCurve(oid);
      if (oid.getName() !== enums.curve.ed25519Legacy) {
        throw new Error('Unexpected OID for eddsaLegacy');
      }
      let Q = util.readMPI(bytes.subarray(read)); read += Q.length + 2;
      Q = util.leftPad(Q, 33);
      return { read: read, publicParams: { oid, Q } };
    }
    case enums.publicKey.ecdh: {
      const oid = new OID(); read += oid.read(bytes);
      checkSupportedCurve(oid);
      const Q = util.readMPI(bytes.subarray(read)); read += Q.length + 2;
      const kdfParams = new KDFParams(); read += kdfParams.read(bytes.subarray(read));
      return { read: read, publicParams: { oid, Q, kdfParams } };
    }
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448:
    case enums.publicKey.x25519:
    case enums.publicKey.x448: {
      const A = util.readExactSubarray(bytes, read, read + getCurvePayloadSize(algo)); read += A.length;
      return { read, publicParams: { A } };
    }
    case enums.publicKey.hmac: {
      const hashAlgo = new HashEnum(); read += hashAlgo.read(bytes);
      const fpSeed = bytes.subarray(read, read + 32); read += 32;
      return { read: read, publicParams: { hashAlgo, fpSeed } };
    }
    case enums.publicKey.aead: {
      const symAlgo = new SymAlgoEnum(); read += symAlgo.read(bytes);
      const aeadMode = new AEADEnum(); read += aeadMode.read(bytes.subarray(read));
      const fpSeed = bytes.subarray(read, read + 32); read += 32;
      return { read: read, publicParams: { symAlgo, aeadMode, fpSeed } };
    }
    case enums.publicKey.pqc_mlkem_x25519: {
      const eccPublicKey = util.readExactSubarray(bytes, read, read + getCurvePayloadSize(enums.publicKey.x25519)); read += eccPublicKey.length;
      const mlkemPublicKey = util.readExactSubarray(bytes, read, read + 1184); read += mlkemPublicKey.length;
      return { read, publicParams: { eccPublicKey, mlkemPublicKey } };
    }
    case enums.publicKey.pqc_mldsa_ed25519: {
      const eccPublicKey = util.readExactSubarray(bytes, read, read + getCurvePayloadSize(enums.publicKey.ed25519)); read += eccPublicKey.length;
      const mldsaPublicKey = util.readExactSubarray(bytes, read, read + 1952); read += mldsaPublicKey.length;
      return { read, publicParams: { eccPublicKey, mldsaPublicKey } };
    }
    default:
      throw new UnsupportedError('Unknown public key encryption algorithm.');
  }
}

/**
 * Parse private key material in binary form to get the key parameters
 * @param {module:enums.publicKey} algo - The key algorithm
 * @param {Uint8Array} bytes - The key material to parse
 * @param {Object} publicParams - (ECC and symmetric only) public params, needed to format some private params
 * @returns {{ read: Number, privateParams: Object }} Number of read bytes plus the key parameters referenced by name.
 */
export async function parsePrivateKeyParams(algo, bytes, publicParams) {
  let read = 0;
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign: {
      const d = util.readMPI(bytes.subarray(read)); read += d.length + 2;
      const p = util.readMPI(bytes.subarray(read)); read += p.length + 2;
      const q = util.readMPI(bytes.subarray(read)); read += q.length + 2;
      const u = util.readMPI(bytes.subarray(read)); read += u.length + 2;
      return { read, privateParams: { d, p, q, u } };
    }
    case enums.publicKey.dsa:
    case enums.publicKey.elgamal: {
      const x = util.readMPI(bytes.subarray(read)); read += x.length + 2;
      return { read, privateParams: { x } };
    }
    case enums.publicKey.ecdsa:
    case enums.publicKey.ecdh: {
      const payloadSize = getCurvePayloadSize(algo, publicParams.oid);
      let d = util.readMPI(bytes.subarray(read)); read += d.length + 2;
      d = util.leftPad(d, payloadSize);
      return { read, privateParams: { d } };
    }
    case enums.publicKey.eddsaLegacy: {
      const payloadSize = getCurvePayloadSize(algo, publicParams.oid);
      if (publicParams.oid.getName() !== enums.curve.ed25519Legacy) {
        throw new Error('Unexpected OID for eddsaLegacy');
      }
      let seed = util.readMPI(bytes.subarray(read)); read += seed.length + 2;
      seed = util.leftPad(seed, payloadSize);
      return { read, privateParams: { seed } };
    }
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448: {
      const payloadSize = getCurvePayloadSize(algo);
      const seed = util.readExactSubarray(bytes, read, read + payloadSize); read += seed.length;
      return { read, privateParams: { seed } };
    }
    case enums.publicKey.x25519:
    case enums.publicKey.x448: {
      const payloadSize = getCurvePayloadSize(algo);
      const k = util.readExactSubarray(bytes, read, read + payloadSize); read += k.length;
      return { read, privateParams: { k } };
    }
    case enums.publicKey.hmac: {
      const { hashAlgo } = publicParams;
      const keySize = hash.getHashByteLength(hashAlgo.getValue());
      const keyMaterial = bytes.subarray(read, read + keySize); read += keySize;
      return { read, privateParams: { keyMaterial } };
    }
    case enums.publicKey.aead: {
      const { symAlgo } = publicParams;
      const { keySize } = getCipherParams(symAlgo.getValue());
      const keyMaterial = bytes.subarray(read, read + keySize); read += keySize;
      return { read, privateParams: { keyMaterial } };
    }
    case enums.publicKey.pqc_mlkem_x25519: {
      const eccSecretKey = util.readExactSubarray(bytes, read, read + getCurvePayloadSize(enums.publicKey.x25519)); read += eccSecretKey.length;
      const mlkemSeed = util.readExactSubarray(bytes, read, read + 64); read += mlkemSeed.length;
      const { mlkemSecretKey } = await publicKey.postQuantum.kem.mlkemExpandSecretSeed(algo, mlkemSeed);
      return { read, privateParams: { eccSecretKey, mlkemSecretKey, mlkemSeed } };
    }
    case enums.publicKey.pqc_mldsa_ed25519: {
      const eccSecretKey = util.readExactSubarray(bytes, read, read + getCurvePayloadSize(enums.publicKey.ed25519)); read += eccSecretKey.length;
      const mldsaSeed = util.readExactSubarray(bytes, read, read + 32); read += mldsaSeed.length;
      const { mldsaSecretKey } = await publicKey.postQuantum.signature.mldsaExpandSecretSeed(algo, mldsaSeed);
      return { read, privateParams: { eccSecretKey, mldsaSecretKey, mldsaSeed } };
    }
    default:
      throw new UnsupportedError('Unknown public key encryption algorithm.');
  }
}

/** Returns the types comprising the encrypted session key of an algorithm
 * @param {module:enums.publicKey} algo - The key algorithm
 * @param {Uint8Array} bytes - The key material to parse
 * @returns {Object} The session key parameters referenced by name.
 */
export function parseEncSessionKeyParams(algo, bytes) {
  let read = 0;
  switch (algo) {
    //   Algorithm-Specific Fields for RSA encrypted session keys:
    //       - MPI of RSA encrypted value m**e mod n.
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign: {
      const c = util.readMPI(bytes.subarray(read));
      return { c };
    }

    //   Algorithm-Specific Fields for Elgamal encrypted session keys:
    //       - MPI of Elgamal value g**k mod p
    //       - MPI of Elgamal value m * y**k mod p
    case enums.publicKey.elgamal: {
      const c1 = util.readMPI(bytes.subarray(read)); read += c1.length + 2;
      const c2 = util.readMPI(bytes.subarray(read));
      return { c1, c2 };
    }
    //   Algorithm-Specific Fields for ECDH encrypted session keys:
    //       - MPI containing the ephemeral key used to establish the shared secret
    //       - ECDH Symmetric Key
    case enums.publicKey.ecdh: {
      const V = util.readMPI(bytes.subarray(read)); read += V.length + 2;
      const C = new ECDHSymkey(); C.read(bytes.subarray(read));
      return { V, C };
    }
    //   Algorithm-Specific Fields for X25519 or X448 encrypted session keys:
    //       - 32 octets representing an ephemeral X25519 public key (or 57 octets for X448).
    //       - A one-octet size of the following fields.
    //       - The one-octet algorithm identifier, if it was passed (in the case of a v3 PKESK packet).
    //       - The encrypted session key.
    case enums.publicKey.x25519:
    case enums.publicKey.x448: {
      const pointSize = getCurvePayloadSize(algo);
      const ephemeralPublicKey = util.readExactSubarray(bytes, read, read + pointSize); read += ephemeralPublicKey.length;
      const C = new ECDHXSymmetricKey(); C.read(bytes.subarray(read));
      return { ephemeralPublicKey, C };
    }
    //   Algorithm-Specific Fields for symmetric AEAD encryption:
    //       - Starting initialization vector
    //       - Symmetric key encryption of "m" using cipher and AEAD mode
    //       - An authentication tag generated by the AEAD mode.
    case enums.publicKey.aead: {
      const ivAndCiphertext = bytes;

      return { ivAndCiphertext };
    }
    case enums.publicKey.pqc_mlkem_x25519: {
      const eccCipherText = util.readExactSubarray(bytes, read, read + getCurvePayloadSize(enums.publicKey.x25519)); read += eccCipherText.length;
      const mlkemCipherText = util.readExactSubarray(bytes, read, read + 1088); read += mlkemCipherText.length;
      const C = new ECDHXSymmetricKey(); C.read(bytes.subarray(read));
      return { eccCipherText, mlkemCipherText, C }; // eccCipherText || mlkemCipherText || len(C) || C
    }
    default:
      throw new UnsupportedError('Unknown public key encryption algorithm.');
  }
}

/**
 * Convert params to MPI and serializes them in the proper order
 * @param {module:enums.publicKey} algo - The public key algorithm
 * @param {Object} params - The key parameters indexed by name
 * @returns {Uint8Array} The array containing the MPIs.
 */
export function serializeParams(algo, params) {
  // Some algorithms do not rely on MPIs to store the binary params
  const algosWithNativeRepresentation = new Set([
    enums.publicKey.ed25519,
    enums.publicKey.x25519,
    enums.publicKey.ed448,
    enums.publicKey.x448,
    enums.publicKey.aead,
    enums.publicKey.hmac,
    enums.publicKey.pqc_mlkem_x25519,
    enums.publicKey.pqc_mldsa_ed25519
  ]);

  const excludedFields = {
    [enums.publicKey.pqc_mlkem_x25519]: new Set(['mlkemSecretKey']), // only `mlkemSeed` is serialized
    [enums.publicKey.pqc_mldsa_ed25519]: new Set(['mldsaSecretKey']) // only `mldsaSeed` is serialized
  };

  const orderedParams = Object.keys(params).map(name => {
    if (excludedFields[algo]?.has(name)) {
      return new Uint8Array();
    }

    const param = params[name];
    if (!util.isUint8Array(param)) return param.write();
    return algosWithNativeRepresentation.has(algo) ? param : util.uint8ArrayToMPI(param);
  });
  return util.concatUint8Array(orderedParams);
}

/**
 * Generate algorithm-specific key parameters
 * @param {module:enums.publicKey} algo - The public key algorithm
 * @param {Integer} bits - Bit length for RSA keys
 * @param {module:type/oid} oid - Object identifier for ECC keys
 * @param {module:enums.symmetric|enums.hash} symmetric - Hash or cipher algorithm for symmetric keys
 * @param {module:enums.aead} aeadMode - AEAD mode for AEAD keys
 * @returns {Promise<{ publicParams: {Object}, privateParams: {Object} }>} The parameters referenced by name.
 * @async
 */
export async function generateParams(algo, bits, oid, symmetric, aeadMode) {
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign:
      return publicKey.rsa.generate(bits, 65537).then(({ n, e, d, p, q, u }) => ({
        privateParams: { d, p, q, u },
        publicParams: { n, e }
      }));
    case enums.publicKey.ecdsa:
      return publicKey.elliptic.generate(oid).then(({ oid, Q, secret }) => ({
        privateParams: { d: secret },
        publicParams: { oid: new OID(oid), Q }
      }));
    case enums.publicKey.eddsaLegacy:
      return publicKey.elliptic.generate(oid).then(({ oid, Q, secret }) => ({
        privateParams: { seed: secret },
        publicParams: { oid: new OID(oid), Q }
      }));
    case enums.publicKey.ecdh:
      return publicKey.elliptic.generate(oid).then(({ oid, Q, secret, hash, cipher }) => ({
        privateParams: { d: secret },
        publicParams: {
          oid: new OID(oid),
          Q,
          kdfParams: new KDFParams({ hash, cipher })
        }
      }));
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448:
      return publicKey.elliptic.eddsa.generate(algo).then(({ A, seed }) => ({
        privateParams: { seed },
        publicParams: { A }
      }));
    case enums.publicKey.x25519:
    case enums.publicKey.x448:
      return publicKey.elliptic.ecdhX.generate(algo).then(({ A, k }) => ({
        privateParams: { k },
        publicParams: { A }
      }));
    case enums.publicKey.hmac: {
      const keyMaterial = await publicKey.hmac.generate(symmetric);
      const fpSeed = getRandomBytes(32);
      return {
        privateParams: {
          keyMaterial
        },
        publicParams: {
          hashAlgo: new HashEnum(symmetric),
          fpSeed
        }
      };
    }
    case enums.publicKey.aead: {
      const keyMaterial = generateSessionKey(symmetric);
      const fpSeed = getRandomBytes(32);
      return {
        privateParams: {
          keyMaterial
        },
        publicParams: {
          symAlgo: new SymAlgoEnum(symmetric),
          aeadMode: new AEADEnum(aeadMode),
          fpSeed
        }
      };
    }
    case enums.publicKey.pqc_mlkem_x25519:
      return publicKey.postQuantum.kem.generate(algo).then(({ eccSecretKey, eccPublicKey, mlkemSeed, mlkemSecretKey, mlkemPublicKey }) => ({
        privateParams: { eccSecretKey, mlkemSeed, mlkemSecretKey },
        publicParams: { eccPublicKey, mlkemPublicKey }
      }));
    case enums.publicKey.pqc_mldsa_ed25519:
      return publicKey.postQuantum.signature.generate(algo).then(({ eccSecretKey, eccPublicKey, mldsaSeed, mldsaSecretKey, mldsaPublicKey }) => ({
        privateParams: { eccSecretKey, mldsaSeed, mldsaSecretKey },
        publicParams: { eccPublicKey, mldsaPublicKey }
      }));
    case enums.publicKey.dsa:
    case enums.publicKey.elgamal:
      throw new Error('Unsupported algorithm for key generation.');
    default:
      throw new Error('Unknown public key algorithm.');
  }
}

/**
 * Validate algorithm-specific key parameters
 * @param {module:enums.publicKey} algo - The public key algorithm
 * @param {Object} publicParams - Algorithm-specific public key parameters
 * @param {Object} privateParams - Algorithm-specific private key parameters
 * @returns {Promise<Boolean>} Whether the parameters are valid.
 * @async
 */
export async function validateParams(algo, publicParams, privateParams) {
  if (!publicParams || !privateParams) {
    throw new Error('Missing key parameters');
  }
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign: {
      const { n, e } = publicParams;
      const { d, p, q, u } = privateParams;
      return publicKey.rsa.validateParams(n, e, d, p, q, u);
    }
    case enums.publicKey.dsa: {
      const { p, q, g, y } = publicParams;
      const { x } = privateParams;
      return publicKey.dsa.validateParams(p, q, g, y, x);
    }
    case enums.publicKey.elgamal: {
      const { p, g, y } = publicParams;
      const { x } = privateParams;
      return publicKey.elgamal.validateParams(p, g, y, x);
    }
    case enums.publicKey.ecdsa:
    case enums.publicKey.ecdh: {
      const algoModule = publicKey.elliptic[enums.read(enums.publicKey, algo)];
      const { oid, Q } = publicParams;
      const { d } = privateParams;
      return algoModule.validateParams(oid, Q, d);
    }
    case enums.publicKey.eddsaLegacy: {
      const { Q, oid } = publicParams;
      const { seed } = privateParams;
      return publicKey.elliptic.eddsaLegacy.validateParams(oid, Q, seed);
    }
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448: {
      const { A } = publicParams;
      const { seed } = privateParams;
      return publicKey.elliptic.eddsa.validateParams(algo, A, seed);
    }
    case enums.publicKey.x25519:
    case enums.publicKey.x448: {
      const { A } = publicParams;
      const { k } = privateParams;
      return publicKey.elliptic.ecdhX.validateParams(algo, A, k);
    }
    case enums.publicKey.hmac:
    case enums.publicKey.aead:
      throw new Error('Persistent symmetric keys must be encrypted using AEAD');
    case enums.publicKey.pqc_mlkem_x25519: {
      const { eccSecretKey, mlkemSeed } = privateParams;
      const { eccPublicKey, mlkemPublicKey } = publicParams;
      return publicKey.postQuantum.kem.validateParams(algo, eccPublicKey, eccSecretKey, mlkemPublicKey, mlkemSeed);
    }
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { eccSecretKey, mldsaSeed } = privateParams;
      const { eccPublicKey, mldsaPublicKey } = publicParams;
      return publicKey.postQuantum.signature.validateParams(algo, eccPublicKey, eccSecretKey, mldsaPublicKey, mldsaSeed);
    }
    default:
      throw new Error('Unknown public key algorithm.');
  }
}

/**
 * Generates a random byte prefix for the specified algorithm
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
 * @param {module:enums.symmetric} algo - Symmetric encryption algorithm
 * @returns {Promise<Uint8Array>} Random bytes with length equal to the block size of the cipher, plus the last two bytes repeated.
 * @async
 */
export async function getPrefixRandom(algo) {
  const { blockSize } = getCipherParams(algo);
  const prefixrandom = await getRandomBytes(blockSize);
  const repeat = new Uint8Array([prefixrandom[prefixrandom.length - 2], prefixrandom[prefixrandom.length - 1]]);
  return util.concat([prefixrandom, repeat]);
}

/**
 * Generating a session key for the specified symmetric algorithm
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
 * @param {module:enums.symmetric} algo - Symmetric encryption algorithm
 * @returns {Uint8Array} Random bytes as a string to be used as a key.
 */
export function generateSessionKey(algo) {
  const { keySize } = getCipherParams(algo);
  return getRandomBytes(keySize);
}

/**
 * Get implementation of the given AEAD mode
 * @param {enums.aead} algo
 * @returns {Object}
 * @throws {Error} on invalid algo
 */
export function getAEADMode(algo) {
  const algoName = enums.read(enums.aead, algo);
  return mode[algoName];
}

/**
 * Check whether the given curve OID is supported
 * @param {module:type/oid} oid - EC object identifier
 * @throws {UnsupportedError} if curve is not supported
 */
function checkSupportedCurve(oid) {
  try {
    oid.getName();
  } catch (e) {
    throw new UnsupportedError('Unknown curve OID');
  }
}

/**
 * Get encoded secret size for a given elliptic algo
 * @param {module:enums.publicKey} algo - alrogithm identifier
 * @param {module:type/oid} [oid] - curve OID if needed by algo
 */
export function getCurvePayloadSize(algo, oid) {
  switch (algo) {
    case enums.publicKey.ecdsa:
    case enums.publicKey.ecdh:
    case enums.publicKey.eddsaLegacy:
      return new publicKey.elliptic.CurveWithOID(oid).payloadSize;
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448:
      return publicKey.elliptic.eddsa.getPayloadSize(algo);
    case enums.publicKey.x25519:
    case enums.publicKey.x448:
      return publicKey.elliptic.ecdhX.getPayloadSize(algo);
    default:
      throw new Error('Unknown elliptic algo');
  }
}

/**
 * Get preferred signing hash algo for a given elliptic algo
 * @param {module:enums.publicKey} algo - alrogithm identifier
 * @param {module:type/oid} [oid] - curve OID if needed by algo
 */
export function getPreferredCurveHashAlgo(algo, oid) {
  switch (algo) {
    case enums.publicKey.ecdsa:
    case enums.publicKey.eddsaLegacy:
      return publicKey.elliptic.getPreferredHashAlgo(oid);
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448:
      return publicKey.elliptic.eddsa.getPreferredHashAlgo(algo);
    default:
      throw new Error('Unknown elliptic signing algo');
  }
}

export function getPQCHashAlgo(algo) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519:
      return enums.hash.sha3_256;
    default:
      throw new Error('Unknown PQC signing algo');
  }
}

export { getCipherParams };
