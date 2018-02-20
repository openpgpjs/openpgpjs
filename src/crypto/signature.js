/**
 * @requires asmcrypto.js
 * @requires crypto/public_key
 * @requires crypto/pkcs1
 * @requires util
 * @module crypto/signature
*/

// FIXME wrap rsa.js around this
import publicKey from './public_key';
import pkcs1 from './pkcs1';
import util from '../util';

export default {
  /**
   *
   * @param {module:enums.publicKey} algo public Key algorithm
   * @param {module:enums.hash} hash_algo Hash algorithm
   * @param {Array<module:type/mpi>} msg_MPIs Signature multiprecision integers
   * @param {Array<module:type/mpi>} publickey_MPIs Public key multiprecision integers
   * @param {Uint8Array} data Data on where the signature was computed on.
   * @return {Boolean} true if signature (sig_data was equal to data over hash)
   */
  verify: async function(algo, hash_algo, msg_MPIs, publickey_MPIs, data) {
    switch (algo) {
      case 1:
        // RSA (Encrypt or Sign) [HAC]
      case 2:
        // RSA Encrypt-Only [HAC]
      case 3: {
        // RSA Sign-Only [HAC]
        const m = msg_MPIs[0].toUint8Array();
        const n = publickey_MPIs[0].toUint8Array();
        const e = publickey_MPIs[1].toUint8Array();
        const EM = publicKey.rsa.verify(m, n, e);
        const EM2 = pkcs1.emsa.encode(hash_algo, util.Uint8Array2str(data), n.length);
        return util.hexidump(EM) === EM2;
      }
      case 16: {
        // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
        throw new Error("signing with Elgamal is not defined in the OpenPGP standard.");
      }
      case 17: {
        // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
        const r = msg_MPIs[0].toBN();
        const s = msg_MPIs[1].toBN();
        const p = publickey_MPIs[0].toBN();
        const q = publickey_MPIs[1].toBN();
        const g = publickey_MPIs[2].toBN();
        const y = publickey_MPIs[3].toBN();
        return publicKey.dsa.verify(hash_algo, r, s, data, p, q, g, y);
      }
      case 19: {
        // ECDSA
        const oid = publickey_MPIs[0];
        const signature = { r: msg_MPIs[0].toUint8Array(), s: msg_MPIs[1].toUint8Array() };
        const Q = publickey_MPIs[1].toUint8Array();
        return publicKey.elliptic.ecdsa.verify(oid, hash_algo, signature, data, Q);
      }
      case 22: {
        // EdDSA
        const oid = publickey_MPIs[0];
        const signature = { R: msg_MPIs[0].toBN(), S: msg_MPIs[1].toBN() };
        const Q = publickey_MPIs[1].toBN();
        return publicKey.elliptic.eddsa.verify(oid, hash_algo, signature, data, Q);
      }
      default:
        throw new Error('Invalid signature algorithm.');
    }
  },

  /**
   * Create a signature on data using the specified algorithm
   * @param {module:enums.publicKey} algo Asymmetric cipher algorithm to use (See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1})
   * @param {module:enums.hash} hash_algo hash Algorithm to use (See {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @param {Array<module:type/mpi>} keyIntegers Public followed by Private key multiprecision algorithm-specific parameters
   * @param {Uint8Array} data Data to be signed
   * @return {Array<module:type/mpi>}
   */
  sign: async function(algo, hash_algo, keyIntegers, data) {

    switch (algo) {
      case 1:
        // RSA (Encrypt or Sign) [HAC]
      case 2:
        // RSA Encrypt-Only [HAC]
      case 3: {
        // RSA Sign-Only [HAC]
        const n = keyIntegers[0].toUint8Array();
        const e = keyIntegers[1].toUint8Array();
        const d = keyIntegers[2].toUint8Array();
        data = util.Uint8Array2str(data);
        const m = util.hex2Uint8Array(
          '00'+pkcs1.emsa.encode(hash_algo, data, n.length)  // FIXME remove '00'
        );
        const signature = publicKey.rsa.sign(m, n, e, d);
        return util.Uint8Array2MPI(signature);
      }
      case 17: {
        // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
        const p = keyIntegers[0].toBN();
        const q = keyIntegers[1].toBN();
        const g = keyIntegers[2].toBN();
        const x = keyIntegers[4].toBN();
        const signature = publicKey.dsa.sign(hash_algo, data, g, p, q, x);
        return util.concatUint8Array([
          util.Uint8Array2MPI(signature.r.toArrayLike(Uint8Array)),
          util.Uint8Array2MPI(signature.s.toArrayLike(Uint8Array))
        ]);
      }
      case 16: {
        // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
        throw new Error('Signing with Elgamal is not defined in the OpenPGP standard.');
      }
      case 19: {
        // ECDSA
        const oid = keyIntegers[0];
        const d = keyIntegers[2].toUint8Array();
        const signature = await publicKey.elliptic.ecdsa.sign(oid, hash_algo, data, d);
        return util.concatUint8Array([
          util.Uint8Array2MPI(signature.r.toArrayLike(Uint8Array)),
          util.Uint8Array2MPI(signature.s.toArrayLike(Uint8Array))
        ]);
      }
      case 22: {
        // EdDSA
        const oid = keyIntegers[0];
        const d = keyIntegers[2].toBN();
        const signature = await publicKey.elliptic.eddsa.sign(oid, hash_algo, data, d);
        return util.concatUint8Array([
          util.Uint8Array2MPI(Uint8Array.from(signature.R)),
          util.Uint8Array2MPI(Uint8Array.from(signature.S))
        ]);
      }
      default:
        throw new Error('Invalid signature algorithm.');
    }
  }
};
