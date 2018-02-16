/**
 * @requires asmcrypto.js
 * @requires crypto/public_key
 * @requires crypto/pkcs1
 * @requires util
 * @module crypto/signature
*/

import { RSA_RAW } from 'asmcrypto.js';
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
    let m;
    let r;
    let s;
    let Q;
    let curve;
    let signature;

    data = util.Uint8Array2str(data);

    switch (algo) {
      case 1:
        // RSA (Encrypt or Sign) [HAC]
      case 2:
        // RSA Encrypt-Only [HAC]
      case 3: {
        // RSA Sign-Only [HAC]
        const n = publickey_MPIs[0].toUint8Array();
        const k = publickey_MPIs[0].byteLength();
        const e = publickey_MPIs[1].toUint8Array();
        m = msg_MPIs[0].toUint8Array();
        const EM = RSA_RAW.verify(m, [n, e]);
        const EM2 = pkcs1.emsa.encode(hash_algo, data, k);
        return util.hexidump(EM) === EM2;
      }
      case 16: {
        // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
        throw new Error("signing with Elgamal is not defined in the OpenPGP standard.");
      }
      case 17: {
        // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
        const dsa = publicKey.dsa;
        r = msg_MPIs[0].toBN();
        s = msg_MPIs[1].toBN();
        const p = publickey_MPIs[0].toBN();
        const q = publickey_MPIs[1].toBN();
        const g = publickey_MPIs[2].toBN();
        const y = publickey_MPIs[3].toBN();
        m = util.str2Uint8Array(data);
        return dsa.verify(hash_algo, r, s, m, p, q, g, y);
      }
      case 19: {
        // ECDSA
        const { ecdsa } = publicKey.elliptic;
        [curve] = publickey_MPIs;
        r = msg_MPIs[0].toBigInteger();
        s = msg_MPIs[1].toBigInteger();
        m = data;
        Q = publickey_MPIs[1].toBigInteger();
        return ecdsa.verify(curve.oid, hash_algo, { r: r, s: s }, m, Q);
      }
      case 22: {
        // EdDSA
        const { eddsa } = publicKey.elliptic;
        [curve] = publickey_MPIs;
        r = msg_MPIs[0].toBigInteger();
        s = msg_MPIs[1].toBigInteger();
        m = data;
        Q = publickey_MPIs[1].toBigInteger();
        return eddsa.verify(curve.oid, hash_algo, { R: r, S: s }, m, Q);
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

    data = util.Uint8Array2str(data);

    let m;
    let d;
    let curve;
    let signature;

    switch (algo) {
      case 1:
        // RSA (Encrypt or Sign) [HAC]
      case 2:
        // RSA Encrypt-Only [HAC]
      case 3: {
        // RSA Sign-Only [HAC]
        const n = keyIntegers[0].toUint8Array();
        const k = keyIntegers[0].byteLength();
        const e = keyIntegers[1].toUint8Array();
        d = keyIntegers[2].toUint8Array();
        m = util.hex2Uint8Array('00'+pkcs1.emsa.encode(hash_algo, data, k)); // FIXME remove '00'
        return util.Uint8Array2MPI(RSA_RAW.sign(m, [n, e, d]));
      }
      case 17: {
        // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
        const dsa = publicKey.dsa;
        const p = keyIntegers[0].toBN();
        const q = keyIntegers[1].toBN();
        const g = keyIntegers[2].toBN();
        const x = keyIntegers[4].toBN();
        m = util.str2Uint8Array(data);
        signature = dsa.sign(hash_algo, m, g, p, q, x);
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
        const { ecdsa } = publicKey.elliptic;
        [curve] = keyIntegers;
        d = keyIntegers[2].toBigInteger();
        m = data;
        signature = await ecdsa.sign(curve.oid, hash_algo, m, d);
        return util.str2Uint8Array(signature.r.toMPI() + signature.s.toMPI());
      }
      case 22: {
        // EdDSA
        const { eddsa } = publicKey.elliptic;
        [curve] = keyIntegers;
        d = keyIntegers[2].toBigInteger();
        m = data;
        signature = await eddsa.sign(curve.oid, hash_algo, m, d);
        return util.concatUint8Array([
          util.Uint8Array2MPI(signature.R.toArrayLike(Uint8Array, 'le', 32)),
          util.Uint8Array2MPI(signature.S.toArrayLike(Uint8Array, 'le', 32))
        ]);
      }
      default:
        throw new Error('Invalid signature algorithm.');
    }
  }
};
