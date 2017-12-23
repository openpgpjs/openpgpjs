/**
 * @requires util
 * @requires crypto/hash
 * @requires crypto/pkcs1
 * @requires crypto/public_key
 * @module crypto/signature */

import util from '../util';
import publicKey from './public_key';
import pkcs1 from './pkcs1.js';

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
  verify: function(algo, hash_algo, msg_MPIs, publickey_MPIs, data) {
    let m;

    data = util.Uint8Array2str(data);

    switch (algo) {
      case 1:
        // RSA (Encrypt or Sign) [HAC]
      case 2:
        // RSA Encrypt-Only [HAC]
      case 3:
        // RSA Sign-Only [HAC]
        const rsa = new publicKey.rsa();
        const n = publickey_MPIs[0].toBigInteger();
        const k = publickey_MPIs[0].byteLength();
        const e = publickey_MPIs[1].toBigInteger();
        m = msg_MPIs[0].toBigInteger();
        const EM = rsa.verify(m, e, n);
        const EM2 = pkcs1.emsa.encode(hash_algo, data, k);
        return EM.compareTo(EM2) === 0;
      case 16:
        // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
        throw new Error("signing with Elgamal is not defined in the OpenPGP standard.");
      case 17:
        // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
        const dsa = new publicKey.dsa();
        const s1 = msg_MPIs[0].toBigInteger();
        const s2 = msg_MPIs[1].toBigInteger();
        const p = publickey_MPIs[0].toBigInteger();
        const q = publickey_MPIs[1].toBigInteger();
        const g = publickey_MPIs[2].toBigInteger();
        const y = publickey_MPIs[3].toBigInteger();
        m = data;
        const dopublic = dsa.verify(hash_algo, s1, s2, m, p, q, g, y);
        return dopublic.compareTo(s1) === 0;
      default:
        throw new Error('Invalid signature algorithm.');
    }
  },

  /**
   * Create a signature on data using the specified algorithm
   * @param {module:enums.hash} hash_algo hash Algorithm to use (See {@link http://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @param {module:enums.publicKey} algo Asymmetric cipher algorithm to use (See {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1})
   * @param {Array<module:type/mpi>} publicMPIs Public key multiprecision integers
   * of the private key
   * @param {Array<module:type/mpi>} secretMPIs Private key multiprecision
   * integers which is used to sign the data
   * @param {Uint8Array} data Data to be signed
   * @return {Array<module:type/mpi>}
   */
  sign: function(hash_algo, algo, keyIntegers, data) {

    data = util.Uint8Array2str(data);

    let m;

    switch (algo) {
      case 1:
        // RSA (Encrypt or Sign) [HAC]
      case 2:
        // RSA Encrypt-Only [HAC]
      case 3:
        // RSA Sign-Only [HAC]
        const rsa = new publicKey.rsa();
        const d = keyIntegers[2].toBigInteger();
        const n = keyIntegers[0].toBigInteger();
        m = pkcs1.emsa.encode(hash_algo,
          data, keyIntegers[0].byteLength());
        return util.str2Uint8Array(rsa.sign(m, d, n).toMPI());

      case 17:
        // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
        const dsa = new publicKey.dsa();

        const p = keyIntegers[0].toBigInteger();
        const q = keyIntegers[1].toBigInteger();
        const g = keyIntegers[2].toBigInteger();
        const x = keyIntegers[4].toBigInteger();
        m = data;
        const result = dsa.sign(hash_algo, m, g, p, q, x);

        return util.str2Uint8Array(result[0].toString() + result[1].toString());
      case 16:
        // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
        throw new Error('Signing with Elgamal is not defined in the OpenPGP standard.');
      default:
        throw new Error('Invalid signature algorithm.');
    }
  }
};
