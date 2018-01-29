// Implementation of EdDSA following RFC4880bis-02 for OpenPGP

/**
 * @requires crypto/hash
 * @requires crypto/public_key/jsbn
 * @requires crypto/public_key/elliptic/curves
 * @module crypto/public_key/elliptic/eddsa
 */

'use strict';

import hash from '../../hash';
import curves from './curves.js';
import BigInteger from '../jsbn.js';

/**
 * Sign a message using the provided key
 * @param  {String}      oid        Elliptic curve for the key
 * @param  {enums.hash}  hash_algo  Hash algorithm used to sign
 * @param  {Uint8Array}  m          Message to sign
 * @param  {BigInteger}  d          Private key used to sign
 * @return {{r: BigInteger, s: BigInteger}}  Signature of the message
 */
async function sign(oid, hash_algo, m, d) {
  const curve = curves.get(oid);
  const key = curve.keyFromSecret(d.toByteArray());
  const signature = await key.sign(m, hash_algo);
  return {
    r: new BigInteger(signature.Rencoded()),
    s: new BigInteger(signature.Sencoded())
  };
}

/**
 * Verifies if a signature is valid for a message
 * @param  {String}      oid        Elliptic curve for the key
 * @param  {enums.hash}  hash_algo  Hash algorithm used in the signature
 * @param  {{r: BigInteger, s: BigInteger}}  signature  Signature to verify
 * @param  {Uint8Array}  m          Message to verify
 * @param  {BigInteger}  Q          Public key used to verify the message
 * @return {Boolean}
 */
async function verify(oid, hash_algo, signature, m, Q) {
  const curve = curves.get(oid);
  const key = curve.keyFromPublic(Q.toByteArray());
  return key.verify(
    m, { R: signature.r.toByteArray(), S: signature.s.toByteArray() }, hash_algo
  );
}

module.exports = {
  sign: sign,
  verify: verify
};
