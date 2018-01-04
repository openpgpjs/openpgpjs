// Implementation of EdDSA for OpenPGP

'use strict';

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
  var signature;
  const curve = curves.get(oid);
  hash_algo = hash_algo ? hash_algo : curve.hash;
  const key = curve.keyFromSecret(d.toByteArray());
  signature = await key.sign(m, hash_algo);
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
  var result;
  const curve = curves.get(oid);
  hash_algo = hash_algo ? hash_algo : curve.hash;  // FIXME is this according to the RFC?
  const key = curve.keyFromPublic(Q.toByteArray());
  return key.verify(
    m, {R: signature.r.toByteArray(), S: signature.s.toByteArray()}, hash_algo
  );
}

module.exports = {
  sign: sign,
  verify: verify
};
