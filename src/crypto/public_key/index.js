/**
 * @requires crypto/public_key/dsa
 * @requires crypto/public_key/elgamal
 * @requires crypto/public_key/elliptic
 * @requires crypto/public_key/rsa
 * @module crypto/public_key
 */

/** @see module:crypto/public_key/rsa */
import rsa from './rsa';
import prime from './prime';
/** @see module:crypto/public_key/elgamal */
import elgamal from './elgamal';
/** @see module:crypto/public_key/elliptic */
import elliptic from './elliptic';
/** @see module:crypto/public_key/dsa */
import dsa from './dsa';

export default {
  rsa: rsa,
  prime: prime,
  elgamal: elgamal,
  elliptic: elliptic,
  dsa: dsa
};
