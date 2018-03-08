/**
 * @fileoverview Asymmetric cryptography functions
 * @see module:crypto/public_key/dsa
 * @see module:crypto/public_key/elgamal
 * @see module:crypto/public_key/elliptic
 * @see module:crypto/public_key/rsa
 * @module crypto/public_key
 */

/** @see module:crypto/public_key/rsa */
import rsa from './rsa';
/** @see module:crypto/public_key/elgamal */
import elgamal from './elgamal';
/** @see module:crypto/public_key/elliptic */
import elliptic from './elliptic';
/** @see module:crypto/public_key/dsa */
import dsa from './dsa';

export default {
  rsa: rsa,
  elgamal: elgamal,
  elliptic: elliptic,
  dsa: dsa
};
