/**
 * @fileoverview Asymmetric cryptography functions
 * @requires tweetnacl
 * @requires crypto/public_key/dsa
 * @requires crypto/public_key/elgamal
 * @requires crypto/public_key/elliptic
 * @requires crypto/public_key/rsa
 * @module crypto/public_key
 */

import nacl from 'tweetnacl/nacl-fast-light.js';
import * as rsa from './rsa';
import * as elgamal from './elgamal';
import * as elliptic from './elliptic';
import * as dsa from './dsa';

export default {
  /** @see module:crypto/public_key/rsa */
  rsa: rsa,
  /** @see module:crypto/public_key/elgamal */
  elgamal: elgamal,
  /** @see module:crypto/public_key/elliptic */
  elliptic: elliptic,
  /** @see module:crypto/public_key/dsa */
  dsa: dsa,
  /** @see tweetnacl */
  nacl: nacl
};
