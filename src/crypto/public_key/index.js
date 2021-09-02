/**
 * @fileoverview Asymmetric cryptography functions
 * @module crypto/public_key
 */

import * as rsa from './rsa';
import * as elgamal from './elgamal';
import * as elliptic from './elliptic';
import * as dsa from './dsa';
import * as hmac from './hmac';

export default {
  /** @see module:crypto/public_key/rsa */
  rsa: rsa,
  /** @see module:crypto/public_key/elgamal */
  elgamal: elgamal,
  /** @see module:crypto/public_key/elliptic */
  elliptic: elliptic,
  /** @see module:crypto/public_key/dsa */
  dsa: dsa,
  /** @see module:crypto/public_key/hmac */
  hmac: hmac
};
