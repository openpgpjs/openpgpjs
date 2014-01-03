/**
 * @requires crypto/public_key/dsa
 * @requires crypto/public_key/elgamal
 * @requires crypto/public_key/rsa
 * @module crypto/public_key
 */
module.exports = {
  /** @see module:crypto/public_key/rsa */
  rsa: require('./rsa.js'),
  /** @see module:crypto/public_key/elgamal */
  elgamal: require('./elgamal.js'),
  /** @see module:crypto/public_key/dsa */
  dsa: require('./dsa.js')
};
