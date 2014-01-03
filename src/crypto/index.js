/**
 * @see module:crypto/crypto
 * @module crypto
 */
module.exports = {
  /** @see module:crypto/cipher */
  cipher: require('./cipher'),
  /** @see module:crypto/hash */
  hash: require('./hash'),
  /** @see module:crypto/cfb */
  cfb: require('./cfb.js'),
  /** @see module:crypto/public_key */
  publicKey: require('./public_key'),
  /** @see module:crypto/signature */
  signature: require('./signature.js'),
  /** @see module:crypto/random */
  random: require('./random.js'),
  /** @see module:crypto/pkcs1 */
  pkcs1: require('./pkcs1.js')
};

var crypto = require('./crypto.js');

for (var i in crypto)
  module.exports[i] = crypto[i];
