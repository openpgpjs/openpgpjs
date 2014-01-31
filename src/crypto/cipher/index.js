/**
 * @requires crypto/cipher/aes
 * @requires crypto/cipher/blowfish
 * @requires crypto/cipher/cast5
 * @requires crypto/cipher/twofish
 * @module crypto/cipher
 */

var desModule = require('./des.js');

module.exports = {
  /** @see module:crypto/cipher/des.originalDes */
  des: desModule.originalDes,
  /** @see module:crypto/cipher/des.des */
  tripledes: desModule.des,
  /** @see module:crypto/cipher/cast5 */
  cast5: require('./cast5.js'),
  /** @see module:crypto/cipher/twofish */
  twofish: require('./twofish.js'),
  /** @see module:crypto/cipher/blowfish */
  blowfish: require('./blowfish.js')
};

var aes = require('./aes.js');

for (var i in aes) {
  module.exports['aes' + i] = aes[i];
}
