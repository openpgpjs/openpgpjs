/**
 * @requires crypto/hash/sha
 * @requires crypto/hash/rusha
 * @requires util
 * @requires config
 * @module crypto/hash
 */
var sha = require('./sha.js'),
  rusha = require('./rusha.js'),
  config = require('../../config')
  util = require('../../util.js');

var rusha_obj = new rusha();

function node_hash(type) {
  return function (data) {
    var nodeCrypto = require('crypto');
    var Buffer = require('buffer').Buffer;
    var shasum = nodeCrypto.createHash(type);
    shasum.update(new Buffer(data));
    return new Uint8Array(shasum.digest());
  }
}

var hash_fns;
if(util.detectNode() && config.useNative) { // Use Node native crypto
  hash_fns = {
    md5: node_hash('md5'),
    sha1: node_hash('sha1'),
    sha224: node_hash('sha224'),
    sha256: node_hash('sha256'),
    sha384: node_hash('sha384'),
    sha512: node_hash('sha512'),
    ripemd: node_hash('ripemd160')
  };
}
else { // JS
  hash_fns = {
    /** @see module:crypto/hash/md5 */
    md5: require('./md5.js'),
    /** @see module:crypto/hash/sha.sha1 */
    /** @see module:crypto/hash/rusha */
    // sha1: sha.sha1,
    sha1: function (data) {
      return util.str2Uint8Array(util.hex2bin(rusha_obj.digest(data)));
    },
    //sha1: asmCrypto.SHA1.bytes,
    /** @see module:crypto/hash/sha.sha224 */
    sha224: sha.sha224,
    /** @see module:crypto/hash/sha.sha256 */
    /** @see module:crypto/asmcrypto */
    //sha256: sha.sha256,
    sha256: asmCrypto.SHA256.bytes,
    /** @see module:crypto/hash/sha.sha384 */
    sha384: sha.sha384,
    /** @see module:crypto/hash/sha.sha512 */
    sha512: sha.sha512,
    /** @see module:crypto/hash/ripe-md */
    ripemd: require('./ripe-md.js')
  };
}

module.exports = {

  md5: hash_fns.md5,
  sha1: hash_fns.sha1,
  sha224: hash_fns.sha224,
  sha256: hash_fns.sha256,
  sha384: hash_fns.sha384,
  sha512: hash_fns.sha512,
  ripemd: hash_fns.ripemd,

  /**
   * Create a hash on the specified data using the specified algorithm
   * @param {module:enums.hash} algo Hash algorithm type (see {@link http://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @param {Uint8Array} data Data to be hashed
   * @return {Uint8Array} hash value
   */
  digest: function(algo, data) {
    switch (algo) {
      case 1:
        // - MD5 [HAC]
        return this.md5(data);
      case 2:
        // - SHA-1 [FIPS180]
        return this.sha1(data);
      case 3:
        // - RIPE-MD/160 [HAC]
        return this.ripemd(data);
      case 8:
        // - SHA256 [FIPS180]
        return this.sha256(data);
      case 9:
        // - SHA384 [FIPS180]
        return this.sha384(data);
      case 10:
        // - SHA512 [FIPS180]
        return this.sha512(data);
      case 11:
        // - SHA224 [FIPS180]
        return this.sha224(data);
      default:
        throw new Error('Invalid hash function.');
    }
  },

  /**
   * Returns the hash size in bytes of the specified hash algorithm type
   * @param {module:enums.hash} algo Hash algorithm type (See {@link http://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @return {Integer} Size in bytes of the resulting hash
   */
  getHashByteLength: function(algo) {
    switch (algo) {
      case 1:
        // - MD5 [HAC]
        return 16;
      case 2:
        // - SHA-1 [FIPS180]
      case 3:
        // - RIPE-MD/160 [HAC]
        return 20;
      case 8:
        // - SHA256 [FIPS180]
        return 32;
      case 9:
        // - SHA384 [FIPS180]
        return 48;
      case 10:
        // - SHA512 [FIPS180]
        return 64;
      case 11:
        // - SHA224 [FIPS180]
        return 28;
      default:
        throw new Error('Invalid hash algorithm.');
    }
  }
};
