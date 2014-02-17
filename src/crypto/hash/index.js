/**
 * @requires crypto/hash/sha
 * @module crypto/hash
 */
var sha = require('./sha.js'),
  forge_sha256 = require('./forge_sha256.js');

module.exports = {
  /** @see module:crypto/hash/md5 */
  md5: require('./md5.js'),
  /** @see module:crypto/hash/sha.sha1 */
  sha1: sha.sha1,
  /** @see module:crypto/hash/sha.sha224 */
  sha224: sha.sha224,
  /** @see module:crypto/hash/sha.sha256 */
  sha256: sha.sha256,
  /** @see module:crypto/hash/sha.sha384 */
  sha384: sha.sha384,
  /** @see module:crypto/hash/sha.sha512 */
  sha512: sha.sha512,
  /** @see module:crypto/hash/ripe-md */
  ripemd: require('./ripe-md.js'),

  /**
   * Create a hash on the specified data using the specified algorithm
   * @param {module:enums.hash} algo Hash algorithm type (see {@link http://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @param {String} data Data to be hashed
   * @return {String} hash value
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
        var sha256 = forge_sha256.create();
        sha256.update(data);
        return sha256.digest().getBytes();
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
