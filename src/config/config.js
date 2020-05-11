// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Global configuration values.
 * @requires enums
 */

import enums from '../enums';

export default {
  /**
   * @memberof module:config
   * @property {Integer} preferHashAlgorithm Default hash algorithm {@link module:enums.hash}
   */
  preferHashAlgorithm: enums.hash.sha256,
  /**
   * @memberof module:config
   * @property {Integer} encryptionCipher Default encryption cipher {@link module:enums.symmetric}
   */
  encryptionCipher: enums.symmetric.aes256,
  /**
   * @memberof module:config
   * @property {Integer} compression Default compression algorithm {@link module:enums.compression}
   */
  compression: enums.compression.uncompressed,
  /**
   * @memberof module:config
   * @property {Integer} deflateLevel Default zip/zlib compression level, between 1 and 9
   */
  deflateLevel: 6,

  /**
   * Use Authenticated Encryption with Additional Data (AEAD) protection for symmetric encryption.
   * Note: not all OpenPGP implementations are compatible with this option.
   * @see {@link https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-07|RFC4880bis-07}
   * @memberof module:config
   * @property {Boolean} aeadProtect
   */
  aeadProtect: true,
  /**
   * Default Authenticated Encryption with Additional Data (AEAD) encryption mode
   * Only has an effect when aeadProtect is set to true.
   * @memberof module:config
   * @property {Integer} aeadMode Default AEAD mode {@link module:enums.aead}
   */
  aeadMode: enums.aead.eax,
  /**
   * Chunk Size Byte for Authenticated Encryption with Additional Data (AEAD) mode
   * Only has an effect when aeadProtect is set to true.
   * Must be an integer value from 0 to 56.
   * @memberof module:config
   * @property {Integer} aeadChunkSizeByte
   */
  aeadChunkSizeByte: 12,
  /**
   * Use V5 keys.
   * Note: not all OpenPGP implementations are compatible with this option
   * @memberof module:config
   * @property {Boolean} v5Keys
   */
  v5Keys: true,
  /**
   * {@link https://tools.ietf.org/html/rfc4880#section-3.7.1.3|RFC4880 3.7.1.3}:
   * Iteration Count Byte for S2K (String to Key)
   * @memberof module:config
   * @property {Integer} s2kIterationCountByte
   */
  s2kIterationCountByte: 224,
  /** Use integrity protection for symmetric encryption
   * @memberof module:config
   * @property {Boolean} integrityProtect
   */
  integrityProtect: true,
  /**
   * @memberof module:config
   * @property {Boolean} ignoreMdcError Fail on decrypt if message is not integrity protected
   */
  ignoreMdcError: false,
  /**
   * @memberof module:config
   * @property {Boolean} allowUnauthenticatedStream Stream unauthenticated data before integrity has been checked
   */
  allowUnauthenticatedStream: false,
  /**
   * @memberof module:config
   * @property {Boolean} checksumRequired Do not throw error when armor is missing a checksum
   */
  checksumRequired: false,
  /**
   * @memberof module:config
   * @property {Boolean} rsaBlinding
   */
  rsaBlinding: true,
  /**
   * Work-around for rare GPG decryption bug when encrypting with multiple passwords.
   * **Slower and slightly less secure**
   * @memberof module:config
   * @property {Boolean} passwordCollisionCheck
   */
  passwordCollisionCheck: false,
  /**
   * @memberof module:config
   * @property {Boolean} revocationsExpire If true, expired revocation signatures are ignored
   */
  revocationsExpire: false,

  /**
   * @memberof module:config
   * @property {Boolean} useNative Use native Node.js crypto/zlib and WebCrypto APIs when available
   */
  useNative: true,
  /**
   * @memberof module:config
   * @property {Integer} minBytesForWebCrypto The minimum amount of bytes for which to use native WebCrypto APIs when available
   */
  minBytesForWebCrypto: 1000,
  /**
   * @memberof module:config
   * @property {Boolean} debug If enabled, debug messages will be printed
   */
  debug: false,
  /**
   * @memberof module:config
   * @property {Boolean} tolerant Ignore unsupported/unrecognizable packets instead of throwing an error
   */
  tolerant: true,

  /**
   * @memberof module:config
   * @property {Boolean} showVersion Whether to include {@link module:config/config.versionString} in armored messages
   */
  showVersion: true,
  /**
   * @memberof module:config
   * @property {Boolean} showComment Whether to include {@link module:config/config.commentString} in armored messages
   */
  showComment: true,
  /**
   * @memberof module:config
   * @property {String} versionString A version string to be included in armored messages
   */
  versionString: "OpenPGP.js VERSION",
  /**
   * @memberof module:config
   * @property {String} commentString A comment string to be included in armored messages
   */
  commentString: "https://openpgpjs.org",

  /**
   * @memberof module:config
   * @property {String} keyserver
   */
  keyserver: "https://keyserver.ubuntu.com",
  /**
   * @memberof module:config
   * @property {String} nodeStore
   */
  nodeStore: "./openpgp.store",
  /**
   * Max userid string length (used for parsing)
   * @memberof module:config
   * @property {Integer} maxUseridLength
   */
  maxUseridLength: 1024 * 5,
  /**
   * Contains notatations that are considered "known". Known notations do not trigger
   * validation error when the notation is marked as critical.
   * @memberof module:config
   * @property {Array} knownNotations
   */
  knownNotations: ["preferred-email-encoding@pgp.com", "pka-address@gnupg.org"],
  /**
   * @memberof module:config
   * @property {Boolean} useIndutnyElliptic Whether to use the indutny/elliptic library. When false, certain curves will not be supported.
   */
  useIndutnyElliptic: true,
  /**
   * @memberof module:config
   * @property {Set<Integer>} reject_hash_algorithms Reject insecure hash algorithms {@link module:enums.hash}
   */
  rejectHashAlgorithms: new globalThis.Set([enums.hash.md5, enums.hash.ripemd]),
  /**
   * @memberof module:config
   * @property {Set<Integer>} reject_message_hash_algorithms Reject insecure message hash algorithms {@link module:enums.hash}
   */
  rejectMessageHashAlgorithms: new globalThis.Set([enums.hash.md5, enums.hash.ripemd, enums.hash.sha1])
};
