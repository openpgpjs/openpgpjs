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
   * @property {Integer} prefer_hash_algorithm Default hash algorithm {@link module:enums.hash}
   */
  prefer_hash_algorithm: enums.hash.sha256,
  /**
   * @memberof module:config
   * @property {Integer} encryption_cipher Default encryption cipher {@link module:enums.symmetric}
   */
  encryption_cipher: enums.symmetric.aes256,
  /**
   * @memberof module:config
   * @property {Integer} compression Default compression algorithm {@link module:enums.compression}
   */
  compression: enums.compression.uncompressed,
  /**
   * @memberof module:config
   * @property {Integer} deflate_level Default zip/zlib compression level, between 1 and 9
   */
  deflate_level: 6,

  /**
   * Use Authenticated Encryption with Additional Data (AEAD) protection for symmetric encryption.
   * **NOT INTEROPERABLE WITH OTHER OPENPGP IMPLEMENTATIONS**
   * **FUTURE OPENPGP.JS VERSIONS MAY BREAK COMPATIBILITY WHEN USING THIS OPTION**
   * @memberof module:config
   * @property {Boolean} aead_protect
   */
  aead_protect:             false,
  /**
   * Use Authenticated Encryption with Additional Data (AEAD) protection for symmetric encryption.
   * 0 means we implement a variant of {@link https://tools.ietf.org/html/draft-ford-openpgp-format-00|this IETF draft}.
   * 4 means we implement {@link https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-04|RFC4880bis-04}.
   * Note that this determines how AEAD packets are parsed even when aead_protect is set to false
   * @memberof module:config
   * @property {Integer} aead_protect_version
   */
  aead_protect_version:     4,
  /**
   * Default Authenticated Encryption with Additional Data (AEAD) encryption mode
   * Only has an effect when aead_protect is set to true.
   * @memberof module:config
   * @property {Integer} aead_mode Default AEAD mode {@link module:enums.aead}
   */
  aead_mode: enums.aead.eax,
  /**
   * Chunk Size Byte for Authenticated Encryption with Additional Data (AEAD) mode
   * Only has an effect when aead_protect is set to true.
   * Must be an integer value from 0 to 56.
   * @memberof module:config
   * @property {Integer} aead_chunk_size_byte
   */
  aead_chunk_size_byte:     12,
  /**
   * {@link https://tools.ietf.org/html/rfc4880#section-3.7.1.3|RFC4880 3.7.1.3}:
   * Iteration Count Byte for S2K (String to Key)
   * @memberof module:config
   * @property {Integer} s2k_iteration_count_byte
   */
  s2k_iteration_count_byte: 224,
  /** Use integrity protection for symmetric encryption
   * @memberof module:config
   * @property {Boolean} integrity_protect
   */
  integrity_protect:        true,
  /**
   * @memberof module:config
   * @property {Boolean} ignore_mdc_error Fail on decrypt if message is not integrity protected
   */
  ignore_mdc_error:         false,
  /**
   * @memberof module:config
   * @property {Boolean} allow_unauthenticated_stream Stream unauthenticated data before integrity has been checked
   */
  allow_unauthenticated_stream: false,
  /**
   * @memberof module:config
   * @property {Boolean} checksum_required Do not throw error when armor is missing a checksum
   */
  checksum_required:        false,
  /**
   * @memberof module:config
   * @property {Boolean} rsa_blinding
   */
  rsa_blinding:             true,
  /**
   * Work-around for rare GPG decryption bug when encrypting with multiple passwords.
   * **Slower and slightly less secure**
   * @memberof module:config
   * @property {Boolean} password_collision_check
   */
  password_collision_check: false,
  /**
   * @memberof module:config
   * @property {Boolean} revocations_expire If true, expired revocation signatures are ignored
   */
  revocations_expire:       false,

  /**
   * @memberof module:config
   * @property {Boolean} use_native Use native Node.js crypto/zlib and WebCrypto APIs when available
   */
  use_native:               true,
  /**
   * @memberof module:config
   * @property {Integer} min_bytes_for_web_crypto The minimum amount of bytes for which to use native WebCrypto APIs when available
   */
  min_bytes_for_web_crypto: 1000,
  /**
   * @memberof module:config
   * @property {Boolean} Use transferable objects between the Web Worker and main thread
   */
  zero_copy:                false,
  /**
   * @memberof module:config
   * @property {Boolean} debug If enabled, debug messages will be printed
   */
  debug:                    false,
  /**
   * @memberof module:config
   * @property {Boolean} tolerant Ignore unsupported/unrecognizable packets instead of throwing an error
   */
  tolerant:                 true,

  /**
   * @memberof module:config
   * @property {Boolean} show_version Whether to include {@link module:config/config.versionstring} in armored messages
   */
  show_version: true,
  /**
   * @memberof module:config
   * @property {Boolean} show_comment Whether to include {@link module:config/config.commentstring} in armored messages
   */
  show_comment: true,
  /**
   * @memberof module:config
   * @property {String} versionstring A version string to be included in armored messages
   */
  versionstring: "OpenPGP.js VERSION",
  /**
   * @memberof module:config
   * @property {String} commentstring A comment string to be included in armored messages
   */
  commentstring: "https://openpgpjs.org",

  /**
   * @memberof module:config
   * @property {String} keyserver
   */
  keyserver:     "https://keyserver.ubuntu.com",
  /**
   * @memberof module:config
   * @property {String} node_store
   */
  node_store:    "./openpgp.store",
  /**
   * Max userid string length (used for parsing)
   * @memberof module:config
   * @property {Integer} max_userid_length
   */
  max_userid_length: 1024 * 5
};
