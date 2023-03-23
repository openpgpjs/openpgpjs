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
 */

import enums from '../enums';

export default {
  /**
   * @memberof module:config
   * @property {Integer} preferredHashAlgorithm Default hash algorithm {@link module:enums.hash}
   */
  preferredHashAlgorithm: enums.hash.sha256,
  /**
   * @memberof module:config
   * @property {Integer} preferredSymmetricAlgorithm Default encryption cipher {@link module:enums.symmetric}
   */
  preferredSymmetricAlgorithm: enums.symmetric.aes256,
  /**
   * @memberof module:config
   * @property {Integer} compression Default compression algorithm {@link module:enums.compression}
   */
  preferredCompressionAlgorithm: enums.compression.uncompressed,
  /**
   * @memberof module:config
   * @property {Integer} deflateLevel Default zip/zlib compression level, between 1 and 9
   */
  deflateLevel: 6,

  /**
   * Use Authenticated Encryption with Additional Data (AEAD) protection for symmetric encryption.
   * Note: not all OpenPGP implementations are compatible with this option.
   * **FUTURE OPENPGP.JS VERSIONS MAY BREAK COMPATIBILITY WHEN USING THIS OPTION**
   * @see {@link https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-07|RFC4880bis-07}
   * @memberof module:config
   * @property {Boolean} aeadProtect
   */
  aeadProtect: false,
  /**
   * Default Authenticated Encryption with Additional Data (AEAD) encryption mode
   * Only has an effect when aeadProtect is set to true.
   * @memberof module:config
   * @property {Integer} preferredAEADAlgorithm Default AEAD mode {@link module:enums.aead}
   */
  preferredAEADAlgorithm: enums.aead.eax,
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
   * Note: not all OpenPGP implementations are compatible with this option.
   * **FUTURE OPENPGP.JS VERSIONS MAY BREAK COMPATIBILITY WHEN USING THIS OPTION**
   * @memberof module:config
   * @property {Boolean} v5Keys
   */
  v5Keys: false,
  /**
   * {@link https://tools.ietf.org/html/rfc4880#section-3.7.1.3|RFC4880 3.7.1.3}:
   * Iteration Count Byte for S2K (String to Key)
   * @memberof module:config
   * @property {Integer} s2kIterationCountByte
   */
  s2kIterationCountByte: 224,
  /**
   * Allow decryption of messages without integrity protection.
   * This is an **insecure** setting:
   *  - message modifications cannot be detected, thus processing the decrypted data is potentially unsafe.
   *  - it enables downgrade attacks against integrity-protected messages.
   * @memberof module:config
   * @property {Boolean} allowUnauthenticatedMessages
   */
  allowUnauthenticatedMessages: false,
  /**
   * Allow streaming unauthenticated data before its integrity has been checked. This would allow the application to
   * process large streams while limiting memory usage by releasing the decrypted chunks as soon as possible
   * and deferring checking their integrity until the decrypted stream has been read in full.
   *
   * This setting is **insecure** if the partially decrypted message is processed further or displayed to the user.
   * @memberof module:config
   * @property {Boolean} allowUnauthenticatedStream
   */
  allowUnauthenticatedStream: false,
  /**
   * @memberof module:config
   * @property {Boolean} checksumRequired Do not throw error when armor is missing a checksum
   */
  checksumRequired: false,
  /**
   * Minimum RSA key size allowed for key generation and message signing, verification and encryption.
   * The default is 2047 since due to a bug, previous versions of OpenPGP.js could generate 2047-bit keys instead of 2048-bit ones.
   * @memberof module:config
   * @property {Number} minRSABits
   */
  minRSABits: 2047,
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
   * Allow decryption using RSA keys without `encrypt` flag.
   * This setting is potentially insecure, but it is needed to get around an old openpgpjs bug
   * where key flags were ignored when selecting a key for encryption.
   * @memberof module:config
   * @property {Boolean} allowInsecureDecryptionWithSigningKeys
   */
  allowInsecureDecryptionWithSigningKeys: false,
  /**
   * Allow verification of message signatures with keys whose validity at the time of signing cannot be determined.
   * Instead, a verification key will also be consider valid as long as it is valid at the current time.
   * This setting is potentially insecure, but it is needed to verify messages signed with keys that were later reformatted,
   * and have self-signature's creation date that does not match the primary key creation date.
   * @memberof module:config
   * @property {Boolean} allowInsecureDecryptionWithSigningKeys
   */
  allowInsecureVerificationWithReformattedKeys: false,

  /**
   * Enable constant-time decryption of RSA- and ElGamal-encrypted session keys, to hinder Bleichenbacher-like attacks (https://link.springer.com/chapter/10.1007/BFb0055716).
   * This setting has measurable performance impact and it is only helpful in application scenarios where both of the following conditions apply:
   * - new/incoming messages are automatically decrypted (without user interaction);
   * - an attacker can determine how long it takes to decrypt each message (e.g. due to decryption errors being logged remotely).
   * See also `constantTimePKCS1DecryptionSupportedSymmetricAlgorithms`.
   * @memberof module:config
   * @property {Boolean} constantTimePKCS1Decryption
   */
  constantTimePKCS1Decryption: false,
  /**
   * This setting is only meaningful if `constantTimePKCS1Decryption` is enabled.
   * Decryption of RSA- and ElGamal-encrypted session keys of symmetric algorithms different from the ones specified here will fail.
   * However, the more algorithms are added, the slower the decryption procedure becomes.
   * @memberof module:config
   * @property {Set<Integer>} constantTimePKCS1DecryptionSupportedSymmetricAlgorithms {@link module:enums.symmetric}
   */
  constantTimePKCS1DecryptionSupportedSymmetricAlgorithms: new Set([enums.symmetric.aes128, enums.symmetric.aes192, enums.symmetric.aes256]),

  /**
   * @memberof module:config
   * @property {Integer} minBytesForWebCrypto The minimum amount of bytes for which to use native WebCrypto APIs when available
   */
  minBytesForWebCrypto: 1000,
  /**
   * @memberof module:config
   * @property {Boolean} ignoreUnsupportedPackets Ignore unsupported/unrecognizable packets on parsing instead of throwing an error
   */
  ignoreUnsupportedPackets: true,
  /**
   * @memberof module:config
   * @property {Boolean} ignoreMalformedPackets Ignore malformed packets on parsing instead of throwing an error
   */
  ignoreMalformedPackets: false,
  /**
   * Parsing of packets is normally restricted to a predefined set of packets. For example a Sym. Encrypted Integrity Protected Data Packet can only
   * contain a certain set of packets including LiteralDataPacket. With this setting we can allow additional packets, which is probably not advisable
   * as a global config setting, but can be used for specific function calls (e.g. decrypt method of Message).
   * @memberof module:config
   * @property {Array} additionalAllowedPackets Allow additional packets on parsing. Defined as array of packet classes, e.g. [PublicKeyPacket]
   */
  additionalAllowedPackets: [],
  /**
   * @memberof module:config
   * @property {Boolean} showVersion Whether to include {@link module:config/config.versionString} in armored messages
   */
  showVersion: false,
  /**
   * @memberof module:config
   * @property {Boolean} showComment Whether to include {@link module:config/config.commentString} in armored messages
   */
  showComment: false,
  /**
   * @memberof module:config
   * @property {String} versionString A version string to be included in armored messages
   */
  versionString: 'OpenPGP.js VERSION',
  /**
   * @memberof module:config
   * @property {String} commentString A comment string to be included in armored messages
   */
  commentString: 'https://openpgpjs.org',

  /**
   * Max userID string length (used for parsing)
   * @memberof module:config
   * @property {Integer} maxUserIDLength
   */
  maxUserIDLength: 1024 * 5,
  /**
   * Contains notatations that are considered "known". Known notations do not trigger
   * validation error when the notation is marked as critical.
   * @memberof module:config
   * @property {Array} knownNotations
   */
  knownNotations: [],
  /**
   * Whether to use the indutny/elliptic library for curves (other than Curve25519) that are not supported by the available native crypto API.
   * When false, certain standard curves will not be supported (depending on the platform).
   * Note: the indutny/elliptic curve library is not designed to be constant time.
   * @memberof module:config
   * @property {Boolean} useIndutnyElliptic
   */
  useIndutnyElliptic: true,
  /**
   * Reject insecure hash algorithms
   * @memberof module:config
   * @property {Set<Integer>} rejectHashAlgorithms {@link module:enums.hash}
   */
  rejectHashAlgorithms: new Set([enums.hash.md5, enums.hash.ripemd]),
  /**
   * Reject insecure message hash algorithms
   * @memberof module:config
   * @property {Set<Integer>} rejectMessageHashAlgorithms {@link module:enums.hash}
   */
  rejectMessageHashAlgorithms: new Set([enums.hash.md5, enums.hash.ripemd, enums.hash.sha1]),
  /**
   * Reject insecure public key algorithms for key generation and message encryption, signing or verification
   * @memberof module:config
   * @property {Set<Integer>} rejectPublicKeyAlgorithms {@link module:enums.publicKey}
   */
  rejectPublicKeyAlgorithms: new Set([enums.publicKey.elgamal, enums.publicKey.dsa]),
  /**
   * Reject non-standard curves for key generation, message encryption, signing or verification
   * @memberof module:config
   * @property {Set<String>} rejectCurves {@link module:enums.curve}
   */
  rejectCurves: new Set([enums.curve.secp256k1])
};
