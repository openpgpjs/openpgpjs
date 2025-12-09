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
 * Global configuration values
 * @access public
 */

import enums from '../enums';

export default {
  /**
   * @memberof module:config
   * @property {Integer} preferredHashAlgorithm Default hash algorithm {@link module:enums.hash}
   */
  preferredHashAlgorithm: enums.hash.sha512,
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
   * Use Authenticated Encryption with Additional Data (AEAD) protection for symmetric encryption.
   * This option is applicable to:
   * - key generation (encryption key preferences),
   * - password-based message encryption, and
   * - private key encryption.
   * In the case of message encryption using public keys, the encryption key preferences are respected instead.
   * Note: not all OpenPGP implementations are compatible with this option.
   * @see {@link https://tools.ietf.org/html/draft-ietf-openpgp-crypto-refresh-10.html|draft-crypto-refresh-10}
   * @memberof module:config
   * @property {Boolean} aeadProtect
   */
  aeadProtect: false,
  /**
   * When reading OpenPGP v4 private keys (e.g. those generated in OpenPGP.js when not setting `config.v5Keys = true`)
   * which were encrypted by OpenPGP.js v5 (or older) using `config.aeadProtect = true`,
   * this option must be set, otherwise key parsing and/or key decryption will fail.
   * Note: only set this flag if you know that the keys are of the legacy type, as non-legacy keys
   * will be processed incorrectly.
   */
  parseAEADEncryptedV4KeysAsLegacy: false,
  /**
   * Default Authenticated Encryption with Additional Data (AEAD) encryption mode
   * Only has an effect when aeadProtect is set to true.
   * @memberof module:config
   * @property {Integer} preferredAEADAlgorithm Default AEAD mode {@link module:enums.aead}
   */
  preferredAEADAlgorithm: enums.aead.gcm,
  /**
   * Chunk Size Byte for Authenticated Encryption with Additional Data (AEAD) mode
   * Only has an effect when aeadProtect is set to true.
   * Must be an integer value from 0 to 56.
   * @memberof module:config
   * @property {Integer} aeadChunkSizeByte
   */
  aeadChunkSizeByte: 12,
  /**
   * Use v6 keys.
   * Note: not all OpenPGP implementations are compatible with this option.
   * **FUTURE OPENPGP.JS VERSIONS MAY BREAK COMPATIBILITY WHEN USING THIS OPTION**
   * @memberof module:config
   * @property {Boolean} v6Keys
   */
  v6Keys: false,
  /**
   * Enable parsing v5 keys and v5 signatures (which is different from the AEAD-encrypted SEIPDv2 packet).
   * These are non-standard entities, which in the crypto-refresh have been superseded
   * by v6 keys and v6 signatures, respectively.
   * However, generation of v5 entities was supported behind config flag in OpenPGP.js v5, and some other libraries,
   * hence parsing them might be necessary in some cases.
   * @memberof module:config
   * @property {Boolean} enableParsingV5Entities
   */
  enableParsingV5Entities: false,
  /**
   * S2K (String to Key) type, used for key derivation in the context of secret key encryption
   * and password-encrypted data. Weaker s2k options are not allowed.
   * Note: Argon2 is the strongest option but not all OpenPGP implementations are compatible with it
   * (pending standardisation).
   * @memberof module:config
   * @property {enums.s2k.argon2|enums.s2k.iterated} s2kType {@link module:enums.s2k}
   */
  s2kType: enums.s2k.iterated,
  /**
   * {@link https://tools.ietf.org/html/rfc4880#section-3.7.1.3| RFC4880 3.7.1.3}:
   * Iteration Count Byte for Iterated and Salted S2K (String to Key).
   * Only relevant if `config.s2kType` is set to `enums.s2k.iterated`.
   * Note: this is the exponent value, not the final number of iterations (refer to specs for more details).
   * @memberof module:config
   * @property {Integer} s2kIterationCountByte
   */
  s2kIterationCountByte: 224,
  /**
   * {@link https://tools.ietf.org/html/draft-ietf-openpgp-crypto-refresh-07.html#section-3.7.1.4| draft-crypto-refresh 3.7.1.4}:
   * Argon2 parameters for S2K (String to Key).
   * Only relevant if `config.s2kType` is set to `enums.s2k.argon2`.
   * Default settings correspond to the second recommendation from RFC9106 ("uniformly safe option"),
   * to ensure compatibility with memory-constrained environments.
   * For more details on the choice of parameters, see https://tools.ietf.org/html/rfc9106#section-4.
   * @memberof module:config
   * @property {Object} params
   * @property {Integer} params.passes - number of iterations t
   * @property {Integer} params.parallelism - degree of parallelism p
   * @property {Integer} params.memoryExponent - one-octet exponent indicating the memory size, which will be: 2**memoryExponent kibibytes.
   */
  s2kArgon2Params: {
    passes: 3,
    parallelism: 4, // lanes
    memoryExponent: 16 // 64 MiB of RAM
  },
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
   * This setting is **insecure** if the encrypted data has been corrupted by a malicious entity:
   * - if the partially decrypted message is processed further or displayed to the user, it opens up the possibility of attacks such as EFAIL
   *    (see https://efail.de/).
   * - an attacker with access to traces or timing info of internal processing errors could learn some info about the data.
   *
   * NB: this setting does not apply to AEAD-encrypted data, where the AEAD data chunk is never released until integrity is confirmed.
   * @memberof module:config
   * @property {Boolean} allowUnauthenticatedStream
   */
  allowUnauthenticatedStream: false,
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
   * Allow using keys that do not have any key flags set.
   * Key flags are needed to restrict key usage to specific purposes: for instance, a signing key could only be allowed to certify other keys, and not sign messages
   * (see https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-10.html#section-5.2.3.29).
   * Some older keys do not declare any key flags, which means they are not allowed to be used for any operation.
   * This setting allows using such keys for any operation for which they are compatible, based on their public key algorithm.
   */
  allowMissingKeyFlags: false,
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
   * @property {Boolean} ignoreUnsupportedPackets Ignore unsupported/unrecognizable packets on parsing instead of throwing an error
   */
  ignoreUnsupportedPackets: true,
  /**
   * @memberof module:config
   * @property {Boolean} ignoreMalformedPackets Ignore malformed packets on parsing instead of throwing an error
   */
  ignoreMalformedPackets: false,
  /**
   * @memberof module:config
   * @property {Boolean} enforceGrammar whether parsed OpenPGP messages must comform to the OpenPGP grammar
   *    defined in https://www.rfc-editor.org/rfc/rfc9580.html#name-openpgp-messages .
   */
  enforceGrammar: true,
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
   * Maximum size of decompressed messages
   * When decompressing a larger message, OpenPGP.js will throw an error.
   * @memberof module:config
   * @property {Integer} maxDecompressedMessageSize
   */
  maxDecompressedMessageSize: Infinity,
  /**
   * Contains notatations that are considered "known". Known notations do not trigger
   * validation error when the notation is marked as critical.
   * @memberof module:config
   * @property {Array} knownNotations
   */
  knownNotations: [],
  /**
   * If true, a salt notation is used to randomize signatures generated by v4 and v5 keys (v6 signatures are always non-deterministic, by design).
   * This protects EdDSA signatures from potentially leaking the secret key in case of faults (i.e. bitflips) which, in principle, could occur
   * during the signing computation. It is added to signatures of any algo for simplicity, and as it may also serve as protection in case of
   * weaknesses in the hash algo, potentially hindering e.g. some chosen-prefix attacks.
   * NOTE: the notation is interoperable, but will reveal that the signature has been generated using OpenPGP.js, which may not be desirable in some cases.
   */
  nonDeterministicSignaturesViaNotation: true,
  /**
   * Whether to use the the noble-curves library for curves (other than Curve25519) that are not supported by the available native crypto API.
   * When false, certain standard curves will not be supported (depending on the platform).
   * @memberof module:config
   * @property {Boolean} useEllipticFallback
   */
  useEllipticFallback: true,
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
