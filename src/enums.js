/**
 * @module enums
 * @access public
 */

const byValue = Symbol('byValue');

export default {

  /** Maps curve names under various standards to one
   * @see {@link https://wiki.gnupg.org/ECC|ECC - GnuPG wiki}
   * @enum {String}
   * @readonly
   */
  curve: {
    /** NIST P-256 Curve */
    'nistP256':               'nistP256',
    /** @deprecated use `nistP256` instead */
    'p256':                   'nistP256',

    /** NIST P-384 Curve */
    'nistP384':               'nistP384',
    /** @deprecated use `nistP384` instead */
    'p384':                   'nistP384',

    /** NIST P-521 Curve */
    'nistP521':               'nistP521',
    /** @deprecated use `nistP521` instead */
    'p521':                   'nistP521',

    /** SECG SECP256k1 Curve */
    'secp256k1':              'secp256k1',

    /** Ed25519 - deprecated by crypto-refresh (replaced by standaone Ed25519 algo) */
    'ed25519Legacy':          'ed25519Legacy',
    /** @deprecated use `ed25519Legacy` instead */
    'ed25519':                'ed25519Legacy',

    /** Curve25519 - deprecated by crypto-refresh (replaced by standaone X25519 algo) */
    'curve25519Legacy':       'curve25519Legacy',
    /** @deprecated use `curve25519Legacy` instead */
    'curve25519':             'curve25519Legacy',

    /** BrainpoolP256r1 Curve */
    'brainpoolP256r1':       'brainpoolP256r1',

    /** BrainpoolP384r1 Curve */
    'brainpoolP384r1':       'brainpoolP384r1',

    /** BrainpoolP512r1 Curve */
    'brainpoolP512r1':       'brainpoolP512r1'
  },

  /** A string to key specifier type
   * @enum {Integer}
   * @readonly
   */
  s2k: {
    simple: 0,
    salted: 1,
    iterated: 3,
    argon2: 4,
    gnu: 101
  },

  /** {@link https://tools.ietf.org/html/draft-ietf-openpgp-crypto-refresh-08.html#section-9.1|crypto-refresh RFC, section 9.1}
   * @enum {Integer}
   * @readonly
   */
  publicKey: {
    /** RSA (Encrypt or Sign) [HAC] */
    rsaEncryptSign: 1,
    /** RSA (Encrypt only) [HAC] */
    rsaEncrypt: 2,
    /** RSA (Sign only) [HAC] */
    rsaSign: 3,
    /** Elgamal (Encrypt only) [ELGAMAL] [HAC] */
    elgamal: 16,
    /** DSA (Sign only) [FIPS186] [HAC] */
    dsa: 17,
    /** ECDH (Encrypt only) [RFC6637] */
    ecdh: 18,
    /** ECDSA (Sign only) [RFC6637] */
    ecdsa: 19,
    /** EdDSA (Sign only) - deprecated by crypto-refresh (replaced by `ed25519` identifier below)
     * [{@link https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-04|Draft RFC}] */
    eddsaLegacy: 22,
    /** Reserved for AEDH */
    aedh: 23,
    /** Reserved for AEDSA */
    aedsa: 24,
    /** X25519 (Encrypt only) */
    x25519: 25,
    /** X448 (Encrypt only) */
    x448: 26,
    /** Ed25519 (Sign only) */
    ed25519: 27,
    /** Ed448 (Sign only) */
    ed448: 28
  },

  /** {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC4880, section 9.2}
   * @enum {Integer}
   * @readonly
   */
  symmetric: {
    /** Not implemented! */
    idea: 1,
    tripledes: 2,
    cast5: 3,
    blowfish: 4,
    aes128: 7,
    aes192: 8,
    aes256: 9,
    twofish: 10
  },

  /** {@link https://tools.ietf.org/html/rfc4880#section-9.3|RFC4880, section 9.3}
   * @enum {Integer}
   * @readonly
   */
  compression: {
    uncompressed: 0,
    /** RFC1951 */
    zip: 1,
    /** RFC1950 */
    zlib: 2,
    bzip2: 3
  },

  /** {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC4880, section 9.4}
   * @enum {Integer}
   * @readonly
   */
  hash: {
    md5: 1,
    sha1: 2,
    ripemd: 3,
    sha256: 8,
    sha384: 9,
    sha512: 10,
    sha224: 11,
    sha3_256: 12,
    sha3_512: 14
  },

  /** A list of hash names as accepted by webCrypto functions.
   * {@link https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest|Parameters, algo}
   * @enum {String}
   */
  webHash: {
    'SHA-1': 2,
    'SHA-256': 8,
    'SHA-384': 9,
    'SHA-512': 10
  },

  /** {@link https://www.rfc-editor.org/rfc/rfc9580.html#name-aead-algorithms}
   * @enum {Integer}
   * @readonly
   */
  aead: {
    eax: 1,
    ocb: 2,
    gcm: 3,
    /** @deprecated used by OpenPGP.js v5 for legacy AEAD support; use `gcm` instead for the RFC9580-standardized ID */
    experimentalGCM: 100 // Private algorithm
  },

  /** A list of packet types and numeric tags associated with them.
   * @enum {Integer}
   * @readonly
   */
  packet: {
    publicKeyEncryptedSessionKey: 1,
    signature: 2,
    symEncryptedSessionKey: 3,
    onePassSignature: 4,
    secretKey: 5,
    publicKey: 6,
    secretSubkey: 7,
    compressedData: 8,
    symmetricallyEncryptedData: 9,
    marker: 10,
    literalData: 11,
    trust: 12,
    userID: 13,
    publicSubkey: 14,
    userAttribute: 17,
    symEncryptedIntegrityProtectedData: 18,
    modificationDetectionCode: 19,
    aeadEncryptedData: 20, // see IETF draft: https://tools.ietf.org/html/draft-ford-openpgp-format-00#section-2.1
    padding: 21
  },

  /** Data types in the literal packet
   * @enum {Integer}
   * @readonly
   */
  literal: {
    /** Binary data 'b' */
    binary: 'b'.charCodeAt(),
    /** Text data 't' */
    text: 't'.charCodeAt(),
    /** Utf8 data 'u' */
    utf8: 'u'.charCodeAt(),
    /** MIME message body part 'm' */
    mime: 'm'.charCodeAt()
  },


  /** One pass signature packet type
   * @enum {Integer}
   * @readonly
   */
  signature: {
    /** 0x00: Signature of a binary document. */
    binary: 0,
    /** 0x01: Signature of a canonical text document.
     *
     * Canonicalyzing the document by converting line endings. */
    text: 1,
    /** 0x02: Standalone signature.
     *
     * This signature is a signature of only its own subpacket contents.
     * It is calculated identically to a signature over a zero-lengh
     * binary document.  Note that it doesn't make sense to have a V3
     * standalone signature. */
    standalone: 2,
    /** 0x10: Generic certification of a User ID and Public-Key packet.
     *
     * The issuer of this certification does not make any particular
     * assertion as to how well the certifier has checked that the owner
     * of the key is in fact the person described by the User ID. */
    certGeneric: 16,
    /** 0x11: Persona certification of a User ID and Public-Key packet.
     *
     * The issuer of this certification has not done any verification of
     * the claim that the owner of this key is the User ID specified. */
    certPersona: 17,
    /** 0x12: Casual certification of a User ID and Public-Key packet.
     *
     * The issuer of this certification has done some casual
     * verification of the claim of identity. */
    certCasual: 18,
    /** 0x13: Positive certification of a User ID and Public-Key packet.
     *
     * The issuer of this certification has done substantial
     * verification of the claim of identity.
     *
     * Most OpenPGP implementations make their "key signatures" as 0x10
     * certifications.  Some implementations can issue 0x11-0x13
     * certifications, but few differentiate between the types. */
    certPositive: 19,
    /** 0x30: Certification revocation signature
     *
     * This signature revokes an earlier User ID certification signature
     * (signature class 0x10 through 0x13) or direct-key signature
     * (0x1F).  It should be issued by the same key that issued the
     * revoked signature or an authorized revocation key.  The signature
     * is computed over the same data as the certificate that it
     * revokes, and should have a later creation date than that
     * certificate. */
    certRevocation: 48,
    /** 0x18: Subkey Binding Signature
     *
     * This signature is a statement by the top-level signing key that
     * indicates that it owns the subkey.  This signature is calculated
     * directly on the primary key and subkey, and not on any User ID or
     * other packets.  A signature that binds a signing subkey MUST have
     * an Embedded Signature subpacket in this binding signature that
     * contains a 0x19 signature made by the signing subkey on the
     * primary key and subkey. */
    subkeyBinding: 24,
    /** 0x19: Primary Key Binding Signature
     *
     * This signature is a statement by a signing subkey, indicating
     * that it is owned by the primary key and subkey.  This signature
     * is calculated the same way as a 0x18 signature: directly on the
     * primary key and subkey, and not on any User ID or other packets.
     *
     * When a signature is made over a key, the hash data starts with the
     * octet 0x99, followed by a two-octet length of the key, and then body
     * of the key packet.  (Note that this is an old-style packet header for
     * a key packet with two-octet length.)  A subkey binding signature
     * (type 0x18) or primary key binding signature (type 0x19) then hashes
     * the subkey using the same format as the main key (also using 0x99 as
     * the first octet). */
    keyBinding: 25,
    /** 0x1F: Signature directly on a key
     *
     * This signature is calculated directly on a key.  It binds the
     * information in the Signature subpackets to the key, and is
     * appropriate to be used for subpackets that provide information
     * about the key, such as the Revocation Key subpacket.  It is also
     * appropriate for statements that non-self certifiers want to make
     * about the key itself, rather than the binding between a key and a
     * name. */
    key: 31,
    /** 0x20: Key revocation signature
     *
     * The signature is calculated directly on the key being revoked.  A
     * revoked key is not to be used.  Only revocation signatures by the
     * key being revoked, or by an authorized revocation key, should be
     * considered valid revocation signatures.a */
    keyRevocation: 32,
    /** 0x28: Subkey revocation signature
     *
     * The signature is calculated directly on the subkey being revoked.
     * A revoked subkey is not to be used.  Only revocation signatures
     * by the top-level signature key that is bound to this subkey, or
     * by an authorized revocation key, should be considered valid
     * revocation signatures.
     *
     * Key revocation signatures (types 0x20 and 0x28)
     * hash only the key being revoked. */
    subkeyRevocation: 40,
    /** 0x40: Timestamp signature.
     * This signature is only meaningful for the timestamp contained in
     * it. */
    timestamp: 64,
    /** 0x50: Third-Party Confirmation signature.
     *
     * This signature is a signature over some other OpenPGP Signature
     * packet(s).  It is analogous to a notary seal on the signed data.
     * A third-party signature SHOULD include Signature Target
     * subpacket(s) to give easy identification.  Note that we really do
     * mean SHOULD.  There are plausible uses for this (such as a blind
     * party that only sees the signature, not the key or source
     * document) that cannot include a target subpacket. */
    thirdParty: 80
  },

  /** Signature subpacket type
   * @enum {Integer}
   * @readonly
   */
  signatureSubpacket: {
    signatureCreationTime: 2,
    signatureExpirationTime: 3,
    exportableCertification: 4,
    trustSignature: 5,
    regularExpression: 6,
    revocable: 7,
    keyExpirationTime: 9,
    placeholderBackwardsCompatibility: 10,
    preferredSymmetricAlgorithms: 11,
    revocationKey: 12,
    issuerKeyID: 16,
    notationData: 20,
    preferredHashAlgorithms: 21,
    preferredCompressionAlgorithms: 22,
    keyServerPreferences: 23,
    preferredKeyServer: 24,
    primaryUserID: 25,
    policyURI: 26,
    keyFlags: 27,
    signersUserID: 28,
    reasonForRevocation: 29,
    features: 30,
    signatureTarget: 31,
    embeddedSignature: 32,
    issuerFingerprint: 33,
    preferredAEADAlgorithms: 34,
    preferredCipherSuites: 39
  },

  /** Key flags
   * @enum {Integer}
   * @readonly
   */
  keyFlags: {
    /** 0x01 - This key may be used to certify other keys. */
    certifyKeys: 1,
    /** 0x02 - This key may be used to sign data. */
    signData: 2,
    /** 0x04 - This key may be used to encrypt communications. */
    encryptCommunication: 4,
    /** 0x08 - This key may be used to encrypt storage. */
    encryptStorage: 8,
    /** 0x10 - The private component of this key may have been split
     *        by a secret-sharing mechanism. */
    splitPrivateKey: 16,
    /** 0x20 - This key may be used for authentication. */
    authentication: 32,
    /** 0x80 - The private component of this key may be in the
     *        possession of more than one person. */
    sharedPrivateKey: 128
  },

  /** Armor type
   * @enum {Integer}
   * @readonly
   */
  armor: {
    multipartSection: 0,
    multipartLast: 1,
    signed: 2,
    message: 3,
    publicKey: 4,
    privateKey: 5,
    signature: 6
  },

  /** {@link https://tools.ietf.org/html/rfc4880#section-5.2.3.23|RFC4880, section 5.2.3.23}
   * @enum {Integer}
   * @readonly
   */
  reasonForRevocation: {
    /** No reason specified (key revocations or cert revocations) */
    noReason: 0,
    /** Key is superseded (key revocations) */
    keySuperseded: 1,
    /** Key material has been compromised (key revocations) */
    keyCompromised: 2,
    /** Key is retired and no longer used (key revocations) */
    keyRetired: 3,
    /** User ID information is no longer valid (cert revocations) */
    userIDInvalid: 32
  },

  /** {@link https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-04#section-5.2.3.25|RFC4880bis-04, section 5.2.3.25}
   * @enum {Integer}
   * @readonly
   */
  features: {
    /** 0x01 - Modification Detection (packets 18 and 19) */
    modificationDetection: 1,
    /** 0x02 - AEAD Encrypted Data Packet (packet 20) and version 5
     *         Symmetric-Key Encrypted Session Key Packets (packet 3) */
    aead: 2,
    /** 0x04 - Version 5 Public-Key Packet format and corresponding new
      *        fingerprint format */
    v5Keys: 4,
    seipdv2: 8
  },

  /**
   * Asserts validity of given value and converts from string/integer to integer.
   * @param {Object} type target enum type
   * @param {String|Integer} e value to check and/or convert
   * @returns {Integer} enum value if it exists
   * @throws {Error} if the value is invalid
   */
  write: function(type, e) {
    if (typeof e === 'number') {
      e = this.read(type, e);
    }

    if (type[e] !== undefined) {
      return type[e];
    }

    throw new Error('Invalid enum value.');
  },

  /**
   * Converts enum integer value to the corresponding string, if it exists.
   * @param {Object} type target enum type
   * @param {Integer} e value to convert
   * @returns {String} name of enum value if it exists
   * @throws {Error} if the value is invalid
   */
  read: function(type, e) {
    if (!type[byValue]) {
      type[byValue] = [];
      Object.entries(type).forEach(([key, value]) => {
        type[byValue][value] = key;
      });
    }

    if (type[byValue][e] !== undefined) {
      return type[byValue][e];
    }

    throw new Error('Invalid enum value.');
  }
};
