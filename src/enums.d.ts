declare namespace enums {
  export function read(type: typeof armor, e: armor): armorNames;
  export function read(type: typeof compression, e: compression): compressionNames;
  export function read(type: typeof hash, e: hash): hashNames;
  export function read(type: typeof packet, e: packet): packetNames;
  export function read(type: typeof publicKey, e: publicKey): publicKeyNames;
  export function read(type: typeof symmetric, e: symmetric): symmetricNames;
  export function read(type: typeof keyStatus, e: keyStatus): keyStatusNames;
  export function read(type: typeof keyFlags, e: keyFlags): keyFlagsNames;

  export type armorNames = 'multipartSection' | 'multipartLast' | 'signed' | 'message' | 'publicKey' | 'privateKey';
  export enum armor {
    multipartSection = 0,
    multipartLast = 1,
    signed = 2,
    message = 3,
    publicKey = 4,
    privateKey = 5,
    signature = 6
  }

  export enum reasonForRevocation {
    noReason = 0, // No reason specified (key revocations or cert revocations)
    keySuperseded = 1, // Key is superseded (key revocations)
    keyCompromised = 2, // Key material has been compromised (key revocations)
    keyRetired = 3, // Key is retired and no longer used (key revocations)
    userIDInvalid = 32 // User ID information is no longer valid (cert revocations)
  }

  export type compressionNames = 'uncompressed' | 'zip' | 'zlib' | 'bzip2';
  export enum compression {
    uncompressed = 0,
    zip = 1,
    zlib = 2,
    bzip2 = 3
  }

  export type hashNames = 'md5' | 'sha1' | 'ripemd' | 'sha256' | 'sha384' | 'sha512' | 'sha224' | 'sha3_256' | 'sha3_512';
  export enum hash {
    md5 = 1,
    sha1 = 2,
    ripemd = 3,
    sha256 = 8,
    sha384 = 9,
    sha512 = 10,
    sha224 = 11,
    sha3_256 = 12,
    sha3_512 = 14
  }

  export type packetNames = 'publicKeyEncryptedSessionKey' | 'signature' | 'symEncryptedSessionKey' | 'onePassSignature' | 'secretKey' | 'publicKey' |
  'secretSubkey' | 'compressed' | 'symmetricallyEncrypted' | 'marker' | 'literal' | 'trust' | 'userID' | 'publicSubkey' | 'userAttribute' |
  'symEncryptedIntegrityProtected' | 'modificationDetectionCode' | 'AEADEncryptedDataPacket' | 'padding';
  export enum packet {
    publicKeyEncryptedSessionKey = 1,
    signature = 2,
    symEncryptedSessionKey = 3,
    onePassSignature = 4,
    secretKey = 5,
    publicKey = 6,
    secretSubkey = 7,
    compressedData = 8,
    symmetricallyEncryptedData = 9,
    marker = 10,
    literalData = 11,
    trust = 12,
    userID = 13,
    publicSubkey = 14,
    userAttribute = 17,
    symEncryptedIntegrityProtectedData = 18,
    modificationDetectionCode = 19,
    aeadEncryptedData = 20,
    padding = 21
  }

  export type publicKeyNames = 'rsaEncryptSign' | 'rsaEncrypt' | 'rsaSign' | 'elgamal' | 'dsa' | 'ecdh' | 'ecdsa' | 'eddsaLegacy' | 'aedh' | 'aedsa' | 'ed25519' | 'x25519' | 'ed448' | 'x448' | 'pqc_mlkem_x25519' | 'pqc_mldsa_ed25519';
  export enum publicKey {
    rsaEncryptSign = 1,
    rsaEncrypt = 2,
    rsaSign = 3,
    elgamal = 16,
    dsa = 17,
    ecdh = 18,
    ecdsa = 19,
    eddsaLegacy = 22,
    aedh = 23,
    aedsa = 24,
    x25519 = 25,
    x448 = 26,
    ed25519 = 27,
    ed448 = 28,
    pqc_mlkem_x25519 = 105,
    pqc_mldsa_ed25519 = 107
  }

  export enum curve {
    /** @deprecated use `nistP256` instead */
    p256 = 'nistP256',
    nistP256 = 'nistP256',
    /** @deprecated use `nistP384` instead */
    p384 = 'nistP384',
    nistP384 = 'nistP384',
    /** @deprecated use `nistP521` instead */
    p521 = 'nistP521',
    nistP521 = 'nistP521',
    /** @deprecated use `ed25519Legacy` instead */
    ed25519 = 'ed25519Legacy',
    ed25519Legacy = 'ed25519Legacy',
    /** @deprecated use `curve25519Legacy` instead */
    curve25519 = 'curve25519Legacy',
    curve25519Legacy = 'curve25519Legacy',
    secp256k1 = 'secp256k1',
    brainpoolP256r1 = 'brainpoolP256r1',
    brainpoolP384r1 = 'brainpoolP384r1',
    brainpoolP512r1 = 'brainpoolP512r1'
  }

  export type symmetricNames = 'idea' | 'tripledes' | 'cast5' | 'blowfish' | 'aes128' | 'aes192' | 'aes256' | 'twofish';
  export enum symmetric {
    idea = 1,
    tripledes = 2,
    cast5 = 3,
    blowfish = 4,
    aes128 = 7,
    aes192 = 8,
    aes256 = 9,
    twofish = 10
  }

  export type keyStatusNames = 'invalid' | 'expired' | 'revoked' | 'valid' | 'noSelfCert';
  export enum keyStatus {
    invalid = 0,
    expired = 1,
    revoked = 2,
    valid = 3,
    noSelfCert = 4
  }

  export type keyFlagsNames = 'certifyKeys' | 'signData' | 'encryptCommunication' | 'encryptStorage' | 'splitPrivateKey' | 'authentication' | 'sharedPrivateKey';
  export enum keyFlags {
    certifyKeys = 1,
    signData = 2,
    encryptCommunication = 4,
    encryptStorage = 8,
    splitPrivateKey = 16,
    authentication = 32,
    forwardedCommunication = 64,
    sharedPrivateKey = 128
  }

  export enum signature {
    binary = 0,
    text = 1,
    standalone = 2,
    certGeneric = 16,
    certPersona = 17,
    certCasual = 18,
    certPositive = 19,
    certRevocation = 48,
    subkeyBinding = 24,
    keyBinding = 25,
    key = 31,
    keyRevocation = 32,
    subkeyRevocation = 40,
    timestamp = 64,
    thirdParty = 80
  }

  export type aeadNames = 'eax' | 'ocb' | 'gcm';
  export enum aead {
    eax = 1,
    ocb = 2,
    gcm = 3,
    /** @deprecated use `gcm` instead */
    experimentalGCM = 100 // Private algorithm
  }

  export type literalFormatNames = 'utf8' | 'binary' | 'text' | 'mime';
  export enum literal {
    binary = 98,
    text = 116,
    utf8 = 117,
    mime = 109
  }

  export enum s2k {
    simple = 0,
    salted = 1,
    iterated = 3,
    argon2 = 4,
    gnu = 101
  }
}

export default enums;
