/**
 * Type definitions for OpenPGP.js http://openpgpjs.org/
 * 
 * Contributors:
 *  - FlowCrypt a. s. <https://flowcrypt.com>
 *  - Guillaume Lacasa <https://blog.lacasa.fr>
 *  - Errietta Kostala <https://github.com/errietta>
 */

declare namespace OpenPGP {

  type DataPacketType = 'utf8' | 'binary' | 'text' | 'mime';

  export interface UserId {
    name?: string;
    email?: string;
  }

  export interface SessionKey {
    data: Uint8Array;
    algorithm: string;
  }

  interface BaseStream<T extends Uint8Array | string> { }
  interface WebStream<T extends Uint8Array | string> extends BaseStream<T> { // copied+simplified version of ReadableStream from lib.dom.d.ts
    readonly locked: boolean; getReader: Function; pipeThrough: Function; pipeTo: Function; tee: Function;
    cancel(reason?: any): Promise<void>;
  }
  interface NodeStream<T extends Uint8Array | string> extends BaseStream<T> { // copied+simplified version of ReadableStream from @types/node/index.d.ts
    readable: boolean; pipe: Function; unpipe: Function; wrap: Function;
    read(size?: number): string | Uint8Array; setEncoding(encoding: string): this; pause(): this; resume(): this;
    isPaused(): boolean; unshift(chunk: string | Uint8Array): void;
  }
  type Stream<T extends Uint8Array | string> = WebStream<T> | NodeStream<T>;

  /**
   * EncryptArmorOptions or EncryptBinaryOptions will be used based on armor option (boolean), defaults to armoring
   */
  interface BaseEncryptOptions {
    /** message to be encrypted as created by openpgp.message.fromText or openpgp.message.fromBinary */
    message: message.Message;
    /** (optional) array of keys or single key, used to encrypt the message */
    publicKeys?: key.Key | key.Key[];
    /** (optional) private keys for signing. If omitted message will not be signed */
    privateKeys?: key.Key | key.Key[];
    /** (optional) array of passwords or a single password to encrypt the message */
    passwords?: string | string[];
    /** (optional) session key in the form: { data:Uint8Array, algorithm:String } */
    sessionKey?: SessionKey;
    /** (optional) which compression algorithm to compress the message with, defaults to what is specified in config */
    compression?: enums.compression;
    /** (optional) whether to return data as a stream. Defaults to the type of stream `message` was created from, if any. */
    streaming?: 'web' | 'node' | false;
    /** (optional) if the signature should be detached (if true, signature will be added to returned object) */
    detached?: boolean;
    /** (optional) a detached signature to add to the encrypted message */
    signature?: signature.Signature;
    /** (optional) if the unencrypted session key should be added to returned object */
    returnSessionKey?: boolean;
    /** (optional) encrypt as of a certain date */
    date?: Date;
    /** (optional) use a key ID of 0 instead of the public key IDs */
    wildcard?: boolean;
    /** (optional) user ID to sign with, e.g. { name:'Steve Sender', email:'steve@openpgp.org' } */
    fromUserId?: UserId;
    /** (optional) user ID to encrypt for, e.g. { name:'Robert Receiver', email:'robert@openpgp.org' } */
    toUserId?: UserId;
  }

  export type EncryptOptions = BaseEncryptOptions | EncryptArmorOptions | EncryptBinaryOptions;

  export interface EncryptArmorOptions extends BaseEncryptOptions {
    /** if the return values should be ascii armored or the message/signature objects */
    armor: true;
  }

  export interface EncryptBinaryOptions extends BaseEncryptOptions {
    /** if the return values should be ascii armored or the message/signature objects */
    armor: false;
  }

  // ########################

  export namespace packet {

    // todo - check this - ListPacket? PacketList? List?
    export class List<PACKET_TYPE> extends Array<PACKET_TYPE> {
      [index: number]: PACKET_TYPE;
      public length: number;
      public read(bytes: Uint8Array): void;
      public write(): Uint8Array;
      public push(...packet: PACKET_TYPE[]): number;
      public pop(): PACKET_TYPE;
      public filter(callback: (packet: PACKET_TYPE, i: number, self: List<PACKET_TYPE>) => void): List<PACKET_TYPE>;
      public filterByTag(...args: enums.packet[]): List<PACKET_TYPE>;
      public forEach(callback: (packet: PACKET_TYPE, i: number, self: List<PACKET_TYPE>) => void): void;
      public map<RETURN_TYPE>(callback: (packet: PACKET_TYPE, i: number, self: List<PACKET_TYPE>) => RETURN_TYPE): List<RETURN_TYPE>;
      // some()
      // every()
      // findPacket()
      // indexOfTag()
      // slice()
      // concat()
      // fromStructuredClone()
    }

    function fromStructuredClone(packetClone: object): AnyPacket;

    function newPacketFromTag(tag: enums.packetNames): AnyPacket;
  }

  export interface EncryptArmorResult {
    data: string;
    signature?: string;
  }

  export interface EncryptBinaryResult {
    message: message.Message;
    signature?: signature.Signature;
  }

  export type EncryptResult = EncryptArmorResult | EncryptBinaryResult;

  export interface SignArmorResult {
    data: string | Stream<string>;
    signature: string | Stream<string>;
  }

  export interface SignBinaryResult {
    message: message.Message | cleartext.CleartextMessage;
    signature: signature.Signature;
  }

  export type SignResult = SignArmorResult | SignBinaryResult;

  export interface DecryptOptions {
    /** the message object with the encrypted data */
    message: message.Message;
    /** (optional) private keys with decrypted secret key data or session key */
    privateKeys?: key.Key | key.Key[];
    /** (optional) passwords to decrypt the message */
    passwords?: string | string[];
    /** (optional) session keys in the form: { data:Uint8Array, algorithm:String } */
    sessionKeys?: SessionKey | SessionKey[];
    /** (optional) array of public keys or single key, to verify signatures */
    publicKeys?: key.Key | key.Key[];
    /** (optional) whether to return data as a string(Stream) or Uint8Array(Stream). If 'utf8' (the default), also normalize newlines. */
    format?: string;
    /** (optional) whether to return data as a stream. Defaults to the type of stream `message` was created from, if any. */
    streaming?: 'web' | 'node' | false;
    /** (optional) detached signature for verification */
    signature?: signature.Signature;
  }

  export interface SignOptions {
    message: cleartext.CleartextMessage | message.Message;
    privateKeys?: key.Key | key.Key[];
    armor?: boolean;
    streaming?: 'web' | 'node' | false;
    dataType?: DataPacketType;
    detached?: boolean;
    date?: Date;
    fromUserId?: UserId;
  }

  export interface KeyContainer {
    key: key.Key;
  }

  export interface KeyPair extends KeyContainer {
    privateKeyArmored: string;
    publicKeyArmored: string;
  }

  export interface KeyOptions {
    userIds: UserId[]; // generating a key with no user defined results in error
    passphrase?: string;
    numBits?: number;
    keyExpirationTime?: number;
    curve?: key.EllipticCurveName;
    date?: Date;
    subkeys?: KeyOptions[];
  }

  /**
   * Intended for internal use with openpgp.key.generate()
   * It's recommended that users choose openpgp.generateKey() that requires KeyOptions instead
   */
  export interface FullKeyOptions {
    userIds: UserId[];
    passphrase?: string;
    numBits?: number;
    keyExpirationTime?: number;
    curve?: key.EllipticCurveName;
    date?: Date;
    subkeys: KeyOptions[]; // required unline KeyOptions.subkeys
  }

  export interface Keyid {
    bytes: string;
  }

  export interface DecryptMessageResult {
    data: Uint8Array | string;
    signatures: signature.Signature[];
    filename: string;
  }

  /**
   * Encrypts message text/data with public keys, passwords or both at once. At least either public keys or passwords
   *   must be specified. If private keys are specified, those will be used to sign the message.
   * @param {EncryptOptions} options               See `EncryptOptions`
   * @returns {Promise<EncryptResult>}             Promise of `EncryptResult` (and optionally signed message) in the form:
   *                                                 {data: ASCII armored message if 'armor' is true;
   *                                                  message: full Message object if 'armor' is false, signature: detached signature if 'detached' is true}
   * @async
   * @static
   */
  export function encrypt(options: EncryptBinaryOptions): Promise<EncryptBinaryResult>;
  export function encrypt(options: EncryptArmorOptions | BaseEncryptOptions): Promise<EncryptArmorResult>;

  /**
   * Signs a cleartext message.
   * @param {String | Uint8Array} data           cleartext input to be signed
   * @param {utf8|binary|text|mime} dataType     (optional) data packet type
   * @param {Key|Array<Key>} privateKeys         array of keys or single key with decrypted secret key data to sign cleartext
   * @param {Boolean} armor                      (optional) if the return value should be ascii armored or the message object
   * @param {Boolean} detached                   (optional) if the return value should contain a detached signature
   * @param {Date} date                          (optional) override the creation date signature
   * @param {Object} fromUserId                  (optional) user ID to sign with, e.g. { name:'Steve Sender', email:'steve@openpgp.org' }
   * @returns {Promise<Object>}                    signed cleartext in the form:
   *                                               {data: ASCII armored message if 'armor' is true;
   *                                                message: full Message object if 'armor' is false, signature: detached signature if 'detached' is true}
   * @async
   * @static
   */
  export function sign(options: SignOptions): Promise<SignResult>;

  /**
   * Decrypts a message with the user's private key, a session key or a password. Either a private key;
   *   a session key or a password must be specified.
   * @param {DecryptOptions} options           see `DecryptOptions`
   * @returns {Promise<DecryptMessageResult>}  Promise of `DecryptMessageResult` and verified message in the form:
   *                                        { data:Uint8Array|String, filename:String, signatures:[{ keyid:String, valid:Boolean }] }
   * @async
   * @static
   */
  export function decrypt(options: DecryptOptions): Promise<DecryptMessageResult>;

  /**
   * Generates a new OpenPGP key pair. Supports RSA and ECC keys. Primary and subkey will be of same type.
   * @param {Array<Object>} userIds   array of user IDs e.g. [{ name:'Phil Zimmermann', email:'phil@openpgp.org' }]
   * @param {String} passphrase       (optional) The passphrase used to encrypt the resulting private key
   * @param {Number} numBits          (optional) number of bits for RSA keys: 2048 or 4096.
   * @param {Number} keyExpirationTime (optional) The number of seconds after the key creation time that the key expires
   * @param {String} curve            (optional) elliptic curve for ECC keys:
   *                                              curve25519, p256, p384, p521, secp256k1;
   *                                              brainpoolP256r1, brainpoolP384r1, or brainpoolP512r1.
   * @param {Date} date               (optional) override the creation date of the key and the key signatures
   * @param {Array<Object>} subkeys   (optional) options for each subkey, default to main key options. e.g. [{sign: true, passphrase: '123'}]
   *                                              sign parameter defaults to false, and indicates whether the subkey should sign rather than encrypt
   * @returns {Promise<Object>}         The generated key object in the form:
   *                                    { key:Key, privateKeyArmored:String, publicKeyArmored:String }
   * @async
   * @static
   */
  export function generateKey(options: KeyOptions): Promise<KeyPair>;

  /* ############## v5 KEY #################### */

  function readArmoredKey(armoredText: string): Promise<key.Key>;
  function readKey(data: Uint8Array): Promise<key.Key>;
  function readArmoredKeys(armoredText: string): Promise<key.Key[]>;
  function readKeys(data: Uint8Array): Promise<key.Key[]>;

  /* ############## v5 SIG #################### */

  function readArmoredSignature(armoredText: string): Promise<signature.Signature>;
  function readSignature(input: Uint8Array): Promise<signature.Signature>;

  /* ############## v5 CLEARTEXT #################### */

  function readArmoredCleartextMessage(armoredText: string): Promise<cleartext.CleartextMessage>;
  function fromText(text: string): cleartext.CleartextMessage;

  /* ############## v5 MSG #################### */

  function readArmoredMessage(armoredText: string | Stream<string>): Promise<message.Message>;
  function readMessage(input: Uint8Array): Promise<message.Message>;
  function fromBinary(bytes: Uint8Array | Stream<Uint8Array>, filename?: string, date?: Date, type?: DataPacketType): message.Message;
  function fromText(text: string | Stream<string>, filename?: string, date?: Date, type?: DataPacketType): message.Message;

  /* ############## v5 PACKET #################### */

  class BasePacket {
    public tag: enums.packet;
    public read(bytes: Uint8Array): void;
    public write(): Uint8Array;
  }

  class BaseKeyPacket extends BasePacket {
    // fingerprint: Uint8Array|null; - not included because not recommended to use. Use getFingerprint() or getFingerprintBytes()
    public algorithm: enums.publicKey;
    public created: Date;

    public version: number;
    public expirationTimeV3: number | null;
    public keyExpirationTime: number | null;
    public getBitSize(): number;
    public getAlgorithmInfo(): key.AlgorithmInfo;
    public getFingerprint(): string;
    public getFingerprintBytes(): Uint8Array | null;
    public getCreationTime(): Date;
    public getKeyId(): Keyid;
    public params: object[];
    public isDecrypted(): boolean;
    public isEncrypted: boolean; // may be null, false or true
  }

  class BasePrimaryKeyPacket extends BaseKeyPacket {
  }

  export class CompressedDataPacket extends BasePacket {
    public tag: enums.packet.compressed;
  }

  export class SymEncryptedIntegrityProtectedDataPacket extends BasePacket {
    public tag: enums.packet.symEncryptedIntegrityProtected;
  }

  export class AEADEncryptedDataPacket extends BasePacket {
    public tag: enums.packet.AEADEncryptedDataPacket;
  }

  export class PublicKeyEncryptedSessionKeyPaclet extends BasePacket {
    public tag: enums.packet.publicKeyEncryptedSessionKey;
  }

  export class SymEncryptedSessionKey extends BasePacket {
    public tag: enums.packet.symEncryptedSessionKey;
  }

  export class LiteralDataPacket extends BasePacket {
    public tag: enums.packet.literal;
  }

  export class PublicKeyPacket extends BasePrimaryKeyPacket {
    public tag: enums.packet.publicKey;
  }

  export class SymmetricallyEncryptedDataPacket extends BasePacket {
    public tag: enums.packet.symmetricallyEncrypted;
  }

  export class MarkerPacket extends BasePacket {
    public tag: enums.packet.marker;
  }

  export class PublicSubkeyPacket extends BaseKeyPacket {
    public tag: enums.packet.publicSubkey;
  }

  export class UserAttributePacket extends BasePacket {
    public tag: enums.packet.userAttribute;
  }

  export class OnePassSignaturePacket extends BasePacket {
    public tag: enums.packet.onePassSignature;
    public correspondingSig?: Promise<SignaturePacket>;
  }

  export class SecretKeyPacket extends BasePrimaryKeyPacket {
    public tag: enums.packet.secretKey;
    // encrypted: null | unknown[]; // Encrypted secret-key data, not meant for public use
    public s2k: { type: string } | null;
    public encrypt(passphrase: string): Promise<boolean>;
    public decrypt(passphrase: string): Promise<true>;
  }

  export class UserIDPacket extends BasePacket {
    public tag: enums.packet.userid;
    public userid: string;
  }

  export class SecretSubkeyPacket extends BaseKeyPacket {
    public tag: enums.packet.secretSubkey;
    // encrypted: null | unknown[]; // Encrypted secret-key data, not meant for public use
    public s2k: { type: string } | null;
    public encrypt(passphrase: string): Promise<boolean>;
    public decrypt(passphrase: string): Promise<true>;
  }

  export class SignaturePacket extends BasePacket {
    public tag: enums.packet.signature;
    public version: number;
    public signatureType: null | number;
    public hashAlgorithm: null | number;
    public publicKeyAlgorithm: null | number;
    public signatureData: null | Uint8Array;
    public unhashedSubpackets: null | Uint8Array;
    public signedHashValue: null | Uint8Array;
    public created: Date;
    public signatureExpirationTime: null | number;
    public signatureNeverExpires: boolean;
    public exportable: null | boolean;
    public trustLevel: null | number;
    public trustAmount: null | number;
    public regularExpression: null | number;
    public revocable: null | boolean;
    public keyExpirationTime: null | number;
    public keyNeverExpires: null | boolean;
    public preferredSymmetricAlgorithms: null | number[];
    public revocationKeyClass: null | number;
    public revocationKeyAlgorithm: null | number;
    public revocationKeyFingerprint: null | Uint8Array;
    public issuerKeyId: Keyid;
    public notation: null | { [name: string]: string };
    public preferredHashAlgorithms: null | number[];
    public preferredCompressionAlgorithms: null | number[];
    public keyServerPreferences: null | number[];
    public preferredKeyServer: null | string;
    public isPrimaryUserID: null | boolean;
    public policyURI: null | string;
    public keyFlags: null | number[];
    public signersUserId: null | string;
    public reasonForRevocationFlag: null | number;
    public reasonForRevocationString: null | string;
    public features: null | number[];
    public signatureTargetPublicKeyAlgorithm: null | number;
    public signatureTargetHashAlgorithm: null | number;
    public signatureTargetHash: null | string;
    public embeddedSignature: null | SignaturePacket;
    public issuerKeyVersion: null | number;
    public issuerFingerprint: null | Uint8Array;
    public preferredAeadAlgorithms: null | Uint8Array;
    public verified: null | boolean;
    public revoked: null | boolean;
    public sign(key: SecretKeyPacket | SecretSubkeyPacket, data: Uint8Array): true;
    public isExpired(date?: Date): boolean;
    public getExpirationTime(): Date | typeof Infinity;
  }

  export class TrustPacket extends BasePacket {
    public tag: enums.packet.trust;
  }

  export type AnyPacket = CompressedDataPacket | SymEncryptedIntegrityProtectedDataPacket | AEADEncryptedDataPacket | PublicKeyEncryptedSessionKeyPaclet | SymEncryptedSessionKey | LiteralDataPacket
    | PublicKeyPacket | SymmetricallyEncryptedDataPacket | MarkerPacket | PublicSubkeyPacket | UserAttributePacket | OnePassSignaturePacket | SecretKeyPacket | UserIDPacket | SecretSubkeyPacket | SignaturePacket | TrustPacket;
  export type AnySecretPacket = SecretKeyPacket | SecretSubkeyPacket;
  export type AnyKeyPacket = PublicKeyPacket | SecretKeyPacket | PublicSubkeyPacket | SecretSubkeyPacket;

  /* ############## v5 END #################### */


  /**
   * Reformats signature packets for a key and rewraps key object.
   * @param {Key} privateKey          private key to reformat
   * @param {Array<Object>} userIds   array of user IDs e.g. [{ name:'Phil Zimmermann', email:'phil@openpgp.org' }]
   * @param {String} passphrase       (optional) The passphrase used to encrypt the resulting private key
   * @param {Number} keyExpirationTime (optional) The number of seconds after the key creation time that the key expires
   * @returns {Promise<Object>}         The generated key object in the form:
   *                                    { key:Key, privateKeyArmored:String, publicKeyArmored:String }
   * @async
   * @static
   */
  export function reformatKey(options: {
    privateKey: key.Key;
    userIds?: (string | UserId)[];
    passphrase?: string;
    keyExpirationTime?: number;
  }): Promise<KeyPair>;

  /**
   * Unlock a private key with your passphrase.
   * @param {Key} privateKey                    the private key that is to be decrypted
   * @param {String|Array<String>} passphrase   the user's passphrase(s) chosen during key generation
   * @returns {Promise<Object>}                  the unlocked key object in the form: { key:Key }
   * @async
   */
  export function decryptKey(options: {
    privateKey: key.Key;
    passphrase?: string | string[];
  }): Promise<KeyContainer>;

  export function encryptKey(options: {
    privateKey: key.Key;
    passphrase?: string
  }): Promise<KeyContainer>;

  export namespace armor {
    /** Armor an OpenPGP binary packet block
     * @param messagetype type of the message
     * @param body
     * @param partindex
     * @param parttotal
     */
    function armor(messagetype: enums.armor, body: object, partindex: number, parttotal: number): string;

    /** DeArmor an OpenPGP armored message; verify the checksum and return the encoded bytes
     *
     *  @param text OpenPGP armored message
     */
    function dearmor(text: string): object;
  }

  export namespace cleartext {
    /** Class that represents an OpenPGP cleartext signed message.
     */
    interface CleartextMessage {
      /** Returns ASCII armored text of cleartext signed message
       */
      armor(): string;

      /** Returns the key IDs of the keys that signed the cleartext message
       */
      getSigningKeyIds(): Array<Keyid>;

      /** Get cleartext
       */
      getText(): string;

      /** Sign the cleartext message
       *
       *  @param privateKeys private keys with decrypted secret key data for signing
       */
      sign(privateKeys: Array<key.Key>): void;

      /** Verify signatures of cleartext signed message
       *  @param keys array of keys to verify signatures
       */
      verify(keys: key.Key[], date?: Date, streaming?: boolean): Promise<message.Verification[]>;
    }
  }

  export namespace config {
    let preferHashAlgorithm: enums.hash;
    let encryptionCipher: enums.symmetric;
    let compression: enums.compression;
    let showVersion: boolean;
    let showComment: boolean;
    let integrityProtect: boolean;
    let debug: boolean;
    let deflateLevel: number;
    let aeadProtect: boolean;
    let ignoreMdcError: boolean;
    let checksumRequired: boolean;
    let rsaBlinding: boolean;
    let passwordCollisionCheck: boolean;
    let revocationsExpire: boolean;
    let useNative: boolean;
    let zeroCopy: boolean;
    let tolerant: boolean;
    let versionString: string;
    let commentString: string;
    let keyserver: string;
    let nodeStore: string;
    let allowInsecureDecryptionWithSigningKeys: boolean;
  }

  export namespace crypto {
    interface Mpi {
      data: number;
      read(input: string): number;
      write(): string;
    }

    /** Generating a session key for the specified symmetric algorithm
     *   @param algo Algorithm to use
     */
    function generateSessionKey(algo: enums.symmetric): string;

    /** generate random byte prefix as string for the specified algorithm
     *   @param algo Algorithm to use
     */
    function getPrefixRandom(algo: enums.symmetric): string;

    /** Returns the number of integers comprising the private key of an algorithm
     *  @param algo The public key algorithm
     */
    function getPrivateMpiCount(algo: enums.symmetric): number;

    /** Decrypts data using the specified public key multiprecision integers of the private key, the specified secretMPIs of the private key and the specified algorithm.
        @param algo Algorithm to be used
        @param publicMPIs Algorithm dependent multiprecision integers of the public key part of the private key
        @param secretMPIs Algorithm dependent multiprecision integers of the private key used
        @param data Data to be encrypted as MPI
    */
    function publicKeyDecrypt(algo: enums.publicKey, publicMPIs: Array<Mpi>, secretMPIs: Array<Mpi>, data: Mpi): Mpi;

    /** Encrypts data using the specified public key multiprecision integers and the specified algorithm.
        @param algo Algorithm to be used
        @param publicMPIs Algorithm dependent multiprecision integers
        @param data Data to be encrypted as MPI
    */
    function publicKeyEncrypt(algo: enums.publicKey, publicMPIs: Array<Mpi>, data: Mpi): Array<Mpi>;

    namespace cfb {
      /** This function decrypts a given plaintext using the specified blockcipher to decrypt a message
          @param cipherfn the algorithm cipher class to decrypt data in one block_size encryption
          @param key binary string representation of key to be used to decrypt the ciphertext. This will be passed to the cipherfn
          @param ciphertext to be decrypted provided as a string
          @param resync a boolean value specifying if a resync of the IV should be used or not. The encrypteddatapacket uses the "old" style with a resync. Decryption within an encryptedintegrityprotecteddata packet is not resyncing the IV.
      */
      function decrypt(cipherfn: string, key: string, ciphertext: string, resync: boolean): string;

      /** This function encrypts a given with the specified prefixrandom using the specified blockcipher to encrypt a message
          @param prefixrandom random bytes of block_size length provided as a string to be used in prefixing the data
          @param cipherfn the algorithm cipher class to encrypt data in one block_size encryption
          @param plaintext data to be encrypted provided as a string
          @param key binary string representation of key to be used to encrypt the plaintext. This will be passed to the cipherfn
          @param resync a boolean value specifying if a resync of the IV should be used or not. The encrypteddatapacket uses the "old" style with a resync. Encryption within an encryptedintegrityprotecteddata packet is not resyncing the IV.
      */
      function encrypt(prefixrandom: string, cipherfn: string, plaintext: string, key: string, resync: boolean): string;

      /** Decrypts the prefixed data for the Modification Detection Code (MDC) computation
          @param cipherfn cipherfn.encrypt Cipher function to use
          @param key binary string representation of key to be used to check the mdc This will be passed to the cipherfn
          @param ciphertext The encrypted data
      */
      function mdc(cipherfn: object, key: string, ciphertext: string): string;
    }

    namespace hash {
      /** Create a hash on the specified data using the specified algorithm
          @param algo Hash algorithm type
          @param data Data to be hashed
      */
      function digest(algo: enums.hash, data: Uint8Array): Promise<Uint8Array>;

      /** Returns the hash size in bytes of the specified hash algorithm type
          @param algo Hash algorithm type
      */
      function getHashByteLength(algo: enums.hash): number;
    }

    namespace random {
      /** Retrieve secure random byte string of the specified length
          @param length Length in bytes to generate
      */
      function getRandomBytes(length: number): Promise<Uint8Array>;
    }

    namespace signature {
      /** Create a signature on data using the specified algorithm
          @param hash_algo hash Algorithm to use
          @param algo Asymmetric cipher algorithm to use
          @param publicMPIs Public key multiprecision integers of the private key
          @param secretMPIs Private key multiprecision integers which is used to sign the data
          @param data Data to be signed
      */
      function sign(hash_algo: enums.hash, algo: enums.publicKey, publicMPIs: Array<Mpi>, secretMPIs: Array<Mpi>, data: string): Mpi;

      /**
          @param algo public Key algorithm
          @param hash_algo Hash algorithm
          @param msg_MPIs Signature multiprecision integers
          @param publickey_MPIs Public key multiprecision integers
          @param data Data on where the signature was computed on
      */
      function verify(algo: enums.publicKey, hash_algo: enums.hash, msg_MPIs: Array<Mpi>, publickey_MPIs: Array<Mpi>, data: string): boolean;
    }
  }

  export namespace enums {

    function read(type: typeof armor, e: armor): armorNames | string | any;
    function read(type: typeof compression, e: compression): compressionNames | string | any;
    function read(type: typeof hash, e: hash): hashNames | string | any;
    function read(type: typeof packet, e: packet): packetNames | string | any;
    function read(type: typeof publicKey, e: publicKey): publicKeyNames | string | any;
    function read(type: typeof symmetric, e: symmetric): symmetricNames | string | any;
    function read(type: typeof keyStatus, e: keyStatus): keyStatusNames | string | any;
    function read(type: typeof keyFlags, e: keyFlags): keyFlagsNames | string | any;

    export type armorNames = 'multipartSection' | 'multipartLast' | 'signed' | 'message' | 'publicKey' | 'privateKey';
    enum armor {
      multipartSection = 0,
      multipartLast = 1,
      signed = 2,
      message = 3,
      publicKey = 4,
      privateKey = 5,
      signature = 6,
    }

    enum reasonForRevocation {
      noReason = 0, // No reason specified (key revocations or cert revocations)
      keySuperseded = 1, // Key is superseded (key revocations)
      keyCompromised = 2, // Key material has been compromised (key revocations)
      keyRetired = 3, // Key is retired and no longer used (key revocations)
      useridInvalid = 32, // User ID information is no longer valid (cert revocations)
    }

    export type compressionNames = 'uncompressed' | 'zip' | 'zlib' | 'bzip2';
    enum compression {
      uncompressed = 0,
      zip = 1,
      zlib = 2,
      bzip2 = 3,
    }

    export type hashNames = 'md5' | 'sha1' | 'ripemd' | 'sha256' | 'sha384' | 'sha512' | 'sha224';
    enum hash {
      md5 = 1,
      sha1 = 2,
      ripemd = 3,
      sha256 = 8,
      sha384 = 9,
      sha512 = 10,
      sha224 = 11,
    }

    export type packetNames = 'publicKeyEncryptedSessionKey' | 'signature' | 'symEncryptedSessionKey' | 'onePassSignature' | 'secretKey' | 'publicKey'
      | 'secretSubkey' | 'compressed' | 'symmetricallyEncrypted' | 'marker' | 'literal' | 'trust' | 'userid' | 'publicSubkey' | 'userAttribute'
      | 'symEncryptedIntegrityProtected' | 'modificationDetectionCode' | 'AEADEncryptedDataPacket';
    enum packet {
      publicKeyEncryptedSessionKey = 1,
      signature = 2,
      symEncryptedSessionKey = 3,
      onePassSignature = 4,
      secretKey = 5,
      publicKey = 6,
      secretSubkey = 7,
      compressed = 8,
      symmetricallyEncrypted = 9,
      marker = 10,
      literal = 11,
      trust = 12,
      userid = 13,
      publicSubkey = 14,
      userAttribute = 17,
      symEncryptedIntegrityProtected = 18,
      modificationDetectionCode = 19,
      AEADEncryptedDataPacket = 20,
    }

    export type publicKeyNames = 'rsaEncryptSign' | 'rsaEncrypt' | 'rsaSign' | 'elgamal' | 'dsa' | 'ecdh' | 'ecdsa' | 'eddsa' | 'aedh' | 'aedsa';
    enum publicKey {
      rsaEncryptSign = 1,
      rsaEncrypt = 2,
      rsaSign = 3,
      elgamal = 16,
      dsa = 17,
      ecdh = 18,
      ecdsa = 19,
      eddsa = 22,
      aedh = 23,
      aedsa = 24,
    }

    export type symmetricNames = 'plaintext' | 'idea' | 'tripledes' | 'cast5' | 'blowfish' | 'aes128' | 'aes192' | 'aes256' | 'twofish';
    enum symmetric {
      plaintext = 0,
      idea = 1,
      tripledes = 2,
      cast5 = 3,
      blowfish = 4,
      aes128 = 7,
      aes192 = 8,
      aes256 = 9,
      twofish = 10,
    }

    export type keyStatusNames = 'invalid' | 'expired' | 'revoked' | 'valid' | 'noSelfCert';
    enum keyStatus {
      invalid = 0,
      expired = 1,
      revoked = 2,
      valid = 3,
      noSelfCert = 4,
    }

    export type keyFlagsNames = 'certifyKeys' | 'signData' | 'encryptCommunication' | 'encryptStorage' | 'splitPrivateKey' | 'authentication'
      | 'sharedPrivateKey';
    enum keyFlags {
      certifyKeys = 1,
      signData = 2,
      encryptCommunication = 4,
      encryptStorage = 8,
      splitPrivateKey = 16,
      authentication = 32,
      sharedPrivateKey = 128,
    }

  }

  export namespace key {

    export type EllipticCurveName = 'curve25519' | 'p256' | 'p384' | 'p521' | 'secp256k1' | 'brainpoolP256r1' | 'brainpoolP384r1' | 'brainpoolP512r1';

    /** Class that represents an OpenPGP key. Must contain a primary key. Can contain additional subkeys, signatures, user ids, user attributes.
     */
    class Key {
      public primaryKey: PublicKeyPacket | SecretKeyPacket;
      public subKeys: SubKey[];
      public users: User[];
      public revocationSignatures: SignaturePacket[];
      public keyPacket: PublicKeyPacket | SecretKeyPacket;
      constructor(packetlist: packet.List<AnyPacket>);
      public armor(): string;
      public decrypt(passphrase: string | string[], keyId?: Keyid): Promise<boolean>;
      public encrypt(passphrase: string | string[]): Promise<void>;
      public getExpirationTime(capability?: 'encrypt' | 'encrypt_sign' | 'sign' | null, keyId?: Keyid | null, userId?: UserId | null): Promise<Date | typeof Infinity | null>; // Returns null if `capabilities` is passed and the key does not have the specified capabilities or is revoked or invalid.
      public getKeyIds(): Keyid[];
      public getPrimaryUser(): Promise<PrimaryUser>; // throws on err
      public getUserIds(): string[];
      public isPrivate(): boolean;
      public isPublic(): boolean;
      public toPublic(): Key;
      public update(key: Key): void;
      public verifyPrimaryKey(): Promise<void>; // throws on err
      public isRevoked(): Promise<boolean>;
      public revoke(reason: { flag?: enums.reasonForRevocation; string?: string; }, date?: Date): Promise<Key>;
      public getRevocationCertificate(): Promise<Stream<string> | string | undefined>;
      public getEncryptionKey(keyid?: Keyid | null, date?: Date, userId?: UserId | null): Promise<key.Key | key.SubKey | null>;
      public getSigningKey(keyid?: Keyid | null, date?: Date, userId?: UserId | null): Promise<key.Key | key.SubKey | null>;
      public getKeys(keyId?: Keyid): (Key | SubKey)[];
      public isDecrypted(): boolean;
      public isFullyEncrypted(): boolean;
      public isFullyDecrypted(): boolean;
      public isPacketDecrypted(keyId: Keyid): boolean;
      public getFingerprint(): string;
      public getCreationTime(): Date;
      public getAlgorithmInfo(): AlgorithmInfo;
      public getKeyId(): Keyid;
    }

    class SubKey {
      public subKey: SecretSubkeyPacket | PublicSubkeyPacket;
      public keyPacket: SecretKeyPacket;
      public bindingSignatures: SignaturePacket[];
      public revocationSignatures: SignaturePacket[];
      constructor(subKeyPacket: SecretSubkeyPacket | PublicSubkeyPacket);
      public verify(primaryKey: PublicKeyPacket | SecretKeyPacket): Promise<enums.keyStatus>;
      public isDecrypted(): boolean;
      public getFingerprint(): string;
      public getCreationTime(): Date;
      public getAlgorithmInfo(): AlgorithmInfo;
      public getKeyId(): Keyid;
    }

    export interface User {
      userId: UserIDPacket | null;
      userAttribute: UserAttributePacket | null;
      selfCertifications: SignaturePacket[];
      otherCertifications: SignaturePacket[];
      revocationSignatures: SignaturePacket[];
    }

    export interface PrimaryUser {
      index: number;
      user: User;
    }

    type AlgorithmInfo = {
      algorithm: enums.publicKeyNames;
      bits: number;
    };

    /** Generates a new OpenPGP key. Currently only supports RSA keys. Primary and subkey will be of same type.
      *  @param options
      */
    function generate(options: FullKeyOptions): Promise<Key>;

  }

  export namespace signature {
    class Signature {
      public packets: packet.List<SignaturePacket>;
      constructor(packetlist: packet.List<SignaturePacket>);
      public armor(): string;
    }
  }

  export namespace message {
    /** Class that represents an OpenPGP message. Can be an encrypted message, signed message, compressed message or literal message
     */
    class Message {

      public packets: packet.List<AnyPacket>;
      constructor(packetlist: packet.List<AnyPacket>);

      /** Returns ASCII armored text of message
       */
      public armor(): string;

      /** Decrypt the message
          @param privateKey private key with decrypted secret data
      */
      public decrypt(privateKeys?: key.Key[] | null, passwords?: string[] | null, sessionKeys?: SessionKey[] | null, streaming?: boolean): Promise<Message>;

      /** Encrypt the message
          @param keys array of keys, used to encrypt the message
      */
      public encrypt(keys: key.Key[]): Promise<Message>;

      /** Returns the key IDs of the keys to which the session key is encrypted
       */
      public getEncryptionKeyIds(): Keyid[];

      /** Get literal data that is the body of the message
       */
      public getLiteralData(): Uint8Array | null | Stream<Uint8Array>;

      /** Returns the key IDs of the keys that signed the message
       */
      public getSigningKeyIds(): Keyid[];

      /** Get literal data as text
       */
      public getText(): string | null | Stream<string>;

      public getFilename(): string | null;

      /** Sign the message (the literal data packet of the message)
          @param privateKey private keys with decrypted secret key data for signing
      */
      public sign(privateKey: key.Key[]): Promise<Message>;

      /** Unwrap compressed message
       */
      public unwrapCompressed(): Message;

      /** Verify message signatures
          @param keys array of keys to verify signatures
      */
      public verify(keys: key.Key[], date?: Date, streaming?: boolean): Promise<Verification[]>;

      /**
       * Append signature to unencrypted message object
       * @param {String|Uint8Array} detachedSignature The detached ASCII-armored or Uint8Array PGP signature
       */
      public appendSignature(detachedSignature: string | Uint8Array): Promise<void>;
    }

    class SessionKey { // todo

    }

    export interface Verification {
      keyid: Keyid;
      verified: Promise<null | boolean>;
      signature: Promise<signature.Signature>;
    }
  }

  export class HKP {
    constructor(keyServerBaseUrl?: string);
    public lookup(options: { keyid?: string, query?: string }): Promise<string | undefined>;
  }

  /**
   * todo - some of these are outdated - check OpenPGP.js api
   */
  export namespace util {
    /** Convert an array of integers(0.255) to a string
        @param bin An array of (binary) integers to convert
    */
    function bin2str(bin: Array<number>): string;

    /** Calculates a 16bit sum of a string by adding each character codes modulus 65535
        @param text string to create a sum of
    */
    function calcChecksum(text: string): number;

    /** Convert a string of utf8 bytes to a native javascript string
        @param utf8 A valid squence of utf8 bytes
    */
    function decodeUtf8(utf8: string): string;

    /** Convert a native javascript string to a string of utf8 bytes
        param str The string to convert
    */
    function encodeUtf8(str: string): string;

    /** Return the algorithm type as string
     */
    function getHashAlgorithmString(): string;

    /** Get native Web Cryptography api. The default configuration is to use the api when available. But it can also be deactivated with config.useWebCrypto
     */
    function getWebCrypto(): object;

    /** Helper function to print a debug message. Debug messages are only printed if
        @param str string of the debug message
    */
    function printDebug(str: string): void;

    /** Helper function to print a debug message. Debug messages are only printed if
        @param str string of the debug message
    */
    function printDebugHexstrDump(str: string): void;

    /** Shifting a string to n bits right
        @param value The string to shift
        @param bitcount Amount of bits to shift (MUST be smaller than 9)
    */
    function shiftRight(value: string, bitcount: number): string;

    /**
     * Convert a string to an array of 8-bit integers
     * @param {String} str String to convert
     * @returns {Uint8Array} An array of 8-bit integers
     */
    function strToUint8Array(str: string): Uint8Array;

    /**
     * Convert an array of 8-bit integers to a string
     * @param {Uint8Array} bytes An array of 8-bit integers to convert
     * @returns {String} String representation of the array
     */
    function uint8ArrayToStr(bin: Uint8Array): string;

    /**
     * Convert an array of 8-bit integers to a hex string
     * @param {Uint8Array} bytes Array of 8-bit integers to convert
     * @returns {String} Hexadecimal representation of the array
     */
    function uint8ArrayToHex(bytes: Uint8Array): string;

    function uint8ArrayToB64(bytes: Uint8Array): string;

    function uint8ArrayToMpi(bytes: Uint8Array): unknown; // todo - MPI

    /**
     * Convert a hex string to an array of 8-bit integers
     * @param {String} hex  A hex string to convert
     * @returns {Uint8Array} An array of 8-bit integers
     */
    function hexToUint8Array(hex: string): Uint8Array;

    /**
     * Create hex string from a binary
     * @param {String} str String to convert
     * @returns {String} String containing the hexadecimal values
     */
    function strToHex(str: string): string;

    /**
     * Create binary string from a hex encoded string
     * @param {String} str Hex string to convert
     * @returns {String}
     */
    function hexToStr(hex: string): string;

    function parseUserId(userid: string): UserId;

    function formatUserId(userid: UserId): string;

    function normalizeDate(date: Date | null): Date | null;

    /**
     * Encode input buffer using Z-Base32 encoding.
     * See: https://tools.ietf.org/html/rfc6189#section-5.1.6
     *
     * @param {Uint8Array} data The binary data to encode
     * @returns {String} Binary data encoded using Z-Base32
     */
    function encodeZBase32(data: Uint8Array): string;
  }

  export namespace stream {
    function readToEnd<T extends Uint8Array | string>(input: Stream<T> | T, concat?: (list: T[]) => T): Promise<T>;
    // concat
    // slice
    // clone
    // webToNode
    // nodeToWeb
  }

}

