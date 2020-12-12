/**
 * Type definitions for OpenPGP.js http://openpgpjs.org/
 * 
 * Contributors:
 *  - FlowCrypt a. s. <https://flowcrypt.com>
 *  - Guillaume Lacasa <https://blog.lacasa.fr>
 *  - Errietta Kostala <https://github.com/errietta>
 */

/* ############## v5 KEY #################### */

export function readArmoredKey(armoredText: string): Promise<Key>;
export function readKey(data: Uint8Array): Promise<Key>;
export function readArmoredKeys(armoredText: string): Promise<Key[]>;
export function readKeys(data: Uint8Array): Promise<Key[]>;
export function generateKey(options: KeyOptions): Promise<KeyPair>;
export function generateSessionKey(options: { publicKeys: Key[], date?: Date, toUserIds?: UserId[] }): Promise<SessionKey>;
export function decryptKey(options: { privateKey: Key; passphrase?: string | string[]; }): Promise<Key>;
export function encryptKey(options: { privateKey: Key; passphrase?: string }): Promise<Key>;
export function reformatKey(options: { privateKey: Key; userIds?: (string | UserId)[]; passphrase?: string; keyExpirationTime?: number; }): Promise<KeyPair>;

export class Key {
  public primaryKey: PublicKeyPacket | SecretKeyPacket;
  public subKeys: SubKey[];
  public users: User[];
  public revocationSignatures: SignaturePacket[];
  public keyPacket: PublicKeyPacket | SecretKeyPacket;
  constructor(packetlist: PacketList<AnyPacket>);
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
  public getEncryptionKey(keyid?: Keyid | null, date?: Date, userId?: UserId | null): Promise<Key | SubKey | null>;
  public getSigningKey(keyid?: Keyid | null, date?: Date, userId?: UserId | null): Promise<Key | SubKey | null>;
  public getKeys(keyId?: Keyid): (Key | SubKey)[];
  public isDecrypted(): boolean;
  public getFingerprint(): string;
  public getCreationTime(): Date;
  public getAlgorithmInfo(): AlgorithmInfo;
  public getKeyId(): Keyid;
}

export class SubKey {
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

/* ############## v5 SIG #################### */

export function readArmoredSignature(armoredText: string): Promise<Signature>;
export function readSignature(input: Uint8Array): Promise<Signature>;

export class Signature {
  public packets: PacketList<SignaturePacket>;
  constructor(packetlist: PacketList<SignaturePacket>);
  public armor(): string;
}

export interface VerificationResult {
  keyid: Keyid;
  verified: Promise<null | boolean>;
  signature: Promise<Signature>;
}

/* ############## v5 CLEARTEXT #################### */

export function readArmoredCleartextMessage(armoredText: string): Promise<CleartextMessage>;

/** Class that represents an OpenPGP cleartext signed message.
 */
export class CleartextMessage {
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
  sign(privateKeys: Array<Key>): void;

  /** Verify signatures of cleartext signed message
   *  @param keys array of keys to verify signatures
   */
  verify(keys: Key[], date?: Date, streaming?: boolean): Promise<VerificationResult[]>;

  static fromText(text: string): CleartextMessage;
}

/* ############## v5 MSG #################### */

export function readArmoredMessage<T extends MaybeStream<string>>(armoredText: T): Promise<Message<T>>;
export function readMessage<T extends MaybeStream<Uint8Array>>(input: T): Promise<Message<T>>;

export function encrypt<T extends 'web' | 'node' | false>(options: EncryptOptions & { streaming: T, armor: false }): Promise<
  T extends 'web' ? WebStream<Uint8Array> :
  T extends 'node' ? NodeStream<Uint8Array> :
  Uint8Array
>;
export function encrypt<T extends 'web' | 'node' | false>(options: EncryptOptions & { streaming: T }): Promise<
  T extends 'web' ? WebStream<string> :
  T extends 'node' ? NodeStream<string> :
  string
>;
export function encrypt<T extends MaybeStream<Data>>(options: EncryptOptions & { message: Message<T>, armor: false }): Promise<
  T extends WebStream<infer X> ? WebStream<Uint8Array> :
  T extends NodeStream<infer X> ? NodeStream<Uint8Array> :
  Uint8Array
>;
export function encrypt<T extends MaybeStream<Data>>(options: EncryptOptions & { message: Message<T> }): Promise<
  T extends WebStream<infer X> ? WebStream<string> :
  T extends NodeStream<infer X> ? NodeStream<string> :
  string
>;

export function sign<T extends 'web' | 'node' | false>(options: SignOptions & { streaming: T, armor: false }): Promise<
  T extends 'web' ? WebStream<Uint8Array> :
  T extends 'node' ? NodeStream<Uint8Array> :
  Uint8Array
>;
export function sign<T extends 'web' | 'node' | false>(options: SignOptions & { streaming: T }): Promise<
  T extends 'web' ? WebStream<string> :
  T extends 'node' ? NodeStream<string> :
  string
>;
export function sign<T extends MaybeStream<Data>>(options: SignOptions & { message: Message<T>, armor: false }): Promise<
  T extends WebStream<infer X> ? WebStream<Uint8Array> :
  T extends NodeStream<infer X> ? NodeStream<Uint8Array> :
  Uint8Array
>;
export function sign<T extends MaybeStream<Data>>(options: SignOptions & { message: Message<T> }): Promise<
  T extends WebStream<infer X> ? WebStream<string> :
  T extends NodeStream<infer X> ? NodeStream<string> :
  string
>;
export function sign(options: SignOptions & { message: CleartextMessage }): Promise<string>;

export function decrypt<T extends 'web' | 'node' | false>(options: DecryptOptions & { streaming: T, format: 'binary' }): Promise<DecryptMessageResult & {
  data:
  T extends 'web' ? WebStream<Uint8Array> :
  T extends 'node' ? NodeStream<Uint8Array> :
  Uint8Array
}>;
export function decrypt<T extends 'web' | 'node' | false>(options: DecryptOptions & { streaming: T }): Promise<DecryptMessageResult & {
  data:
  T extends 'web' ? WebStream<string> :
  T extends 'node' ? NodeStream<string> :
  string
}>;
export function decrypt<T extends MaybeStream<Data>>(options: DecryptOptions & { message: Message<T>, format: 'binary' }): Promise<DecryptMessageResult & {
  data:
  T extends WebStream<infer X> ? WebStream<Uint8Array> :
  T extends NodeStream<infer X> ? NodeStream<Uint8Array> :
  Uint8Array
}>;
export function decrypt<T extends MaybeStream<Data>>(options: DecryptOptions & { message: Message<T> }): Promise<DecryptMessageResult & {
  data:
  T extends WebStream<infer X> ? WebStream<string> :
  T extends NodeStream<infer X> ? NodeStream<string> :
  string
}>;

export function verify<T extends 'web' | 'node' | false>(options: VerifyOptions & { streaming: T, format: 'binary' }): Promise<VerifyMessageResult & {
  data:
  T extends 'web' ? WebStream<Uint8Array> :
  T extends 'node' ? NodeStream<Uint8Array> :
  Uint8Array
}>;
export function verify<T extends 'web' | 'node' | false>(options: VerifyOptions & { streaming: T }): Promise<VerifyMessageResult & {
  data:
  T extends 'web' ? WebStream<string> :
  T extends 'node' ? NodeStream<string> :
  string
}>;
export function verify<T extends MaybeStream<Data>>(options: VerifyOptions & { message: Message<T>, format: 'binary' }): Promise<VerifyMessageResult & {
  data:
  T extends WebStream<infer X> ? WebStream<Uint8Array> :
  T extends NodeStream<infer X> ? NodeStream<Uint8Array> :
  Uint8Array
}>;
export function verify<T extends MaybeStream<Data>>(options: VerifyOptions & { message: Message<T> }): Promise<VerifyMessageResult & {
  data:
  T extends WebStream<infer X> ? WebStream<string> :
  T extends NodeStream<infer X> ? NodeStream<string> :
  string
}>;

/** Class that represents an OpenPGP message.  Can be an encrypted message, signed message, compressed message or literal message
 */
export class Message<T extends MaybeStream<Data>> {

  public packets: PacketList<AnyPacket>;
  constructor(packetlist: PacketList<AnyPacket>);

  /** Returns ASCII armored text of message
   */
  public armor(): string;

  /** Decrypt the message
      @param privateKey private key with decrypted secret data
  */
  public decrypt(privateKeys?: Key[] | null, passwords?: string[] | null, sessionKeys?: SessionKey[] | null, streaming?: boolean): Promise<Message<MaybeStream<Data>>>;

  /** Encrypt the message
      @param keys array of keys, used to encrypt the message
  */
  public encrypt(keys: Key[]): Promise<Message<MaybeStream<Data>>>;

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
  public sign(privateKey: Key[]): Promise<Message<T>>;

  /** Unwrap compressed message
   */
  public unwrapCompressed(): Message<T>;

  /** Verify message signatures
      @param keys array of keys to verify signatures
  */
  public verify(keys: Key[], date?: Date, streaming?: boolean): Promise<VerificationResult[]>;

  /**
   * Append signature to unencrypted message object
   * @param {String|Uint8Array} detachedSignature The detached ASCII-armored or Uint8Array PGP signature
   */
  public appendSignature(detachedSignature: string | Uint8Array): Promise<void>;

  static fromText<T extends MaybeStream<string>>(text: T, filename?: string, date?: Date, type?: DataPacketType): Message<T>;
  static fromBinary<T extends MaybeStream<Uint8Array>>(bytes: T, filename?: string, date?: Date, type?: DataPacketType): Message<T>;
}


/* ############## v5 CONFIG #################### */

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

/* ############## v5 PACKET #################### */

declare class BasePacket {
  public tag: enums.packet;
  public read(bytes: Uint8Array): void;
  public write(): Uint8Array;
}

declare class BaseKeyPacket extends BasePacket {
  // fingerprint: Uint8Array|null; - not included because not recommended to use. Use getFingerprint() or getFingerprintBytes()
  public algorithm: enums.publicKey;
  public created: Date;

  public version: number;
  public expirationTimeV3: number | null;
  public keyExpirationTime: number | null;
  public getBitSize(): number;
  public getAlgorithmInfo(): AlgorithmInfo;
  public getFingerprint(): string;
  public getFingerprintBytes(): Uint8Array | null;
  public getCreationTime(): Date;
  public getKeyId(): Keyid;
  public params: object[];
  public isDecrypted(): boolean;
  public isEncrypted: boolean; // may be null, false or true
}

declare class BasePrimaryKeyPacket extends BaseKeyPacket {
}

export class CompressedDataPacket extends BasePacket {
  public tag: enums.packet.compressedData;
}

export class SymEncryptedIntegrityProtectedDataPacket extends BasePacket {
  public tag: enums.packet.symEncryptedIntegrityProtectedData;
}

export class AEADEncryptedDataPacket extends BasePacket {
  public tag: enums.packet.AEADEncryptedData;
}

export class PublicKeyEncryptedSessionKeyPaclet extends BasePacket {
  public tag: enums.packet.publicKeyEncryptedSessionKey;
}

export class SymEncryptedSessionKey extends BasePacket {
  public tag: enums.packet.symEncryptedSessionKey;
}

export class LiteralDataPacket extends BasePacket {
  public tag: enums.packet.literalData;
}

export class PublicKeyPacket extends BasePrimaryKeyPacket {
  public tag: enums.packet.publicKey;
}

export class SymmetricallyEncryptedDataPacket extends BasePacket {
  public tag: enums.packet.symmetricallyEncryptedData;
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
  public tag: enums.packet.userID;
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

type DataPacketType = 'utf8' | 'binary' | 'text' | 'mime';


export class PacketList<PACKET_TYPE> extends Array<PACKET_TYPE> {
  [index: number]: PACKET_TYPE;
  public length: number;
  public read(bytes: Uint8Array): void;
  public write(): Uint8Array;
  public push(...packet: PACKET_TYPE[]): number;
  public pop(): PACKET_TYPE;
  public filter(callback: (packet: PACKET_TYPE, i: number, self: PacketList<PACKET_TYPE>) => void): PacketList<PACKET_TYPE>;
  public filterByTag(...args: enums.packet[]): PacketList<PACKET_TYPE>;
  public forEach(callback: (packet: PACKET_TYPE, i: number, self: PacketList<PACKET_TYPE>) => void): void;
  public map<RETURN_TYPE>(callback: (packet: PACKET_TYPE, i: number, self: PacketList<PACKET_TYPE>) => RETURN_TYPE): PacketList<RETURN_TYPE>;
  // some()
  // every()
  // findPacket()
  // indexOfTag()
  // slice()
  // concat()
  // fromStructuredClone()
}

/* ############## v5 STREAM #################### */

type Data = Uint8Array | string;
interface BaseStream<T extends Data> { }
interface WebStream<T extends Data> extends BaseStream<T> { // copied+simplified version of ReadableStream from lib.dom.d.ts
  readonly locked: boolean; getReader: Function; pipeThrough: Function; pipeTo: Function; tee: Function;
  cancel(reason?: any): Promise<void>;
}
interface NodeStream<T extends Data> extends BaseStream<T> { // copied+simplified version of ReadableStream from @types/node/index.d.ts
  readable: boolean; pipe: Function; unpipe: Function; wrap: Function;
  read(size?: number): string | Uint8Array; setEncoding(encoding: string): this; pause(): this; resume(): this;
  isPaused(): boolean; unshift(chunk: string | Uint8Array): void;
}
type Stream<T extends Data> = WebStream<T> | NodeStream<T>;
type MaybeStream<T extends Data> = T | Stream<T>;

export namespace stream {
  function readToEnd<T extends Data>(input: MaybeStream<T>, concat?: (list: T[]) => T): Promise<T>;
  // concat
  // slice
  // clone
  // webToNode
  // nodeToWeb
}

/* ############## v5 GENERAL #################### */

export interface UserId { name?: string; email?: string; }
export interface SessionKey { data: Uint8Array; algorithm: string; }


interface EncryptOptions {
  /** message to be encrypted as created by Message.fromText or Message.fromBinary */
  message: Message<MaybeStream<Data>>;
  /** (optional) array of keys or single key, used to encrypt the message */
  publicKeys?: Key | Key[];
  /** (optional) private keys for signing. If omitted message will not be signed */
  privateKeys?: Key | Key[];
  /** (optional) array of passwords or a single password to encrypt the message */
  passwords?: string | string[];
  /** (optional) session key in the form: { data:Uint8Array, algorithm:String } */
  sessionKey?: SessionKey;
  /** (optional) which compression algorithm to compress the message with, defaults to what is specified in config */
  compression?: enums.compression;
  /** if the return values should be ascii armored or the message/signature objects */
  armor?: boolean;
  /** (optional) whether to return data as a stream. Defaults to the type of stream `message` was created from, if any. */
  streaming?: 'web' | 'node' | false;
  /** (optional) if the signature should be detached (if true, signature will be added to returned object) */
  signature?: Signature;
  /** (optional) encrypt as of a certain date */
  date?: Date;
  /** (optional) use a key ID of 0 instead of the public key IDs */
  wildcard?: boolean;
  /** (optional) user ID to sign with, e.g. { name:'Steve Sender', email:'steve@openpgp.org' } */
  fromUserId?: UserId;
  /** (optional) user ID to encrypt for, e.g. { name:'Robert Receiver', email:'robert@openpgp.org' } */
  toUserId?: UserId;
}

export interface DecryptOptions {
  /** the message object with the encrypted data */
  message: Message<MaybeStream<Data>>;
  /** (optional) private keys with decrypted secret key data or session key */
  privateKeys?: Key | Key[];
  /** (optional) passwords to decrypt the message */
  passwords?: string | string[];
  /** (optional) session keys in the form: { data:Uint8Array, algorithm:String } */
  sessionKeys?: SessionKey | SessionKey[];
  /** (optional) array of public keys or single key, to verify signatures */
  publicKeys?: Key | Key[];
  /** (optional) whether to return data as a string(Stream) or Uint8Array(Stream). If 'utf8' (the default), also normalize newlines. */
  format?: 'utf8' | 'binary';
  /** (optional) whether to return data as a stream. Defaults to the type of stream `message` was created from, if any. */
  streaming?: 'web' | 'node' | false;
  /** (optional) detached signature for verification */
  signature?: Signature;
  /** (optional) use the given date for verification instead of the current time */
  date?: Date;
}

export interface SignOptions {
  message: CleartextMessage | Message<MaybeStream<Data>>;
  privateKeys?: Key | Key[];
  armor?: boolean;
  streaming?: 'web' | 'node' | false;
  dataType?: DataPacketType;
  detached?: boolean;
  date?: Date;
  fromUserId?: UserId;
}

export interface VerifyOptions {
  /** array of publicKeys or single key, to verify signatures */
  publicKeys: Key | Key[];
  /** (cleartext) message object with signatures */
  message: CleartextMessage | Message<MaybeStream<Data>>;
  /** (optional) whether to return data as a string(Stream) or Uint8Array(Stream). If 'utf8' (the default), also normalize newlines. */
  format?: 'utf8' | 'binary';
  /** (optional) whether to return data as a stream. Defaults to the type of stream `message` was created from, if any. */
  streaming?: 'web' | 'node' | false;
  /** (optional) detached signature for verification */
  signature?: Signature;
  /** (optional) use the given date for verification instead of the current time */
  date?: Date;
}

export interface KeyPair {
  key: Key;
  privateKeyArmored: string;
  publicKeyArmored: string;
}

export type EllipticCurveName = 'curve25519' | 'p256' | 'p384' | 'p521' | 'secp256k1' | 'brainpoolP256r1' | 'brainpoolP384r1' | 'brainpoolP512r1';

export interface KeyOptions {
  userIds: UserId[]; // generating a key with no user defined results in error
  passphrase?: string;
  numBits?: number;
  keyExpirationTime?: number;
  curve?: EllipticCurveName;
  date?: Date;
  subkeys?: KeyOptions[];
}

/**
 * Intended for internal use with openpgp.generate()
 * It's recommended that users choose openpgp.generateKey() that requires KeyOptions instead
 */
export interface FullKeyOptions {
  userIds: UserId[];
  passphrase?: string;
  numBits?: number;
  keyExpirationTime?: number;
  curve?: EllipticCurveName;
  date?: Date;
  subkeys: KeyOptions[]; // required unlike KeyOptions.subkeys
}

export interface Keyid {
  bytes: string;
}

export interface DecryptMessageResult {
  data: MaybeStream<Data>;
  signatures: VerificationResult[];
  filename: string;
}

export interface VerifyMessageResult {
  data: MaybeStream<Data>;
  signatures: VerificationResult[];
}


/**
 * Armor an OpenPGP binary packet block
 */
export function armor(messagetype: enums.armor, body: object, partindex: number, parttotal: number): string;

/**
 * DeArmor an OpenPGP armored message; verify the checksum and return the encoded bytes
 */
export function unarmor(text: string): Promise<{ text: string, data: Stream<Uint8Array>, type: enums.armor }>;

export class HKP {
  constructor(keyServerBaseUrl?: string);
  public lookup(options: { keyid?: string, query?: string }): Promise<string | undefined>;
}

/* ############## v5 ENUMS #################### */

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
    AEADEncryptedData = 20,
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

/* ############## v5 UTIL #################### */

export namespace util {
  /** Convert a string of utf8 bytes to a native javascript string
      @param utf8 A valid squence of utf8 bytes
  */
  function decodeUtf8(utf8: string): string;

  /** Convert a native javascript string to a string of utf8 bytes
      param str The string to convert
  */
  function encodeUtf8(str: string): string;

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

  function uint8ArrayToMpi(bytes: Uint8Array): Uint8Array;

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
