/**
 * Type definitions for OpenPGP.js http://openpgpjs.org/
 * 
 * Contributors:
 *  - FlowCrypt a. s. <https://flowcrypt.com>
 *  - Guillaume Lacasa <https://blog.lacasa.fr>
 *  - Errietta Kostala <https://github.com/errietta>
 */

/* ############## v5 KEY #################### */

export function readKey(options: { armoredKey: string, config?: PartialConfig }): Promise<PublicKey>;
export function readKey(options: { binaryKey: Uint8Array, config?: PartialConfig }): Promise<PublicKey>;
export function readKeys(options: { armoredKeys: string, config?: PartialConfig }): Promise<PublicKey[]>;
export function readKeys(options: { binaryKeys: Uint8Array, config?: PartialConfig }): Promise<PublicKey[]>;
export function readPrivateKey(options: { armoredKey: string, config?: PartialConfig }): Promise<PrivateKey>;
export function readPrivateKey(options: { binaryKey: Uint8Array, config?: PartialConfig }): Promise<PrivateKey>;
export function readPrivateKeys(options: { armoredKeys: string, config?: PartialConfig }): Promise<PrivateKey[]>;
export function readPrivateKeys(options: { binaryKeys: Uint8Array, config?: PartialConfig }): Promise<PrivateKey[]>;
export function generateKey(options: KeyOptions): Promise<KeyPair>;
export function generateSessionKey(options: { encryptionKeys: PublicKey[], date?: Date, encryptionUserIDs?: UserID[], config?: PartialConfig }): Promise<SessionKey>;
export function decryptKey(options: { privateKey: PrivateKey; passphrase?: string | string[]; config?: PartialConfig }): Promise<PrivateKey>;
export function encryptKey(options: { privateKey: PrivateKey; passphrase?: string | string[]; config?: PartialConfig }): Promise<PrivateKey>;
export function reformatKey(options: { privateKey: PrivateKey; userIDs?: UserID|UserID[]; passphrase?: string; keyExpirationTime?: number; config?: PartialConfig }): Promise<KeyPair>;

export abstract class Key {
  private primaryKey: PublicKeyPacket | SecretKeyPacket;
  private keyPacket: PublicKeyPacket | SecretKeyPacket;
  public subKeys: SubKey[];
  public users: User[];
  public revocationSignatures: SignaturePacket[];
  public write(): Uint8Array;
  public armor(config?: Config): string;
  public getExpirationTime(capability?: 'encrypt' | 'encrypt_sign' | 'sign', keyID?: KeyID, userID?: UserID, config?: Config): Promise<Date | typeof Infinity | null>; // Returns null if `capabilities` is passed and the key does not have the specified capabilities or is revoked or invalid.
  public getKeyIDs(): KeyID[];
  public getPrimaryUser(date?: Date, userID?: UserID, config?: Config): Promise<PrimaryUser>; // throws on error
  public getUserIDs(): string[];
  public isPrivate(): boolean;
  public isPublic(): boolean;
  public toPublic(): PublicKey;
  public update(sourceKey: PublicKey, config?: Config): Promise<PublicKey>;
  public signPrimaryUser(privateKeys: PrivateKey[], date?: Date, userID?: UserID, config?: Config): Promise<PublicKey>
  public signAllUsers(privateKeys: PrivateKey[], config?: Config): Promise<PublicKey>
  public verifyPrimaryKey(date?: Date, userID?: UserID, config?: Config): Promise<void>; // throws on error
  public verifyPrimaryUser(publicKeys: PublicKey[], date?: Date, userIDs?: UserID, config?: Config): Promise<{ keyID: KeyID, valid: boolean | null }[]>;
  public verifyAllUsers(publicKeys: PublicKey[], config?: Config): Promise<{ userID: string, keyID: KeyID, valid: boolean | null }[]>;
  public isRevoked(signature: SignaturePacket, key?: AnyKeyPacket, date?: Date, config?: Config): Promise<boolean>;
  public getRevocationCertificate(date?: Date, config?: Config): Promise<Stream<string> | string | undefined>;
  public getEncryptionKey(keyID?: KeyID, date?: Date | null, userID?: UserID, config?: Config): Promise<PublicKey | SubKey>;
  public getSigningKey(keyID?: KeyID, date?: Date | null, userID?: UserID, config?: Config): Promise<PublicKey | SubKey>;
  public getKeys(keyID?: KeyID): (PublicKey | SubKey)[];
  public getSubkeys(keyID?: KeyID): SubKey[];
  public getFingerprint(): string;
  public getCreationTime(): Date;
  public getAlgorithmInfo(): AlgorithmInfo;
  public getKeyID(): KeyID;
  public toPacketList(): PacketList<AllowedKeyPackets>;
}

type AllowedKeyPackets = PublicKeyPacket | PublicSubkeyPacket | SecretKeyPacket | SecretSubkeyPacket | UserIDPacket | UserAttributePacket | SignaturePacket;
export class PublicKey extends Key {
  constructor(packetlist: PacketList<AnyKeyPacket>);
}

export class PrivateKey extends PublicKey {
  constructor(packetlist: PacketList<AnyKeyPacket>);
  public revoke(reason: { flag?: enums.reasonForRevocation; string?: string; }, date?: Date, config?: Config): Promise<PrivateKey>;
  public isDecrypted(): boolean;
  public addSubkey(options: SubKeyOptions): Promise<PrivateKey>;
  public getDecryptionKeys(keyID?: KeyID, date?: Date | null, userID?: UserID, config?: Config): Promise<PrivateKey | SubKey>
  public update(sourceKey: PublicKey, config?: Config): Promise<PrivateKey>;
  public getKeys(keyID?: KeyID): (PrivateKey | SubKey)[];
}

export class SubKey {
  constructor(subKeyPacket: SecretSubkeyPacket | PublicSubkeyPacket);
  private keyPacket: SecretSubkeyPacket | PublicSubkeyPacket;
  public bindingSignatures: SignaturePacket[];
  public revocationSignatures: SignaturePacket[];
  public verify(primaryKey: PublicKeyPacket | SecretKeyPacket, date?: Date, config?: Config): Promise<SignaturePacket>;
  public isDecrypted(): boolean;
  public getFingerprint(): string;
  public getCreationTime(): Date;
  public getAlgorithmInfo(): AlgorithmInfo;
  public getKeyID(): KeyID;
}

export interface User {
  userID: UserIDPacket | null;
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
  bits?: number;
  curve?: EllipticCurveName;
};

/* ############## v5 SIG #################### */

export function readSignature(options: { armoredSignature: string, config?: PartialConfig }): Promise<Signature>;
export function readSignature(options: { binarySignature: Uint8Array, config?: PartialConfig }): Promise<Signature>;

export class Signature {
  private packets: PacketList<SignaturePacket>;
  constructor(packetlist: PacketList<SignaturePacket>);
  public write(): MaybeStream<Uint8Array>;
  public armor(config?: Config): string;
  public getSigningKeyIDs(): Array<KeyID>;
}

interface VerificationResult {
  keyID: KeyID;
  verified: Promise<null | boolean>;
  signature: Promise<Signature>;
}

/* ############## v5 CLEARTEXT #################### */

export function readCleartextMessage(options: { cleartextMessage: string, config?: PartialConfig }): Promise<CleartextMessage>;

export function createCleartextMessage(options: { text: string }): Promise<CleartextMessage>;

/** Class that represents an OpenPGP cleartext signed message.
 */
export class CleartextMessage {
  /** Returns ASCII armored text of cleartext signed message
   */
  armor(config?: Config): string;

  /** Returns the key IDs of the keys that signed the cleartext message
   */
  getSigningKeyIDs(): KeyID[];

  /** Get cleartext
   */
  getText(): string;

  /** Sign the cleartext message
   *
   *  @param privateKeys private keys with decrypted secret key data for signing
   */
  sign(privateKeys: PrivateKey[], signature?: Signature, signingKeyIDs?: KeyID[], date?: Date, userIDs?: UserID[], config?: Config): void;

  /** Verify signatures of cleartext signed message
   *  @param keys array of keys to verify signatures
   */
  verify(keys: PublicKey[], date?: Date, config?: Config): Promise<VerificationResult[]>;
}

/* ############## v5 MSG #################### */

export function readMessage<T extends MaybeStream<string>>(options: { armoredMessage: T, config?: PartialConfig }): Promise<Message<T>>;
export function readMessage<T extends MaybeStream<Uint8Array>>(options: { binaryMessage: T, config?: PartialConfig }): Promise<Message<T>>;

export function createMessage<T extends MaybeStream<string>>(options: { text: T, filename?: string, date?: Date, type?: DataPacketType }): Promise<Message<T>>;
export function createMessage<T extends MaybeStream<Uint8Array>>(options: { binary: T, filename?: string, date?: Date, type?: DataPacketType }): Promise<Message<T>>;

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

  private packets: PacketList<AnyPacket>;
  constructor(packetlist: PacketList<AnyPacket>);

  /** Returns binary representation of message
   */
  public write(): MaybeStream<Uint8Array>;

  /** Returns ASCII armored text of message
   */
  public armor(config?: Config): string;

  /** Decrypt the message
      @param decryptionKeys array of private keys with decrypted secret data
  */
  public decrypt(decryptionKeys?: PrivateKey[], passwords?: string[], sessionKeys?: SessionKey[], config?: Config): Promise<Message<MaybeStream<Data>>>;

  /** Encrypt the message
      @param encryptionKeys array of public keys, used to encrypt the message
  */
  public encrypt(encryptionKeys?: PublicKey[],  passwords?: string[], sessionKeys?: SessionKey[], wildcard?: boolean, encryptionKeyIDs?: KeyID[], date?: Date, userIDs?: UserID[], config?: Config): Promise<Message<MaybeStream<Data>>>;

  /** Returns the key IDs of the keys to which the session key is encrypted
   */
  public getEncryptionKeyIDs(): KeyID[];

  /** Get literal data that is the body of the message
   */
  public getLiteralData(): Uint8Array | Stream<Uint8Array> | null;

  /** Returns the key IDs of the keys that signed the message
   */
  public getSigningKeyIDs(): KeyID[];

  /** Get literal data as text
   */
  public getText(): string | Stream<string> | null;

  public getFilename(): string | null;

  /** Sign the message (the literal data packet of the message)
      @param signingKeys private keys with decrypted secret key data for signing
  */
  public sign(signingKeys: PrivateKey[], signature?: Signature, signingKeyIDs?: KeyID[], date?: Date, userIDs?: UserID[], config?: Config): Promise<Message<T>>;

  /** Unwrap compressed message
   */
  public unwrapCompressed(): Message<T>;

  /** Verify message signatures
      @param verificationKeys array of public keys to verify signatures
  */
  public verify(verificationKeys: PublicKey[], date?: Date, config?: Config): Promise<VerificationResult[]>;

  /**
   * Append signature to unencrypted message object
   * @param {String|Uint8Array} detachedSignature - The detached ASCII-armored or Uint8Array PGP signature
   */
  public appendSignature(detachedSignature: string | Uint8Array, config?: Config): Promise<void>;
}


/* ############## v5 CONFIG #################### */

interface Config {
  preferredHashAlgorithm: enums.hash;
  preferredSymmetricAlgorithm: enums.symmetric;
  preferredCompressionAlgorithm: enums.compression;
  showVersion: boolean;
  showComment: boolean;
  deflateLevel: number;
  aeadProtect: boolean;
  allowUnauthenticatedMessages: boolean;
  allowUnauthenticatedStream: boolean;
  checksumRequired: boolean;
  minRSABits: number;
  passwordCollisionCheck: boolean;
  revocationsExpire: boolean;
  tolerant: boolean;
  versionString: string;
  commentString: string;
  allowInsecureDecryptionWithSigningKeys: boolean;
  v5Keys: boolean;
}
export var config: Config;

// PartialConfig has the same properties as Config, but declared as optional.
// This interface is relevant for top-level functions, which accept a subset of configuration options
interface PartialConfig extends Partial<Config> {}

/* ############## v5 PACKET #################### */

declare abstract class BasePacket {
  static readonly tag: enums.packet;
  public read(bytes: Uint8Array): void;
  public write(): Uint8Array;
}

/**
 * The relationship between the KeyPacket classes is modeled by considering the following:
 * - A Secret (Sub)Key Packet can always be used when a Public one is expected.
 * - A Subkey Packet cannot always be used when a Primary Key Packet is expected (and vice versa).
 */
declare abstract class BasePublicKeyPacket extends BasePacket {
  public algorithm: enums.publicKeyNames;
  public created: Date;
  public version: number;
  public getAlgorithmInfo(): AlgorithmInfo;
  public getFingerprint(): string;
  public getFingerprintBytes(): Uint8Array | null;
  public hasSameFingerprintAs(other: BasePublicKeyPacket): boolean;
  public getCreationTime(): Date;
  public getKeyID(): KeyID;
  public isDecrypted(): boolean;
  public publicParams: object;
  // `isSubkey` is a dummy method to ensure that Subkey packets are not accepted as Key one, and vice versa.
  // The key class hierarchy is already modelled to cover this, but the concrete key packet classes
  // have compatible structure and TS can't detect the difference.
  protected isSubkey(): boolean;
}

export class PublicKeyPacket extends BasePublicKeyPacket {
  static readonly tag: enums.packet.publicKey;
  protected isSubkey(): false;
}

export class PublicSubkeyPacket extends BasePublicKeyPacket {
  static readonly tag: enums.packet.publicSubkey;
  protected isSubkey(): true;
}

declare abstract class BaseSecretKeyPacket extends BasePublicKeyPacket {
  public privateParams: object | null;
  public encrypt(passphrase: string, config?: Config): Promise<void>; // throws on error
  public decrypt(passphrase: string): Promise<void>; // throws on error
  public validate(): Promise<void>; // throws on error
  public isDummy(): boolean;
  public makeDummy(config?: Config): void;
}

export class SecretKeyPacket extends BaseSecretKeyPacket {
  static readonly tag: enums.packet.secretKey;
  protected isSubkey(): false;
}

export class SecretSubkeyPacket extends BaseSecretKeyPacket {
  static readonly tag: enums.packet.secretSubkey;
  protected isSubkey(): true;
}

export class CompressedDataPacket extends BasePacket {
  static readonly tag: enums.packet.compressedData;
  private compress(): void;
  private decompress(config?: Config): void;
}

export class SymEncryptedIntegrityProtectedDataPacket extends BasePacket {
  static readonly tag: enums.packet.symEncryptedIntegrityProtectedData;
}

export class AEADEncryptedDataPacket extends BasePacket {
  static readonly tag: enums.packet.aeadEncryptedData;
  private decrypt(sessionKeyAlgorithm: string, sessionKey: Uint8Array, config?: Config): void;
  private encrypt(sessionKeyAlgorithm: string, sessionKey: Uint8Array, config?: Config): void;
  private crypt(fn: Function, sessionKey: Uint8Array, data: MaybeStream<Uint8Array>): MaybeStream<Uint8Array>
}

export class PublicKeyEncryptedSessionKeyPacket extends BasePacket {
  static readonly tag: enums.packet.publicKeyEncryptedSessionKey;
  private decrypt(keyPacket: SecretKeyPacket): void; // throws on error
  private encrypt(keyPacket: PublicKeyPacket): void; // throws on error
}

export class SymEncryptedSessionKey extends BasePacket {
  static readonly tag: enums.packet.symEncryptedSessionKey;
  private decrypt(passphrase: string): Promise<void>;
  private encrypt(passphrase: string, config?: Config): Promise<void>;
}

export class LiteralDataPacket extends BasePacket {
  static readonly tag: enums.packet.literalData;
  private getText(clone?: boolean): MaybeStream<string>;
  private getBytes(clone?: boolean): MaybeStream<Uint8Array>;
  private setText(text: MaybeStream<string>, format?: DataPacketType);
  private setBytes(bytes: MaybeStream<Uint8Array>, format?: DataPacketType);
  private setFilename(filename: string);
  private getFilename(): string;
  private writeHeader(): Uint8Array;
}

export class SymmetricallyEncryptedDataPacket extends BasePacket {
  static readonly tag: enums.packet.symmetricallyEncryptedData;
  private decrypt(sessionKeyAlgorithm: enums.symmetric, sessionKey: Uint8Array, config?: Config): void;
  private encrypt(sessionKeyAlgorithm: enums.symmetric, sessionKey: Uint8Array, config?: Config): void;
}

export class MarkerPacket extends BasePacket {
  static readonly tag: enums.packet.marker;
}

export class UserAttributePacket extends BasePacket {
  static readonly tag: enums.packet.userAttribute;
  private equals(packet: UserAttributePacket): boolean;
}

export class OnePassSignaturePacket extends BasePacket {
  static readonly tag: enums.packet.onePassSignature;
  public correspondingSig?: Promise<SignaturePacket>;
  private verify: SignaturePacket['verify'];
}

export class UserIDPacket extends BasePacket {
  static readonly tag: enums.packet.userID;
  public readonly name: string;
  public readonly comment: string;
  public readonly email: string;
  public readonly userID: string;
  static fromObject(userID: UserID): UserIDPacket;
}

export class SignaturePacket extends BasePacket {
  static readonly tag: enums.packet.signature;
  public version: number;
  public signatureType: enums.signature | null;
  public hashAlgorithm: enums.hash | null;
  public publicKeyAlgorithm: enums.publicKey | null;
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
  public preferredSymmetricAlgorithms: enums.symmetric[] | null;
  public revocationKeyClass: null | number;
  public revocationKeyAlgorithm: null | enums.publicKey;
  public revocationKeyFingerprint: null | Uint8Array;
  public issuerKeyID: KeyID;
  public notation: null | { [name: string]: string };
  public preferredHashAlgorithms: enums.hash[] | null;
  public preferredCompressionAlgorithms: enums.compression[] | null;
  public keyServerPreferences: null | number[];
  public preferredKeyServer: null | string;
  public isPrimaryUserID: null | boolean;
  public policyURI: null | string;
  public keyFlags: Uint8Array | null;
  public signersUserID: null | string;
  public reasonForRevocationFlag: null | enums.reasonForRevocation;
  public reasonForRevocationString: null | string;
  public features: Uint8Array | null;
  public signatureTargetPublicKeyAlgorithm: enums.publicKey | null;
  public signatureTargetHashAlgorithm: enums.hash | null;
  public signatureTargetHash: null | string;
  public embeddedSignature: null | SignaturePacket;
  public issuerKeyVersion: null | number;
  public issuerFingerprint: null | Uint8Array;
  public preferredAEADAlgorithms: enums.aead[] | null;
  public verified: null | boolean;
  public revoked: null | boolean;
  public sign(key: AnySecretKeyPacket, data: Uint8Array, detached?: boolean): Promise<void>;
  public verify(key: AnyKeyPacket, signatureType: enums.signature, data: Uint8Array, detached?: boolean, config?: Config): Promise<void>; // throws on error
  public isExpired(date?: Date): boolean;
  public getExpirationTime(): Date | typeof Infinity;
}

export class TrustPacket extends BasePacket {
  static readonly tag: enums.packet.trust;
}

export type AnyPacket = BasePacket;
export type AnySecretKeyPacket = SecretKeyPacket | SecretSubkeyPacket;
export type AnyKeyPacket = BasePublicKeyPacket;

type DataPacketType = 'utf8' | 'binary' | 'text' | 'mime';

type AllowedPackets = Map<enums.packet, object>; // mapping to Packet classes (i.e. typeof LiteralDataPacket etc.)
export class PacketList<T extends AnyPacket> extends Array<T> {
  static fromBinary(bytes: MaybeStream<Uint8Array>, allowedPackets: AllowedPackets, config?: Config): PacketList<AnyPacket>; // the packet types depend on`allowedPackets`
  public read(bytes: MaybeStream<Uint8Array>, allowedPackets: AllowedPackets, config?: Config): void;
  public write(): Uint8Array;
  public filterByTag(...args: enums.packet[]): PacketList<T>;
  public indexOfTag(...tags: enums.packet[]): number[];
  public findPacket(tag: enums.packet): T | undefined;
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

export interface UserID { name?: string; email?: string; comment?: string; }
export interface SessionKey { data: Uint8Array; algorithm: string; }


interface EncryptOptions {
  /** message to be encrypted as created by createMessage */
  message: Message<MaybeStream<Data>>;
  /** (optional) array of keys or single key, used to encrypt the message */
  encryptionKeys?: PublicKey | PublicKey[];
  /** (optional) private keys for signing. If omitted message will not be signed */
  signingKeys?: PrivateKey | PrivateKey[];
  /** (optional) array of passwords or a single password to encrypt the message */
  passwords?: string | string[];
  /** (optional) session key in the form: { data:Uint8Array, algorithm:String } */
  sessionKey?: SessionKey;
  /** if the return values should be ascii armored or the message/signature objects */
  armor?: boolean;
  /** (optional) if the signature should be detached (if true, signature will be added to returned object) */
  signature?: Signature;
  /** (optional) encrypt as of a certain date */
  date?: Date;
  /** (optional) use a key ID of 0 instead of the public key IDs */
  wildcard?: boolean;
  /** (optional) Array of key IDs to use for signing. Each `signingKeyIDs[i]` corresponds to `signingKeys[i]` */
  signingKeyIDs?: KeyID[];
  /** (optional) Array of key IDs to use for encryption. Each `encryptionKeyIDs[i]` corresponds to `encryptionKeys[i]`*/
  encryptionKeyIDs?: KeyID[];
  /** (optional) Array of user IDs to sign with, e.g. { name:'Steve Sender', email:'steve@openpgp.org' } */
  signingUserIDs?: UserID[];
  /** (optional) array of user IDs to encrypt for, e.g. { name:'Robert Receiver', email:'robert@openpgp.org' } */
  encryptionUserIDs?: UserID[];
  config?: PartialConfig;
}

interface DecryptOptions {
  /** the message object with the encrypted data */
  message: Message<MaybeStream<Data>>;
  /** (optional) private keys with decrypted secret key data or session key */
  decryptionKeys?: PrivateKey | PrivateKey[];
  /** (optional) passwords to decrypt the message */
  passwords?: string | string[];
  /** (optional) session keys in the form: { data:Uint8Array, algorithm:String } */
  sessionKeys?: SessionKey | SessionKey[];
  /** (optional) array of public keys or single key, to verify signatures */
  verificationKeys?: PublicKey | PublicKey[];
  /** (optional) whether data decryption should fail if the message is not signed with the provided publicKeys */
  expectSigned?: boolean;
  /** (optional) whether to return data as a string(Stream) or Uint8Array(Stream). If 'utf8' (the default), also normalize newlines. */
  format?: 'utf8' | 'binary';
  /** (optional) detached signature for verification */
  signature?: Signature;
  /** (optional) use the given date for verification instead of the current time */
  date?: Date;
  config?: PartialConfig;
}

interface SignOptions {
  message: CleartextMessage | Message<MaybeStream<Data>>;
  signingKeys?: PrivateKey | PrivateKey[];
  armor?: boolean;
  dataType?: DataPacketType;
  detached?: boolean;
  signingKeyIDs?: KeyID[];
  date?: Date;
  signingUserIDs?: UserID[];
  config?: PartialConfig;
}

interface VerifyOptions {
  /** (cleartext) message object with signatures */
  message: CleartextMessage | Message<MaybeStream<Data>>;
  /** array of publicKeys or single key, to verify signatures */
  verificationKeys: PublicKey | PublicKey[];
  /** (optional) whether verification should throw if the message is not signed with the provided publicKeys */
  expectSigned?: boolean;
  /** (optional) whether to return data as a string(Stream) or Uint8Array(Stream). If 'utf8' (the default), also normalize newlines. */
  format?: 'utf8' | 'binary';
  /** (optional) detached signature for verification */
  signature?: Signature;
  /** (optional) use the given date for verification instead of the current time */
  date?: Date;
  config?: PartialConfig;
}

interface KeyPair {
  key: PrivateKey;
  privateKeyArmored: string;
  publicKeyArmored: string;
  revocationCertificate: string;
}

export type EllipticCurveName = 'ed25519' | 'curve25519' | 'p256' | 'p384' | 'p521' | 'secp256k1' | 'brainpoolP256r1' | 'brainpoolP384r1' | 'brainpoolP512r1';

interface KeyOptions {
  userIDs: UserID|UserID[];
  passphrase?: string;
  type?: 'ecc' | 'rsa';
  curve?: EllipticCurveName;
  rsaBits?: number;
  keyExpirationTime?: number;
  date?: Date;
  subkeys?: SubKeyOptions[];
  config?: PartialConfig;
}

interface SubKeyOptions {
  type?: 'ecc' | 'rsa';
  curve?: EllipticCurveName;
  rsaBits?: number;
  keyExpirationTime?: number;
  date?: Date;
  sign?: boolean;
  config?: PartialConfig;
}

declare class KeyID {
  bytes: string;
  equals(keyID: KeyID, matchWildcard?: boolean): boolean;
  toHex(): string;
  static fromID(hex: string): KeyID;
}

interface DecryptMessageResult {
  data: MaybeStream<Data>;
  signatures: VerificationResult[];
  filename: string;
}

interface VerifyMessageResult {
  data: MaybeStream<Data>;
  signatures: VerificationResult[];
}


/**
 * Armor an OpenPGP binary packet block
 */
export function armor(messagetype: enums.armor, body: object, partindex: number, parttotal: number, config?: Config): string;

/**
 * DeArmor an OpenPGP armored message; verify the checksum and return the encoded bytes
 */
export function unarmor(input: string, config?: Config): Promise<{ text: string, data: Stream<Uint8Array>, type: enums.armor }>;

/* ############## v5 ENUMS #################### */

export namespace enums {
  function read(type: typeof armor, e: armor): armorNames;
  function read(type: typeof compression, e: compression): compressionNames;
  function read(type: typeof hash, e: hash): hashNames;
  function read(type: typeof packet, e: packet): packetNames;
  function read(type: typeof publicKey, e: publicKey): publicKeyNames;
  function read(type: typeof symmetric, e: symmetric): symmetricNames;
  function read(type: typeof keyStatus, e: keyStatus): keyStatusNames;
  function read(type: typeof keyFlags, e: keyFlags): keyFlagsNames;

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
    userIDInvalid = 32, // User ID information is no longer valid (cert revocations)
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
    | 'secretSubkey' | 'compressed' | 'symmetricallyEncrypted' | 'marker' | 'literal' | 'trust' | 'userID' | 'publicSubkey' | 'userAttribute'
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
    aeadEncryptedData = 20,
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

  enum signature {
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

  enum aead {
    eax = 1,
    ocb = 2,
    experimentalGCM = 100 // Private algorithm
  }
}
