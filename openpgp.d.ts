/* eslint-disable max-lines, @typescript-eslint/indent */

/**
 * Type definitions for OpenPGP.js http://openpgpjs.org/
 *
 * Contributors:
 *  - FlowCrypt a. s. <https://flowcrypt.com>
 *  - Guillaume Lacasa <https://blog.lacasa.fr>
 *  - Errietta Kostala <https://github.com/errietta>
 */

import type { WebStream as GenericWebStream, NodeWebStream as GenericNodeWebStream } from '@openpgp/web-stream-tools';
import enums from './src/enums';
import config, { type Config, type PartialConfig } from './src/config';

export { enums, config, Config, PartialConfig };

/* ############## STREAM #################### */
type Data = Uint8Array | string;
// web-stream-tools might end up supporting additional data types, so we re-declare the types
// to enforce the type contraint that we need.
export type WebStream<T extends Data> = GenericWebStream<T>;
export type NodeWebStream<T extends Data> = GenericNodeWebStream<T>;
export type Stream<T extends Data> = WebStream<T> | NodeWebStream<T>;
export type MaybeStream<T extends Data> = T | Stream<T>;
type MaybeArray<T> = T | Array<T>;

/* ############## KEY #################### */
// The Key and PublicKey types can be used interchangably since TS cannot detect the difference, as they have the same class properties.
// The declared readKey(s) return type is Key instead of a PublicKey since it seems more obvious that a Key can be cast to a PrivateKey.
export function readKey(options: { armoredKey: string, config?: PartialConfig }): Promise<Key>;
export function readKey(options: { binaryKey: Uint8Array, config?: PartialConfig }): Promise<Key>;
export function readKeys(options: { armoredKeys: string, config?: PartialConfig }): Promise<Key[]>;
export function readKeys(options: { binaryKeys: Uint8Array, config?: PartialConfig }): Promise<Key[]>;
export function readPrivateKey(options: { armoredKey: string, config?: PartialConfig }): Promise<PrivateKey>;
export function readPrivateKey(options: { binaryKey: Uint8Array, config?: PartialConfig }): Promise<PrivateKey>;
export function readPrivateKeys(options: { armoredKeys: string, config?: PartialConfig }): Promise<PrivateKey[]>;
export function readPrivateKeys(options: { binaryKeys: Uint8Array, config?: PartialConfig }): Promise<PrivateKey[]>;
export function generateKey(options: GenerateKeyOptions & { format?: 'armored' }): Promise<SerializedKeyPair<string> & { revocationCertificate: string }>;
export function generateKey(options: GenerateKeyOptions & { format: 'binary' }): Promise<SerializedKeyPair<Uint8Array> & { revocationCertificate: string }>;
export function generateKey(options: GenerateKeyOptions & { format: 'object' }): Promise<KeyPair & { revocationCertificate: string }>;
export function decryptKey(options: { privateKey: PrivateKey; passphrase?: MaybeArray<string>; config?: PartialConfig }): Promise<PrivateKey>;
export function encryptKey(options: { privateKey: PrivateKey; passphrase?: MaybeArray<string>; config?: PartialConfig }): Promise<PrivateKey>;
export function reformatKey(options: { privateKey: PrivateKey; userIDs?: MaybeArray<UserID>; passphrase?: string; keyExpirationTime?: number; date?: Date, format?: 'armored', config?: PartialConfig }): Promise<SerializedKeyPair<string> & { revocationCertificate: string }>;
export function reformatKey(options: { privateKey: PrivateKey; userIDs?: MaybeArray<UserID>; passphrase?: string; keyExpirationTime?: number; date?: Date, format: 'binary', config?: PartialConfig }): Promise<SerializedKeyPair<Uint8Array> & { revocationCertificate: string }>;
export function reformatKey(options: { privateKey: PrivateKey; userIDs?: MaybeArray<UserID>; passphrase?: string; keyExpirationTime?: number; date?: Date, format: 'object', config?: PartialConfig }): Promise<KeyPair & { revocationCertificate: string }>;
export function revokeKey(options: { key: PrivateKey, reasonForRevocation?: ReasonForRevocation, date?: Date, format?: 'armored', config?: PartialConfig }): Promise<SerializedKeyPair<string>>;
export function revokeKey(options: { key: PrivateKey, reasonForRevocation?: ReasonForRevocation, date?: Date, format: 'binary', config?: PartialConfig }): Promise<SerializedKeyPair<Uint8Array>>;
export function revokeKey(options: { key: PrivateKey, reasonForRevocation?: ReasonForRevocation, date?: Date, format: 'object', config?: PartialConfig }): Promise<KeyPair>;
export function revokeKey(options: { key: PrivateKey, revocationCertificate: string, date?: Date, format?: 'armored', config?: PartialConfig }): Promise<SerializedKeyPair<string>>;
export function revokeKey(options: { key: PrivateKey, revocationCertificate: string, date?: Date, format: 'binary', config?: PartialConfig }): Promise<SerializedKeyPair<Uint8Array>>;
export function revokeKey(options: { key: PrivateKey, revocationCertificate: string, date?: Date, format: 'object', config?: PartialConfig }): Promise<KeyPair>;
export function revokeKey(options: { key: PublicKey, revocationCertificate: string, date?: Date, format?: 'armored', config?: PartialConfig }): Promise<{ publicKey: string, privateKey: null }>;
export function revokeKey(options: { key: PublicKey, revocationCertificate: string, date?: Date, format: 'binary', config?: PartialConfig }): Promise<{ publicKey: Uint8Array, privateKey: null }>;
export function revokeKey(options: { key: PublicKey, revocationCertificate: string, date?: Date, format: 'object', config?: PartialConfig }): Promise<{ publicKey: PublicKey, privateKey: null }>;

export abstract class Key {
  public readonly keyPacket: PublicKeyPacket | SecretKeyPacket;
  public subkeys: Subkey[]; // do not add/replace users directly
  public users: User[]; // do not add/replace subkeys directly
  public revocationSignatures: SignaturePacket[];
  public write(): Uint8Array;
  public armor(config?: Config): string;
  public getExpirationTime(userID?: UserID, config?: Config): Promise<Date | typeof Infinity | null>;
  public getKeyIDs(): KeyID[];
  public getPrimaryUser(date?: Date, userID?: UserID, config?: Config): Promise<PrimaryUser>; // throws on error
  public getUserIDs(): string[];
  public isPrivate(): this is PrivateKey;
  public toPublic(): PublicKey;
  // NB: the order of the `update` declarations matters, since PublicKey includes PrivateKey
  public update(sourceKey: PrivateKey, date?: Date, config?: Config): Promise<PrivateKey>;
  public update(sourceKey: PublicKey, date?: Date, config?: Config): Promise<PublicKey>;
  public signPrimaryUser(privateKeys: PrivateKey[], date?: Date, userID?: UserID, config?: Config): Promise<this>;
  public signAllUsers(privateKeys: PrivateKey[], date?: Date, config?: Config): Promise<this>;
  public verifyPrimaryKey(date?: Date, userID?: UserID, config?: Config): Promise<void>; // throws on error
  public verifyPrimaryUser(publicKeys: PublicKey[], date?: Date, userIDs?: UserID, config?: Config): Promise<{ keyID: KeyID, valid: boolean | null }[]>;
  public verifyAllUsers(publicKeys?: PublicKey[], date?: Date, config?: Config): Promise<{ userID: string, keyID: KeyID, valid: boolean | null }[]>;
  public isRevoked(signature?: SignaturePacket, key?: AnyKeyPacket, date?: Date, config?: Config): Promise<boolean>;
  public getRevocationCertificate(date?: Date, config?: Config): Promise<MaybeStream<string> | undefined>;
  public getEncryptionKey(keyID?: KeyID, date?: Date | null, userID?: UserID, config?: Config): Promise<this | Subkey>;
  public getSigningKey(keyID?: KeyID, date?: Date | null, userID?: UserID, config?: Config): Promise<this | Subkey>;
  public getKeys(keyID?: KeyID): (this | Subkey)[];
  public getSubkeys(keyID?: KeyID): Subkey[];
  public getFingerprint(): string;
  public getCreationTime(): Date;
  public getAlgorithmInfo(): AlgorithmInfo;
  public getKeyID(): KeyID;
  public toPacketList(): PacketList<AllowedKeyPackets>;
}

type AllowedKeyPackets = PublicKeyPacket | PublicSubkeyPacket | SecretKeyPacket | SecretSubkeyPacket | UserIDPacket | UserAttributePacket | SignaturePacket;
export class PublicKey extends Key {
  constructor(packetlist: PacketList<AnyPacket>);
}

export class PrivateKey extends PublicKey {
  constructor(packetlist: PacketList<AnyPacket>);
  public revoke(reason?: ReasonForRevocation, date?: Date, config?: Config): Promise<PrivateKey>;
  public isDecrypted(): boolean;
  public addSubkey(options: SubkeyOptions): Promise<PrivateKey>;
  public getDecryptionKeys(keyID?: KeyID, date?: Date | null, userID?: UserID, config?: Config): Promise<(PrivateKey | Subkey)[]>;
  public update(sourceKey: PublicKey, date?: Date, config?: Config): Promise<PrivateKey>;
}

export class Subkey {
  constructor(subkeyPacket: SecretSubkeyPacket | PublicSubkeyPacket, mainKey: PublicKey);
  public readonly keyPacket: SecretSubkeyPacket | PublicSubkeyPacket;
  public readonly mainKey: PublicKey;
  public bindingSignatures: SignaturePacket[];
  public revocationSignatures: SignaturePacket[];
  public verify(date?: Date, config?: Config): Promise<SignaturePacket>;
  public isDecrypted(): boolean;
  public getFingerprint(): string;
  public getCreationTime(): Date;
  public getAlgorithmInfo(): AlgorithmInfo;
  public getKeyID(): KeyID;
  public getExpirationTime(date?: Date, config?: Config): Promise<Date | typeof Infinity | null>;
  public isRevoked(signature: SignaturePacket, key: AnyKeyPacket, date?: Date, config?: Config): Promise<boolean>;
  public update(subKey: Subkey, date?: Date, config?: Config): Promise<void>;
  public revoke(primaryKey: SecretKeyPacket, reasonForRevocation?: ReasonForRevocation, date?: Date, config?: Config): Promise<Subkey>;
}

export class User {
  constructor(userPacket: UserIDPacket | UserAttributePacket, mainKey: Key);
  public readonly userID: UserIDPacket | null;
  public readonly userAttribute: UserAttributePacket | null;
  public selfCertifications: SignaturePacket[];
  public otherCertifications: SignaturePacket[];
  public revocationSignatures: SignaturePacket[];
  public readonly mainKey: Key;
  public toPacketList(): PacketList<AnyPacket>;
  public clone(): User;
  public certify(signingKeys: PrivateKey[], date?: Date, config?: Config): Promise<User>;
  public isRevoked(
    certificate: SignaturePacket,
    keyPacket?: PublicSubkeyPacket | SecretSubkeyPacket | PublicKeyPacket | SecretKeyPacket,
    date?: Date,
    config?: Config,
  ): Promise<boolean>;
  public verifyCertificate(certificate: SignaturePacket, verificationKeys: PublicKey[], date?: Date, config?: Config): Promise<true | null>;
  public verifyAllCertifications(verificationKeys: PublicKey[], date?: Date, config?: Config): Promise<{ keyID: KeyID; valid: boolean | null }[]>;
  public verify(date?: Date, config?: Config): Promise<true>;
  public update(sourceUser: User, date?: Date, config?: Config): Promise<void>;
  public revoke(primaryKey: SecretKeyPacket, reasonForRevocation?: ReasonForRevocation, date?: Date, config?: Config): Promise<User>;
}

export interface PrimaryUser {
  index: number;
  user: User;
  selfCertification: SignaturePacket;
}

export type AlgorithmInfo = {
  algorithm: enums.publicKeyNames;
  bits?: number;
  curve?: EllipticCurveName;
};

/* ############## SIG #################### */

export function readSignature(options: { armoredSignature: string, config?: PartialConfig }): Promise<Signature>;
export function readSignature(options: { binarySignature: Uint8Array, config?: PartialConfig }): Promise<Signature>;

export class Signature {
  public readonly packets: PacketList<SignaturePacket>;
  constructor(packetlist: PacketList<SignaturePacket>);
  public write(): MaybeStream<Uint8Array>;
  public armor(config?: Config): string;
  public getSigningKeyIDs(): Array<KeyID>;
}

interface VerificationResult {
  keyID: KeyID;
  verified: Promise<true>; // throws on invalid signature
  signature: Promise<Signature>;
}

/* ############## CLEARTEXT #################### */

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
  sign(privateKeys: PrivateKey[], signature?: Signature, signingKeyIDs?: KeyID[], date?: Date, userIDs?: UserID[], notations?: RawNotation[], config?: Config): void;

  /** Verify signatures of cleartext signed message
   *  @param keys array of keys to verify signatures
   */
  verify(keys: PublicKey[], date?: Date, config?: Config): Promise<VerificationResult[]>;
}

/* ############## MSG #################### */
export function generateSessionKey(options: { encryptionKeys: MaybeArray<PublicKey>, date?: Date, encryptionUserIDs?: MaybeArray<UserID>, config?: PartialConfig }): Promise<SessionKey>;
export function encryptSessionKey(options: EncryptSessionKeyOptions & { format?: 'armored' }): Promise<string>;
export function encryptSessionKey(options: EncryptSessionKeyOptions & { format: 'binary' }): Promise<Uint8Array>;
export function encryptSessionKey(options: EncryptSessionKeyOptions & { format: 'object' }): Promise<Message<Data>>;
export function decryptSessionKeys<T extends MaybeStream<Data>>(options: { message: Message<T>, decryptionKeys?: MaybeArray<PrivateKey>, passwords?: MaybeArray<string>, date?: Date, config?: PartialConfig }): Promise<DecryptedSessionKey[]>;

export function readMessage<T extends MaybeStream<string>>(options: { armoredMessage: T, config?: PartialConfig }): Promise<Message<T>>;
export function readMessage<T extends MaybeStream<Uint8Array>>(options: { binaryMessage: T, config?: PartialConfig }): Promise<Message<T>>;

export function createMessage<T extends MaybeStream<string>>(options: { text: T, filename?: string, date?: Date, format?: enums.literalFormatNames }): Promise<Message<T>>;
export function createMessage<T extends MaybeStream<Uint8Array>>(options: { binary: T, filename?: string, date?: Date, format?: enums.literalFormatNames }): Promise<Message<T>>;

export function encrypt<T extends MaybeStream<Data>>(options: EncryptOptions & { message: Message<T>, format?: 'armored' }): Promise<
  T extends WebStream<Data> ? WebStream<string> :
  T extends NodeWebStream<Data> ? NodeWebStream<string> :
  string
>;
export function encrypt<T extends MaybeStream<Data>>(options: EncryptOptions & { message: Message<T>, format: 'binary' }): Promise<
  T extends WebStream<Data> ? WebStream<Uint8Array> :
  T extends NodeWebStream<Data> ? NodeWebStream<Uint8Array> :
  Uint8Array
>;
export function encrypt<T extends MaybeStream<Data>>(options: EncryptOptions & { message: Message<T>, format: 'object' }): Promise<Message<T>>;

export function sign<T extends MaybeStream<Data>>(options: SignOptions & { message: Message<T>, format?: 'armored' }): Promise<
  T extends WebStream<Data> ? WebStream<string> :
  T extends NodeWebStream<Data> ? NodeWebStream<string> :
  string
>;
export function sign<T extends MaybeStream<Data>>(options: SignOptions & { message: Message<T>, format: 'binary' }): Promise<
  T extends WebStream<Data> ? WebStream<Uint8Array> :
  T extends NodeWebStream<Data> ? NodeWebStream<Uint8Array> :
  Uint8Array
>;
export function sign<T extends MaybeStream<Data>>(options: SignOptions & { message: Message<T>, format: 'object' }): Promise<Message<T>>;
export function sign(options: SignOptions & { message: CleartextMessage, format?: 'armored' }): Promise<string>;
export function sign(options: SignOptions & { message: CleartextMessage, format: 'object' }): Promise<CleartextMessage>;

export function decrypt<T extends MaybeStream<Data>>(options: DecryptOptions & { message: Message<T>, format: 'binary' }): Promise<DecryptMessageResult & {
  data:
  T extends WebStream<Data> ? WebStream<Uint8Array> :
  T extends NodeWebStream<Data> ? NodeWebStream<Uint8Array> :
  Uint8Array
}>;
export function decrypt<T extends MaybeStream<Data>>(options: DecryptOptions & { message: Message<T> }): Promise<DecryptMessageResult & {
  data:
  T extends WebStream<Data> ? WebStream<string> :
  T extends NodeWebStream<Data> ? NodeWebStream<string> :
  string
}>;

export function verify(options: VerifyOptions & { message: CleartextMessage, format?: 'utf8' }): Promise<VerifyMessageResult<string>>;
export function verify<T extends MaybeStream<Data>>(options: VerifyOptions & { message: Message<T>, format: 'binary' }): Promise<VerifyMessageResult<
  T extends WebStream<Data> ? WebStream<Uint8Array> :
  T extends NodeWebStream<Data> ? NodeWebStream<Uint8Array> :
  Uint8Array
>>;
export function verify<T extends MaybeStream<Data>>(options: VerifyOptions & { message: Message<T> }): Promise<VerifyMessageResult<
  T extends WebStream<Data> ? WebStream<string> :
  T extends NodeWebStream<Data> ? NodeWebStream<string> :
  string
>>;

/** Class that represents an OpenPGP message.  Can be an encrypted message, signed message, compressed message or literal message
 */
export class Message<T extends MaybeStream<Data>> {

  public readonly packets: PacketList<AnyPacket>;
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
  public decrypt(decryptionKeys?: PrivateKey[], passwords?: string[], sessionKeys?: SessionKey[], date?: Date, config?: Config): Promise<Message<MaybeStream<Data>>>;

  /** Encrypt the message
      @param encryptionKeys array of public keys, used to encrypt the message
  */
  public encrypt(encryptionKeys?: PublicKey[], passwords?: string[], sessionKeys?: SessionKey[], wildcard?: boolean, encryptionKeyIDs?: KeyID[], date?: Date, userIDs?: UserID[], config?: Config): Promise<Message<MaybeStream<Data>>>;

  /** Returns the key IDs of the keys to which the session key is encrypted
   */
  public getEncryptionKeyIDs(): KeyID[];

  /** Get literal data that is the body of the message
   */
  public getLiteralData(): (T extends Stream<Data> ? WebStream<Uint8Array> : Uint8Array) | null;

  /** Returns the key IDs of the keys that signed the message
   */
  public getSigningKeyIDs(): KeyID[];

  /** Get literal data as text
   */
  public getText(): (T extends Stream<Data> ? WebStream<string> : string) | null;

  public getFilename(): string | null;

  /** Sign the message (the literal data packet of the message)
      @param signingKeys private keys with decrypted secret key data for signing
  */
  public sign(signingKeys: PrivateKey[], signature?: Signature, signingKeyIDs?: KeyID[], date?: Date, userIDs?: UserID[], notations?: RawNotation[], config?: Config): Promise<Message<T>>;

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

/* ############## PACKET #################### */

export declare abstract class BasePacket {
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
  public algorithm: enums.publicKey;
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
  public isMissingSecretKeyMaterial(): boolean;
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
  private decrypt(sessionKeyAlgorithm: enums.symmetric, sessionKey: Uint8Array, config?: Config): void;
  private encrypt(sessionKeyAlgorithm: enums.symmetric, sessionKey: Uint8Array, config?: Config): void;
  private crypt(fn: Function, sessionKey: Uint8Array, data: MaybeStream<Uint8Array>): MaybeStream<Uint8Array>;
}

export class PublicKeyEncryptedSessionKeyPacket extends BasePacket {
  static readonly tag: enums.packet.publicKeyEncryptedSessionKey;
  private decrypt(keyPacket: SecretKeyPacket): void; // throws on error
  private encrypt(keyPacket: PublicKeyPacket): void; // throws on error
}

export class SymEncryptedSessionKeyPacket extends BasePacket {
  static readonly tag: enums.packet.symEncryptedSessionKey;
  private decrypt(passphrase: string): Promise<void>;
  private encrypt(passphrase: string, config?: Config): Promise<void>;
}

export class LiteralDataPacket extends BasePacket {
  static readonly tag: enums.packet.literalData;
  private getText(clone?: boolean): MaybeStream<string>;
  private getBytes(clone?: boolean): MaybeStream<Uint8Array>;
  private setText(text: MaybeStream<string>, format?: enums.literal);
  private setBytes(bytes: MaybeStream<Uint8Array>, format: enums.literal);
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
  public unhashedSubpackets: RawSubpacket[];
  public unknownSubpackets: RawSubpacket[];
  public signedHashValue: null | Uint8Array;
  public created: Date | null;
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
  public revoked: null | boolean;
  public rawNotations: RawNotation[];
  public sign(key: AnySecretKeyPacket, data: Uint8Array, date?: Date, detached?: boolean): Promise<void>;
  public verify(key: AnyKeyPacket, signatureType: enums.signature, data: Uint8Array | object, date?: Date, detached?: boolean, config?: Config): Promise<void>; // throws on error
  public isExpired(date?: Date): boolean;
  public getExpirationTime(): Date | typeof Infinity;
}

export interface RawSubpacket {
  type: number;
  critical: boolean;
  body: Uint8Array;
}

export interface RawNotation {
  name: string;
  value: Uint8Array;
  humanReadable: boolean;
  critical: boolean;
}

export class TrustPacket extends BasePacket {
  static readonly tag: enums.packet.trust;
}

export class UnparseablePacket {
  tag: enums.packet;
  write: () => Uint8Array;
}

export type AnyPacket = BasePacket | UnparseablePacket;
export type AnySecretKeyPacket = SecretKeyPacket | SecretSubkeyPacket;
export type AnyKeyPacket = BasePublicKeyPacket;

type AllowedPackets = Map<enums.packet, object>; // mapping to Packet classes (i.e. typeof LiteralDataPacket etc.)
export class PacketList<T extends AnyPacket> extends Array<T> {
  static fromBinary(bytes: MaybeStream<Uint8Array>, allowedPackets: AllowedPackets, config?: Config): PacketList<AnyPacket>; // the packet types depend on`allowedPackets`
  public read(bytes: MaybeStream<Uint8Array>, allowedPackets: AllowedPackets, config?: Config): void;
  public write(): Uint8Array;
  public filterByTag(...args: enums.packet[]): PacketList<T>;
  public indexOfTag(...tags: enums.packet[]): number[];
  public findPacket(tag: enums.packet): T | undefined;
}

/* ############## GENERAL #################### */

export interface UserID { name?: string; email?: string; comment?: string; }
export interface SessionKey {
  data: Uint8Array;
  algorithm: enums.symmetricNames;
  aeadAlgorithm?: enums.aeadNames;
}

export interface DecryptedSessionKey {
  data: Uint8Array;
  algorithm: enums.symmetricNames | null; // `null` if the session key is associated with a SEIPDv2 packet
}

export interface ReasonForRevocation { flag?: enums.reasonForRevocation, string?: string }

export interface EncryptOptions {
  /** message to be encrypted as created by createMessage */
  message: Message<MaybeStream<Data>>;
  /** (optional) array of keys or single key, used to encrypt the message */
  encryptionKeys?: MaybeArray<PublicKey>;
  /** (optional) private keys for signing. If omitted message will not be signed */
  signingKeys?: MaybeArray<PrivateKey>;
  /** (optional) array of passwords or a single password to encrypt the message */
  passwords?: MaybeArray<string>;
  /** (optional) session key */
  sessionKey?: SessionKey;
  /** if the return values should be ascii armored or the message/signature objects */
  format?: 'armored' | 'binary' | 'object';
  /** (optional) if the signature should be detached (if true, signature will be added to returned object) */
  signature?: Signature;
  /** (optional) encrypt as of a certain date */
  date?: Date;
  /** (optional) use a key ID of 0 instead of the public key IDs */
  wildcard?: boolean;
  /** (optional) Array of key IDs to use for signing. Each `signingKeyIDs[i]` corresponds to `signingKeys[i]` */
  signingKeyIDs?: MaybeArray<KeyID>;
  /** (optional) Array of key IDs to use for encryption. Each `encryptionKeyIDs[i]` corresponds to `encryptionKeys[i]`*/
  encryptionKeyIDs?: MaybeArray<KeyID>;
  /** (optional) Array of user IDs to sign with, e.g. { name:'Steve Sender', email:'steve@openpgp.org' } */
  signingUserIDs?: MaybeArray<UserID>;
  /** (optional) array of user IDs to encrypt for, e.g. { name:'Robert Receiver', email:'robert@openpgp.org' } */
  encryptionUserIDs?: MaybeArray<UserID>;
  /** (optional) array of notations to add to the signatures, e.g. { name: 'test@example.org', value: new TextEncoder().encode('test'), humanReadable: true, critical: false } */
  signatureNotations?: MaybeArray<RawNotation>;
  config?: PartialConfig;
}

export interface DecryptOptions {
  /** the message object with the encrypted data */
  message: Message<MaybeStream<Data>>;
  /** (optional) private keys with decrypted secret key data or session key */
  decryptionKeys?: MaybeArray<PrivateKey>;
  /** (optional) passwords to decrypt the message */
  passwords?: MaybeArray<string>;
  /** (optional) session keys in the form: { data:Uint8Array, algorithm:String } */
  sessionKeys?: MaybeArray<SessionKey>;
  /** (optional) array of public keys or single key, to verify signatures */
  verificationKeys?: MaybeArray<PublicKey>;
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

export interface SignOptions {
  message: CleartextMessage | Message<MaybeStream<Data>>;
  signingKeys: MaybeArray<PrivateKey>;
  format?: 'armored' | 'binary' | 'object';
  detached?: boolean;
  signingKeyIDs?: MaybeArray<KeyID>;
  date?: Date;
  signingUserIDs?: MaybeArray<UserID>;
  signatureNotations?: MaybeArray<RawNotation>;
  config?: PartialConfig;
}

export interface VerifyOptions {
  /** (cleartext) message object with signatures */
  message: CleartextMessage | Message<MaybeStream<Data>>;
  /** array of publicKeys or single key, to verify signatures */
  verificationKeys: MaybeArray<PublicKey>;
  /** (optional) whether verification should throw if the message is not signed with the provided publicKeys */
  expectSigned?: boolean;
  /** (optional) whether to return data as a string(Stream) or Uint8Array(Stream). If 'utf8' (the default), also normalize newlines. */
  format?: 'utf8' | 'binary';
  /** (optional) detached signature for verification */
  signature?: Signature;
  /** (optional) use the given date for verification instead of the current time */
  date?: Date | null;
  config?: PartialConfig;
}

export interface EncryptSessionKeyOptions extends SessionKey {
  encryptionKeys?: MaybeArray<PublicKey>,
  passwords?: MaybeArray<string>,
  format?: 'armored' | 'binary' | 'object',
  date?: Date,
  wildcard?: boolean,
  encryptionKeyIDs?: MaybeArray<KeyID>,
  encryptionUserIDs?: MaybeArray<UserID>,
  config?: PartialConfig
}

interface SerializedKeyPair<T extends string | Uint8Array> {
  privateKey: T;
  publicKey: T;
}
interface KeyPair {
  privateKey: PrivateKey;
  publicKey: PublicKey;
}

export type EllipticCurveName = 'ed25519Legacy' | 'curve25519Legacy' | 'nistP256' | 'nistP384' | 'nistP521' | 'secp256k1' | 'brainpoolP256r1' | 'brainpoolP384r1' | 'brainpoolP512r1';

interface GenerateKeyOptions {
  userIDs: MaybeArray<UserID>;
  passphrase?: string;
  type?: 'ecc' | 'rsa' | 'curve25519' | 'curve448';
  curve?: EllipticCurveName;
  rsaBits?: number;
  keyExpirationTime?: number;
  date?: Date;
  subkeys?: SubkeyOptions[];
  format?: 'armored' | 'object' | 'binary';
  config?: PartialConfig;
}
export type KeyOptions = GenerateKeyOptions;

export interface SubkeyOptions extends Pick<GenerateKeyOptions, 'type' | 'curve' | 'rsaBits' | 'keyExpirationTime' | 'date' | 'config'> {
  sign?: boolean;
}

export declare class KeyID {
  bytes: string;
  equals(keyID: KeyID, matchWildcard?: boolean): boolean;
  toHex(): string;
  static fromID(hex: string): KeyID;
}

export interface DecryptMessageResult {
  data: MaybeStream<Data>;
  signatures: VerificationResult[];
  filename: string;
}

export interface VerifyMessageResult<T extends MaybeStream<Data> = MaybeStream<Data>> {
  data: T;
  signatures: VerificationResult[];
}


/**
 * Armor an OpenPGP binary packet block
 */
export function armor(messagetype: enums.armor, body: object, partindex?: number, parttotal?: number, customComment?: string, emitChecksum?: boolean, config?: Config): string;

/**
 * DeArmor an OpenPGP armored message; verify the checksum and return the encoded bytes
 */
export function unarmor(input: string, config?: Config): Promise<{ text: string, data: Stream<Uint8Array>, type: enums.armor }>;

