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

import * as stream from '@openpgp/web-stream-tools';
import { readSimpleLength, UnsupportedError, writeSimpleLength } from './packet';
import KeyID from '../type/keyid.js';
import crypto from '../crypto';
import enums from '../enums';
import util from '../util';
import defaultConfig from '../config';

// Symbol to store cryptographic validity of the signature, to avoid recomputing multiple times on verification.
const verified = Symbol('verified');

// GPG puts the Issuer and Signature subpackets in the unhashed area.
// Tampering with those invalidates the signature, so we still trust them and parse them.
// All other unhashed subpackets are ignored.
const allowedUnhashedSubpackets = new Set([
  enums.signatureSubpacket.issuer,
  enums.signatureSubpacket.issuerFingerprint,
  enums.signatureSubpacket.embeddedSignature
]);

/**
 * Implementation of the Signature Packet (Tag 2)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.2|RFC4480 5.2}:
 * A Signature packet describes a binding between some public key and
 * some data.  The most common signatures are a signature of a file or a
 * block of text, and a signature that is a certification of a User ID.
 */
class SignaturePacket {
  static get tag() {
    return enums.packet.signature;
  }

  constructor() {
    this.version = null;
    this.signatureType = null;
    this.hashAlgorithm = null;
    this.publicKeyAlgorithm = null;

    this.signatureData = null;
    this.unhashedSubpackets = [];
    this.signedHashValue = null;

    this.created = null;
    this.signatureExpirationTime = null;
    this.signatureNeverExpires = true;
    this.exportable = null;
    this.trustLevel = null;
    this.trustAmount = null;
    this.regularExpression = null;
    this.revocable = null;
    this.keyExpirationTime = null;
    this.keyNeverExpires = null;
    this.preferredSymmetricAlgorithms = null;
    this.revocationKeyClass = null;
    this.revocationKeyAlgorithm = null;
    this.revocationKeyFingerprint = null;
    this.issuerKeyID = new KeyID();
    this.rawNotations = [];
    this.notations = {};
    this.preferredHashAlgorithms = null;
    this.preferredCompressionAlgorithms = null;
    this.keyServerPreferences = null;
    this.preferredKeyServer = null;
    this.isPrimaryUserID = null;
    this.policyURI = null;
    this.keyFlags = null;
    this.signersUserID = null;
    this.reasonForRevocationFlag = null;
    this.reasonForRevocationString = null;
    this.features = null;
    this.signatureTargetPublicKeyAlgorithm = null;
    this.signatureTargetHashAlgorithm = null;
    this.signatureTargetHash = null;
    this.embeddedSignature = null;
    this.issuerKeyVersion = null;
    this.issuerFingerprint = null;
    this.preferredAEADAlgorithms = null;

    this.revoked = null;
    this[verified] = null;
  }

  /**
   * parsing function for a signature packet (tag 2).
   * @param {String} bytes - Payload of a tag 2 packet
   * @returns {SignaturePacket} Object representation.
   */
  read(bytes) {
    let i = 0;
    this.version = bytes[i++];

    if (this.version !== 4 && this.version !== 5) {
      throw new UnsupportedError(`Version ${this.version} of the signature packet is unsupported.`);
    }

    this.signatureType = bytes[i++];
    this.publicKeyAlgorithm = bytes[i++];
    this.hashAlgorithm = bytes[i++];

    // hashed subpackets
    i += this.readSubPackets(bytes.subarray(i, bytes.length), true);
    if (!this.created) {
      throw new Error('Missing signature creation time subpacket.');
    }

    // A V4 signature hashes the packet body
    // starting from its first field, the version number, through the end
    // of the hashed subpacket data.  Thus, the fields hashed are the
    // signature version, the signature type, the public-key algorithm, the
    // hash algorithm, the hashed subpacket length, and the hashed
    // subpacket body.
    this.signatureData = bytes.subarray(0, i);

    // unhashed subpackets
    i += this.readSubPackets(bytes.subarray(i, bytes.length), false);

    // Two-octet field holding left 16 bits of signed hash value.
    this.signedHashValue = bytes.subarray(i, i + 2);
    i += 2;

    this.params = crypto.signature.parseSignatureParams(this.publicKeyAlgorithm, bytes.subarray(i, bytes.length));
  }

  /**
   * @returns {Uint8Array | ReadableStream<Uint8Array>}
   */
  writeParams() {
    if (this.params instanceof Promise) {
      return stream.fromAsync(
        async () => crypto.serializeParams(this.publicKeyAlgorithm, await this.params)
      );
    }
    return crypto.serializeParams(this.publicKeyAlgorithm, this.params);
  }

  write() {
    const arr = [];
    arr.push(this.signatureData);
    arr.push(this.writeUnhashedSubPackets());
    arr.push(this.signedHashValue);
    arr.push(this.writeParams());
    return util.concat(arr);
  }

  /**
   * Signs provided data. This needs to be done prior to serialization.
   * @param {SecretKeyPacket} key - Private key used to sign the message.
   * @param {Object} data - Contains packets to be signed.
   * @param {Date} [date] - The signature creation time.
   * @param {Boolean} [detached] - Whether to create a detached signature
   * @throws {Error} if signing failed
   * @async
   */
  async sign(key, data, date = new Date(), detached = false) {
    const signatureType = enums.write(enums.signature, this.signatureType);
    const publicKeyAlgorithm = enums.write(enums.publicKey, this.publicKeyAlgorithm);
    const hashAlgorithm = enums.write(enums.hash, this.hashAlgorithm);

    if (key.version === 5) {
      this.version = 5;
    } else {
      this.version = 4;
    }
    const arr = [new Uint8Array([this.version, signatureType, publicKeyAlgorithm, hashAlgorithm])];

    this.created = util.normalizeDate(date);
    this.issuerKeyVersion = key.version;
    this.issuerFingerprint = key.getFingerprintBytes();
    this.issuerKeyID = key.getKeyID();

    // Add hashed subpackets
    arr.push(this.writeHashedSubPackets());

    this.signatureData = util.concat(arr);

    const toHash = this.toHash(signatureType, data, detached);
    const hash = await this.hash(signatureType, data, toHash, detached);

    this.signedHashValue = stream.slice(stream.clone(hash), 0, 2);
    const signed = async () => crypto.signature.sign(
      publicKeyAlgorithm, hashAlgorithm, key.publicParams, key.privateParams, toHash, await stream.readToEnd(hash)
    );
    if (util.isStream(hash)) {
      this.params = signed();
    } else {
      this.params = await signed();

      // Store the fact that this signature is valid, e.g. for when we call `await
      // getLatestValidSignature(this.revocationSignatures, key, data)` later.
      // Note that this only holds up if the key and data passed to verify are the
      // same as the ones passed to sign.
      this[verified] = true;
    }
  }

  /**
   * Creates Uint8Array of bytes of all subpacket data except Issuer and Embedded Signature subpackets
   * @returns {Uint8Array} Subpacket data.
   */
  writeHashedSubPackets() {
    const sub = enums.signatureSubpacket;
    const arr = [];
    let bytes;
    if (this.created === null) {
      throw new Error('Missing signature creation time');
    }
    arr.push(writeSubPacket(sub.signatureCreationTime, util.writeDate(this.created)));
    if (this.signatureExpirationTime !== null) {
      arr.push(writeSubPacket(sub.signatureExpirationTime, util.writeNumber(this.signatureExpirationTime, 4)));
    }
    if (this.exportable !== null) {
      arr.push(writeSubPacket(sub.exportableCertification, new Uint8Array([this.exportable ? 1 : 0])));
    }
    if (this.trustLevel !== null) {
      bytes = new Uint8Array([this.trustLevel, this.trustAmount]);
      arr.push(writeSubPacket(sub.trustSignature, bytes));
    }
    if (this.regularExpression !== null) {
      arr.push(writeSubPacket(sub.regularExpression, this.regularExpression));
    }
    if (this.revocable !== null) {
      arr.push(writeSubPacket(sub.revocable, new Uint8Array([this.revocable ? 1 : 0])));
    }
    if (this.keyExpirationTime !== null) {
      arr.push(writeSubPacket(sub.keyExpirationTime, util.writeNumber(this.keyExpirationTime, 4)));
    }
    if (this.preferredSymmetricAlgorithms !== null) {
      bytes = util.stringToUint8Array(util.uint8ArrayToString(this.preferredSymmetricAlgorithms));
      arr.push(writeSubPacket(sub.preferredSymmetricAlgorithms, bytes));
    }
    if (this.revocationKeyClass !== null) {
      bytes = new Uint8Array([this.revocationKeyClass, this.revocationKeyAlgorithm]);
      bytes = util.concat([bytes, this.revocationKeyFingerprint]);
      arr.push(writeSubPacket(sub.revocationKey, bytes));
    }
    this.rawNotations.forEach(([{ name, value, humanReadable }]) => {
      bytes = [new Uint8Array([humanReadable ? 0x80 : 0, 0, 0, 0])];
      // 2 octets of name length
      bytes.push(util.writeNumber(name.length, 2));
      // 2 octets of value length
      bytes.push(util.writeNumber(value.length, 2));
      bytes.push(util.stringToUint8Array(name));
      bytes.push(value);
      bytes = util.concat(bytes);
      arr.push(writeSubPacket(sub.notationData, bytes));
    });
    if (this.preferredHashAlgorithms !== null) {
      bytes = util.stringToUint8Array(util.uint8ArrayToString(this.preferredHashAlgorithms));
      arr.push(writeSubPacket(sub.preferredHashAlgorithms, bytes));
    }
    if (this.preferredCompressionAlgorithms !== null) {
      bytes = util.stringToUint8Array(util.uint8ArrayToString(this.preferredCompressionAlgorithms));
      arr.push(writeSubPacket(sub.preferredCompressionAlgorithms, bytes));
    }
    if (this.keyServerPreferences !== null) {
      bytes = util.stringToUint8Array(util.uint8ArrayToString(this.keyServerPreferences));
      arr.push(writeSubPacket(sub.keyServerPreferences, bytes));
    }
    if (this.preferredKeyServer !== null) {
      arr.push(writeSubPacket(sub.preferredKeyServer, util.stringToUint8Array(this.preferredKeyServer)));
    }
    if (this.isPrimaryUserID !== null) {
      arr.push(writeSubPacket(sub.primaryUserID, new Uint8Array([this.isPrimaryUserID ? 1 : 0])));
    }
    if (this.policyURI !== null) {
      arr.push(writeSubPacket(sub.policyURI, util.stringToUint8Array(this.policyURI)));
    }
    if (this.keyFlags !== null) {
      bytes = util.stringToUint8Array(util.uint8ArrayToString(this.keyFlags));
      arr.push(writeSubPacket(sub.keyFlags, bytes));
    }
    if (this.signersUserID !== null) {
      arr.push(writeSubPacket(sub.signersUserID, util.stringToUint8Array(this.signersUserID)));
    }
    if (this.reasonForRevocationFlag !== null) {
      bytes = util.stringToUint8Array(String.fromCharCode(this.reasonForRevocationFlag) + this.reasonForRevocationString);
      arr.push(writeSubPacket(sub.reasonForRevocation, bytes));
    }
    if (this.features !== null) {
      bytes = util.stringToUint8Array(util.uint8ArrayToString(this.features));
      arr.push(writeSubPacket(sub.features, bytes));
    }
    if (this.signatureTargetPublicKeyAlgorithm !== null) {
      bytes = [new Uint8Array([this.signatureTargetPublicKeyAlgorithm, this.signatureTargetHashAlgorithm])];
      bytes.push(util.stringToUint8Array(this.signatureTargetHash));
      bytes = util.concat(bytes);
      arr.push(writeSubPacket(sub.signatureTarget, bytes));
    }
    if (this.preferredAEADAlgorithms !== null) {
      bytes = util.stringToUint8Array(util.uint8ArrayToString(this.preferredAEADAlgorithms));
      arr.push(writeSubPacket(sub.preferredAEADAlgorithms, bytes));
    }

    const result = util.concat(arr);
    const length = util.writeNumber(result.length, 2);

    return util.concat([length, result]);
  }

  /**
   * Creates Uint8Array of bytes of Issuer and Embedded Signature subpackets
   * @returns {Uint8Array} Subpacket data.
   */
  writeUnhashedSubPackets() {
    const sub = enums.signatureSubpacket;
    const arr = [];
    let bytes;
    if (!this.issuerKeyID.isNull() && this.issuerKeyVersion !== 5) {
      // If the version of [the] key is greater than 4, this subpacket
      // MUST NOT be included in the signature.
      arr.push(writeSubPacket(sub.issuer, this.issuerKeyID.write()));
    }
    if (this.embeddedSignature !== null) {
      arr.push(writeSubPacket(sub.embeddedSignature, this.embeddedSignature.write()));
    }
    if (this.issuerFingerprint !== null) {
      bytes = [new Uint8Array([this.issuerKeyVersion]), this.issuerFingerprint];
      bytes = util.concat(bytes);
      arr.push(writeSubPacket(sub.issuerFingerprint, bytes));
    }
    this.unhashedSubpackets.forEach(data => {
      arr.push(writeSimpleLength(data.length));
      arr.push(data);
    });

    const result = util.concat(arr);
    const length = util.writeNumber(result.length, 2);

    return util.concat([length, result]);
  }

  // V4 signature sub packets
  readSubPacket(bytes, hashed = true) {
    let mypos = 0;

    // The leftmost bit denotes a "critical" packet
    const critical = bytes[mypos] & 0x80;
    const type = bytes[mypos] & 0x7F;

    if (!hashed && !allowedUnhashedSubpackets.has(type)) {
      this.unhashedSubpackets.push(bytes.subarray(mypos, bytes.length));
      return;
    }

    mypos++;

    // subpacket type
    switch (type) {
      case enums.signatureSubpacket.signatureCreationTime:
        // Signature Creation Time
        this.created = util.readDate(bytes.subarray(mypos, bytes.length));
        break;
      case enums.signatureSubpacket.signatureExpirationTime: {
        // Signature Expiration Time in seconds
        const seconds = util.readNumber(bytes.subarray(mypos, bytes.length));

        this.signatureNeverExpires = seconds === 0;
        this.signatureExpirationTime = seconds;

        break;
      }
      case enums.signatureSubpacket.exportableCertification:
        // Exportable Certification
        this.exportable = bytes[mypos++] === 1;
        break;
      case enums.signatureSubpacket.trustSignature:
        // Trust Signature
        this.trustLevel = bytes[mypos++];
        this.trustAmount = bytes[mypos++];
        break;
      case enums.signatureSubpacket.regularExpression:
        // Regular Expression
        this.regularExpression = bytes[mypos];
        break;
      case enums.signatureSubpacket.revocable:
        // Revocable
        this.revocable = bytes[mypos++] === 1;
        break;
      case enums.signatureSubpacket.keyExpirationTime: {
        // Key Expiration Time in seconds
        const seconds = util.readNumber(bytes.subarray(mypos, bytes.length));

        this.keyExpirationTime = seconds;
        this.keyNeverExpires = seconds === 0;

        break;
      }
      case enums.signatureSubpacket.preferredSymmetricAlgorithms:
        // Preferred Symmetric Algorithms
        this.preferredSymmetricAlgorithms = [...bytes.subarray(mypos, bytes.length)];
        break;
      case enums.signatureSubpacket.revocationKey:
        // Revocation Key
        // (1 octet of class, 1 octet of public-key algorithm ID, 20
        // octets of
        // fingerprint)
        this.revocationKeyClass = bytes[mypos++];
        this.revocationKeyAlgorithm = bytes[mypos++];
        this.revocationKeyFingerprint = bytes.subarray(mypos, mypos + 20);
        break;

      case enums.signatureSubpacket.issuer:
        // Issuer
        this.issuerKeyID.read(bytes.subarray(mypos, bytes.length));
        break;

      case enums.signatureSubpacket.notationData: {
        // Notation Data
        const humanReadable = !!(bytes[mypos] & 0x80);

        // We extract key/value tuple from the byte stream.
        mypos += 4;
        const m = util.readNumber(bytes.subarray(mypos, mypos + 2));
        mypos += 2;
        const n = util.readNumber(bytes.subarray(mypos, mypos + 2));
        mypos += 2;

        const name = util.uint8ArrayToString(bytes.subarray(mypos, mypos + m));
        const value = bytes.subarray(mypos + m, mypos + m + n);

        this.rawNotations.push({ name, humanReadable, value, critical });

        if (humanReadable) {
          this.notations[name] = util.uint8ArrayToString(value);
        }
        break;
      }
      case enums.signatureSubpacket.preferredHashAlgorithms:
        // Preferred Hash Algorithms
        this.preferredHashAlgorithms = [...bytes.subarray(mypos, bytes.length)];
        break;
      case enums.signatureSubpacket.preferredCompressionAlgorithms:
        // Preferred Compression Algorithms
        this.preferredCompressionAlgorithms = [...bytes.subarray(mypos, bytes.length)];
        break;
      case enums.signatureSubpacket.keyServerPreferences:
        // Key Server Preferences
        this.keyServerPreferences = [...bytes.subarray(mypos, bytes.length)];
        break;
      case enums.signatureSubpacket.preferredKeyServer:
        // Preferred Key Server
        this.preferredKeyServer = util.uint8ArrayToString(bytes.subarray(mypos, bytes.length));
        break;
      case enums.signatureSubpacket.primaryUserID:
        // Primary User ID
        this.isPrimaryUserID = bytes[mypos++] !== 0;
        break;
      case enums.signatureSubpacket.policyURI:
        // Policy URI
        this.policyURI = util.uint8ArrayToString(bytes.subarray(mypos, bytes.length));
        break;
      case enums.signatureSubpacket.keyFlags:
        // Key Flags
        this.keyFlags = [...bytes.subarray(mypos, bytes.length)];
        break;
      case enums.signatureSubpacket.signersUserID:
        // Signer's User ID
        this.signersUserID = util.uint8ArrayToString(bytes.subarray(mypos, bytes.length));
        break;
      case enums.signatureSubpacket.reasonForRevocation:
        // Reason for Revocation
        this.reasonForRevocationFlag = bytes[mypos++];
        this.reasonForRevocationString = util.uint8ArrayToString(bytes.subarray(mypos, bytes.length));
        break;
      case enums.signatureSubpacket.features:
        // Features
        this.features = [...bytes.subarray(mypos, bytes.length)];
        break;
      case enums.signatureSubpacket.signatureTarget: {
        // Signature Target
        // (1 octet public-key algorithm, 1 octet hash algorithm, N octets hash)
        this.signatureTargetPublicKeyAlgorithm = bytes[mypos++];
        this.signatureTargetHashAlgorithm = bytes[mypos++];

        const len = crypto.getHashByteLength(this.signatureTargetHashAlgorithm);

        this.signatureTargetHash = util.uint8ArrayToString(bytes.subarray(mypos, mypos + len));
        break;
      }
      case enums.signatureSubpacket.embeddedSignature:
        // Embedded Signature
        this.embeddedSignature = new SignaturePacket();
        this.embeddedSignature.read(bytes.subarray(mypos, bytes.length));
        break;
      case enums.signatureSubpacket.issuerFingerprint:
        // Issuer Fingerprint
        this.issuerKeyVersion = bytes[mypos++];
        this.issuerFingerprint = bytes.subarray(mypos, bytes.length);
        if (this.issuerKeyVersion === 5) {
          this.issuerKeyID.read(this.issuerFingerprint);
        } else {
          this.issuerKeyID.read(this.issuerFingerprint.subarray(-8));
        }
        break;
      case enums.signatureSubpacket.preferredAEADAlgorithms:
        // Preferred AEAD Algorithms
        this.preferredAEADAlgorithms = [...bytes.subarray(mypos, bytes.length)];
        break;
      default: {
        const err = new Error(`Unknown signature subpacket type ${type}`);
        if (critical) {
          throw err;
        } else {
          util.printDebug(err);
        }
      }
    }
  }

  readSubPackets(bytes, trusted = true, config) {
    // Two-octet scalar octet count for following subpacket data.
    const subpacketLength = util.readNumber(bytes.subarray(0, 2));

    let i = 2;

    // subpacket data set (zero or more subpackets)
    while (i < 2 + subpacketLength) {
      const len = readSimpleLength(bytes.subarray(i, bytes.length));
      i += len.offset;

      this.readSubPacket(bytes.subarray(i, i + len.len), trusted, config);

      i += len.len;
    }

    return i;
  }

  // Produces data to produce signature on
  toSign(type, data) {
    const t = enums.signature;

    switch (type) {
      case t.binary:
        if (data.text !== null) {
          return util.encodeUTF8(data.getText(true));
        }
        return data.getBytes(true);

      case t.text: {
        const bytes = data.getBytes(true);
        // normalize EOL to \r\n
        return util.canonicalizeEOL(bytes);
      }
      case t.standalone:
        return new Uint8Array(0);

      case t.certGeneric:
      case t.certPersona:
      case t.certCasual:
      case t.certPositive:
      case t.certRevocation: {
        let packet;
        let tag;

        if (data.userID) {
          tag = 0xB4;
          packet = data.userID;
        } else if (data.userAttribute) {
          tag = 0xD1;
          packet = data.userAttribute;
        } else {
          throw new Error('Either a userID or userAttribute packet needs to be ' +
            'supplied for certification.');
        }

        const bytes = packet.write();

        return util.concat([this.toSign(t.key, data),
          new Uint8Array([tag]),
          util.writeNumber(bytes.length, 4),
          bytes]);
      }
      case t.subkeyBinding:
      case t.subkeyRevocation:
      case t.keyBinding:
        return util.concat([this.toSign(t.key, data), this.toSign(t.key, {
          key: data.bind
        })]);

      case t.key:
        if (data.key === undefined) {
          throw new Error('Key packet is required for this signature.');
        }
        return data.key.writeForHash(this.version);

      case t.keyRevocation:
        return this.toSign(t.key, data);
      case t.timestamp:
        return new Uint8Array(0);
      case t.thirdParty:
        throw new Error('Not implemented');
      default:
        throw new Error('Unknown signature type.');
    }
  }

  calculateTrailer(data, detached) {
    let length = 0;
    return stream.transform(stream.clone(this.signatureData), value => {
      length += value.length;
    }, () => {
      const arr = [];
      if (this.version === 5 && (this.signatureType === enums.signature.binary || this.signatureType === enums.signature.text)) {
        if (detached) {
          arr.push(new Uint8Array(6));
        } else {
          arr.push(data.writeHeader());
        }
      }
      arr.push(new Uint8Array([this.version, 0xFF]));
      if (this.version === 5) {
        arr.push(new Uint8Array(4));
      }
      arr.push(util.writeNumber(length, 4));
      // For v5, this should really be writeNumber(length, 8) rather than the
      // hardcoded 4 zero bytes above
      return util.concat(arr);
    });
  }

  toHash(signatureType, data, detached = false) {
    const bytes = this.toSign(signatureType, data);

    return util.concat([bytes, this.signatureData, this.calculateTrailer(data, detached)]);
  }

  async hash(signatureType, data, toHash, detached = false) {
    const hashAlgorithm = enums.write(enums.hash, this.hashAlgorithm);
    if (!toHash) toHash = this.toHash(signatureType, data, detached);
    return crypto.hash.digest(hashAlgorithm, toHash);
  }

  /**
   * verifies the signature packet. Note: not all signature types are implemented
   * @param {PublicSubkeyPacket|PublicKeyPacket|
   *         SecretSubkeyPacket|SecretKeyPacket} key - the public key to verify the signature
   * @param {module:enums.signature} signatureType - Expected signature type
   * @param {String|Object} data - Data which on the signature applies
   * @param {Date} [date] - Use the given date instead of the current time to check for signature validity and expiration
   * @param {Boolean} [detached] - Whether to verify a detached signature
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @throws {Error} if signature validation failed
   * @async
   */
  async verify(key, signatureType, data, date = new Date(), detached = false, config = defaultConfig) {
    const publicKeyAlgorithm = enums.write(enums.publicKey, this.publicKeyAlgorithm);
    const hashAlgorithm = enums.write(enums.hash, this.hashAlgorithm);
    if (!this.issuerKeyID.equals(key.getKeyID())) {
      throw new Error('Signature was not issued by the given public key');
    }
    if (publicKeyAlgorithm !== enums.write(enums.publicKey, key.algorithm)) {
      throw new Error('Public key algorithm used to sign signature does not match issuer key algorithm.');
    }

    const isMessageSignature = signatureType === enums.signature.binary || signatureType === enums.signature.text;
    // Cryptographic validity is cached after one successful verification.
    // However, for message signatures, we always re-verify, since the passed `data` can change
    const skipVerify = this[verified] && !isMessageSignature;
    if (!skipVerify) {
      let toHash;
      let hash;
      if (this.hashed) {
        hash = await this.hashed;
      } else {
        toHash = this.toHash(signatureType, data, detached);
        hash = await this.hash(signatureType, data, toHash);
      }
      hash = await stream.readToEnd(hash);
      if (this.signedHashValue[0] !== hash[0] ||
          this.signedHashValue[1] !== hash[1]) {
        throw new Error('Signed digest did not match');
      }

      this.params = await this.params;

      this[verified] = await crypto.signature.verify(
        publicKeyAlgorithm, hashAlgorithm, this.params, key.publicParams,
        toHash, hash
      );

      if (!this[verified]) {
        throw new Error('Signature verification failed');
      }
    }

    const normDate = util.normalizeDate(date);
    if (normDate && this.created > normDate) {
      throw new Error('Signature creation time is in the future');
    }
    if (normDate && normDate >= this.getExpirationTime()) {
      throw new Error('Signature is expired');
    }
    if (config.rejectHashAlgorithms.has(hashAlgorithm)) {
      throw new Error('Insecure hash algorithm: ' + enums.read(enums.hash, hashAlgorithm).toUpperCase());
    }
    if (config.rejectMessageHashAlgorithms.has(hashAlgorithm) &&
      [enums.signature.binary, enums.signature.text].includes(this.signatureType)) {
      throw new Error('Insecure message hash algorithm: ' + enums.read(enums.hash, hashAlgorithm).toUpperCase());
    }
    this.rawNotations.forEach(({ name, critical }) => {
      if (critical && (config.knownNotations.indexOf(name) < 0)) {
        throw new Error(`Unknown critical notation: ${name}`);
      }
    });
    if (this.revocationKeyClass !== null) {
      throw new Error('This key is intended to be revoked with an authorized key, which OpenPGP.js does not support.');
    }
  }

  /**
   * Verifies signature expiration date
   * @param {Date} [date] - Use the given date for verification instead of the current time
   * @returns {Boolean} True if expired.
   */
  isExpired(date = new Date()) {
    const normDate = util.normalizeDate(date);
    if (normDate !== null) {
      return !(this.created <= normDate && normDate < this.getExpirationTime());
    }
    return false;
  }

  /**
   * Returns the expiration time of the signature or Infinity if signature does not expire
   * @returns {Date | Infinity} Expiration time.
   */
  getExpirationTime() {
    return this.signatureNeverExpires ? Infinity : new Date(this.created.getTime() + this.signatureExpirationTime * 1000);
  }
}

export default SignaturePacket;

/**
 * Creates a string representation of a sub signature packet
 * @see {@link https://tools.ietf.org/html/rfc4880#section-5.2.3.1|RFC4880 5.2.3.1}
 * @see {@link https://tools.ietf.org/html/rfc4880#section-5.2.3.2|RFC4880 5.2.3.2}
 * @param {Integer} type - Subpacket signature type.
 * @param {String} data - Data to be included
 * @returns {String} A string-representation of a sub signature packet.
 * @private
 */
function writeSubPacket(type, data) {
  const arr = [];
  arr.push(writeSimpleLength(data.length + 1));
  arr.push(new Uint8Array([type]));
  arr.push(data);
  return util.concat(arr);
}
