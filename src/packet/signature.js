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
import KeyID from '../type/keyid';
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
  enums.signatureSubpacket.issuerKeyID,
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
    /** @type {enums.signature} */
    this.signatureType = null;
    /** @type {enums.hash} */
    this.hashAlgorithm = null;
    /** @type {enums.publicKey} */
    this.publicKeyAlgorithm = null;

    this.signatureData = null;
    this.unhashedSubpackets = [];
    this.signedHashValue = null;
    this.salt = null;

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
    this.preferredCipherSuites = null;

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

    if (this.version !== 4 && this.version !== 5 && this.version !== 6) {
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

    // Only for v6 signatures, a variable-length field containing:
    if (this.version === 6) {
      // A one-octet salt size. The value MUST match the value defined
      // for the hash algorithm as specified in Table 23 (Hash algorithm registry).
      const saltLength = bytes[i++];
      if (saltLength !== saltLengthForHash(this.hashAlgorithm)) {
        throw new Error('Unexpected salt size for the hash algorithm');
      }

      // The salt; a random value value of the specified size.
      this.salt = bytes.subarray(i, i + saltLength);
      i += saltLength;
    }

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
    if (this.version === 6) {
      arr.push(new Uint8Array([this.salt.length]));
      arr.push(this.salt);
    }
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
    this.version = key.version;

    this.created = util.normalizeDate(date);
    this.issuerKeyVersion = key.version;
    this.issuerFingerprint = key.getFingerprintBytes();
    this.issuerKeyID = key.getKeyID();

    const arr = [new Uint8Array([this.version, this.signatureType, this.publicKeyAlgorithm, this.hashAlgorithm])];

    // Add hashed subpackets
    arr.push(this.writeHashedSubPackets());

    // Remove unhashed subpackets, in case some allowed unhashed
    // subpackets existed, in order not to duplicate them (in both
    // the hashed and unhashed subpackets) when re-signing.
    this.unhashedSubpackets = [];

    this.signatureData = util.concat(arr);

    if (this.version === 6) {
      const saltLength = saltLengthForHash(this.hashAlgorithm);
      if (this.salt === null) {
        this.salt = crypto.random.getRandomBytes(saltLength);
      } else if (saltLength !== this.salt.length) {
        throw new Error('Provided salt does not have the required length');
      }
    }
    const toHash = this.toHash(this.signatureType, data, detached);
    const hash = await this.hash(this.signatureType, data, toHash, detached);

    this.signedHashValue = stream.slice(stream.clone(hash), 0, 2);
    const signed = async () => crypto.signature.sign(
      this.publicKeyAlgorithm, this.hashAlgorithm, key.publicParams, key.privateParams, toHash, await stream.readToEnd(hash)
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
    arr.push(writeSubPacket(sub.signatureCreationTime, true, util.writeDate(this.created)));
    if (this.signatureExpirationTime !== null) {
      arr.push(writeSubPacket(sub.signatureExpirationTime, true, util.writeNumber(this.signatureExpirationTime, 4)));
    }
    if (this.exportable !== null) {
      arr.push(writeSubPacket(sub.exportableCertification, true, new Uint8Array([this.exportable ? 1 : 0])));
    }
    if (this.trustLevel !== null) {
      bytes = new Uint8Array([this.trustLevel, this.trustAmount]);
      arr.push(writeSubPacket(sub.trustSignature, true, bytes));
    }
    if (this.regularExpression !== null) {
      arr.push(writeSubPacket(sub.regularExpression, true, this.regularExpression));
    }
    if (this.revocable !== null) {
      arr.push(writeSubPacket(sub.revocable, true, new Uint8Array([this.revocable ? 1 : 0])));
    }
    if (this.keyExpirationTime !== null) {
      arr.push(writeSubPacket(sub.keyExpirationTime, true, util.writeNumber(this.keyExpirationTime, 4)));
    }
    if (this.preferredSymmetricAlgorithms !== null) {
      bytes = util.stringToUint8Array(util.uint8ArrayToString(this.preferredSymmetricAlgorithms));
      arr.push(writeSubPacket(sub.preferredSymmetricAlgorithms, false, bytes));
    }
    if (this.revocationKeyClass !== null) {
      bytes = new Uint8Array([this.revocationKeyClass, this.revocationKeyAlgorithm]);
      bytes = util.concat([bytes, this.revocationKeyFingerprint]);
      arr.push(writeSubPacket(sub.revocationKey, false, bytes));
    }
    if (!this.issuerKeyID.isNull() && this.issuerKeyVersion < 5) {
      // If the version of [the] key is greater than 4, this subpacket
      // MUST NOT be included in the signature.
      arr.push(writeSubPacket(sub.issuerKeyID, true, this.issuerKeyID.write()));
    }
    this.rawNotations.forEach(({ name, value, humanReadable, critical }) => {
      bytes = [new Uint8Array([humanReadable ? 0x80 : 0, 0, 0, 0])];
      const encodedName = util.encodeUTF8(name);
      // 2 octets of name length
      bytes.push(util.writeNumber(encodedName.length, 2));
      // 2 octets of value length
      bytes.push(util.writeNumber(value.length, 2));
      bytes.push(encodedName);
      bytes.push(value);
      bytes = util.concat(bytes);
      arr.push(writeSubPacket(sub.notationData, critical, bytes));
    });
    if (this.preferredHashAlgorithms !== null) {
      bytes = util.stringToUint8Array(util.uint8ArrayToString(this.preferredHashAlgorithms));
      arr.push(writeSubPacket(sub.preferredHashAlgorithms, false, bytes));
    }
    if (this.preferredCompressionAlgorithms !== null) {
      bytes = util.stringToUint8Array(util.uint8ArrayToString(this.preferredCompressionAlgorithms));
      arr.push(writeSubPacket(sub.preferredCompressionAlgorithms, false, bytes));
    }
    if (this.keyServerPreferences !== null) {
      bytes = util.stringToUint8Array(util.uint8ArrayToString(this.keyServerPreferences));
      arr.push(writeSubPacket(sub.keyServerPreferences, false, bytes));
    }
    if (this.preferredKeyServer !== null) {
      arr.push(writeSubPacket(sub.preferredKeyServer, false, util.encodeUTF8(this.preferredKeyServer)));
    }
    if (this.isPrimaryUserID !== null) {
      arr.push(writeSubPacket(sub.primaryUserID, false, new Uint8Array([this.isPrimaryUserID ? 1 : 0])));
    }
    if (this.policyURI !== null) {
      arr.push(writeSubPacket(sub.policyURI, false, util.encodeUTF8(this.policyURI)));
    }
    if (this.keyFlags !== null) {
      bytes = util.stringToUint8Array(util.uint8ArrayToString(this.keyFlags));
      arr.push(writeSubPacket(sub.keyFlags, true, bytes));
    }
    if (this.signersUserID !== null) {
      arr.push(writeSubPacket(sub.signersUserID, false, util.encodeUTF8(this.signersUserID)));
    }
    if (this.reasonForRevocationFlag !== null) {
      bytes = util.stringToUint8Array(String.fromCharCode(this.reasonForRevocationFlag) + this.reasonForRevocationString);
      arr.push(writeSubPacket(sub.reasonForRevocation, true, bytes));
    }
    if (this.features !== null) {
      bytes = util.stringToUint8Array(util.uint8ArrayToString(this.features));
      arr.push(writeSubPacket(sub.features, false, bytes));
    }
    if (this.signatureTargetPublicKeyAlgorithm !== null) {
      bytes = [new Uint8Array([this.signatureTargetPublicKeyAlgorithm, this.signatureTargetHashAlgorithm])];
      bytes.push(util.stringToUint8Array(this.signatureTargetHash));
      bytes = util.concat(bytes);
      arr.push(writeSubPacket(sub.signatureTarget, true, bytes));
    }
    if (this.embeddedSignature !== null) {
      arr.push(writeSubPacket(sub.embeddedSignature, true, this.embeddedSignature.write()));
    }
    if (this.issuerFingerprint !== null) {
      bytes = [new Uint8Array([this.issuerKeyVersion]), this.issuerFingerprint];
      bytes = util.concat(bytes);
      arr.push(writeSubPacket(sub.issuerFingerprint, this.version >= 5, bytes));
    }
    if (this.preferredAEADAlgorithms !== null) {
      bytes = util.stringToUint8Array(util.uint8ArrayToString(this.preferredAEADAlgorithms));
      arr.push(writeSubPacket(sub.preferredAEADAlgorithms, false, bytes));
    }
    if (this.preferredCipherSuites !== null) {
      bytes = new Uint8Array([].concat(...this.preferredCipherSuites));
      arr.push(writeSubPacket(sub.preferredCipherSuites, false, bytes));
    }

    const result = util.concat(arr);
    const length = util.writeNumber(result.length, this.version === 6 ? 4 : 2);

    return util.concat([length, result]);
  }

  /**
   * Creates an Uint8Array containing the unhashed subpackets
   * @returns {Uint8Array} Subpacket data.
   */
  writeUnhashedSubPackets() {
    const arr = [];
    this.unhashedSubpackets.forEach(data => {
      arr.push(writeSimpleLength(data.length));
      arr.push(data);
    });

    const result = util.concat(arr);
    const length = util.writeNumber(result.length, this.version === 6 ? 4 : 2);

    return util.concat([length, result]);
  }

  // V4 signature sub packets
  readSubPacket(bytes, hashed = true) {
    let mypos = 0;

    // The leftmost bit denotes a "critical" packet
    const critical = !!(bytes[mypos] & 0x80);
    const type = bytes[mypos] & 0x7F;

    if (!hashed) {
      this.unhashedSubpackets.push(bytes.subarray(mypos, bytes.length));
      if (!allowedUnhashedSubpackets.has(type)) {
        return;
      }
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

      case enums.signatureSubpacket.issuerKeyID:
        // Issuer
        if (this.version === 4) {
          this.issuerKeyID.read(bytes.subarray(mypos, bytes.length));
        } else if (hashed) {
          // If the version of the key is greater than 4, this subpacket MUST NOT be included in the signature,
          // since the Issuer Fingerprint subpacket is to be used instead.
          // The `issuerKeyID` value will be set when reading the issuerFingerprint packet.
          // For this reason, if the issuer Key ID packet is present but unhashed, we simply ignore it,
          // to avoid situations where `.getSigningKeyIDs()` returns a keyID potentially different from the (signed)
          // issuerFingerprint.
          // If the packet is hashed, then we reject the signature, to avoid verifying data different from
          // what was parsed.
          throw new Error('Unexpected Issuer Key ID subpacket');
        }
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

        const name = util.decodeUTF8(bytes.subarray(mypos, mypos + m));
        const value = bytes.subarray(mypos + m, mypos + m + n);

        this.rawNotations.push({ name, humanReadable, value, critical });

        if (humanReadable) {
          this.notations[name] = util.decodeUTF8(value);
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
        this.preferredKeyServer = util.decodeUTF8(bytes.subarray(mypos, bytes.length));
        break;
      case enums.signatureSubpacket.primaryUserID:
        // Primary User ID
        this.isPrimaryUserID = bytes[mypos++] !== 0;
        break;
      case enums.signatureSubpacket.policyURI:
        // Policy URI
        this.policyURI = util.decodeUTF8(bytes.subarray(mypos, bytes.length));
        break;
      case enums.signatureSubpacket.keyFlags:
        // Key Flags
        this.keyFlags = [...bytes.subarray(mypos, bytes.length)];
        break;
      case enums.signatureSubpacket.signersUserID:
        // Signer's User ID
        this.signersUserID = util.decodeUTF8(bytes.subarray(mypos, bytes.length));
        break;
      case enums.signatureSubpacket.reasonForRevocation:
        // Reason for Revocation
        this.reasonForRevocationFlag = bytes[mypos++];
        this.reasonForRevocationString = util.decodeUTF8(bytes.subarray(mypos, bytes.length));
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
        if (this.issuerKeyVersion >= 5) {
          this.issuerKeyID.read(this.issuerFingerprint);
        } else {
          this.issuerKeyID.read(this.issuerFingerprint.subarray(-8));
        }
        break;
      case enums.signatureSubpacket.preferredAEADAlgorithms:
        // Preferred AEAD Algorithms
        this.preferredAEADAlgorithms = [...bytes.subarray(mypos, bytes.length)];
        break;
      case enums.signatureSubpacket.preferredCipherSuites:
        // Preferred AEAD Cipher Suites
        this.preferredCipherSuites = [];
        for (let i = mypos; i < bytes.length; i += 2) {
          this.preferredCipherSuites.push([bytes[i], bytes[i + 1]]);
        }
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
    const subpacketLengthBytes = this.version === 6 ? 4 : 2;

    // Two-octet scalar octet count for following subpacket data.
    const subpacketLength = util.readNumber(bytes.subarray(0, subpacketLengthBytes));

    let i = subpacketLengthBytes;

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

    return util.concat([this.salt || new Uint8Array(), bytes, this.signatureData, this.calculateTrailer(data, detached)]);
  }

  async hash(signatureType, data, toHash, detached = false) {
    if (!toHash) toHash = this.toHash(signatureType, data, detached);
    return crypto.hash.digest(this.hashAlgorithm, toHash);
  }

  /**
   * verifies the signature packet. Note: not all signature types are implemented
   * @param {PublicSubkeyPacket|PublicKeyPacket|
   *         SecretSubkeyPacket|SecretKeyPacket} key - the public key to verify the signature
   * @param {module:enums.signature} signatureType - Expected signature type
   * @param {Uint8Array|Object} data - Data which on the signature applies
   * @param {Date} [date] - Use the given date instead of the current time to check for signature validity and expiration
   * @param {Boolean} [detached] - Whether to verify a detached signature
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @throws {Error} if signature validation failed
   * @async
   */
  async verify(key, signatureType, data, date = new Date(), detached = false, config = defaultConfig) {
    if (!this.issuerKeyID.equals(key.getKeyID())) {
      throw new Error('Signature was not issued by the given public key');
    }
    if (this.publicKeyAlgorithm !== key.algorithm) {
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
        this.publicKeyAlgorithm, this.hashAlgorithm, this.params, key.publicParams,
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
    if (config.rejectHashAlgorithms.has(this.hashAlgorithm)) {
      throw new Error('Insecure hash algorithm: ' + enums.read(enums.hash, this.hashAlgorithm).toUpperCase());
    }
    if (config.rejectMessageHashAlgorithms.has(this.hashAlgorithm) &&
      [enums.signature.binary, enums.signature.text].includes(this.signatureType)) {
      throw new Error('Insecure message hash algorithm: ' + enums.read(enums.hash, this.hashAlgorithm).toUpperCase());
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
 * Creates a Uint8Array representation of a sub signature packet
 * @see {@link https://tools.ietf.org/html/rfc4880#section-5.2.3.1|RFC4880 5.2.3.1}
 * @see {@link https://tools.ietf.org/html/rfc4880#section-5.2.3.2|RFC4880 5.2.3.2}
 * @param {Integer} type - Subpacket signature type.
 * @param {Boolean} critical - Whether the subpacket should be critical.
 * @param {String} data - Data to be included
 * @returns {Uint8Array} The signature subpacket.
 * @private
 */
function writeSubPacket(type, critical, data) {
  const arr = [];
  arr.push(writeSimpleLength(data.length + 1));
  arr.push(new Uint8Array([(critical ? 0x80 : 0) | type]));
  arr.push(data);
  return util.concat(arr);
}

/**
 * Select the required salt length for the given hash algorithm, as per Table 23 (Hash algorithm registry) of the crypto refresh.
 * @see {@link https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#section-9.5|Crypto Refresh Section 9.5}
 * @param {enums.hash} hashAlgorithm - Hash algorithm.
 * @returns {Integer} Salt length.
 * @private
 */
export function saltLengthForHash(hashAlgorithm) {
  switch (hashAlgorithm) {
    case enums.hash.sha256: return 16;
    case enums.hash.sha384: return 24;
    case enums.hash.sha512: return 32;
    case enums.hash.sha224: return 16;
    case enums.hash.sha3_256: return 16;
    case enums.hash.sha3_512: return 32;
    default: throw new Error('Unsupported hash function for V6 signatures');
  }
}
