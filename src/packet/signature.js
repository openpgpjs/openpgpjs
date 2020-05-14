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
 * @requires web-stream-tools
 * @requires packet/packet
 * @requires type/keyid
 * @requires type/mpi
 * @requires crypto
 * @requires enums
 * @requires util
 */

import stream from 'web-stream-tools';
import packet from './packet';
import type_keyid from '../type/keyid.js';
import type_mpi from '../type/mpi.js';
import crypto from '../crypto';
import enums from '../enums';
import util from '../util';
import config from '../config';

/**
 * Implementation of the Signature Packet (Tag 2)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.2|RFC4480 5.2}:
 * A Signature packet describes a binding between some public key and
 * some data.  The most common signatures are a signature of a file or a
 * block of text, and a signature that is a certification of a User ID.
 * @memberof module:packet
 * @constructor
 * @param {Date} date the creation date of the signature
 */
function SignaturePacket(date = new Date()) {
  this.tag = enums.packet.signature;
  this.version = 4; // This is set to 5 below if we sign with a V5 key.
  this.signatureType = null;
  this.hashAlgorithm = null;
  this.publicKeyAlgorithm = null;

  this.signatureData = null;
  this.unhashedSubpackets = [];
  this.signedHashValue = null;

  this.created = util.normalizeDate(date);
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
  this.issuerKeyId = new type_keyid();
  this.notations = [];
  this.preferredHashAlgorithms = null;
  this.preferredCompressionAlgorithms = null;
  this.keyServerPreferences = null;
  this.preferredKeyServer = null;
  this.isPrimaryUserID = null;
  this.policyURI = null;
  this.keyFlags = null;
  this.signersUserId = null;
  this.reasonForRevocationFlag = null;
  this.reasonForRevocationString = null;
  this.features = null;
  this.signatureTargetPublicKeyAlgorithm = null;
  this.signatureTargetHashAlgorithm = null;
  this.signatureTargetHash = null;
  this.embeddedSignature = null;
  this.issuerKeyVersion = null;
  this.issuerFingerprint = null;
  this.preferredAeadAlgorithms = null;

  this.verified = null;
  this.revoked = null;
}

/**
 * parsing function for a signature packet (tag 2).
 * @param {String} bytes payload of a tag 2 packet
 * @returns {SignaturePacket} object representation
 */
SignaturePacket.prototype.read = function (bytes) {
  let i = 0;
  this.version = bytes[i++];

  if (this.version !== 4 && this.version !== 5) {
    throw new Error('Version ' + this.version + ' of the signature is unsupported.');
  }

  this.signatureType = bytes[i++];
  this.publicKeyAlgorithm = bytes[i++];
  this.hashAlgorithm = bytes[i++];

  // hashed subpackets
  i += this.read_sub_packets(bytes.subarray(i, bytes.length), true);

  // A V4 signature hashes the packet body
  // starting from its first field, the version number, through the end
  // of the hashed subpacket data.  Thus, the fields hashed are the
  // signature version, the signature type, the public-key algorithm, the
  // hash algorithm, the hashed subpacket length, and the hashed
  // subpacket body.
  this.signatureData = bytes.subarray(0, i);

  // unhashed subpackets
  i += this.read_sub_packets(bytes.subarray(i, bytes.length), false);

  // Two-octet field holding left 16 bits of signed hash value.
  this.signedHashValue = bytes.subarray(i, i + 2);
  i += 2;

  this.signature = bytes.subarray(i, bytes.length);
};

SignaturePacket.prototype.write = function () {
  const arr = [];
  arr.push(this.signatureData);
  arr.push(this.write_unhashed_sub_packets());
  arr.push(this.signedHashValue);
  arr.push(stream.clone(this.signature));
  return util.concat(arr);
};

/**
 * Signs provided data. This needs to be done prior to serialization.
 * @param {SecretKeyPacket} key private key used to sign the message.
 * @param {Object} data Contains packets to be signed.
 * @param {Boolean} detached (optional) whether to create a detached signature
 * @param {Boolean} streaming (optional) whether to process data as a stream
 * @returns {Promise<Boolean>}
 * @async
 */
SignaturePacket.prototype.sign = async function (key, data, detached = false, streaming = false) {
  const signatureType = enums.write(enums.signature, this.signatureType);
  const publicKeyAlgorithm = enums.write(enums.publicKey, this.publicKeyAlgorithm);
  const hashAlgorithm = enums.write(enums.hash, this.hashAlgorithm);

  if (key.version === 5) {
    this.version = 5;
  }
  const arr = [new Uint8Array([this.version, signatureType, publicKeyAlgorithm, hashAlgorithm])];

  if (key.version === 5) {
    // We could also generate this subpacket for version 4 keys, but for
    // now we don't.
    this.issuerKeyVersion = key.version;
    this.issuerFingerprint = key.getFingerprintBytes();
  }

  this.issuerKeyId = key.getKeyId();

  // Add hashed subpackets
  arr.push(this.write_hashed_sub_packets());

  this.signatureData = util.concat(arr);

  const toHash = this.toHash(signatureType, data, detached);
  const hash = await this.hash(signatureType, data, toHash, detached);

  this.signedHashValue = stream.slice(stream.clone(hash), 0, 2);
  const params = key.params;
  const signed = async () => crypto.signature.sign(
    publicKeyAlgorithm, hashAlgorithm, params, toHash, await stream.readToEnd(hash)
  );
  if (streaming) {
    this.signature = stream.fromAsync(signed);
  } else {
    this.signature = await signed();

    // Store the fact that this signature is valid, e.g. for when we call `await
    // getLatestValidSignature(this.revocationSignatures, key, data)` later.
    // Note that this only holds up if the key and data passed to verify are the
    // same as the ones passed to sign.
    this.verified = true;
  }
  return true;
};

/**
 * Creates Uint8Array of bytes of all subpacket data except Issuer and Embedded Signature subpackets
 * @returns {Uint8Array} subpacket data
 */
SignaturePacket.prototype.write_hashed_sub_packets = function () {
  const sub = enums.signatureSubpacket;
  const arr = [];
  let bytes;
  if (this.created !== null) {
    arr.push(write_sub_packet(sub.signatureCreationTime, util.writeDate(this.created)));
  }
  if (this.signatureExpirationTime !== null) {
    arr.push(write_sub_packet(sub.signatureExpirationTime, util.writeNumber(this.signatureExpirationTime, 4)));
  }
  if (this.exportable !== null) {
    arr.push(write_sub_packet(sub.exportableCertification, new Uint8Array([this.exportable ? 1 : 0])));
  }
  if (this.trustLevel !== null) {
    bytes = new Uint8Array([this.trustLevel, this.trustAmount]);
    arr.push(write_sub_packet(sub.trustSignature, bytes));
  }
  if (this.regularExpression !== null) {
    arr.push(write_sub_packet(sub.regularExpression, this.regularExpression));
  }
  if (this.revocable !== null) {
    arr.push(write_sub_packet(sub.revocable, new Uint8Array([this.revocable ? 1 : 0])));
  }
  if (this.keyExpirationTime !== null) {
    arr.push(write_sub_packet(sub.keyExpirationTime, util.writeNumber(this.keyExpirationTime, 4)));
  }
  if (this.preferredSymmetricAlgorithms !== null) {
    bytes = util.strToUint8Array(util.uint8ArrayToStr(this.preferredSymmetricAlgorithms));
    arr.push(write_sub_packet(sub.preferredSymmetricAlgorithms, bytes));
  }
  if (this.revocationKeyClass !== null) {
    bytes = new Uint8Array([this.revocationKeyClass, this.revocationKeyAlgorithm]);
    bytes = util.concat([bytes, this.revocationKeyFingerprint]);
    arr.push(write_sub_packet(sub.revocationKey, bytes));
  }
  this.notations.forEach(([name, value]) => {
    bytes = [new Uint8Array([0x80, 0, 0, 0])];
    // 2 octets of name length
    bytes.push(util.writeNumber(name.length, 2));
    // 2 octets of value length
    bytes.push(util.writeNumber(value.length, 2));
    bytes.push(util.strToUint8Array(name + value));
    bytes = util.concat(bytes);
    arr.push(write_sub_packet(sub.notationData, bytes));
  });
  if (this.preferredHashAlgorithms !== null) {
    bytes = util.strToUint8Array(util.uint8ArrayToStr(this.preferredHashAlgorithms));
    arr.push(write_sub_packet(sub.preferredHashAlgorithms, bytes));
  }
  if (this.preferredCompressionAlgorithms !== null) {
    bytes = util.strToUint8Array(util.uint8ArrayToStr(this.preferredCompressionAlgorithms));
    arr.push(write_sub_packet(sub.preferredCompressionAlgorithms, bytes));
  }
  if (this.keyServerPreferences !== null) {
    bytes = util.strToUint8Array(util.uint8ArrayToStr(this.keyServerPreferences));
    arr.push(write_sub_packet(sub.keyServerPreferences, bytes));
  }
  if (this.preferredKeyServer !== null) {
    arr.push(write_sub_packet(sub.preferredKeyServer, util.strToUint8Array(this.preferredKeyServer)));
  }
  if (this.isPrimaryUserID !== null) {
    arr.push(write_sub_packet(sub.primaryUserId, new Uint8Array([this.isPrimaryUserID ? 1 : 0])));
  }
  if (this.policyURI !== null) {
    arr.push(write_sub_packet(sub.policyUri, util.strToUint8Array(this.policyURI)));
  }
  if (this.keyFlags !== null) {
    bytes = util.strToUint8Array(util.uint8ArrayToStr(this.keyFlags));
    arr.push(write_sub_packet(sub.keyFlags, bytes));
  }
  if (this.signersUserId !== null) {
    arr.push(write_sub_packet(sub.signersUserId, util.strToUint8Array(this.signersUserId)));
  }
  if (this.reasonForRevocationFlag !== null) {
    bytes = util.strToUint8Array(String.fromCharCode(this.reasonForRevocationFlag) + this.reasonForRevocationString);
    arr.push(write_sub_packet(sub.reasonForRevocation, bytes));
  }
  if (this.features !== null) {
    bytes = util.strToUint8Array(util.uint8ArrayToStr(this.features));
    arr.push(write_sub_packet(sub.features, bytes));
  }
  if (this.signatureTargetPublicKeyAlgorithm !== null) {
    bytes = [new Uint8Array([this.signatureTargetPublicKeyAlgorithm, this.signatureTargetHashAlgorithm])];
    bytes.push(util.strToUint8Array(this.signatureTargetHash));
    bytes = util.concat(bytes);
    arr.push(write_sub_packet(sub.signatureTarget, bytes));
  }
  if (this.preferredAeadAlgorithms !== null) {
    bytes = util.strToUint8Array(util.uint8ArrayToStr(this.preferredAeadAlgorithms));
    arr.push(write_sub_packet(sub.preferredAeadAlgorithms, bytes));
  }

  const result = util.concat(arr);
  const length = util.writeNumber(result.length, 2);

  return util.concat([length, result]);
};

/**
 * Creates Uint8Array of bytes of Issuer and Embedded Signature subpackets
 * @returns {Uint8Array} subpacket data
 */
SignaturePacket.prototype.write_unhashed_sub_packets = function() {
  const sub = enums.signatureSubpacket;
  const arr = [];
  let bytes;
  if (!this.issuerKeyId.isNull() && this.issuerKeyVersion !== 5) {
    // If the version of [the] key is greater than 4, this subpacket
    // MUST NOT be included in the signature.
    arr.push(write_sub_packet(sub.issuer, this.issuerKeyId.write()));
  }
  if (this.embeddedSignature !== null) {
    arr.push(write_sub_packet(sub.embeddedSignature, this.embeddedSignature.write()));
  }
  if (this.issuerFingerprint !== null) {
    bytes = [new Uint8Array([this.issuerKeyVersion]), this.issuerFingerprint];
    bytes = util.concat(bytes);
    arr.push(write_sub_packet(sub.issuerFingerprint, bytes));
  }
  this.unhashedSubpackets.forEach(data => {
    arr.push(packet.writeSimpleLength(data.length));
    arr.push(data);
  });

  const result = util.concat(arr);
  const length = util.writeNumber(result.length, 2);

  return util.concat([length, result]);
};

/**
 * Creates a string representation of a sub signature packet
 * @see {@link https://tools.ietf.org/html/rfc4880#section-5.2.3.1|RFC4880 5.2.3.1}
 * @see {@link https://tools.ietf.org/html/rfc4880#section-5.2.3.2|RFC4880 5.2.3.2}
 * @param {Integer} type subpacket signature type.
 * @param {String} data data to be included
 * @returns {String} a string-representation of a sub signature packet
 * @private
 */
function write_sub_packet(type, data) {
  const arr = [];
  arr.push(packet.writeSimpleLength(data.length + 1));
  arr.push(new Uint8Array([type]));
  arr.push(data);
  return util.concat(arr);
}

// V4 signature sub packets

SignaturePacket.prototype.read_sub_packet = function (bytes, trusted = true) {
  let mypos = 0;

  const read_array = (prop, bytes) => {
    this[prop] = [];

    for (let i = 0; i < bytes.length; i++) {
      this[prop].push(bytes[i]);
    }
  };

  // The leftmost bit denotes a "critical" packet
  const critical = bytes[mypos] & 0x80;
  const type = bytes[mypos] & 0x7F;

  // GPG puts the Issuer and Signature subpackets in the unhashed area.
  // Tampering with those invalidates the signature, so we can trust them.
  // Ignore all other unhashed subpackets.
  if (!trusted && ![
    enums.signatureSubpacket.issuer,
    enums.signatureSubpacket.issuerFingerprint,
    enums.signatureSubpacket.embeddedSignature
  ].includes(type)) {
    this.unhashedSubpackets.push(bytes.subarray(mypos, bytes.length));
    return;
  }

  mypos++;

  // subpacket type
  switch (type) {
    case 2:
      // Signature Creation Time
      this.created = util.readDate(bytes.subarray(mypos, bytes.length));
      break;
    case 3: {
      // Signature Expiration Time in seconds
      const seconds = util.readNumber(bytes.subarray(mypos, bytes.length));

      this.signatureNeverExpires = seconds === 0;
      this.signatureExpirationTime = seconds;

      break;
    }
    case 4:
      // Exportable Certification
      this.exportable = bytes[mypos++] === 1;
      break;
    case 5:
      // Trust Signature
      this.trustLevel = bytes[mypos++];
      this.trustAmount = bytes[mypos++];
      break;
    case 6:
      // Regular Expression
      this.regularExpression = bytes[mypos];
      break;
    case 7:
      // Revocable
      this.revocable = bytes[mypos++] === 1;
      break;
    case 9: {
      // Key Expiration Time in seconds
      const seconds = util.readNumber(bytes.subarray(mypos, bytes.length));

      this.keyExpirationTime = seconds;
      this.keyNeverExpires = seconds === 0;

      break;
    }
    case 11:
      // Preferred Symmetric Algorithms
      read_array('preferredSymmetricAlgorithms', bytes.subarray(mypos, bytes.length));
      break;
    case 12:
      // Revocation Key
      // (1 octet of class, 1 octet of public-key algorithm ID, 20
      // octets of
      // fingerprint)
      this.revocationKeyClass = bytes[mypos++];
      this.revocationKeyAlgorithm = bytes[mypos++];
      this.revocationKeyFingerprint = bytes.subarray(mypos, mypos + 20);
      break;

    case 16:
      // Issuer
      this.issuerKeyId.read(bytes.subarray(mypos, bytes.length));
      break;

    case 20:
      // Notation Data
      // We don't know how to handle anything but a text flagged data.
      if (bytes[mypos] === 0x80) {
        // We extract key/value tuple from the byte stream.
        mypos += 4;
        const m = util.readNumber(bytes.subarray(mypos, mypos + 2));
        mypos += 2;
        const n = util.readNumber(bytes.subarray(mypos, mypos + 2));
        mypos += 2;

        const name = util.uint8ArrayToStr(bytes.subarray(mypos, mypos + m));
        const value = util.uint8ArrayToStr(bytes.subarray(mypos + m, mypos + m + n));

        this.notations.push([name, value]);

        if (critical && (config.knownNotations.indexOf(name) === -1)) {
          throw new Error("Unknown critical notation: " + name);
        }
      } else {
        util.printDebug("Unsupported notation flag " + bytes[mypos]);
      }
      break;
    case 21:
      // Preferred Hash Algorithms
      read_array('preferredHashAlgorithms', bytes.subarray(mypos, bytes.length));
      break;
    case 22:
      // Preferred Compression Algorithms
      read_array('preferredCompressionAlgorithms', bytes.subarray(mypos, bytes.length));
      break;
    case 23:
      // Key Server Preferences
      read_array('keyServerPreferences', bytes.subarray(mypos, bytes.length));
      break;
    case 24:
      // Preferred Key Server
      this.preferredKeyServer = util.uint8ArrayToStr(bytes.subarray(mypos, bytes.length));
      break;
    case 25:
      // Primary User ID
      this.isPrimaryUserID = bytes[mypos++] !== 0;
      break;
    case 26:
      // Policy URI
      this.policyURI = util.uint8ArrayToStr(bytes.subarray(mypos, bytes.length));
      break;
    case 27:
      // Key Flags
      read_array('keyFlags', bytes.subarray(mypos, bytes.length));
      break;
    case 28:
      // Signer's User ID
      this.signersUserId = util.uint8ArrayToStr(bytes.subarray(mypos, bytes.length));
      break;
    case 29:
      // Reason for Revocation
      this.reasonForRevocationFlag = bytes[mypos++];
      this.reasonForRevocationString = util.uint8ArrayToStr(bytes.subarray(mypos, bytes.length));
      break;
    case 30:
      // Features
      read_array('features', bytes.subarray(mypos, bytes.length));
      break;
    case 31: {
      // Signature Target
      // (1 octet public-key algorithm, 1 octet hash algorithm, N octets hash)
      this.signatureTargetPublicKeyAlgorithm = bytes[mypos++];
      this.signatureTargetHashAlgorithm = bytes[mypos++];

      const len = crypto.getHashByteLength(this.signatureTargetHashAlgorithm);

      this.signatureTargetHash = util.uint8ArrayToStr(bytes.subarray(mypos, mypos + len));
      break;
    }
    case 32:
      // Embedded Signature
      this.embeddedSignature = new SignaturePacket();
      this.embeddedSignature.read(bytes.subarray(mypos, bytes.length));
      break;
    case 33:
      // Issuer Fingerprint
      this.issuerKeyVersion = bytes[mypos++];
      this.issuerFingerprint = bytes.subarray(mypos, bytes.length);
      if (this.issuerKeyVersion === 5) {
        this.issuerKeyId.read(this.issuerFingerprint);
      } else {
        this.issuerKeyId.read(this.issuerFingerprint.subarray(-8));
      }
      break;
    case 34:
      // Preferred AEAD Algorithms
      read_array.call(this, 'preferredAeadAlgorithms', bytes.subarray(mypos, bytes.length));
      break;
    default: {
      const err = new Error("Unknown signature subpacket type " + type + " @:" + mypos);
      if (critical) {
        throw err;
      } else {
        util.printDebug(err);
      }
    }
  }
};

SignaturePacket.prototype.read_sub_packets = function(bytes, trusted = true) {
  // Two-octet scalar octet count for following subpacket data.
  const subpacket_length = util.readNumber(bytes.subarray(0, 2));

  let i = 2;

  // subpacket data set (zero or more subpackets)
  while (i < 2 + subpacket_length) {
    const len = packet.readSimpleLength(bytes.subarray(i, bytes.length));
    i += len.offset;

    this.read_sub_packet(bytes.subarray(i, i + len.len), trusted);

    i += len.len;
  }

  return i;
};

// Produces data to produce signature on
SignaturePacket.prototype.toSign = function (type, data) {
  const t = enums.signature;

  switch (type) {
    case t.binary:
      if (data.text !== null) {
        return util.encodeUtf8(data.getText(true));
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

      if (data.userId) {
        tag = 0xB4;
        packet = data.userId;
      } else if (data.userAttribute) {
        tag = 0xD1;
        packet = data.userAttribute;
      } else {
        throw new Error('Either a userId or userAttribute packet needs to be ' +
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
};


SignaturePacket.prototype.calculateTrailer = function (data, detached) {
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
};


SignaturePacket.prototype.toHash = function(signatureType, data, detached = false) {
  const bytes = this.toSign(signatureType, data);

  return util.concat([bytes, this.signatureData, this.calculateTrailer(data, detached)]);
};

SignaturePacket.prototype.hash = async function(signatureType, data, toHash, detached = false, streaming = true) {
  const hashAlgorithm = enums.write(enums.hash, this.hashAlgorithm);
  if (!toHash) toHash = this.toHash(signatureType, data, detached);
  if (!streaming && util.isStream(toHash)) {
    return stream.fromAsync(async () => this.hash(signatureType, data, await stream.readToEnd(toHash), detached));
  }
  return crypto.hash.digest(hashAlgorithm, toHash);
};


/**
 * verifies the signature packet. Note: not all signature types are implemented
 * @param {PublicSubkeyPacket|PublicKeyPacket|
 *         SecretSubkeyPacket|SecretKeyPacket} key the public key to verify the signature
 * @param {module:enums.signature} signatureType expected signature type
 * @param {String|Object} data data which on the signature applies
 * @param {Boolean} detached (optional) whether to verify a detached signature
 * @returns {Promise<Boolean>} True if message is verified, else false.
 * @async
 */
SignaturePacket.prototype.verify = async function (key, signatureType, data, detached = false, streaming = false) {
  const publicKeyAlgorithm = enums.write(enums.publicKey, this.publicKeyAlgorithm);
  const hashAlgorithm = enums.write(enums.hash, this.hashAlgorithm);

  if (publicKeyAlgorithm !== enums.write(enums.publicKey, key.algorithm)) {
    throw new Error('Public key algorithm used to sign signature does not match issuer key algorithm.');
  }

  let toHash;
  let hash;
  if (this.hashed) {
    hash = await this.hashed;
  } else {
    toHash = this.toHash(signatureType, data, detached);
    if (!streaming) toHash = await stream.readToEnd(toHash);
    hash = await this.hash(signatureType, data, toHash);
  }
  hash = await stream.readToEnd(hash);
  if (this.signedHashValue[0] !== hash[0] ||
      this.signedHashValue[1] !== hash[1]) {
    throw new Error('Message digest did not match');
  }

  let mpicount = 0;
  // Algorithm-Specific Fields for RSA signatures:
  //      - multiprecision number (MPI) of RSA signature value m**d mod n.
  if (publicKeyAlgorithm > 0 && publicKeyAlgorithm < 4) {
    mpicount = 1;

  //    Algorithm-Specific Fields for DSA, ECDSA, and EdDSA signatures:
  //      - MPI of DSA value r.
  //      - MPI of DSA value s.
  } else if (publicKeyAlgorithm === enums.publicKey.dsa ||
            publicKeyAlgorithm === enums.publicKey.ecdsa ||
            publicKeyAlgorithm === enums.publicKey.eddsa) {
    mpicount = 2;
  }

  // EdDSA signature parameters are encoded in little-endian format
  // https://tools.ietf.org/html/rfc8032#section-5.1.2
  const endian = publicKeyAlgorithm === enums.publicKey.eddsa ? 'le' : 'be';
  const mpi = [];
  let i = 0;
  this.signature = await stream.readToEnd(this.signature);
  for (let j = 0; j < mpicount; j++) {
    mpi[j] = new type_mpi();
    i += mpi[j].read(this.signature.subarray(i, this.signature.length), endian);
  }
  const verified = await crypto.signature.verify(
    publicKeyAlgorithm, hashAlgorithm, mpi, key.params,
    toHash, hash
  );
  if (!verified) {
    throw new Error('Signature verification failed');
  }
  if (config.rejectHashAlgorithms.has(hashAlgorithm)) {
    throw new Error('Insecure hash algorithm: ' + enums.read(enums.hash, hashAlgorithm).toUpperCase());
  }
  if (config.rejectMessageHashAlgorithms.has(hashAlgorithm) &&
    [enums.signature.binary, enums.signature.text].includes(this.signatureType)) {
    throw new Error('Insecure message hash algorithm: ' + enums.read(enums.hash, hashAlgorithm).toUpperCase());
  }
  if (this.revocationKeyClass !== null) {
    throw new Error('This key is intended to be revoked with an authorized key, which OpenPGP.js does not support.');
  }
  this.verified = true;
  return true;
};

/**
 * Verifies signature expiration date
 * @param {Date} date (optional) use the given date for verification instead of the current time
 * @returns {Boolean} true if expired
 */
SignaturePacket.prototype.isExpired = function (date = new Date()) {
  const normDate = util.normalizeDate(date);
  if (normDate !== null) {
    const expirationTime = this.getExpirationTime();
    return !(this.created <= normDate && normDate <= expirationTime);
  }
  return false;
};

/**
 * Returns the expiration time of the signature or Infinity if signature does not expire
 * @returns {Date} expiration time
 */
SignaturePacket.prototype.getExpirationTime = function () {
  return !this.signatureNeverExpires ? new Date(this.created.getTime() + this.signatureExpirationTime * 1000) : Infinity;
};

export default SignaturePacket;
