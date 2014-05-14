// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
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
 * Implementation of the Signature Packet (Tag 2)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.2|RFC4480 5.2}:
 * A Signature packet describes a binding between some public key and
 * some data.  The most common signatures are a signature of a file or a
 * block of text, and a signature that is a certification of a User ID.
 * @requires crypto
 * @requires enums
 * @requires packet/packet
 * @requires type/keyid
 * @requires type/mpi
 * @requires util
 * @module packet/signature
 */

module.exports = Signature;

var util = require('../util.js'),
  packet = require('./packet.js'),
  enums = require('../enums.js'),
  crypto = require('../crypto'),
  type_mpi = require('../type/mpi.js'),
  type_keyid = require('../type/keyid.js');

/**
 * @constructor
 */
function Signature() {
  this.tag = enums.packet.signature;
  this.version = 4;
  this.signatureType = null;
  this.hashAlgorithm = null;
  this.publicKeyAlgorithm = null;

  this.signatureData = null;
  this.unhashedSubpackets = null;
  this.signedHashValue = null;

  this.created = new Date();
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
  this.notation = null;
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

  this.verified = false;
}

/**
 * parsing function for a signature packet (tag 2).
 * @param {String} bytes payload of a tag 2 packet
 * @param {Integer} position position to start reading from the bytes string
 * @param {Integer} len length of the packet or the remaining length of bytes at position
 * @return {module:packet/signature} object representation
 */
Signature.prototype.read = function (bytes) {
  var i = 0;

  this.version = bytes.charCodeAt(i++);
  // switch on version (3 and 4)
  switch (this.version) {
    case 3:
      // One-octet length of following hashed material. MUST be 5.
      if (bytes.charCodeAt(i++) != 5)
        util.print_debug("packet/signature.js\n" +
          'invalid One-octet length of following hashed material.' +
          'MUST be 5. @:' + (i - 1));

      var sigpos = i;
      // One-octet signature type.
      this.signatureType = bytes.charCodeAt(i++);

      // Four-octet creation time.
      this.created = util.readDate(bytes.substr(i, 4));
      i += 4;

      // storing data appended to data which gets verified
      this.signatureData = bytes.substring(sigpos, i);

      // Eight-octet Key ID of signer.
      this.issuerKeyId.read(bytes.substring(i, i + 8));
      i += 8;

      // One-octet public-key algorithm.
      this.publicKeyAlgorithm = bytes.charCodeAt(i++);

      // One-octet hash algorithm.
      this.hashAlgorithm = bytes.charCodeAt(i++);
      break;
    case 4:
      this.signatureType = bytes.charCodeAt(i++);
      this.publicKeyAlgorithm = bytes.charCodeAt(i++);
      this.hashAlgorithm = bytes.charCodeAt(i++);

      function subpackets(bytes) {
        // Two-octet scalar octet count for following subpacket data.
        var subpacket_length = util.readNumber(
          bytes.substr(0, 2));

        var i = 2;

        // subpacket data set (zero or more subpackets)
        var subpacked_read = 0;
        while (i < 2 + subpacket_length) {

          var len = packet.readSimpleLength(bytes.substr(i));
          i += len.offset;

          this.read_sub_packet(bytes.substr(i, len.len));

          i += len.len;
        }

        return i;
      }

      // hashed subpackets
      i += subpackets.call(this, bytes.substr(i), true);

      // A V4 signature hashes the packet body
      // starting from its first field, the version number, through the end
      // of the hashed subpacket data.  Thus, the fields hashed are the
      // signature version, the signature type, the public-key algorithm, the
      // hash algorithm, the hashed subpacket length, and the hashed
      // subpacket body.
      this.signatureData = bytes.substr(0, i);
      var sigDataLength = i;

      // unhashed subpackets
      i += subpackets.call(this, bytes.substr(i), false);
      this.unhashedSubpackets = bytes.substr(sigDataLength, i - sigDataLength);

      break;
    default:
      throw new Error('Version ' + this.version + ' of the signature is unsupported.');
  }

  // Two-octet field holding left 16 bits of signed hash value.
  this.signedHashValue = bytes.substr(i, 2);
  i += 2;

  this.signature = bytes.substr(i);
};

Signature.prototype.write = function () {
  var result = '';
  switch (this.version) {
    case 3:
      result += String.fromCharCode(3); // version
      result += String.fromCharCode(5); // One-octet length of following hashed material.  MUST be 5
      result += this.signatureData;
      result += this.issuerKeyId.write();
      result += String.fromCharCode(this.publicKeyAlgorithm);
      result += String.fromCharCode(this.hashAlgorithm);
      break;
    case 4:
      result += this.signatureData;
      result += this.unhashedSubpackets ? this.unhashedSubpackets : util.writeNumber(0, 2);
      break;
  }
  result += this.signedHashValue + this.signature;
  return result;
};

/**
 * Signs provided data. This needs to be done prior to serialization.
 * @param {module:packet/secret_key} key private key used to sign the message.
 * @param {Object} data Contains packets to be signed.
 */
Signature.prototype.sign = function (key, data) {
  var signatureType = enums.write(enums.signature, this.signatureType),
    publicKeyAlgorithm = enums.write(enums.publicKey, this.publicKeyAlgorithm),
    hashAlgorithm = enums.write(enums.hash, this.hashAlgorithm);

  var result = String.fromCharCode(4);
  result += String.fromCharCode(signatureType);
  result += String.fromCharCode(publicKeyAlgorithm);
  result += String.fromCharCode(hashAlgorithm);

  this.issuerKeyId = key.getKeyId();

  // Add hashed subpackets
  result += this.write_all_sub_packets();

  this.signatureData = result;

  var trailer = this.calculateTrailer();

  var toHash = this.toSign(signatureType, data) +
    this.signatureData + trailer;

  var hash = crypto.hash.digest(hashAlgorithm, toHash);

  this.signedHashValue = hash.substr(0, 2);

  this.signature = crypto.signature.sign(hashAlgorithm,
    publicKeyAlgorithm, key.mpi, toHash);
};

/**
 * Creates string of bytes with all subpacket data
 * @return {String} a string-representation of a all subpacket data
 */
Signature.prototype.write_all_sub_packets = function () {
  var sub = enums.signatureSubpacket;
  var result = '';
  var bytes = '';
  if (this.created !== null) {
    result += write_sub_packet(sub.signature_creation_time, util.writeDate(this.created));
  }
  if (this.signatureExpirationTime !== null) {
    result += write_sub_packet(sub.signature_expiration_time, util.writeNumber(this.signatureExpirationTime, 4));
  }
  if (this.exportable !== null) {
    result += write_sub_packet(sub.exportable_certification, String.fromCharCode(this.exportable ? 1 : 0));
  }
  if (this.trustLevel !== null) {
    bytes = String.fromCharCode(this.trustLevel) + String.fromCharCode(this.trustAmount);
    result += write_sub_packet(sub.trust_signature, bytes);
  }
  if (this.regularExpression !== null) {
    result += write_sub_packet(sub.regular_expression, this.regularExpression);
  }
  if (this.revocable !== null) {
    result += write_sub_packet(sub.revocable, String.fromCharCode(this.revocable ? 1 : 0));
  }
  if (this.keyExpirationTime !== null) {
    result += write_sub_packet(sub.key_expiration_time, util.writeNumber(this.keyExpirationTime, 4));
  }
  if (this.preferredSymmetricAlgorithms !== null) {
    bytes = util.bin2str(this.preferredSymmetricAlgorithms);
    result += write_sub_packet(sub.preferred_symmetric_algorithms, bytes);
  }
  if (this.revocationKeyClass !== null) {
    bytes = String.fromCharCode(this.revocationKeyClass);
    bytes += String.fromCharCode(this.revocationKeyAlgorithm);
    bytes += this.revocationKeyFingerprint;
    result += write_sub_packet(sub.revocation_key, bytes);
  }
  if (!this.issuerKeyId.isNull()) {
    result += write_sub_packet(sub.issuer, this.issuerKeyId.write());
  }
  if (this.notation !== null) {
    for (var name in this.notation) {
      if (this.notation.hasOwnProperty(name)) {
        var value = this.notation[name];
        bytes = String.fromCharCode(0x80);
        bytes += String.fromCharCode(0);
        bytes += String.fromCharCode(0);
        bytes += String.fromCharCode(0);
        // 2 octets of name length
        bytes += util.writeNumber(name.length, 2);
        // 2 octets of value length
        bytes += util.writeNumber(value.length, 2);
        bytes += name + value;
        result += write_sub_packet(sub.notation_data, bytes);
      }
    }
  }
  if (this.preferredHashAlgorithms !== null) {
    bytes = util.bin2str(this.preferredHashAlgorithms);
    result += write_sub_packet(sub.preferred_hash_algorithms, bytes);
  }
  if (this.preferredCompressionAlgorithms !== null) {
    bytes = util.bin2str(this.preferredCompressionAlgorithms);
    result += write_sub_packet(sub.preferred_compression_algorithms, bytes);
  }
  if (this.keyServerPreferences !== null) {
    bytes = util.bin2str(this.keyServerPreferences);
    result += write_sub_packet(sub.key_server_preferences, bytes);
  }
  if (this.preferredKeyServer !== null) {
    result += write_sub_packet(sub.preferred_key_server, this.preferredKeyServer);
  }
  if (this.isPrimaryUserID !== null) {
    result += write_sub_packet(sub.primary_user_id, String.fromCharCode(this.isPrimaryUserID ? 1 : 0));
  }
  if (this.policyURI !== null) {
    result += write_sub_packet(sub.policy_uri, this.policyURI);
  }
  if (this.keyFlags !== null) {
    bytes = util.bin2str(this.keyFlags);
    result += write_sub_packet(sub.key_flags, bytes);
  }
  if (this.signersUserId !== null) {
    result += write_sub_packet(sub.signers_user_id, this.signersUserId);
  }
  if (this.reasonForRevocationFlag !== null) {
    bytes = String.fromCharCode(this.reasonForRevocationFlag);
    bytes += this.reasonForRevocationString;
    result += write_sub_packet(sub.reason_for_revocation, bytes);
  }
  if (this.features !== null) {
    bytes = util.bin2str(this.features);
    result += write_sub_packet(sub.features, bytes);
  }
  if (this.signatureTargetPublicKeyAlgorithm !== null) {
    bytes = String.fromCharCode(this.signatureTargetPublicKeyAlgorithm);
    bytes += String.fromCharCode(this.signatureTargetHashAlgorithm);
    bytes += this.signatureTargetHash;
    result += write_sub_packet(sub.signature_target, bytes);
  }
  if (this.embeddedSignature !== null) {
    result += write_sub_packet(sub.embedded_signature, this.embeddedSignature.write());
  }
  result = util.writeNumber(result.length, 2) + result;
  return result;
};

/**
 * creates a string representation of a sub signature packet (See {@link http://tools.ietf.org/html/rfc4880#section-5.2.3.1|RFC 4880 5.2.3.1})
 * @param {Integer} type subpacket signature type. Signature types as described
 * in {@link http://tools.ietf.org/html/rfc4880#section-5.2.3.2|RFC4880 Section 5.2.3.2}
 * @param {String} data data to be included
 * @return {String} a string-representation of a sub signature packet (See {@link http://tools.ietf.org/html/rfc4880#section-5.2.3.1|RFC 4880 5.2.3.1})
 */
function write_sub_packet(type, data) {
  var result = "";
  result += packet.writeSimpleLength(data.length + 1);
  result += String.fromCharCode(type);
  result += data;
  return result;
}

// V4 signature sub packets

Signature.prototype.read_sub_packet = function (bytes) {
  var mypos = 0;

  function read_array(prop, bytes) {
    this[prop] = [];

    for (var i = 0; i < bytes.length; i++) {
      this[prop].push(bytes.charCodeAt(i));
    }
  }

  // The leftwost bit denotes a "critical" packet, but we ignore it.
  var type = bytes.charCodeAt(mypos++) & 0x7F;
  var seconds;

  // subpacket type
  switch (type) {
    case 2:
      // Signature Creation Time
      this.created = util.readDate(bytes.substr(mypos));
      break;
    case 3:
      // Signature Expiration Time in seconds
      seconds = util.readNumber(bytes.substr(mypos));

      this.signatureNeverExpires = seconds === 0;
      this.signatureExpirationTime = seconds;

      break;
    case 4:
      // Exportable Certification
      this.exportable = bytes.charCodeAt(mypos++) == 1;
      break;
    case 5:
      // Trust Signature
      this.trustLevel = bytes.charCodeAt(mypos++);
      this.trustAmount = bytes.charCodeAt(mypos++);
      break;
    case 6:
      // Regular Expression
      this.regularExpression = bytes.substr(mypos);
      break;
    case 7:
      // Revocable
      this.revocable = bytes.charCodeAt(mypos++) == 1;
      break;
    case 9:
      // Key Expiration Time in seconds
      seconds = util.readNumber(bytes.substr(mypos));

      this.keyExpirationTime = seconds;
      this.keyNeverExpires = seconds === 0;

      break;
    case 11:
      // Preferred Symmetric Algorithms
      read_array.call(this, 'preferredSymmetricAlgorithms', bytes.substr(mypos));
      break;
    case 12:
      // Revocation Key
      // (1 octet of class, 1 octet of public-key algorithm ID, 20
      // octets of
      // fingerprint)
      this.revocationKeyClass = bytes.charCodeAt(mypos++);
      this.revocationKeyAlgorithm = bytes.charCodeAt(mypos++);
      this.revocationKeyFingerprint = bytes.substr(mypos, 20);
      break;

    case 16:
      // Issuer
      this.issuerKeyId.read(bytes.substr(mypos));
      break;

    case 20:
      // Notation Data
      // We don't know how to handle anything but a text flagged data.
      if (bytes.charCodeAt(mypos) == 0x80) {

        // We extract key/value tuple from the byte stream.
        mypos += 4;
        var m = util.readNumber(bytes.substr(mypos, 2));
        mypos += 2;
        var n = util.readNumber(bytes.substr(mypos, 2));
        mypos += 2;

        var name = bytes.substr(mypos, m),
          value = bytes.substr(mypos + m, n);

        this.notation = this.notation || {};
        this.notation[name] = value;
      } else {
    	  util.print_debug("Unsupported notation flag "+bytes.charCodeAt(mypos));
      	}
      break;
    case 21:
      // Preferred Hash Algorithms
      read_array.call(this, 'preferredHashAlgorithms', bytes.substr(mypos));
      break;
    case 22:
      // Preferred Compression Algorithms
      read_array.call(this, 'preferredCompressionAlgorithms', bytes.substr(mypos));
      break;
    case 23:
      // Key Server Preferences
      read_array.call(this, 'keyServerPreferencess', bytes.substr(mypos));
      break;
    case 24:
      // Preferred Key Server
      this.preferredKeyServer = bytes.substr(mypos);
      break;
    case 25:
      // Primary User ID
      this.isPrimaryUserID = bytes[mypos++] !== 0;
      break;
    case 26:
      // Policy URI
      this.policyURI = bytes.substr(mypos);
      break;
    case 27:
      // Key Flags
      read_array.call(this, 'keyFlags', bytes.substr(mypos));
      break;
    case 28:
      // Signer's User ID
      this.signersUserId += bytes.substr(mypos);
      break;
    case 29:
      // Reason for Revocation
      this.reasonForRevocationFlag = bytes.charCodeAt(mypos++);
      this.reasonForRevocationString = bytes.substr(mypos);
      break;
    case 30:
      // Features
      read_array.call(this, 'features', bytes.substr(mypos));
      break;
    case 31:
      // Signature Target
      // (1 octet public-key algorithm, 1 octet hash algorithm, N octets hash)
      this.signatureTargetPublicKeyAlgorithm = bytes.charCodeAt(mypos++);
      this.signatureTargetHashAlgorithm = bytes.charCodeAt(mypos++);

      var len = crypto.getHashByteLength(this.signatureTargetHashAlgorithm);

      this.signatureTargetHash = bytes.substr(mypos, len);
      break;
    case 32:
      // Embedded Signature
      this.embeddedSignature = new Signature();
      this.embeddedSignature.read(bytes.substr(mypos));
      break;
    default:
    	util.print_debug("Unknown signature subpacket type " + type + " @:" + mypos);
  }
};

// Produces data to produce signature on
Signature.prototype.toSign = function (type, data) {
  var t = enums.signature;

  switch (type) {
    case t.binary:
    case t.text:
      return data.getBytes();

    case t.standalone:
      return '';

    case t.cert_generic:
    case t.cert_persona:
    case t.cert_casual:
    case t.cert_positive:
    case t.cert_revocation:
      var packet, tag;

      if (data.userid !== undefined) {
        tag = 0xB4;
        packet = data.userid;
      } else if (data.userattribute !== undefined) {
        tag = 0xD1;
        packet = data.userattribute;
      } else throw new Error('Either a userid or userattribute packet needs to be ' +
          'supplied for certification.');

      var bytes = packet.write();

      if (this.version == 4) {
        return this.toSign(t.key, data) +
        String.fromCharCode(tag) +
        util.writeNumber(bytes.length, 4) +
        bytes;
      } else if (this.version == 3) {
        return this.toSign(t.key, data) +
        bytes;
      }
      break;

    case t.subkey_binding:
    case t.subkey_revocation:
    case t.key_binding:
      return this.toSign(t.key, data) + this.toSign(t.key, {
        key: data.bind
      });

    case t.key:
      if (data.key === undefined)
        throw new Error('Key packet is required for this signature.');

      return data.key.writeOld();

    case t.key_revocation:
      return this.toSign(t.key, data);
    case t.timestamp:
      return '';
    case t.third_party:
      throw new Error('Not implemented');
    default:
      throw new Error('Unknown signature type.');
  }
};


Signature.prototype.calculateTrailer = function () {
  // calculating the trailer
  var trailer = '';
  // V3 signatures don't have a trailer
  if (this.version == 3) return trailer;
  trailer += String.fromCharCode(4); // Version
  trailer += String.fromCharCode(0xFF);
  trailer += util.writeNumber(this.signatureData.length, 4);
  return trailer;
};


/**
 * verifys the signature packet. Note: not signature types are implemented
 * @param {String|Object} data data which on the signature applies
 * @param {module:packet/public_subkey|module:packet/public_key|
 *         module:packet/secret_subkey|module:packet/secret_key} key the public key to verify the signature
 * @return {boolean} True if message is verified, else false.
 */
Signature.prototype.verify = function (key, data) {
  var signatureType = enums.write(enums.signature, this.signatureType),
    publicKeyAlgorithm = enums.write(enums.publicKey, this.publicKeyAlgorithm),
    hashAlgorithm = enums.write(enums.hash, this.hashAlgorithm);

  var bytes = this.toSign(signatureType, data),
    trailer = this.calculateTrailer();


  var mpicount = 0;
  // Algorithm-Specific Fields for RSA signatures:
  //      - multiprecision number (MPI) of RSA signature value m**d mod n.
  if (publicKeyAlgorithm > 0 && publicKeyAlgorithm < 4)
    mpicount = 1;
  //    Algorithm-Specific Fields for DSA signatures:
  //      - MPI of DSA value r.
  //      - MPI of DSA value s.
  else if (publicKeyAlgorithm == 17)
    mpicount = 2;

  var mpi = [],
    i = 0;
  for (var j = 0; j < mpicount; j++) {
    mpi[j] = new type_mpi();
    i += mpi[j].read(this.signature.substr(i));
  }

  this.verified = crypto.signature.verify(publicKeyAlgorithm,
    hashAlgorithm, mpi, key.mpi,
    bytes + this.signatureData + trailer);

  return this.verified;
};

/**
 * Verifies signature expiration date
 * @return {Boolean} true if expired
 */
Signature.prototype.isExpired = function () {
  if (!this.signatureNeverExpires) {
    return Date.now() > (this.created.getTime() + this.signatureExpirationTime*1000);
  }
  return false;
};

/**
 * Fix custom types after cloning
 */
Signature.prototype.postCloneTypeFix = function() {
  this.issuerKeyId = type_keyid.fromClone(this.issuerKeyId);
};
