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
 * @requires encoding/armor
 * @requires enums
 * @requires util
 * @requires packet
 * @requires signature
 * @module cleartext
 */

import armor from './encoding/armor';
import enums from './enums';
import util from './util';
import packet from './packet';
import { Signature } from './signature';
import { createVerificationObjects, createSignaturePackets } from './message';

/**
 * @class
 * @classdesc Class that represents an OpenPGP cleartext signed message.
 * See {@link https://tools.ietf.org/html/rfc4880#section-7}
 * @param  {String}           text       The cleartext of the signed message
 * @param  {module:signature.Signature} signature  The detached signature or an empty signature for unsigned messages
 */
export function CleartextMessage(text, signature) {
  if (!(this instanceof CleartextMessage)) {
    return new CleartextMessage(text, signature);
  }
  // normalize EOL to canonical form <CR><LF>
  this.text = util.removeTrailingSpaces(text).replace(/\r?\n/g, '\r\n');
  if (signature && !(signature instanceof Signature)) {
    throw new Error('Invalid signature input');
  }
  this.signature = signature || new Signature(new packet.List());
}

/**
 * Returns the key IDs of the keys that signed the cleartext message
 * @returns {Array<module:type/keyid>} array of keyid objects
 */
CleartextMessage.prototype.getSigningKeyIds = function() {
  const keyIds = [];
  const signatureList = this.signature.packets;
  signatureList.forEach(function(packet) {
    keyIds.push(packet.issuerKeyId);
  });
  return keyIds;
};

/**
 * Sign the cleartext message
 * @param  {Array<module:key.Key>} privateKeys private keys with decrypted secret key data for signing
 * @param  {Signature} signature             (optional) any existing detached signature
 * @param  {Date} date                       (optional) The creation time of the signature that should be created
 * @param  {Array} userIds                   (optional) user IDs to sign with, e.g. [{ name:'Steve Sender', email:'steve@openpgp.org' }]
 * @returns {Promise<module:cleartext.CleartextMessage>} new cleartext message with signed content
 * @async
 */
CleartextMessage.prototype.sign = async function(privateKeys, signature = null, date = new Date(), userIds = []) {
  return new CleartextMessage(this.text, await this.signDetached(privateKeys, signature, date, userIds));
};

/**
 * Sign the cleartext message
 * @param  {Array<module:key.Key>} privateKeys private keys with decrypted secret key data for signing
 * @param  {Signature} signature             (optional) any existing detached signature
 * @param  {Date} date                       (optional) The creation time of the signature that should be created
 * @param  {Array} userIds                   (optional) user IDs to sign with, e.g. [{ name:'Steve Sender', email:'steve@openpgp.org' }]
 * @returns {Promise<module:signature.Signature>}      new detached signature of message content
 * @async
 */
CleartextMessage.prototype.signDetached = async function(privateKeys, signature = null, date = new Date(), userIds = []) {
  const literalDataPacket = new packet.Literal();
  literalDataPacket.setText(this.text);

  return new Signature(await createSignaturePackets(literalDataPacket, privateKeys, signature, date, userIds, true));
};

/**
 * Verify signatures of cleartext signed message
 * @param {Array<module:key.Key>} keys array of keys to verify signatures
 * @param {Date} date (optional) Verify the signature against the given date, i.e. check signature creation time < date < expiration time
 * @returns {Promise<Array<{keyid: module:type/keyid, valid: Boolean}>>} list of signer's keyid and validity of signature
 * @async
 */
CleartextMessage.prototype.verify = function(keys, date = new Date()) {
  return this.verifyDetached(this.signature, keys, date);
};

/**
 * Verify signatures of cleartext signed message
 * @param {Array<module:key.Key>} keys array of keys to verify signatures
 * @param {Date} date (optional) Verify the signature against the given date, i.e. check signature creation time < date < expiration time
 * @returns {Promise<Array<{keyid: module:type/keyid, valid: Boolean}>>} list of signer's keyid and validity of signature
 * @async
 */
CleartextMessage.prototype.verifyDetached = function(signature, keys, date = new Date()) {
  const signatureList = signature.packets;
  const literalDataPacket = new packet.Literal();
  // we assume that cleartext signature is generated based on UTF8 cleartext
  literalDataPacket.setText(this.text);
  return createVerificationObjects(signatureList, [literalDataPacket], keys, date, true);
};

/**
 * Get cleartext
 * @returns {String} cleartext of message
 */
CleartextMessage.prototype.getText = function() {
  // normalize end of line to \n
  return this.text.replace(/\r\n/g, '\n');
};

/**
 * Returns ASCII armored text of cleartext signed message
 * @returns {String | ReadableStream<String>} ASCII armor
 */
CleartextMessage.prototype.armor = function() {
  let hashes = this.signature.packets.map(function(packet) {
    return enums.read(enums.hash, packet.hashAlgorithm).toUpperCase();
  });
  hashes = hashes.filter(function(item, i, ar) { return ar.indexOf(item) === i; });
  const body = {
    hash: hashes.join(),
    text: this.text,
    data: this.signature.packets.write()
  };
  return armor.encode(enums.armor.signed, body);
};


/**
 * reads an OpenPGP cleartext signed message and returns a CleartextMessage object
 * @param {String | ReadableStream<String>} armoredText text to be parsed
 * @returns {module:cleartext.CleartextMessage} new cleartext message object
 * @async
 * @static
 */
export async function readArmored(armoredText) {
  const input = await armor.decode(armoredText);
  if (input.type !== enums.armor.signed) {
    throw new Error('No cleartext signed message.');
  }
  const packetlist = new packet.List();
  await packetlist.read(input.data);
  verifyHeaders(input.headers, packetlist);
  const signature = new Signature(packetlist);
  return new CleartextMessage(input.text, signature);
}

/**
 * Compare hash algorithm specified in the armor header with signatures
 * @param  {Array<String>} headers    Armor headers
 * @param  {module:packet.List} packetlist The packetlist with signature packets
 * @private
 */
function verifyHeaders(headers, packetlist) {
  const checkHashAlgos = function(hashAlgos) {
    const check = packet => algo => packet.hashAlgorithm === algo;

    for (let i = 0; i < packetlist.length; i++) {
      if (packetlist[i].tag === enums.packet.signature && !hashAlgos.some(check(packetlist[i]))) {
        return false;
      }
    }
    return true;
  };

  let oneHeader = null;
  let hashAlgos = [];
  headers.forEach(function(header) {
    oneHeader = header.match(/Hash: (.+)/); // get header value
    if (oneHeader) {
      oneHeader = oneHeader[1].replace(/\s/g, ''); // remove whitespace
      oneHeader = oneHeader.split(',');
      oneHeader = oneHeader.map(function(hash) {
        hash = hash.toLowerCase();
        try {
          return enums.write(enums.hash, hash);
        } catch (e) {
          throw new Error('Unknown hash algorithm in armor header: ' + hash);
        }
      });
      hashAlgos = hashAlgos.concat(oneHeader);
    } else {
      throw new Error('Only "Hash" header allowed in cleartext signed message');
    }
  });

  if (!hashAlgos.length && !checkHashAlgos([enums.hash.md5])) {
    throw new Error('If no "Hash" header in cleartext signed message, then only MD5 signatures allowed');
  } else if (hashAlgos.length && !checkHashAlgos(hashAlgos)) {
    throw new Error('Hash algorithm mismatch in armor header and signature');
  }
}

/**
 * Creates a new CleartextMessage object from text
 * @param {String} text
 * @static
 */
export function fromText(text) {
  return new CleartextMessage(text);
}
