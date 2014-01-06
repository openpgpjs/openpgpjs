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
 * @fileoverview The openpgp base module should provide all of the functionality 
 * to consume the openpgp.js library. All additional classes are documented 
 * for extending and developing on top of the base library.
 */

/**
 * @requires cleartext
 * @requires config
 * @requires encoding/armor
 * @requires enums
 * @requires message
 * @requires packet
 * @module openpgp
 */

var armor = require('./encoding/armor.js'),
  packet = require('./packet'),
  enums = require('./enums.js'),
  config = require('./config'),
  message = require('./message.js'),
  cleartext = require('./cleartext.js'),
  key = require('./key.js');


/**
 * Encrypts message text with keys
 * @param  {Array<module:key~Key>}  keys array of keys, used to encrypt the message
 * @param  {String} text message as native JavaScript string
 * @return {String}      encrypted ASCII armored message
 * @static
 */
function encryptMessage(keys, text) {
  var msg = message.fromText(text);
  msg = msg.encrypt(keys);
  var armored = armor.encode(enums.armor.message, msg.packets.write());
  return armored;
}

/**
 * Signs message text and encrypts it
 * @param  {Array<module:key~Key>}  publicKeys array of keys, used to encrypt the message
 * @param  {module:key~Key}    privateKey private key with decrypted secret key data for signing
 * @param  {String} text       message as native JavaScript string
 * @return {String}            encrypted ASCII armored message
 * @static
 */
function signAndEncryptMessage(publicKeys, privateKey, text) {
  var msg = message.fromText(text);
  msg = msg.sign([privateKey]);
  msg = msg.encrypt(publicKeys);
  var armored = armor.encode(enums.armor.message, msg.packets.write());
  return armored;
}

/**
 * Decrypts message
 * @param  {module:key~Key}     privateKey private key with decrypted secret key data
 * @param  {module:message~Message} message    the message object with the encrypted data
 * @return {(String|null)}        decrypted message as as native JavaScript string
 *                              or null if no literal data found
 * @static
 */
function decryptMessage(privateKey, message) {
  message = message.decrypt(privateKey);
  return message.getText();
}

/**
 * Decrypts message and verifies signatures
 * @param  {module:key~Key}     privateKey private key with decrypted secret key data
 * @param  {Array<module:key~Key>}   publicKeys public keys to verify signatures
 * @param  {module:message~Message} message    the message object with signed and encrypted data
 * @return {{text: String, signatures: Array<{keyid: module:type/keyid, valid: Boolean}>}}
 *                              decrypted message as as native JavaScript string
 *                              with verified signatures or null if no literal data found
 * @static
 */
function decryptAndVerifyMessage(privateKey, publicKeys, message) {
  var result = {};
  message = message.decrypt(privateKey);
  result.text = message.getText();
  if (result.text) {
    result.signatures = message.verify(publicKeys);
    return result;
  }
  return null;
}

/**
 * Signs a cleartext message
 * @param  {Array<module:key~Key>}  privateKeys private key with decrypted secret key data to sign cleartext
 * @param  {String} text        cleartext
 * @return {String}             ASCII armored message
 * @static
 */
function signClearMessage(privateKeys, text) {
  var cleartextMessage = new cleartext.CleartextMessage(text);
  cleartextMessage.sign(privateKeys);
  return cleartextMessage.armor();
}

/**
 * Verifies signatures of cleartext signed message
 * @param  {Array<module:key~Key>}            publicKeys public keys to verify signatures
 * @param  {module:cleartext~CleartextMessage} message    cleartext message object with signatures
 * @return {{text: String, signatures: Array<{keyid: module:type/keyid, valid: Boolean}>}}
 *                                       cleartext with status of verified signatures
 * @static
 */
function verifyClearSignedMessage(publicKeys, message) {
  var result = {};
  if (!(message instanceof cleartext.CleartextMessage)) {
    throw new Error('Parameter [message] needs to be of type CleartextMessage.');
  }
  result.text = message.getText();
  result.signatures = message.verify(publicKeys);
  return result;
}

/**
 * Generates a new OpenPGP key pair. Currently only supports RSA keys.
 * Primary and subkey will be of same type.
 * @param {module:enums.publicKey} keyType    to indicate what type of key to make.
 *                             RSA is 1. See {@link http://tools.ietf.org/html/rfc4880#section-9.1}
 * @param {Integer} numBits    number of bits for the key creation. (should be 1024+, generally)
 * @param {String}  userId     assumes already in form of "User Name <username@email.com>"
 * @param {String}  passphrase The passphrase used to encrypt the resulting private key
 * @return {Object} {key: Array<module:key~Key>, privateKeyArmored: Array<String>, publicKeyArmored: Array<String>}
 * @static
 */
function generateKeyPair(keyType, numBits, userId, passphrase) {
  var result = {};
  var newKey = key.generate(keyType, numBits, userId, passphrase);
  result.key = newKey;
  result.privateKeyArmored = newKey.armor();
  result.publicKeyArmored = newKey.toPublic().armor();
  return result;
}

exports.encryptMessage = encryptMessage;
exports.signAndEncryptMessage = signAndEncryptMessage;
exports.decryptMessage = decryptMessage;
exports.decryptAndVerifyMessage = decryptAndVerifyMessage;
exports.signClearMessage = signClearMessage;
exports.verifyClearSignedMessage = verifyClearSignedMessage;
exports.generateKeyPair = generateKeyPair;
