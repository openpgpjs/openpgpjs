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

var armor = require('./encoding/armor.js');
var packet = require('./packet');
var enums = require('./enums.js');
var config = require('./config');
var message = require('./message.js');
var cleartext = require('./cleartext.js');


/**
 * Encrypts message text with keys
 * @param  {[key]}  keys array of keys, used to encrypt the message
 * @param  {String} text message as native JavaScript string
 * @return {String}      encrypted ASCII armored message
 */
function encryptMessage(keys, text) {
  var msg = message.fromText(text);
  msg = msg.encrypt(keys);
  var armored = armor.encode(enums.armor.message, msg.packets.write());
  return armored;
}

/**
 * Signs message text and encrypts it
 * @param  {[key]}  publicKeys array of keys, used to encrypt the message
 * @param  {key}    privateKey private key with decrypted secret key data for signing
 * @param  {String} text       message as native JavaScript string
 * @return {String}            encrypted ASCII armored message
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
 * @param  {key}     privateKey private key with decrypted secret key data
 * @param  {message} message    the message object with the encrypted data
 * @return {String|null}        decrypted message as as native JavaScript string
 *                              or null if no literal data found
 */
function decryptMessage(privateKey, message) {
  message = message.decrypt(privateKey);
  return message.getText();
}

/**
 * Decrypts message and verifies signatures
 * @param  {key}     privateKey private key with decrypted secret key data
 * @param  {[key]}   publicKeys public keys to verify signatures
 * @param  {message} message    the message object with signed and encrypted data
 * @return {{'text': String, signatures: [{'keyid': keyid, 'status': Boolean}]}}
 *                              decrypted message as as native JavaScript string
 *                              with verified signatures or null if no literal data found
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
 * @param  {[Key]}  privateKeys private key with decrypted secret key data to sign cleartext
 * @param  {String} text        cleartext
 * @return {String}             ASCII armored message
 */
function signClearMessage(privateKeys, text) {
  var cleartextMessage = new cleartext.CleartextMessage(text);
  cleartextMessage.sign(privateKeys);
  return cleartextMessage.armor();
}

/**
 * Verifies signatures of cleartext signed message
 * @param  {[Key]}            publicKeys public keys to verify signatures
 * @param  {CleartextMessage} message    cleartext message object with signatures
 * @return {{'text': String, signatures: [{'keyid': keyid, 'status': Boolean}]}}
 *                                       cleartext with status of verified signatures
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
 * TODO: update this doc
 * generates a new key pair for openpgp. Beta stage. Currently only 
 * supports RSA keys, and no subkeys.
 * @param {Integer} keyType to indicate what type of key to make. 
 * RSA is 1. Follows algorithms outlined in OpenPGP.
 * @param {Integer} numBits number of bits for the key creation. (should 
 * be 1024+, generally)
 * @param {String} userId assumes already in form of "User Name 
 * <username@email.com>"
 * @param {String} passphrase The passphrase used to encrypt the resulting private key
 * @return {Object} {privateKey: [openpgp_msg_privatekey], 
 * privateKeyArmored: [string], publicKeyArmored: [string]}
 */
function generateKeyPair(keyType, numBits, userId, passphrase) {
  var packetlist = new packet.list();

  var secretKeyPacket = new packet.secret_key();
  secretKeyPacket.algorithm = enums.read(enums.publicKey, keyType);
  secretKeyPacket.generate(numBits);
  secretKeyPacket.encrypt(passphrase);

  var userIdPacket = new packet.userid();
  userIdPacket.read(userId);

  var dataToSign = {};
  dataToSign.userid = userIdPacket;
  dataToSign.key = secretKeyPacket;
  var signaturePacket = new packet.signature();
  signaturePacket.signatureType = enums.signature.cert_generic;
  signaturePacket.publicKeyAlgorithm = keyType;
  //TODO we should load preferred hash from config, or as input to this function
  signaturePacket.hashAlgorithm = enums.hash.sha256;
  signaturePacket.keyFlags = [enums.keyFlags.certify_keys | enums.keyFlags.sign_data];
  signaturePacket.sign(secretKeyPacket, dataToSign);

  var secretSubkeyPacket = new packet.secret_subkey();
  secretSubkeyPacket.algorithm = enums.read(enums.publicKey, keyType);
  secretSubkeyPacket.generate(numBits);
  secretSubkeyPacket.encrypt(passphrase);

  dataToSign = {};
  dataToSign.key = secretKeyPacket;
  dataToSign.bind = secretSubkeyPacket;
  var subkeySignaturePacket = new packet.signature();
  subkeySignaturePacket.signatureType = enums.signature.subkey_binding;
  subkeySignaturePacket.publicKeyAlgorithm = keyType;
  //TODO we should load preferred hash from config, or as input to this function
  subkeySignaturePacket.hashAlgorithm = enums.hash.sha256;
  subkeySignaturePacket.keyFlags = [enums.keyFlags.encrypt_communication | enums.keyFlags.encrypt_storage];
  subkeySignaturePacket.sign(secretKeyPacket, dataToSign);

  packetlist.push(secretKeyPacket);
  packetlist.push(userIdPacket);
  packetlist.push(signaturePacket);
  packetlist.push(secretSubkeyPacket);
  packetlist.push(subkeySignaturePacket);

  var armored = armor.encode(enums.armor.private_key, packetlist.write());
  return armored;
}

/**
 * creates a binary string representation a signed message.
 * The message will be signed with the specified private key.
 * @param {Object} privatekey {obj: [openpgp_msg_privatekey]}
 * - the private key to be used to sign the message 
 * @param {String} messagetext message text to sign
 * @return {Object} {Object: text [String]}, openpgp: {String} a binary
 *  string representation of the message which can be OpenPGP
 *   armored(openpgp) and a text representation of the message (text). 
 * This can be directly used to OpenPGP armor the message
 */
/*
function write_signed_message(privatekey, messagetext) {
  var sig = new openpgp_packet_signature().write_message_signature(1, messagetext.replace(/\r\n/g, "\n").replace(/\n/,
    "\r\n"), privatekey);
  var result = {
    text: messagetext.replace(/\r\n/g, "\n").replace(/\n/, "\r\n"),
    openpgp: sig.openpgp,
    hash: sig.hash
  };
  return armor.encode(2, result, null, null);
}
*/

exports.encryptMessage = encryptMessage;
exports.signAndEncryptMessage = signAndEncryptMessage;
exports.decryptMessage = decryptMessage;
exports.decryptAndVerifyMessage = decryptAndVerifyMessage
exports.signClearMessage = signClearMessage;
exports.verifyClearSignedMessage = verifyClearSignedMessage;
exports.generateKeyPair = generateKeyPair;
