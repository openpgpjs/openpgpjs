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

window = {}; // to make UMD bundles work

importScripts('openpgp.js');


onmessage = function (event) {
  var data = null, 
      err = null, 
      msg = event.data;
  switch (msg.event) {
    case 'seed-random':
      window.openpgp.crypto.random.seedRandom(msg.buf);
      break;
    case 'encrypt-message':
      try {
        msg.keys = msg.keys.map(packetlistCloneToKey);
        data = window.openpgp.encryptMessage(msg.keys, msg.text);
      } catch (e) {
        err = e.message;
      }
      postMessage({event: 'method-return', data: data, err: err});
      break;
    case 'sign-and-encrypt-message':
      try {
        msg.publicKeys = msg.publicKeys.map(packetlistCloneToKey);
        msg.privateKey = packetlistCloneToKey(msg.privateKey);
        data = window.openpgp.signAndEncryptMessage(msg.publicKeys, msg.privateKey, msg.text);
      } catch (e) {
        err = e.message;
      }
      postMessage({event: 'method-return', data: data, err: err});
      break;
    case 'decrypt-message':
      try {
        msg.privateKey = packetlistCloneToKey(msg.privateKey);
        msg.message = packetlistCloneToMessage(msg.message.packets);
        data = window.openpgp.decryptMessage(msg.privateKey, msg.message);
      } catch (e) {
        err = e.message;
      }
      postMessage({event: 'method-return', data: data, err: err});
      break;
    case 'decrypt-and-verify-message':
      try {
        msg.privateKey = packetlistCloneToKey(msg.privateKey);
        msg.publicKeys = msg.publicKeys.map(packetlistCloneToKey);
        msg.message = packetlistCloneToMessage(msg.message.packets);
        data = window.openpgp.decryptAndVerifyMessage(msg.privateKey, msg.publicKeys, msg.message);
      } catch (e) {
        err = e.message;
      }
      postMessage({event: 'method-return', data: data, err: err});
      break;
    case 'sign-clear-message':
      try {
        msg.privateKeys = msg.privateKeys.map(packetlistCloneToKey);
        data = window.openpgp.signClearMessage(msg.privateKeys, msg.text);
      } catch (e) {
        err = e.message;
      }
      postMessage({event: 'method-return', data: data, err: err});
      break;
    case 'verify-clear-signed-message':
      try {
        msg.publicKeys = msg.publicKeys.map(packetlistCloneToKey);
        var packetlist = window.openpgp.packet.List.fromStructuredClone(msg.message.packets);
        msg.message = new window.openpgp.cleartext.CleartextMessage(msg.message.text, packetlist); 
        data = window.openpgp.verifyClearSignedMessage(msg.publicKeys, msg.message);
      } catch (e) {
        err = e.message;
      }
      postMessage({event: 'method-return', data: data, err: err});
      break;
    case 'generate-key-pair':
      try {
        data = window.openpgp.generateKeyPair(msg.keyType, msg.numBits, msg.userId, msg.passphrase);
        data.key = data.key.toPacketlist();
      } catch (e) {
        err = e.message;
      }
      postMessage({event: 'method-return', data: data, err: err});
      break;
    default:
      throw new Error('Unknown Worker Event.');
  }
};

function packetlistCloneToKey(packetlistClone) {
  var packetlist = window.openpgp.packet.List.fromStructuredClone(packetlistClone);
  return new window.openpgp.key.Key(packetlist);
}

function packetlistCloneToMessage(packetlistClone) {
  var packetlist = window.openpgp.packet.List.fromStructuredClone(packetlistClone);
  return new window.openpgp.message.Message(packetlist);
}