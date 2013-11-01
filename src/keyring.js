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

var packet = require('./packet');
var enums = require('./enums.js');
var armor = require('./encoding/armor.js');

/**
 * @class
 * @classdesc The class that deals with storage of the keyring. Currently the only option is to use HTML5 local storage.
 */
var keyring = function() {
  this.armoredPacketlists = [];
  this.parsedPacketlists = [];

  /**
   * Initialization routine for the keyring. This method reads the 
   * keyring from HTML5 local storage and initializes this instance.
   * This method is called by openpgp.init().
   */
  function init() {
    var armoredPacketlists = JSON.parse(window.localStorage.getItem("armoredPacketlists"));
    if (armoredPacketlists === null || armoredPacketlists.length === 0) {
      armoredPacketlists = [];
    }
    this.armoredPacketlists = armoredPacketlists;

    var packetlist;
    for (var i = 0; i < armoredPacketlists.length; i++) {
      packetlist = new packet.list();
      packetlist.read(armoredPacketlists[i]);
      this.parsedPacketlists.push(packetlist);
    }
  }
  this.init = init;

  /**
   * Saves the current state of the keyring to HTML5 local storage.
   * The privateKeys array and publicKeys array gets Stringified using JSON
   */
  function store() {
    window.localStorage.setItem("armoredPacketlists", JSON.stringify(this.armoredPacketlists));
  }
  this.store = store;

  function emailPacketCheck(packet, email) {
    var emailMatch = false;
    var packetEmail;
    email = email.toLowerCase();
    if (packet.tag == enums.packet.userid) {
      packetEmail = packet.userid;
      //we need to get just the email from the userid packet
      packetEmail = packetEmail.split('<')[1].split('<')[0].trim.toLowerCase();
      if (packetEmail == email) {
        emailMatch = true;
      }
    }
    return emailMatch;
  }

  function idPacketCheck(packet, id) {
    if (packet.getKeyId && packet.getKeyId().write() == id) {
      return true;
    }
    return false;
  }

  function helperCheckIdentityAndPacketMatch(identityFunction, identityInput, packetType, packetlist) {
    var packet;
    for (var l = 0; l < packetlist.length; l++) {
      packet = packetlist[l];
      identityMatch = identityFunction(packet, identityInput);
      if (!packetType) {
        packetMatch = true;
      } else if (packet.tag == packetType) {
        packetMatch = true;
      }
      if (packetMatch && identityMatch) {
        return true;
      }
    }
    return false;
  }

  function checkForIdentityAndPacketMatch(identityFunction, identityInput, packetType) {
    var results = [];
    var packetlist;
    var identityMatch;
    var packetMatch;
    for (var p = 0; p < this.parsedPacketlists.length; p++) {
      identityMatch = false;
      packetMatch = false;
      packetlist = this.parsedPacketlists[p];
      if (helperCheckIdentityAndPacketMatch(identityFunction, identityInput, packetType, packetlist)) {
        results.push(packetlist);
      }
    }
    return results;
  }
  this.checkForIdentityAndPacketMatch = checkForIdentityAndPacketMatch;

  /**
   * searches all public keys in the keyring matching the address or address part of the user ids
   * @param {String} email_address
   * @return {openpgp_msg_publickey[]} The public keys associated with provided email address.
   */
  function getPublicKeyForAddress(email) {
    return checkForIdentityAndPacketMatch(emailPacketCheck, email, enums.packet.public_key);
  }
  this.getPublicKeyForAddress = getPublicKeyForAddress;

  /**
   * Searches the keyring for a private key containing the specified email address
   * @param {String} email_address email address to search for
   * @return {openpgp_msg_privatekey[]} private keys found
   */
  function getPrivateKeyForAddress(email_address) {
    return checkForIdentityAndPacketMatch(emailPacketCheck, email, enums.packet.secret_key);
  }
  this.getPrivateKeyForAddress = getPrivateKeyForAddress;

  /**
   * Searches the keyring for public keys having the specified key id
   * @param {String} keyId provided as string of hex number (lowercase)
   * @return {openpgp_msg_privatekey[]} public keys found
   */
  function getPacketlistsForKeyId(keyId) {
    return this.checkForIdentityAndPacketMatch(idPacketCheck, keyId);
  }
  this.getPacketlistsForKeyId = getPacketlistsForKeyId;

  /**
   * Imports a packet list (public or private key block) from an ascii armored message 
   * @param {String} armored message to read the packets/key from
   */
  function importPacketlist(armored) {
    this.armoredPacketlists.push(armored);

    var dearmored = armor.decode(armored.replace(/\r/g, '')).openpgp;

    packetlist = new packet.list();
    packetlist.read(dearmored);
    this.parsedPacketlists.push(packetlist);

    return true;
  }
  this.importPacketlist = importPacketlist;

  /**
   * TODO
   * returns the openpgp_msg_privatekey representation of the public key at public key ring index  
   * @param {Integer} index the index of the public key within the publicKeys array
   * @return {openpgp_msg_privatekey} the public key object
   */
  function exportPublicKey(index) {
    return this.publicKey[index];
  }
  this.exportPublicKey = exportPublicKey;

  /**
   * TODO
   * Removes a public key from the public key keyring at the specified index 
   * @param {Integer} index the index of the public key within the publicKeys array
   * @return {openpgp_msg_privatekey} The public key object which has been removed
   */
  function removePublicKey(index) {
    var removed = this.publicKeys.splice(index, 1);
    this.store();
    return removed;
  }
  this.removePublicKey = removePublicKey;

};

module.exports = new keyring();
