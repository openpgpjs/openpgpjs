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

function openpgp_keyring() {
		
	/**
	 * Initialization routine for the keyring. This method reads the 
	 * keyring from HTML5 local storage and initializes this instance.
	 * This method is called by openpgp.init().
	 * @return [null] undefined
	 */
	function init() {
		var sprivatekeys = JSON.parse(window.localStorage.getItem("privatekeys"));
		var spublickeys = JSON.parse(window.localStorage.getItem("publickeys"));
		if (sprivatekeys == null || sprivatekeys.length == 0) {
			sprivatekeys = new Array();
		}

		if (spublickeys == null || spublickeys.length == 0) {
			spublickeys = new Array();
		}
		this.publicKeys = new Array();
		this.privateKeys = new Array();
		var k = 0;
		for (var i =0; i < sprivatekeys.length; i++) {
			var r = openpgp.read_privateKey(sprivatekeys[i]);
			this.privateKeys[k] = { armored: sprivatekeys[i], obj: r[0], keyId: r[0].getKeyId()};
			k++;
		}
		k = 0;
		for (var i =0; i < spublickeys.length; i++) {
			var r = openpgp.read_publicKey(spublickeys[i]);
			if (r[0] != null) {
				this.publicKeys[k] = { armored: spublickeys[i], obj: r[0], keyId: r[0].getKeyId()};
				k++;
			}
		}
	}
	this.init = init;

	/**
	 * Checks if at least one private key is in the keyring
	 * @return
	 */
	function hasPrivateKey() {
		return this.privateKeys.length > 0;
	}
	this.hasPrivateKey = hasPrivateKey;

	/**
	 * Saves the current state of the keyring to HTML5 local storage.
	 * The privateKeys array and publicKeys array gets Stringified using JSON
	 * @return [null] undefined
	 */
	function store() { 
		var priv = new Array();
		for (var i = 0; i < this.privateKeys.length; i++) {
			priv[i] = this.privateKeys[i].armored;
		}
		var pub = new Array();
		for (var i = 0; i < this.publicKeys.length; i++) {
			pub[i] = this.publicKeys[i].armored;
		}
		window.localStorage.setItem("privatekeys",JSON.stringify(priv));
		window.localStorage.setItem("publickeys",JSON.stringify(pub));
	}
	this.store = store;
	/**
	 * searches all public keys in the keyring matching the address or address part of the user ids
	 * @param email_address
	 * @return
	 */
	function getPublicKeyForAddress(email_address) {
		var results = new Array();
		var spl = string.split("<");
		var email = "";
		if (spl.length > 0) {
			email = spl[1].split(">")[0];
		} else {
			email = string.trim();
		}
		for (var i =0; i < this.publicKeys.length; i++) {
			
			for (var j = 0; j < this.publicKeys[i].userIds; j++) {
				if (this.publicKeys[i].userIds[j].indexOf(email) >= 0)
					results[results.length] = this.publicKeys[i];
			}
		}
		return result;
	}

	/**
	 * Searches the keyring for a private key containing the specified email address
	 * @param email_address [String] email address to search for
	 * @return [Array[openpgp_msg_privatekey] private keys found
	 */
	function getPrivateKeyForAddress(email_address) {
		var results = new Array();
		var spl = email_address.split("<");
		var email = "";
		if (spl.length > 1) {
			email = spl[1].split(">")[0];
		} else {
			email = email_address.trim();
		}
		for (var i =0; i < this.privateKeys.length; i++) {
			
			for (var j = 0; j < this.privateKeys[i].obj.userIds.length; j++) {
				if (this.privateKeys[i].obj.userIds[j].text.indexOf(email) >= 0)
					results[results.length] = this.privateKeys[i];
			}
		}
		return results;
	}

	this.getPrivateKeyForAddress = getPrivateKeyForAddress;
	/**
	 * Searches the keyring for public keys having the specified key id
	 * @param keyId provided as string of hex number (lowercase)
	 * @return Array[openpgp_msg_privatekey] public keys found
	 */
	function getPublicKeysForKeyId(keyId) {
		var result = new Array();
		for (var i=0; i < this.publicKeys.length; i++)
			if (keyId == this.publicKeys[i].obj.getKeyId())
				result[result.length] = this.publicKeys[i];
		return result;
	}
	this.getPublicKeysForKeyId = getPublicKeysForKeyId;
	
	/**
	 * Searches the keyring for private keys having the specified key id
	 * @param keyId [String] 8 bytes as string containing the key id to look for
	 * @return Array[openpgp_msg_privatekey] private keys found
	 */
	function getPrivateKeyForKeyId(keyId) {
		var result = new Array();
		for (var i=0; i < this.privateKeys.length; i++) {
			if (keyId == util.hexstrdump(this.privateKeys[i].obj.getKeyId())) {
				result[result.length] = { key: this.privateKeys[i], keymaterial: this.privateKeys[i].obj.privateKeyPacket};
			}
			if (this.privateKeys[i].obj.subKeys != null) {
				var subkeyids = this.privateKeys[i].obj.getSubKeyIds();
				for (var j=0; j < subkeyids.length; j++)
					if (keyId == util.hexstrdump(subkeyids[j])) {
						result[result.length] = { key: this.privateKeys[i], keymaterial: this.privateKeys[i].obj.subKeys[j]};
					}
			}
		}
		return result;
	}
	this.getPrivateKeyForKeyId = getPrivateKeyForKeyId;
	
	/**
	 * Imports a public key from an exported ascii armored message 
	 * @param armored_text [String] PUBLIC KEY BLOCK message to read the public key from
	 * @return [null] nothing
	 */
	function importPublicKey (armored_text) {
		var result = openpgp.read_publicKey(armored_text);
		for (var i = 0; i < result.length; i++) {
			this.publicKeys[this.publicKeys.length] = {armored: armored_text, obj: result[i]};
		}
	}

	/**
	 * Imports a private key from an exported ascii armored message 
	 * @param armored_text [String] PRIVATE KEY BLOCK message to read the private key from
	 * @return [null] nothing
	 */
	function importPrivateKey (armored_text) {
		var result = openpgp.read_privateKey(armored_text);
		for (var i = 0; i < result.length; i++) {
			this.privateKeys[this.privateKeys.length] = {armored: armored_text, obj: result[i]};
		}
	}

	this.importPublicKey = importPublicKey;
	this.importPrivateKey = importPrivateKey;
	
	/**
	 * returns the PUBLIC KEY BLOCK message representation of the public key at public key ring index  
	 * @param index [Integer] the index of the public key within the publicKeys array
	 * @return [String] the PUBLIC KEY BLOCK message
	 */
	function exportPublicKey(index) {
		return this.publicKey[index];
	}
	this.exportPublicKey = exportPublicKey;
		
	
	/**
	 * Removes a public key from the public key keyring at the specified index 
	 * @param index [Integer] the index of the public key within the publicKeys array
	 * @return [String The public key object which has been removed
	 */
	function removePublicKey(index) {
		var removed = this.publicKeys.splice(index,1);
		this.store();
		return removed;
	}
	this.removePublicKey = removePublicKey;

	/**
	 * returns the PRIVATE KEY BLOCK message representation of the private key at private key ring index  
	 * @param index [Integer] the index of the private key within the privateKeys array
	 * @return [String] the PRIVATE KEY BLOCK message
	 */	
	function exportPrivateKey(index) {
		return this.privateKeys[index];
	}
	this.exportPrivateKey = exportPrivateKey;
}