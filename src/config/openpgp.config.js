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
 *
 * This object contains configuration values and implements
 * storing and retrieving configuration them from HTML5 local storage.
 *
 * This object can be accessed after calling openpgp.init()
 * using openpgp.config
 * Stored config parameters can be accessed using
 * openpgp.config.config
 * @class
 * @classdesc Implementation of the GPG4Browsers config object
 */
function openpgp_config() {
	/**
	 * The variable with the actual configuration
	 * @property {Integer} prefer_hash_algorithm
	 * @property {Integer} encryption_cipher
	 * @property {Integer} compression
	 * @property {Boolean} show_version
	 * @property {Boolean} show_comment
	 * @property {Boolean} integrity_protect
	 * @property {Integer} composition_behavior
	 * @property {String} keyserver
	 */
	this.config = null;

	/**
	 * The default config object which is used if no
	 * configuration was in place
	 */
	this.default_config = {
			prefer_hash_algorithm: 8,
			encryption_cipher: 9,
			compression: 1,
			show_version: true,
			show_comment: true,
			integrity_protect: true,
			composition_behavior: 0,
			keyserver: "keyserver.linux.it" // "pgp.mit.edu:11371"
	};

	this.versionstring ="OpenPGP.js VERSION";
	this.commentstring ="http://openpgpjs.org";
	/**
	 * Reads the config out of the HTML5 local storage
	 * and initializes the object config.
	 * if config is null the default config will be used
	 */
	function read() {
		var cf = JSON.parse(window.localStorage.getItem("config"));
		if (cf == null) {
			this.config = this.default_config;
			this.write();
		}
		else
			this.config = cf;
	}

	/**
	 * If enabled, debug messages will be printed
	 */
	this.debug = false;

	/**
	 * Writes the config to HTML5 local storage
	 */
	function write() {
		window.localStorage.setItem("config",JSON.stringify(this.config));
	}

	this.read = read;
	this.write = write;
}
