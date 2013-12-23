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

/** @module config/config */

var enums = require('../enums.js');

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
var config = function() {
  /**
   * @property {Integer} prefer_hash_algorithm
   * @property {Integer} encryption_cipher
   * @property {Integer} compression
   * @property {Boolean} show_version
   * @property {Boolean} show_comment
   * @property {Boolean} integrity_protect
   * @property {String} keyserver
   */
  this.prefer_hash_algorithm = enums.hash.sha256;
  this.encryption_cipher = enums.symmetric.aes256;
  this.compression = enums.compression.zip;
  this.show_version = true;
  this.show_comment = true;
  this.integrity_protect = true;
  this.keyserver = "keyserver.linux.it"; // "pgp.mit.edu:11371"

  this.versionstring = "OpenPGP.js VERSION";
  this.commentstring = "http://openpgpjs.org";

  /**
   * If enabled, debug messages will be printed
   */
  this.debug = false;

};

module.exports = new config();
