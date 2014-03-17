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
 * This object contains configuration values.
 * @requires enums
 * @property {Integer} prefer_hash_algorithm
 * @property {Integer} encryption_cipher
 * @property {Integer} compression
 * @property {Boolean} show_version
 * @property {Boolean} show_comment
 * @property {Boolean} integrity_protect
 * @property {String} keyserver
 * @property {Boolean} debug If enabled, debug messages will be printed
 * @module config/config
 */

var enums = require('../enums.js');

module.exports = {
  prefer_hash_algorithm: enums.hash.sha256,
  encryption_cipher: enums.symmetric.aes256,
  compression: enums.compression.zip,
  integrity_protect: true,
  rsa_blinding: true,

  show_version: true,
  show_comment: true,
  versionstring: "OpenPGP.js VERSION",
  commentstring: "http://openpgpjs.org",

  keyserver: "keyserver.linux.it", // "pgp.mit.edu:11371"
  node_store: './openpgp.store',

  debug: false
};
