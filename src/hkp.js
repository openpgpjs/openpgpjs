// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015 Tankred Hase
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
 * @fileoverview This class implements a client for the OpenPGP HTTP Keyserver Protocol (HKP)
 * in order to lookup and upload keys on standard public key servers.
 */

'use strict';

import config from './config';

/**
 * Initialize the HKP client and configure it with the key server url and fetch function.
 * @constructor
 * @param {String}    keyServerBaseUrl  (optional) The HKP key server base url including
 *   the protocol to use e.g. https://pgp.mit.edu
 */
export default function HKP(keyServerBaseUrl) {
  this._baseUrl = keyServerBaseUrl ? keyServerBaseUrl : config.keyserver;
  this._fetch = typeof window !== 'undefined' ? window.fetch : require('node-fetch');
}

/**
 * Search for a public key on the key server either by key ID or part of the user ID.
 * @param  {String}   options.query   This can be any part of the key user ID such as name
 *   or email address.
 * @return {Array} An array of key IDs, fingerprints, usernames, mail addresses and key IDs
 */
HKP.prototype.search = function (options) {
  var uri = this._baseUrl + '/pks/lookup?op=index&options=mr&search=',
      fetch = this._fetch;

  if (options.query) {
    uri += encodeURIComponent(options.query);
  } else {
    throw new Error('You must provide a query parameter!');
  }

  return fetch(uri).then(function (response) {
    var result;
    if (response.status === 404) {
      return "";
    } else if (response.status === 200) {
      result = response.text();
      return result;
    }
  }).then(function(uids){
    var result, uidary, values;
    uidary = uids.match(/pub:(.|\nuid)*/gm);
    result = {};
    for (var i in uidary) {
      var keyID;
      values = uidary[i].match(/pub:.*/)[0].split(":");
      keyID = values[1].substr(24,16);
      result[keyID] = {};
      result[keyID].fingerprint = values[1];
      result[keyID].algo = values[2];
      result[keyID].keylength = values[3];
      result[keyID].created = new Date(parseInt(values[4])*1000);
      result[keyID].valid = new Date(parseInt(values[5])*1000);

      result[keyID].uids = [];
      values = uidary[i].match(/uid:.*/g);
      for (var n in values) {
        result[keyID].uids.push(values[n].split(":")[1]);
      }
    }
    return result;
  });
};

/**
 * Search for a public key on the key server either by key ID or part of the user ID.
 * @param  {String}   options.keyID   The long public key ID.
 * @param  {String}   options.query   This can be any part of the key user ID such as name
 *   or email address.
 * @return {Promise<String>}          The ascii armored public key.
 */
HKP.prototype.lookup = function(options) {
  var uri = this._baseUrl + '/pks/lookup?op=get&options=mr&search=',
    fetch = this._fetch;

  if (options.keyId) {
    uri += '0x' + encodeURIComponent(options.keyId);
  } else if (options.query) {
    uri += encodeURIComponent(options.query);
  } else {
    throw new Error('You must provide a query parameter!');
  }

  return fetch(uri).then(function(response) {
    if (response.status === 200) {
      return response.text();
    }

  }).then(function(publicKeyArmored) {
    if (!publicKeyArmored || publicKeyArmored.indexOf('-----END PGP PUBLIC KEY BLOCK-----') < 0) {
      return;
    }
    return publicKeyArmored.trim();
  });
};

/**
 * Upload a public key to the server.
 * @param  {String}   publicKeyArmored  An ascii armored public key to be uploaded.
 * @return {Promise}
 */
HKP.prototype.upload = function(publicKeyArmored) {
  var uri = this._baseUrl + '/pks/add',
    fetch = this._fetch;

  return fetch(uri, {
    method: 'post',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    },
    body: 'keytext=' + encodeURIComponent(publicKeyArmored)
  });
};