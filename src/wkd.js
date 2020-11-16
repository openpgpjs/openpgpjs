// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2018 Wiktor Kwapisiewicz
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
 * @fileoverview This class implements a client for the Web Key Directory (wkd) protocol
 * in order to lookup keys on designated servers.
 * See: https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/
 * @module wkd
 */

import util from './util';
import crypto from './crypto';
import * as keyMod from './key';

/**
 * Initialize the WKD client
 * @constructor
 */
function WKD() {
  this._fetch = typeof global.fetch === 'function' ? global.fetch : require('node-fetch');
}

/**
 * Search for a public key using Web Key Directory protocol.
 * @param   {String}   options.email         User's email.
 * @param   {Boolean}  options.rawBytes      Returns Uint8Array instead of parsed key.
 * @returns {Promise<Uint8Array|
 *           {keys: Array<module:key.Key>,
 *            err: (Array<Error>|null)}>}     The public key.
 * @async
 */
WKD.prototype.lookup = async function(options) {
  const fetch = this._fetch;

  if (!options.email) {
    throw new Error('You must provide an email parameter!');
  }

  if (!util.isEmailAddress(options.email)) {
    throw new Error('Invalid e-mail address.');
  }

  const [, localPart, domain] = /(.*)@(.*)/.exec(options.email);
  const localEncoded = util.encodeZBase32(await crypto.hash.sha1(util.str_to_Uint8Array(localPart.toLowerCase())));

  const urlAdvanced = `https://openpgpkey.${domain}/.well-known/openpgpkey/${domain}/hu/${localEncoded}`;
  const urlDirect = `https://${domain}/.well-known/openpgpkey/hu/${localEncoded}`;

  let response;
  try {
    response = await fetch(urlAdvanced);
    if (response.status !== 200) {
      throw new Error('Advanced WKD lookup failed: ' + response.statusText);
    }
  } catch (err) {
    util.print_debug_error(err);
    response = await fetch(urlDirect);
    if (response.status !== 200) {
      throw new Error('Direct WKD lookup failed: ' + response.statusText);
    }
  }

  const rawBytes = new Uint8Array(await response.arrayBuffer());
  if (options.rawBytes) {
    return rawBytes;
  }
  return keyMod.read(rawBytes);
};

export default WKD;
