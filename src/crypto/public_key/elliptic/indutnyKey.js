// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015-2016 Decentral
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
 * @fileoverview Wrapper for a KeyPair of an curve from indutny/elliptic library
 * @requires enums
 * @requires asn1.js
 * @module crypto/public_key/elliptic/indutnyKey
 */

import { loadScript, dl } from '../../../lightweight_helper';
import config from '../../../config';
import util from '../../../util';

/**
 * @constructor
 */
export function KeyPair(indutnyCurve, options) {
  this.keyPair = indutnyCurve.keyPair(options);
  if (this.keyPair.validate().result !== true) {
    throw new Error('Invalid elliptic public key');
  }
}


let elliptic;  // instance of the indutny/elliptic
/**
 * Load elliptic by path or from node_modules
 */
export async function loadElliptic() {
  const path = config.external_indutny_elliptic_path;
  const options = config.indutny_elliptic_fetch_options;
  if(typeof window !== 'undefined' && config.external_indutny_elliptic) {
    // Fetch again if it fails, mainly to solve chrome bug "body stream has been lost and cannot be disturbed"
    const ellipticPromise = dl(path, options).catch(() => dl(path, options));
    const ellipticContents = await ellipticPromise;
    const mainUrl = URL.createObjectURL(new Blob([ellipticContents], { type: 'text/javascript' }));
    await loadScript(mainUrl);
    URL.revokeObjectURL(mainUrl);
    elliptic = window.openpgp.elliptic;
    return elliptic;
  } else if(util.detectNode() && config.external_indutny_elliptic) {
    // eslint-disable-next-line
    elliptic = require('./' + path);
    return elliptic;
  }
  elliptic = require('elliptic');
  return elliptic;
}

export function getElliptic() {
  return elliptic;
}

export async function getIndutnyCurve(name) {
  const elliptic = getElliptic() || await loadElliptic();
  return new elliptic.ec(name);
}
