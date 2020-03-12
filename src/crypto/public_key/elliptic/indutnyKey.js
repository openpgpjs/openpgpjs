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

export function keyFromPrivate(indutnyCurve, priv) {
  const keyPair = indutnyCurve.keyPair({ priv: priv });
  return keyPair;
}

export function keyFromPublic(indutnyCurve, pub) {
  const keyPair = indutnyCurve.keyPair({ pub: pub });
  if (keyPair.validate().result !== true) {
    throw new Error('Invalid elliptic public key');
  }
  return keyPair;
}

/**
 * Load elliptic on demand to global.openpgp.elliptic
 * @returns {Promise<elliptic>}
 */
async function loadEllipticPromise() {
  const path = config.indutny_elliptic_path;
  const options = config.indutny_elliptic_fetch_options;
  const ellipticDlPromise = dl(path, options).catch(() => dl(path, options));
  const ellipticContents = await ellipticDlPromise;
  const mainUrl = URL.createObjectURL(new Blob([ellipticContents], { type: 'text/javascript' }));
  await loadScript(mainUrl);
  URL.revokeObjectURL(mainUrl);
  if (!global.openpgp.elliptic) {
    throw new Error('Elliptic library failed to load correctly');
  }
  return global.openpgp.elliptic;
}

let ellipticPromise;

function loadElliptic() {
  if (!config.external_indutny_elliptic) {
    return require('elliptic');
  }
  if (util.detectNode()) {
    // eslint-disable-next-line
    return require(config.indutny_elliptic_path);
  }
  if (!ellipticPromise) {
    ellipticPromise = loadEllipticPromise().catch(e => {
      ellipticPromise = undefined;
      throw e;
    });
  }
  return ellipticPromise;
}

export async function getIndutnyCurve(name) {
  if (!config.use_indutny_elliptic) {
    throw new Error('This curve is only supported in the full build of OpenPGP.js');
  }
  const elliptic = await loadElliptic();
  return new elliptic.ec(name);
}
