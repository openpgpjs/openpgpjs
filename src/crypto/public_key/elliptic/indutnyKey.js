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

let ellipticPromise;

/**
 * Load elliptic on demand to the window.openpgp.elliptic
 * @returns {Promise<elliptic>}
 */
async function loadEllipticPromise() {
  const path = config.external_indutny_elliptic_path;
  const options = config.indutny_elliptic_fetch_options;
  const ellipticPromise = dl(path, options).catch(() => dl(path, options));
  const ellipticContents = await ellipticPromise;
  const mainUrl = URL.createObjectURL(new Blob([ellipticContents], { type: 'text/javascript' }));
  try {
    await loadScript(mainUrl);
  } catch (e) {
    throw new Error('elliptic library has not loaded correctly');
  }
  if(!window.openpgp.elliptic) {
    throw new Error('elliptic library has not loaded correctly');
  }
  URL.revokeObjectURL(mainUrl);
  return window.openpgp.elliptic;
}

function loadElliptic() {
  if(typeof window !== 'undefined' && config.external_indutny_elliptic) {
    if (!ellipticPromise) {
      ellipticPromise = loadEllipticPromise().catch(e => {
        ellipticPromise = undefined;
        throw e;
      });
    }
    return ellipticPromise;
  }
  if(util.detectNode() && config.external_indutny_elliptic) {
    // eslint-disable-next-line
    return require('./' + config.external_indutny_elliptic_path);
  }
  return require('elliptic');
}

export async function getIndutnyCurve(name) {
  const elliptic = await loadElliptic();
  return new elliptic.ec(name);
}
