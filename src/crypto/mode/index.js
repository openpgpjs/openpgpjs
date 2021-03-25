/**
 * @fileoverview Cipher modes
 * @module crypto/mode
 * @private
 */

import * as cfb from './cfb';
import eax from './eax';
import ocb from './ocb';
import gcm from './gcm';

export default {
  /** @see module:crypto/mode/cfb */
  cfb: cfb,
  /** @see module:crypto/mode/gcm */
  gcm: gcm,
  experimentalGCM: gcm,
  /** @see module:crypto/mode/eax */
  eax: eax,
  /** @see module:crypto/mode/ocb */
  ocb: ocb
};
