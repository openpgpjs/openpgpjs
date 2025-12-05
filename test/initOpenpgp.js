/**
 * This module centralises the openpgp import and ensures that the module is initialised
 * at the top of the test bundle, and that the config is initialised before the tests code runs (incl. that outside of `describe`).
 */

import * as openpgp from 'openpgp';
import * as webStreamsPonyfill from 'web-streams-polyfill';

if (typeof window !== 'undefined') {
  window.openpgp = openpgp;
}

openpgp.config.s2kIterationCountByte = 0;

if (typeof window !== 'undefined' &&
  /** Mobile Safari 26 reloads the page if Argon2 tries to allocate memory above 1GB */
  window.navigator.userAgent.match(/Version\/26\.\d(\.\d)* (Mobile\/\w+ )Safari/)) {

  openpgp.config.maxArgon2MemoryExponent = 20;
}

if (!globalThis.TransformStream) {
  Object.assign(globalThis, webStreamsPonyfill);
}

export default openpgp;
