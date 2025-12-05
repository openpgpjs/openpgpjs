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

if (!globalThis.TransformStream) {
  Object.assign(globalThis, webStreamsPonyfill);
}

export default openpgp;
