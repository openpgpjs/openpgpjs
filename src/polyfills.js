/**
 * @fileoverview Old browser polyfills
 * All are listed as dev dependencies because Node does not need them
 * and for browser babel will take care of it
 * @module polyfills
 */

if (typeof globalThis !== 'undefined') {
  /********************************************************************
   * NOTE: This list is duplicated in Gruntfile.js,                   *
   * so that these polyfills are only included in the compat bundle.  *
   ********************************************************************/

  try {
    if (typeof globalThis.fetch === 'undefined') {
      require('whatwg-fetch');
    }
    if (typeof Array.prototype.fill === 'undefined') {
      require('core-js/fn/array/fill');
    }
    if (typeof Array.prototype.find === 'undefined') {
      require('core-js/fn/array/find');
    }
    if (typeof Array.prototype.includes === 'undefined') {
      require('core-js/fn/array/includes');
    }
    if (typeof Array.from === 'undefined') {
      require('core-js/fn/array/from');
    }

    // No if-statement on Promise because of IE11. Otherwise Promise is undefined in the service worker.
    require('core-js/fn/promise');

    if (typeof Uint8Array.from === 'undefined') {
      require('core-js/fn/typed/uint8-array');
    }
    if (typeof String.prototype.repeat === 'undefined') {
      require('core-js/fn/string/repeat');
    }
    if (typeof Symbol === 'undefined') {
      require('core-js/fn/symbol');
    }
    if (typeof Object.assign === 'undefined') {
      require('core-js/fn/object/assign');
    }
  } catch (e) {}
}

if (typeof TextEncoder === 'undefined') {
  const nodeUtil = require('util') || {};
  globalThis.TextEncoder = nodeUtil.TextEncoder;
  globalThis.TextDecoder = nodeUtil.TextDecoder;
}
if (typeof TextEncoder === 'undefined') {
  const textEncoding = require('text-encoding-utf-8');
  globalThis.TextEncoder = textEncoding.TextEncoder;
  globalThis.TextDecoder = textEncoding.TextDecoder;
}
