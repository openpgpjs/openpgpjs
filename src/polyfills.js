/**
 * @fileoverview Old browser polyfills
 * All are listed as dev dependencies because Node does not need them
 * and for browser babel will take care of it
 * @requires util
 * @module polyfills
 */

import util from './util';

if (typeof global !== 'undefined') {
  /********************************************************************
   * NOTE: This list is duplicated in Gruntfile.js,                   *
   * so that these polyfills are only included in the compat bundle.  *
   ********************************************************************/

  try {
    if (typeof global.fetch === 'undefined') {
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

if (typeof TransformStream === 'undefined') {
  require('@mattiasbuelens/web-streams-polyfill/es6');
}
if (typeof TextEncoder === 'undefined') {
  const nodeUtil = util.nodeRequire('util') || {};
  global.TextEncoder = nodeUtil.TextEncoder;
  global.TextDecoder = nodeUtil.TextDecoder;
}
if (typeof TextEncoder === 'undefined') {
  const textEncoding = require('text-encoding-utf-8');
  global.TextEncoder = textEncoding.TextEncoder;
  global.TextDecoder = textEncoding.TextDecoder;
}
