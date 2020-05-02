/**
 * @module polyfills
 */

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
