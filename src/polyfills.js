// Old browser polyfills
// All are listed as dev dependencies because Node does not need them
// and for browser babel will take care of it

if (typeof window.fetch === 'undefined') {
  // eslint-disable-next-line import/no-extraneous-dependencies
  require('whatwg-fetch');
}
if (typeof Array.prototype.fill === 'undefined') {
  // eslint-disable-next-line import/no-extraneous-dependencies
  require('core-js/fn/array/fill');
}
if (typeof Array.prototype.find === 'undefined') {
  // eslint-disable-next-line import/no-extraneous-dependencies
  require('core-js/fn/array/find');
}
if (typeof Array.from === 'undefined') {
  // eslint-disable-next-line import/no-extraneous-dependencies
  require('core-js/fn/array/from');
}
if (typeof Promise === 'undefined') {
  // eslint-disable-next-line import/no-extraneous-dependencies
  require('core-js/fn/promise');
}
if (typeof Uint8Array.from === 'undefined') {
  // eslint-disable-next-line import/no-extraneous-dependencies
  require('core-js/fn/typed/uint8-array');
}
if (typeof String.prototype.repeat === 'undefined') {
  // eslint-disable-next-line import/no-extraneous-dependencies
  require('core-js/fn/string/repeat');
}
if (typeof Symbol === 'undefined') {
  // eslint-disable-next-line import/no-extraneous-dependencies
  require('core-js/fn/symbol');
}
