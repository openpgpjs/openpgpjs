if (typeof window === 'undefined') {
  // load ES6 Promises polyfill under node.js
  require('es6-promise').polyfill();
}

describe('Unit Tests', function () {
  require('./general');
  require('./crypto');
  if (typeof window !== 'undefined') {
    require('./worker');
  }
});
