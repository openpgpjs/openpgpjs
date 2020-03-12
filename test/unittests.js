// Old browser polyfills
if (typeof Symbol === 'undefined') {
  require('core-js/fn/symbol');
}
if (typeof Promise === 'undefined') {
  require('core-js/fn/promise');
}
if (typeof TransformStream === 'undefined') {
  require('@mattiasbuelens/web-streams-polyfill');
}

(typeof window !== 'undefined' ? window : global).resolves = function(val) {
  return new Promise(function(res) { res(val); });
};

(typeof window !== 'undefined' ? window : global).rejects = function(val) {
  return new Promise(function(res, rej) { rej(val); });
};

(typeof window !== 'undefined' ? window : global).tryTests = function(name, tests, options) {
  if (options.if) {
    describe(name, function() {
      if (options.before) { before(options.before); }
      if (options.beforeEach) { beforeEach(options.beforeEach); }

      tests();

      if (options.afterEach) { afterEach(options.afterEach); }
      if (options.after) { after(options.after); }
    });
  } else {
    describe.skip(name + ' (no support --> skipping tests)', tests);
  }
};

describe('Unit Tests', function () {

  if (typeof window !== 'undefined') {
    openpgp.config.s2k_iteration_count_byte = 0;
    openpgp.config.indutny_elliptic_path = '../dist/elliptic.min.js';

    afterEach(function () {
      if (window.scrollY >= document.body.scrollHeight - window.innerHeight - 100
        || openpgp.config.ci) {
        window.scrollTo(0, document.body.scrollHeight);
      }
    });

    window.location.search.substr(1).split('&').forEach(param => {
      const [key, value] = param.split('=');
      if (key && key !== 'grep') {
        openpgp.config[key] = decodeURIComponent(value);
        try {
          openpgp.config[key] = eval(openpgp.config[key]);
        } catch(e) {}
      }
    });
  }

  require('./crypto');
  require('./general');
  require('./worker');
  require('./security');
});
