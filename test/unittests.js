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
    openpgp.config.s2kIterationCountByte = 0;

    window.location.search.substr(1).split('&').forEach(param => {
      const [key, value] = param.split('=');
      if (key && key !== 'grep') {
        openpgp.config[key] = decodeURIComponent(value);
        try {
          openpgp.config[key] = window.eval(openpgp.config[key]);
        } catch(e) {}
      }
    });
  }

  require('./crypto')();
  require('./general')();
  require('./worker')();
  require('./security')();
});
