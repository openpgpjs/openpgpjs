import openpgp from './initOpenpgp.js';

(typeof window !== 'undefined' ? window : global).globalThis = (typeof window !== 'undefined' ? window : global);

globalThis.resolves = function(val) {
  return new Promise(function(res) { res(val); });
};

globalThis.rejects = function(val) {
  return new Promise(function(res, rej) { rej(val); });
};

globalThis.tryTests = function(name, tests, options) {
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

globalThis.loadStreamsPolyfill = function() {
  return import('web-streams-polyfill');
};

import runWorkerTests from './worker';
import runCryptoTests from './crypto';
import runGeneralTests from './general';
import runSecurityTests from './security';

describe('Unit Tests', function () {
  if (typeof window !== 'undefined') {
    // Safari 14.1.*, 15.* and 16.* seem to have issues handling rejections when their native TransformStream implementation is involved,
    // so for now we ignore unhandled rejections for those browser versions.
    if (!window.navigator.userAgent.match(/Version\/1(4|5|6)\.\d(\.\d)* Safari/)) {
      window.addEventListener('unhandledrejection', function (event) {
        throw event.reason;
      });
    }

    window.location.search.substr(1).split('&').forEach(param => {
      const [key, value] = param.split('=');
      if (key && key !== 'grep') {
        openpgp.config[key] = decodeURIComponent(value);
        try {
          openpgp.config[key] = window.eval(openpgp.config[key]); // eslint-disable-line no-eval
        } catch (e) {}
      }
    });
  } else {
    process.on('unhandledRejection', error => {
      console.error(error); // eslint-disable-line no-console
      process.exit(1); // eslint-disable-line no-process-exit
    });
  }

  runWorkerTests();
  runCryptoTests();
  runGeneralTests();
  runSecurityTests();
});
