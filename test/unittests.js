(typeof window !== 'undefined' ? window : global).resolves = function(val) {
  return new Promise(function(res) { res(val); });
};

(typeof window !== 'undefined' ? window : global).rejects = function(val) {
  return new Promise(function(res, rej) { rej(val); });
};

(typeof window !== 'undefined' ? window : global).tryWorker = function(name, tests, beforeFn, afterFn) {
  if (typeof window !== 'undefined' && window.Worker) {
    describe(name, function() {
      before(beforeFn);

      tests();

      after(afterFn);
    });
  } else {
    describe.skip(name + ' (No Web Worker support --> skipping tests)', tests);
  }
};

describe('Unit Tests', function () {
  require('./crypto');
  require('./general');
  require('./worker');
});
