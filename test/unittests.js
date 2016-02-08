(typeof window !== 'undefined' ? window : global).resolves = function(val) {
  return new Promise(function(res) { res(val); });
};

(typeof window !== 'undefined' ? window : global).rejects = function(val) {
  return new Promise(function(res, rej) { rej(val); });
};

describe('Unit Tests', function () {
  require('./general');
  require('./crypto');
  if (typeof window !== 'undefined') {
    require('./worker');
  }
});
