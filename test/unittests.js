describe('Unit Tests', function () {
  require('./general');
  require('./crypto');
  require('./stream');
  if (typeof window !== 'undefined') {
    require('./worker');
  }
});
