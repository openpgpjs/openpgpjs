describe('Unit Tests', function () {
  require('./general');
  require('./crypto');
  if (typeof window !== 'undefined') {
    require('./worker');
  }
});
