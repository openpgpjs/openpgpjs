module.exports = () => describe('Hash', function () {
  require('./md5')();
  require('./ripemd')();
  require('./sha')();
});
