module.exports = () => describe('Cipher', function () {
  require('./aes')();
  require('./blowfish')();
  require('./cast5')();
  require('./des')();
  require('./twofish')();
});
