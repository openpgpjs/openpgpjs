module.exports = () => describe('Crypto', function () {
  require('./cipher')();
  require('./hash')();
  require('./crypto')();
  require('./elliptic')();
  require('./ecdh')();
  require('./pkcs5')();
  require('./aes_kw')();
  require('./hkdf')();
  require('./gcm')();
  require('./eax')();
  require('./ocb')();
  require('./rsa')();
  require('./validate')();
});
