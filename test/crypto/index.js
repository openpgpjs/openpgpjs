import testCipher from './cipher';
import testHash from './hash';
import testCrypto from './crypto';
import testElliptic from './elliptic';
import testECDH from './ecdh';
import testPKCS5 from './pkcs5';
import testAESKW from './aes_kw';
import testGCM from './gcm';
import testEAX from './eax';
import testOCB from './ocb';
import testRSA from './rsa';
import testValidate from './validate';

export default () => describe('Crypto', function () {
  testCipher();
  testHash();
  testCrypto();
  testElliptic();
  testECDH();
  testPKCS5();
  testAESKW();
  testGCM();
  testEAX();
  testOCB();
  testRSA();
  testValidate();
});
