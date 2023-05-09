import testAES from './aes';
import testBlowfish from './blowfish';
import testCAST5 from './cast5';
import testDES from './des';
import testTwofish from './twofish';

export default () => describe('Cipher', function () {
  testAES();
  testBlowfish();
  testCAST5();
  testDES();
  testTwofish();
});
