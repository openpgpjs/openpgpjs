import testMD5 from './md5';
import testRipeMD from './ripemd';
import testSHA from './sha';

export default () => describe('Hash', function () {
  testMD5();
  testRipeMD();
  testSHA();
});
