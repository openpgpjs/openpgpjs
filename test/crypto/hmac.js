import { use as chaiUse, expect } from 'chai';
import chaiAsPromised from 'chai-as-promised'; // eslint-disable-line import/newline-after-import
chaiUse(chaiAsPromised);

import { sign, verify } from '../../src/crypto/public_key/hmac';
import enums from '../../src/enums';
import util from '../../src/util';

export default () => describe('HMAC', function () {
  it('Test vectors', async function() {
    const vectors = [
      {
        algo: enums.hash.sha256,
        key: util.hexToUint8Array('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
        data: util.hexToUint8Array('4869205468657265'),
        expected: util.hexToUint8Array('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7')
      },
      {
        algo: enums.hash.sha512,
        key: util.hexToUint8Array('4a656665'),
        data: util.hexToUint8Array('7768617420646f2079612077616e7420666f72206e6f7468696e673f'),
        expected: util.hexToUint8Array('164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737')
      }
    ];

    await Promise.all(vectors.map(async vec => {
      const res = await sign(vec.algo, vec.key, vec.data);
      const verified = await verify(vec.algo, vec.key, vec.expected, vec.data);
      expect(util.equalsUint8Array(res, vec.expected)).to.be.true;
      expect(verified).to.be.true;
    }));
  });
});

