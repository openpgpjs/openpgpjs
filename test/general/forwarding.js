import { expect } from 'chai';

import openpgp from '../initOpenpgp.js';

const charlieKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.10.4
Comment: https://openpgpjs.org

xVgEXqG7KRYJKwYBBAHaRw8BAQdA/q4cs9Pwms3R4trjUd7YyrsRYdQHC9wI
MqLdefob4KUAAQDfy9e8qleM+a1EnPCjDpm69FIY769mo/dpwYlkuI2T/RQt
zSlCb2IgKEZvcndhcmRlZCB0byBDaGFybGllKSA8aW5mb0Bib2IuY29tPsJ4
BBAWCgAgBQJeobspBgsJBwgDAgQVCAoCBBYCAQACGQECGwMCHgEACgkQN2cz
+W7U/RnS8AEArtRly8vW6uUSng9EJ0iuIwJpwgZfykSLl/t4u3HTBZ4BALzY
3XsnvKtZZVvaKvFvCUu/2NvC/1yw2wJk9wGbCwEOx3YEXqG7KRIKKwYBBAGX
VQEFAQEHQCGxSJahhDUdTKnlqT3UIn3rXn5i47I4MsG4kSWfTwcOHAIIBwPe
7fJ+kOrMea9aIUeYtGpUzABa9gMBCAcAAP95QjbjU7kyugp39vhi60YW5T8p
Me0kKFCWzmSYzstgGBBbwmEEGBYIAAkFAl6huykCGwwACgkQN2cz+W7U/RkP
WQD+KcU1HKn6PkVJKxg6RS0Q7RcCZwaQ1DyEyjUoneMCRAgA/jUl9uvPAoCS
3+4Wqg9Q//zOwXNImimIPIdpWNXYZJID
=FVvG
-----END PGP PRIVATE KEY BLOCK-----`;

const fwdCiphertextArmored = `-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.10.4
Comment: https://openpgpjs.org

wV4Dog8LAQLriGUSAQdA/I6k0IvGxyNG2SdSDHrv3bZQDWH18OhTWkcmSF0M
Bxcw3w8KMjr2v69ro5cyZztymEXi5RemRx+oPZGKIZ9N5T+26TaOltH7h8eR
Mu4H03Lp0k4BRsjpFNUBL3HsAuMIemNf4369g+szlpuzjNE1KQhQzZbh87AU
T7KAKygwz0EpOWpx2RHtshDy/bZ1EC8Ia4qDAebameIqCU929OmY1uI=
=3iIr
-----END PGP MESSAGE-----`;

export default () => describe('Forwarding', function() {
  it('can decrypt forwarded ciphertext', async function() {
    const charlieKey = await openpgp.readKey({ armoredKey: charlieKeyArmored });
    const msg = await openpgp.readMessage({ armoredMessage: fwdCiphertextArmored });
    const result = await openpgp.decrypt({ decryptionKeys: charlieKey, message: msg });

    expect(result).to.exist;
    expect(result.data).to.equal('Hello Bob, hello world');
  });
});
