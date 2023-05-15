import { expect } from 'chai';

import openpgp from '../initOpenpgp.js';

const charlieKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEZAdtGBYJKwYBBAHaRw8BAQdAcNgHyRGEaqGmzEqEwCobfUkyrJnY8faBvsf9
R2c5ZzYAAP9bFL4nPBdo04ei0C2IAh5RXOpmuejGC3GAIn/UmL5cYQ+XzRtjaGFy
bGVzIDxjaGFybGVzQHByb3Rvbi5tZT7CigQTFggAPAUCZAdtGAmQFXJtmBzDhdcW
IQRl2gNflypl1XjRUV8Vcm2YHMOF1wIbAwIeAQIZAQILBwIVCAIWAAIiAQAAJKYA
/2qY16Ozyo5erNz51UrKViEoWbEpwY3XaFVNzrw+b54YAQC7zXkf/t5ieylvjmA/
LJz3/qgH5GxZRYAH9NTpWyW1AsdxBGQHbRgSCisGAQQBl1UBBQEBB0CxmxoJsHTW
TiETWh47ot+kwNA1hCk1IYB9WwKxkXYyIBf/CgmKXzV1ODP/mRmtiBYVV+VQk5MF
EAAA/1NW8D8nMc2ky140sPhQrwkeR7rVLKP2fe5n4BEtAnVQEB3CeAQYFggAKgUC
ZAdtGAmQFXJtmBzDhdcWIQRl2gNflypl1XjRUV8Vcm2YHMOF1wIbUAAAl/8A/iIS
zWBsBR8VnoOVfEE+VQk6YAi7cTSjcMjfsIez9FYtAQDKo9aCMhUohYyqvhZjn8aS
3t9mIZPc+zRJtCHzQYmhDg==
=lESj
-----END PGP PRIVATE KEY BLOCK-----`;

const fwdCiphertextArmored = `-----BEGIN PGP MESSAGE-----

wV4DB27Wn97eACkSAQdA62TlMU2QoGmf5iBLnIm4dlFRkLIg+6MbaatghwxK+Ccw
yGZuVVMAK/ypFfebDf4D/rlEw3cysv213m8aoK8nAUO8xQX3XQq3Sg+EGm0BNV8E
0kABEPyCWARoo5klT1rHPEhelnz8+RQXiOIX3G685XCWdCmaV+tzW082D0xGXSlC
7lM8r1DumNnO8srssko2qIja
=pVRa
-----END PGP MESSAGE-----`;

export default () => describe('Forwarding', function() {
  it('can decrypt forwarded ciphertext', async function() {
    const charlieKey = await openpgp.readKey({ armoredKey: charlieKeyArmored });

    await expect(openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage: fwdCiphertextArmored }),
      decryptionKeys: charlieKey
    })).to.be.rejectedWith(/Error decrypting message/);

    const result = await openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage: fwdCiphertextArmored }),
      decryptionKeys: charlieKey,
      config: { allowForwardedMessages: true }
    });

    expect(result.data).to.equal('Message for Bob');
  });

  it('supports serialising key with KDF params for forwarding', async function() {
    const charlieKey = await openpgp.readKey({ armoredKey: charlieKeyArmored });

    const serializedKey = charlieKey.write();
    const { data: expectedSerializedKey } = await openpgp.unarmor(charlieKeyArmored);
    expect(serializedKey).to.deep.equal(expectedSerializedKey);
  });
});
