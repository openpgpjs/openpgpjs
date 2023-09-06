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

  it('generates subkey with forwarding flag (0x40)', async function() {
    const { privateKey: armoredKey } = await openpgp.generateKey({ userIDs: { email: 'test@forwarding.it' }, subkeys: [{ forwarding: true }, {}] });
    const privateKey = await openpgp.readKey({ armoredKey });

    expect(privateKey.subkeys[0].bindingSignatures[0].keyFlags[0]).to.equal(openpgp.enums.keyFlags.forwardedCommunication);
    expect(privateKey.subkeys[1].bindingSignatures[0].keyFlags[0]).to.equal(openpgp.enums.keyFlags.encryptCommunication | openpgp.enums.keyFlags.encryptStorage);
  });

  it('reformatting a key preserves its forwarding flags (0x40)', async function() {
    // two subkeys, the first with forwarding flag, the second with standard encryption ones
    const privateKey = await openpgp.readKey({ armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEZPhkahYJKwYBBAHaRw8BAQdARUPOBft22XPObTCYNRD2VB8ESYHOZsII
XrpUHn2AstUAAQCl30ZHts8cyRRXw7B2595L8RIovkwxhnCRTqe+V92+2BFK
zRQ8dGVzdEBmb3J3YXJkaW5nLml0PsKMBBAWCgA+BYJk+GRqBAsJBwgJkLvy
KUWO/JamAxUICgQWAAIBAhkBApsDAh4BFiEEM00dF5bOjezdbhYlu/IpRY78
lqYAAP6uAQDt7Xxoh+VUB/xkOX1cj7at7U7zrKAxq7Xh1YbGM+RHKgEAgRoz
UGXKsQigC2KyXGW0nObT8RfUcQIUyrkVdImWiAjHXQRk+GRqEgorBgEEAZdV
AQUBAQdA1E/PrQHG7g8UW7v7fKwgc0x+jTHp8cOa3SGAqd3Pc3gDAQgHAAD/
TY0mClFVWkDM/W6CnN7pOO36baJ0o1LJAVHucDTbxOgSMMJ4BBgWCAAqBYJk
+GRqCZC78ilFjvyWpgKbQBYhBDNNHReWzo3s3W4WJbvyKUWO/JamAABzegEA
mP3WSG1pceOppv5ncSoZJ9GZoaiXxnkk2TyLvmBQi7kA/1MoAjQDjF3XbX8y
ScSjs3juhSAQ/MnFj8RsDaI7XdIBx10EZPhkahIKKwYBBAGXVQEFAQEHQEyC
E9n5Jo23u9OfoVcUwEfQj4yAMhNBII3j5ePRDaYXAwEIBwAA/2M7YfJN9jV4
LuiY7ldrWsd875xA5s6I6/8aOtUHuJcYEmPCeAQYFggAKgWCZPhkagmQu/Ip
RY78lqYCmwwWIQQzTR0Xls6N7N1uFiW78ilFjvyWpgAA5KEBAKaoHbyi3wpr
jt2m75fdx10rDOxJDR9H6ilI5ygLWeLsAPoCozX/3KhXLx8WbTe7MFcGl47J
YdgLdgXl0dn/xdXjCQ==
=eC8z
-----END PGP PRIVATE KEY BLOCK-----` });

    const { privateKey: reformattedKey } = await openpgp.reformatKey({ privateKey, userIDs: { email: 'test@forwarding.it' }, format: 'object' });

    expect(reformattedKey.subkeys[0].bindingSignatures[0].keyFlags[0]).to.equal(openpgp.enums.keyFlags.forwardedCommunication);
    expect(reformattedKey.subkeys[1].bindingSignatures[0].keyFlags[0]).to.equal(openpgp.enums.keyFlags.encryptCommunication | openpgp.enums.keyFlags.encryptStorage);
  });

  it('refuses to encrypt using encryption key with forwarding flag (0x40)', async function() {
    const charlieKey = await openpgp.readKey({ armoredKey: charlieKeyArmored });

    await expect(openpgp.encrypt({
      message: await openpgp.createMessage({ text: 'abc' }),
      encryptionKeys: charlieKey
    })).to.be.rejectedWith(/Could not find valid encryption key packet/);
  });
});
