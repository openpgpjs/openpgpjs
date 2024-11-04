import { use as chaiUse, expect } from 'chai';
import chaiAsPromised from 'chai-as-promised'; // eslint-disable-line import/newline-after-import
chaiUse(chaiAsPromised);

import openpgp from '../initOpenpgp.js';

import util from '../../src/util.js';

import * as input from './testInputs.js';

export default () => describe('Elliptic Curve Cryptography for NIST P-256,P-384,P-521 curves @lightweight', function () {
  function omnibus() {
    it('Omnibus NIST P-256 Test', async function () {
      const testData = input.createSomeMessage();
      const testData2 = input.createSomeMessage();

      const { privateKey: hi, publicKey: pubHi } = await openpgp.generateKey({ userIDs: { name: 'Hi', email: 'hi@hel.lo' }, curve: 'nistP256', format: 'object' });
      const { privateKey: bye, publicKey: pubBye } = await openpgp.generateKey({ userIDs: { name: 'Bye', email: 'bye@good.bye' }, curve: 'nistP256', format: 'object' });

      const cleartextMessage = await openpgp.sign({ message: await openpgp.createCleartextMessage({ text: testData }), signingKeys: hi });
      await openpgp.verify({
        message: await openpgp.readCleartextMessage({ cleartextMessage }),
        verificationKeys: pubHi
      }).then(output => expect(output.signatures[0].verified).to.eventually.be.true);
      // Verifying detached signature
      await openpgp.verify({
        message: await openpgp.createMessage({ text: util.removeTrailingSpaces(testData) }),
        verificationKeys: pubHi,
        signature: (await openpgp.readCleartextMessage({ cleartextMessage })).signature
      }).then(output => expect(output.signatures[0].verified).to.eventually.be.true);

      // Encrypting and signing
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: testData2 }),
        encryptionKeys: [pubBye],
        signingKeys: [hi]
      });
      // Decrypting and verifying
      return openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage: encrypted }),
        decryptionKeys: bye,
        verificationKeys: [pubHi]
      }).then(async output => {
        expect(output.data).to.equal(testData2);
        await expect(output.signatures[0].verified).to.eventually.be.true;
      });
    });
  }

  omnibus();

  it('Sign message', async function () {
    const testData = input.createSomeMessage();
    const options = { userIDs: { name: 'Hi', email: 'hi@hel.lo' }, curve: 'nistP256', format: 'object' };
    const { privateKey, publicKey } = await openpgp.generateKey(options);
    const signature = await openpgp.sign({ message: await openpgp.createCleartextMessage({ text: testData }), signingKeys: privateKey });
    const msg = await openpgp.readCleartextMessage({ cleartextMessage: signature });
    const result = await openpgp.verify({ message: msg, verificationKeys: publicKey });
    expect(await result.signatures[0].verified).to.be.true;
  });

  it('Encrypt and sign message', async function () {
    const testData = input.createSomeMessage();
    let options = { userIDs: { name: 'Hi', email: 'hi@hel.lo' }, curve: 'nistP256', format: 'object' };
    const firstKey = await openpgp.generateKey(options);
    options = { userIDs: { name: 'Bye', email: 'bye@good.bye' }, curve: 'nistP256', format: 'object' };
    const secondKey = await openpgp.generateKey(options);
    const encrypted = await openpgp.encrypt({
      message: await openpgp.createMessage({ text: testData }),
      encryptionKeys: secondKey.publicKey,
      signingKeys: firstKey.privateKey
    });
    const message = await openpgp.readMessage({ armoredMessage: encrypted });
    const result = await openpgp.decrypt({ message, decryptionKeys: secondKey.privateKey, verificationKeys: firstKey.publicKey });
    expect(await result.signatures[0].verified).to.be.true;
  });

  it('should decrypt a message using the correct fingerprint size in the KDF (v6 key)', async function() {
    // this test is to ensure the KDF function uses the correct fingerprint size (the fingerprint should not be truncated)
    const key = await openpgp.readKey({
      armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xXkGZoVjGhMAAABMCCqGSM49AwEHAgMEUqR9vqdSZv8I+DGuSOYUSf4cNVlE
H16loiqRcAsDY9SHSTVHQkEWbc63HyEvV3jGSbSk2dNF64faN3nbhlZ0PgAB
APcoOjqcdJ9/LHRgxWvSbrKAmKNm0yJE9U9DY9hwshqhwqEGHxMIAAAAPgWC
ZoVjGgMLCQcFFQgKDA4EFgACAQKbAwIeASKhBk+e6Xq0rbnjKzVy/3Qitc2h
eW/w/IuxgPXjJW3nfTRxAAAAABQOEKxf0tyJS3Pbs1xApVxWKP4BAM8Bkygn
ddtiBifou11xgxOjT0y0CsbjIKyOnPTvIh/4AQCfyLJIAmQUN36mSInEepvy
NVk8jmweVYOCT8RluvFtG80OPHRlc3RAdGVzdC5pdD7CjwYTEwgAAAAsBYJm
hWMaAhkBIqEGT57perStueMrNXL/dCK1zaF5b/D8i7GA9eMlbed9NHEAAAAA
g9UQJqaRsvniF1WYuuRLpqMpOAEAvAhGhNpom/L2iIZLCpeyFCfGe5VDUBQB
1cjGpTbnrJoBAIjy1tgUH1gjixchymNf5LfUqwdXwEiLfv2f/Iq+KEX/x30G
ZoVjGhIAAABQCCqGSM49AwEHAgMESZrMsc0UrXB5/C8FHXAepykqAyueem7p
cjVvWFP9V59w/O/VXVyJBrZqleN0w/KexznRyzvQjH36HRlwVFwJ5QMBCAcA
AQDiiISRsjcPcaGXSAEYmvd80nH1oP8CJ/TQsi8od5nhqMKPBhgTCAAAACwF
gmaFYxoCmwwioQZPnul6tK254ys1cv90IrXNoXlv8PyLsYD14yVt5300cQAA
AAC2GhBn4S5eLyGPjccfUkFRKKWmAP4iHESir/KDsmsfhE5m/RwQcy7feCl7
2bny7QRNGY8dFQD8CwmHJ0EvMDQcvVWPrj8WdgPblJEEgWd9AUItEFcDee0=
-----END PGP PRIVATE KEY BLOCK-----`
    });
    const message = await openpgp.readMessage({
      armoredMessage: `-----BEGIN PGP MESSAGE-----

wX4DYKEfntV7jkcSAgMEXplJPwjsvhh7xNeBeZtgepG1f0hUaW4eoeFCDpYH
IOr2RZFgRd6KbtmNsI1saqDwDg7EjFk+AWOe7av2xcFStTDfz+9mus03A6tk
7mPFWGsDUrxP2b+tyO6ofr9I4gyj5tI2X7R94AfRWgQxy+O2PvLSNAFXcx4o
SsrtSQmZUKpxuBROy+bZNheNgmN966vqnFBiM1vXikv5OVyprUV0EzzQ3Hnt
69s=
=0Agg
-----END PGP MESSAGE-----`
    });
    const decrypted = await openpgp.decrypt({ message, decryptionKeys: key });
    expect(decrypted.data).to.equal('abc');
  });


  // TODO find test vectors
});
