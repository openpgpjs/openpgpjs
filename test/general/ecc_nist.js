const { use: chaiUse, expect } = require('chai');
chaiUse(require('chai-as-promised'));

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');

const util = require('../../src/util');

const input = require('./testInputs');

module.exports = () => describe('Elliptic Curve Cryptography for NIST P-256,P-384,P-521 curves @lightweight', function () {
  function omnibus() {
    it('Omnibus NIST P-256 Test', async function () {
      const testData = input.createSomeMessage();
      const testData2 = input.createSomeMessage();

      const { privateKey: hi, publicKey: pubHi } = await openpgp.generateKey({ userIDs: { name: 'Hi', email: 'hi@hel.lo' }, curve: 'p256', format: 'object' });
      const { privateKey: bye, publicKey: pubBye } = await openpgp.generateKey({ userIDs: { name: 'Bye', email: 'bye@good.bye' }, curve: 'p256', format: 'object' });

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
    const options = { userIDs: { name: 'Hi', email: 'hi@hel.lo' }, curve: 'p256', format: 'object' };
    const { privateKey, publicKey } = await openpgp.generateKey(options);
    const signature = await openpgp.sign({ message: await openpgp.createCleartextMessage({ text: testData }), signingKeys: privateKey });
    const msg = await openpgp.readCleartextMessage({ cleartextMessage: signature });
    const result = await openpgp.verify({ message: msg, verificationKeys: publicKey });
    expect(await result.signatures[0].verified).to.be.true;
  });

  it('Encrypt and sign message', async function () {
    const testData = input.createSomeMessage();
    let options = { userIDs: { name: 'Hi', email: 'hi@hel.lo' }, curve: 'p256', format: 'object' };
    const firstKey = await openpgp.generateKey(options);
    options = { userIDs: { name: 'Bye', email: 'bye@good.bye' }, curve: 'p256', format: 'object' };
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

  // TODO find test vectors
});
