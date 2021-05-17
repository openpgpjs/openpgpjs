const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');

const chai = require('chai');
chai.use(require('chai-as-promised'));
const input = require('./testInputs.js');
const util = require('../../src/util');

const expect = chai.expect;

module.exports = () => describe('Elliptic Curve Cryptography for NIST P-256,P-384,P-521 curves @lightweight', function () {
  function omnibus() {
    it('Omnibus NIST P-256 Test', async function () {
      const testData = input.createSomeMessage();
      const testData2 = input.createSomeMessage();

      const firstKey = await openpgp.generateKey({ userIDs: { name: "Hi", email: "hi@hel.lo" }, curve: "p256" });
      const hi = firstKey.key;
      const pubHi = hi.toPublic();
      const secondKey = await openpgp.generateKey({ userIDs: { name: "Bye", email: "bye@good.bye" }, curve: "p256" });
      const bye = secondKey.key;
      const pubBye = bye.toPublic();

      const cleartextMessage = await openpgp.sign({ message: await openpgp.createCleartextMessage({ text: testData }), signingKeys: hi });
      await openpgp.verify({
        message: await openpgp.readCleartextMessage({ cleartextMessage }),
        verificationKeys: pubHi
      }).then(output => expect(output.signatures[0].valid).to.be.true);
      // Verifying detached signature
      await openpgp.verify({
        message: await openpgp.createMessage({ text: util.removeTrailingSpaces(testData) }),
        verificationKeys: pubHi,
        signature: (await openpgp.readCleartextMessage({ cleartextMessage })).signature
      }).then(output => expect(output.signatures[0].valid).to.be.true);

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
      }).then(output => {
        expect(output.data).to.equal(testData2);
        expect(output.signatures[0].valid).to.be.true;
      });
    });
  }

  omnibus();

  it('Sign message', async function () {
    const testData = input.createSomeMessage();
    const options = { userIDs: { name: "Hi", email: "hi@hel.lo" }, curve: "p256" };
    const firstKey = await openpgp.generateKey(options);
    const signature = await openpgp.sign({ message: await openpgp.createCleartextMessage({ text: testData }), signingKeys: firstKey.key });
    const msg = await openpgp.readCleartextMessage({ cleartextMessage: signature });
    const result = await openpgp.verify({ message: msg, verificationKeys: firstKey.key.toPublic() });
    expect(result.signatures[0].valid).to.be.true;
  });

  it('encrypt and sign message', async function () {
    const testData = input.createSomeMessage();
    let options = { userIDs: { name: "Hi", email: "hi@hel.lo" }, curve: "p256" };
    const firstKey = await openpgp.generateKey(options);
    options = { userIDs: { name: "Bye", email: "bye@good.bye" }, curve: "p256" };
    const secondKey = await openpgp.generateKey(options);
    const encrypted = await openpgp.encrypt(
      { message: await openpgp.createMessage({ text: testData }),
        encryptionKeys: [secondKey.key.toPublic()],
        signingKeys: [firstKey.key] }
    );
    const msg = await openpgp.readMessage({ armoredMessage: encrypted });
    const result = await openpgp.decrypt(
      { message: msg,
        decryptionKeys: secondKey.key,
        verificationKeys: [firstKey.key.toPublic()] }
    );
    expect(result.signatures[0].valid).to.be.true;
  });

  // TODO find test vectors
});
