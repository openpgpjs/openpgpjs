/* globals tryTests: true */

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const chai = require('chai');
chai.use(require('chai-as-promised'));
const input = require('./testInputs.js');

const expect = chai.expect;

describe('Elliptic Curve Cryptography for NIST P-256,P-384,P-521 curves @lightweight', function () {
  function omnibus() {
    it('Omnibus NIST P-256 Test', function () {
      const options = { userIds: {name: "Hi", email: "hi@hel.lo"}, curve: "p256" };
      const testData = input.createSomeMessage();
      const testData2 = input.createSomeMessage();
      return openpgp.generateKey(options).then(function (firstKey) {
        const hi = firstKey.key;
        const pubHi = hi.toPublic();

        const options = { userIds: { name: "Bye", email: "bye@good.bye" }, curve: "p256" };
        return openpgp.generateKey(options).then(function (secondKey) {
          const bye = secondKey.key;
          const pubBye = bye.toPublic();

          return Promise.all([
            // Signing message

            openpgp.sign(
              { message: openpgp.cleartext.fromText(testData), privateKeys: hi }
            ).then(async signed => {
              const msg = await openpgp.cleartext.readArmored(signed.data);
              // Verifying signed message
              return Promise.all([
                openpgp.verify(
                  { message: msg, publicKeys: pubHi }
                ).then(output => expect(output.signatures[0].valid).to.be.true),
                // Verifying detached signature
                openpgp.verify(
                  { message: openpgp.cleartext.fromText(testData),
                    publicKeys: pubHi,
                    signature: await openpgp.signature.readArmored(signed.data) }
                ).then(output => expect(output.signatures[0].valid).to.be.true)
              ]);
            }),
            // Encrypting and signing
            openpgp.encrypt(
              { message: openpgp.message.fromText(testData2),
                publicKeys: [pubBye],
                privateKeys: [hi] }
            ).then(async encrypted => {
              const msg = await openpgp.message.readArmored(encrypted.data);
              // Decrypting and verifying
              return openpgp.decrypt(
                { message: msg,
                  privateKeys: bye,
                  publicKeys: [pubHi] }
              ).then(output => {
                expect(output.data).to.equal(testData2);
                expect(output.signatures[0].valid).to.be.true;
              });
            })
          ]);
        });
      });
    });
  }

  omnibus();

  it('Sign message', async function () {
    const testData = input.createSomeMessage();
    let options = { userIds: {name: "Hi", email: "hi@hel.lo"}, curve: "p256" };
    const firstKey = await openpgp.generateKey(options);
    const signature =  await openpgp.sign({ message: openpgp.cleartext.fromText(testData), privateKeys: firstKey.key });
    const msg = await openpgp.cleartext.readArmored(signature.data);
    const result = await openpgp.verify({ message: msg, publicKeys: firstKey.key.toPublic()});
    expect(result.signatures[0].valid).to.be.true;
  });

  it('encrypt and sign message', async function () {
    const testData = input.createSomeMessage();
    let options = { userIds: {name: "Hi", email: "hi@hel.lo"}, curve: "p256" };
    const firstKey = await openpgp.generateKey(options);
    options = { userIds: { name: "Bye", email: "bye@good.bye" }, curve: "p256" };
    const secondKey = await openpgp.generateKey(options);
    const encrypted =  await openpgp.encrypt(
      { message: openpgp.message.fromText(testData),
        publicKeys: [secondKey.key.toPublic()],
        privateKeys: [firstKey.key] }
    );
    const msg = await openpgp.message.readArmored(encrypted.data);
    const result = await openpgp.decrypt(
      { message: msg,
        privateKeys: secondKey.key,
        publicKeys: [firstKey.key.toPublic()] }
    )
    expect(result.signatures[0].valid).to.be.true;
  });

  tryTests('ECC Worker Tests', omnibus, {
    if: typeof window !== 'undefined' && window.Worker,
    before: async function() {
      await openpgp.initWorker({ path:'../dist/openpgp.worker.js' });
    },
    beforeEach: function() {
      openpgp.config.use_native = true;
    },
    after: function() {
      openpgp.destroyWorker();
    }
  });

  // TODO find test vectors
});
