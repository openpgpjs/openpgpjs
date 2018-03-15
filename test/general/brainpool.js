/* globals tryTests: true */

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;

describe('Brainpool Cryptography', function () {
  // TODO add test vectors encrypted and signed by GnuPG or other implementation

  function omnibus() {
    it('Omnibus BrainpoolP256r1 Test', function () {
      const options = { userIds: {name: "Hi", email: "hi@hel.lo"}, curve: "brainpoolP256r1" };
      return openpgp.generateKey(options).then(function (firstKey) {
        const hi = firstKey.key;
        const pubHi = hi.toPublic();

        const options = { userIds: { name: "Bye", email: "bye@good.bye" }, curve: "brainpoolP256r1" };
        return openpgp.generateKey(options).then(function (secondKey) {
          const bye = secondKey.key;
          const pubBye = bye.toPublic();

          return Promise.all([
            // Signing message
            openpgp.sign(
              { data: 'Hi, this is me, Hi!', privateKeys: hi }
            ).then(signed => {
              const msg = openpgp.cleartext.readArmored(signed.data);
              // Verifying signed message
              return Promise.all([
                openpgp.verify(
                  { message: msg, publicKeys: pubHi }
                ).then(output => expect(output.signatures[0].valid).to.be.true),
                // Verifying detached signature
                openpgp.verify(
                  { message: openpgp.message.fromText('Hi, this is me, Hi!'),
                    publicKeys: pubHi,
                    signature: openpgp.signature.readArmored(signed.data) }
                ).then(output => expect(output.signatures[0].valid).to.be.true)
              ]);
            }),
            // Encrypting and signing
            openpgp.encrypt(
              { data: 'Hi, Hi wrote this but only Bye can read it!',
                publicKeys: [pubBye],
                privateKeys: [hi] }
            ).then(encrypted => {
              const msg = openpgp.message.readArmored(encrypted.data);
              // Decrypting and verifying
              return openpgp.decrypt(
                { message: msg,
                  privateKeys: bye,
                  publicKeys: [pubHi] }
              ).then(output => {
                expect(output.data).to.equal('Hi, Hi wrote this but only Bye can read it!');
                expect(output.signatures[0].valid).to.be.true;
              });
            })
          ]);
        });
      });
    });
  }

  omnibus();

  tryTests('Brainpool Worker Tests', omnibus, {
    if: typeof window !== 'undefined' && window.Worker,
    before: function() {
      openpgp.initWorker({ path:'../dist/openpgp.worker.js' });
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
