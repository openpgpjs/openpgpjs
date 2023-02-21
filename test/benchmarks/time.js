const Benchmark = require('benchmark');
const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');

const wrapAsync = func => ({
  fn: async deferred => {
    await func().catch(onError);
    deferred.resolve();
  },
  defer: true
});

const onError = err => {
  // eslint-disable-next-line no-console
  console.error('The time benchmark tests failed by throwing the following error:');
  // eslint-disable-next-line no-console
  console.error(err);
  // eslint-disable-next-line no-process-exit
  process.exit(1);
};

/**
 * Time benchmark tests.
 * NB: each test will be run multiple times, so any input must be consumable multiple times.
 */
(async () => {
  const suite = new Benchmark.Suite();
  const { armoredKey, privateKey, publicKey, armoredEncryptedMessage, armoredSignedMessage } = await getTestData();

  suite.add('openpgp.readKey', wrapAsync(async () => {
    await openpgp.readKey({ armoredKey });
  }));

  suite.add('openpgp.readMessage', wrapAsync(async () => {
    await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
  }));

  suite.add('openpgp.generateKey', wrapAsync(async () => {
    await openpgp.generateKey({ userIDs: { email: 'test@test.it' } });
  }));

  suite.add('openpgp.encrypt', wrapAsync(async () => {
    const message = await openpgp.createMessage({ text: 'plaintext' });
    await openpgp.encrypt({ message, encryptionKeys: publicKey });
  }));

  suite.add('openpgp.sign', wrapAsync(async () => {
    const message = await openpgp.createMessage({ text: 'plaintext' });
    await openpgp.sign({ message, signingKeys: privateKey });
  }));

  suite.add('openpgp.decrypt', wrapAsync(async () => {
    const message = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    await openpgp.decrypt({ message, decryptionKeys: privateKey });
  }));

  suite.add('openpgp.verify', wrapAsync(async () => {
    const message = await openpgp.readMessage({ armoredMessage: armoredSignedMessage });
    await openpgp.verify({ message, verificationKeys: publicKey, expectSigned: true });
  }));

  suite.on('cycle', event => {
    // Output benchmark result by converting benchmark result to string
    // eslint-disable-next-line no-console
    console.log(String(event.target));
  });

  suite.run({ 'async': true });
})();

async function getTestData() {
  const armoredKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEYS4KIRYJKwYBBAHaRw8BAQdAOl5Ij0p8llEOLqalwRM8+YWKXELm+Zl1
arT2orL/42MAAP9SQBdl+A/i4AtIOr33rn6OKzmXQ2EQH0xoSPJcVxX7BA5U
zRR0ZXN0IDx0ZXN0QHRlc3QuY29tPsKMBBAWCgAdBQJhLgohBAsJBwgDFQgK
BBYAAgECGQECGwMCHgEAIQkQ2RFo4G/cGHQWIQRL9hTrZduw8+42e1rZEWjg
b9wYdEi3AP91NftBKXLfcMRz/g540cQ/0+ax8pvsiqFSb+Sqz87YPwEAkoYK
8I9rVAlVABIhy/g7ZStHu/u0zsPbiquZFKoVLgPHXQRhLgohEgorBgEEAZdV
AQUBAQdAqY5VZYX6axscpfVN3EED83T3WO3+Hzxfq31dXJXKrRkDAQgHAAD/
an6zziN/Aw0ruIxuZTjmkYriDW34hys8F2nRR23PO6gPjsJ4BBgWCAAJBQJh
LgohAhsMACEJENkRaOBv3Bh0FiEES/YU62XbsPPuNnta2RFo4G/cGHQjlgEA
gbOEmauiq2avut4e7pSJ98t50zai2dzNies1OpqTU58BAM1pWI99FxM6thX9
aDa+Qhz0AxhA9P+3eQCXYTZR7CEE
=LPl8
-----END PGP PRIVATE KEY BLOCK-----`;

  const privateKey = await openpgp.readKey({ armoredKey });
  const publicKey = privateKey.toPublic();
  const plaintextMessage = await openpgp.createMessage({ text: 'plaintext' });
  const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, encryptionKeys: publicKey });
  const armoredSignedMessage = await openpgp.sign({ message: await openpgp.createMessage({ text: 'plaintext' }), signingKeys: privateKey });

  return {
    armoredKey,
    privateKey,
    publicKey,
    armoredEncryptedMessage,
    armoredSignedMessage
  };
}
