/* globals tryTests: true */
const { use: chaiUse, expect } = require('chai');
chaiUse(require('chai-as-promised'));

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');
const util = require('../../src/util');

const input = require('./testInputs');


module.exports = () => (openpgp.config.ci ? describe.skip : describe)('Brainpool Cryptography @lightweight', function () {
  let rejectCurvesVal;
  before(function() {
    //only x25519 crypto is fully functional in lightbuild
    if (!openpgp.config.useIndutnyElliptic && !util.getNodeCrypto()) {
      this.skip(); // eslint-disable-line no-invalid-this
    }
  });

  beforeEach(function () {
    rejectCurvesVal = openpgp.config.rejectCurves;
    openpgp.config.rejectCurves = new Set();
  });

  afterEach(function () {
    openpgp.config.rejectCurves = rejectCurvesVal;
  });

  const data = {
    romeo: {
      id: 'fa3d64c9bcf338bc',
      pass: '321',
      pub: [
        '-----BEGIN PGP PUBLIC KEY BLOCK-----',
        '',
        'mHMEWq8ruRMJKyQDAwIIAQELAwMEhi/66JLo1vMhpytb1bYvBhd/aKHde2Zwke7r',
        'zWFTYBZQl/DUrpMrVAhkQhk5G3kqFWf98O/DpvVmY6EDr3IjmODWowNvGfC4Avc9',
        'rYRgV8GbMBUVLIS+ytS1YNpAKW4vtBlidW5ueSA8YnVubnlAYnVubnkuYnVubnk+',
        'iLAEExMKADgWIQSLliWLcmzBLxv2/X36PWTJvPM4vAUCWq8ruQIbAwULCQgHAwUV',
        'CgkICwUWAgMBAAIeAQIXgAAKCRD6PWTJvPM4vIcVAYCIO41QylZkb9W4FP+kd3bz',
        'b73xxwojWpCiw1bWV9Xe/dKA23DtCYhlmhF/Twjh9lkBfihHXs/negGMnqbA8TQF',
        'U1IvBflDcA7yj677lgLkze/yd5hg/ZVx7M8XyUzcEm9xi7h3BFqvK7kSCSskAwMC',
        'CAEBCwMDBCkGskA01sBvG/B1bl0EN+yxF6xPn74WQoAMm7K4n1PlZ1u8RWg+BJVG',
        'Kna/88ZGcT5BZSUvRrYWgqb4/SPAPea5C1p6UYd+C0C0dVf0FaGv5z0gCtc/+kwF',
        '3sLGLZh3rAMBCQmImAQYEwoAIBYhBIuWJYtybMEvG/b9ffo9ZMm88zi8BQJaryu5',
        'AhsMAAoJEPo9ZMm88zi8w1QBfR4k1d5ElME3ef7viE+Mud4qGv1ra56pKa86hS9+',
        'l262twTxe1hk08/FySeJW08P3wF/WrhCrE9UDD6FQiZk1lqekhd9bf84v6i5Smbi',
        'oml1QWkiI6BtbLD39Su6zQKR7u+Y',
        '=wB7z',
        '-----END PGP PUBLIC KEY BLOCK-----'
      ].join('\n'),
      priv: [
        '-----BEGIN PGP PRIVATE KEY BLOCK-----',
        '',
        'lNYEWq8ruRMJKyQDAwIIAQELAwMEhi/66JLo1vMhpytb1bYvBhd/aKHde2Zwke7r',
        'zWFTYBZQl/DUrpMrVAhkQhk5G3kqFWf98O/DpvVmY6EDr3IjmODWowNvGfC4Avc9',
        'rYRgV8GbMBUVLIS+ytS1YNpAKW4v/gcDAtyjmSfDquSq5ffphtkwJ56Zz5jc+jSm',
        'yZaPgmnPOwcgYhWy1g7BcBKYFPNKZlajnV4Rut2VUWkELwWrRmchX4ENJoAKZob0',
        'l/zjgOPug3FtEGirOPmvi7nOkjDEFNJwtBlidW5ueSA8YnVubnlAYnVubnkuYnVu',
        'bnk+iLAEExMKADgWIQSLliWLcmzBLxv2/X36PWTJvPM4vAUCWq8ruQIbAwULCQgH',
        'AwUVCgkICwUWAgMBAAIeAQIXgAAKCRD6PWTJvPM4vIcVAYCIO41QylZkb9W4FP+k',
        'd3bzb73xxwojWpCiw1bWV9Xe/dKA23DtCYhlmhF/Twjh9lkBfihHXs/negGMnqbA',
        '8TQFU1IvBflDcA7yj677lgLkze/yd5hg/ZVx7M8XyUzcEm9xi5zaBFqvK7kSCSsk',
        'AwMCCAEBCwMDBCkGskA01sBvG/B1bl0EN+yxF6xPn74WQoAMm7K4n1PlZ1u8RWg+',
        'BJVGKna/88ZGcT5BZSUvRrYWgqb4/SPAPea5C1p6UYd+C0C0dVf0FaGv5z0gCtc/',
        '+kwF3sLGLZh3rAMBCQn+BwMC6RvzFHWyKqPlVqrm6+j797Y9vHdZW1zixtmEK0Wg',
        'lvQRpZF8AbpSzk/XolsoeQyic1e18C6ubFZFw7cI7ekINiRu/OXOvBnTbc5TdbDi',
        'kKTuOkL+lEwWrUTEwdshbJ+ImAQYEwoAIBYhBIuWJYtybMEvG/b9ffo9ZMm88zi8',
        'BQJaryu5AhsMAAoJEPo9ZMm88zi8w1QBfR4k1d5ElME3ef7viE+Mud4qGv1ra56p',
        'Ka86hS9+l262twTxe1hk08/FySeJW08P3wF/WrhCrE9UDD6FQiZk1lqekhd9bf84',
        'v6i5Smbioml1QWkiI6BtbLD39Su6zQKR7u+Y',
        '=uGZP',
        '-----END PGP PRIVATE KEY BLOCK-----'
      ].join('\n'),
      message: 'test message\n',
      message_encrypted: [
        '-----BEGIN PGP MESSAGE-----',
        '',
        'hJ4Dry/W2EFbOT4SAwMEiTrIh02fyvPytwIsd9iGDYPFlvFSQmIvz4YW08mKfWrl',
        's4fEAQQBoBPL5k2sZa/sFfapQyyJHhLpv4FyHGY+7zagsv7B47RLbc4jGJhWFJyf',
        'DvCFqJCLH/T9p9nb5qHRMHdSZbXipTymcm9AJvCymKpLQLQFqL7lejjW0lSrVaas',
        'WhCVgYgmoOtgjipYlaGc9NLACAEzHA2B4T5PpTlfQOsp3KkKNkByughSyaRbgppw',
        'M9xxM+Fy0fSvWozKdvn7C2EFMuDbcTRSp2yb8k+ICyGuXvVN2ahASzdtkn+S6+GW',
        'OQUOpu+VxbOf8zICR0FwLkHjIOE6/eUrGX+QIqlej/OTtqBoik2OAbNuqLlFQXsC',
        'Cfp08rB83eU9UIpMgx3hq6tuad7m8Qa8e+/9eLe+Oc67rhWqWcDIKXExmqpMX9Qv',
        'tZa9Z9Eq1OfX2n8kR7BnPnWn9qlhg/63sgNT',
        '=lNCW',
        '-----END PGP MESSAGE-----'
      ].join('\n'),
      message_with_leading_zero_in_hash: 'test message\n277',
      message_encrypted_with_leading_zero_in_hash:
`-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.5.5
Comment: https://openpgpjs.org

wX4DSpmSuiUYN4MSAgMERlxfWMZgb9Xdu9v5mYq1TP2QZO9lLloIIO45tn/W
3Eg5DbJfGiBvR7QUXbFY1KiILiXXYxEm1x8i0qw793NlizAdHSiZmifeBJXX
4sV1NDOaIUXVs6Aes7rhV7G3jADlDVu2N50Ti+MdGHz8rWqYt1zSwBgBo4ag
i7YemCOYIHqpa+R6lId0+BOXKUFZYCTH8J7QSZYYkH06DFvt1LOPXJHuJrX9
E++ph0fvdrZVm9kpOFv3fnn/EeDOL4chvemC0dawTLhs0rg+bin9xhGjzpl+
tbIxp3v4WG6xt9fkNwDSVC7yYMj+LeYcF+ZG1Bw5pCdMoBnJtqKLAJbqP3Ph
TRELeagBcoQblRDF03XxrjpeCbLqZFwpFQqac9T2eqDRtvi2DA+JYCJdJorO
KnthADE6hYMCSZVS9Q1IGN3TjROB5rrB/N3xItPsXuc=
=A7qX
-----END PGP MESSAGE-----`,
      message_encrypted_with_leading_zero_in_hash_signed_by_elliptic_with_old_implementation:
`-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.6.0
Comment: https://openpgpjs.org

wX4DSpmSuiUYN4MSAgMEdWwp5tYcxcyj3G36EkQ61Xx/gVzYbgh7U54sDsl9
NKyc9gqjtEn5OQzXJ7Uteb+ojZsRy4b5cWBNQPdXJci0kTC+s98RugN7vEHe
ulmNfwICTJ7SA4OSb0WEeACG6B1yUZmwWDcPxUfotFL3BCZGxN7SwBgBm2bQ
wzRBU3SZ8xtqSCwC50PhXXmtqlDmQqJ84oTsyikH8e6zEgI78QXTf1WK530K
0W/r+OqQufWu5ZKXK9AyeDyLc577P6/CnDcjjoJOsOZm5XMcSXlJWAvsH7KJ
X/ua3tHArWaOmBYTtbfeZc3NpI5ne/gin3Gsz0llbWKG2KF4Op2/nt+Vhqa9
tkYrARUF5n9K9+TEasU4z1k898YkS5cIzFyBSGMhGDzdj7t1K93EyOxXPc84
EJ4QcD/oQ6x1M/8X/iKQCtxZP8RnlrbH7ExkNON5s5g=
=KDoL
-----END PGP MESSAGE-----`,
      message_with_leading_zero_in_hash_old_elliptic_implementation: 'test message\n199'
    },
    juliet: {
      id: '37e16a986b8af99e',
      pass: '123',
      pub: [
        '-----BEGIN PGP PUBLIC KEY BLOCK-----',
        '',
        'mFMEWq7fNxMJKyQDAwIIAQEHAgMESvoep0lgc4/HqO0snFMMlVM3Pv19ljC+Ko1k',
        'MkCmJygQTpfxaEBvVm3ChJmkfgWOcgxa5BJUnCg/JaMKkJmr3rQZc3VubnkgPHN1',
        'bm55QHN1bm55LnN1bm55PoiQBBMTCgA4FiEEItRnV1URxiv5gJu+N+FqmGuK+Z4F',
        'Alqu3zcCGwMFCwkIBwMFFQoJCAsFFgIDAQACHgECF4AACgkQN+FqmGuK+Z511QD+',
        'KZLNqlkXkGcoopGdeS9O4oS0mxhAzi++p9btkTZSE24BAJvgM4aR/mwrQB4/5O2f',
        'uA+wEc4vF69fbPIWM/VltNDPuFcEWq7fNxIJKyQDAwIIAQEHAgMEPC4wYIRcxwz8',
        'FVZxihCex/kU/n7n8iP91ZeAXMqx68c0oTwwYweZgf2QPSqwDea6YIcIrCfbHHeE',
        'vtzzyrZllgMBCAeIeAQYEwoAIBYhBCLUZ1dVEcYr+YCbvjfhaphrivmeBQJart83',
        'AhsMAAoJEDfhaphrivmenswBAKm7hI2qGtOZ5kTkOmRELJq76enPSQtdrvtbR5dv',
        'ziZiAP9mU1Kajp2PVmj3IPpd+Q+F/2U8H7nrRndo97c2vPqFtQ==',
        '=SwMu',
        '-----END PGP PUBLIC KEY BLOCK-----'
      ].join('\n'),
      priv: [
        '-----BEGIN PGP PRIVATE KEY BLOCK-----',
        '',
        'lKYEWq7fNxMJKyQDAwIIAQEHAgMESvoep0lgc4/HqO0snFMMlVM3Pv19ljC+Ko1k',
        'MkCmJygQTpfxaEBvVm3ChJmkfgWOcgxa5BJUnCg/JaMKkJmr3v4HAwK7JkccdLrR',
        'Q+UXlwIhInNv95GHFscWoWYaCXMYtyaRleKvGGpKpQjZFvZ6SZncMs/EPQfJwl2L',
        'I2lf8IdzqltNni5shQztIdBiIKm63+TjtBlzdW5ueSA8c3VubnlAc3Vubnkuc3Vu',
        'bnk+iJAEExMKADgWIQQi1GdXVRHGK/mAm7434WqYa4r5ngUCWq7fNwIbAwULCQgH',
        'AwUVCgkICwUWAgMBAAIeAQIXgAAKCRA34WqYa4r5nnXVAP4pks2qWReQZyiikZ15',
        'L07ihLSbGEDOL76n1u2RNlITbgEAm+AzhpH+bCtAHj/k7Z+4D7ARzi8Xr19s8hYz',
        '9WW00M+cqgRart83EgkrJAMDAggBAQcCAwQ8LjBghFzHDPwVVnGKEJ7H+RT+fufy',
        'I/3Vl4BcyrHrxzShPDBjB5mB/ZA9KrAN5rpghwisJ9scd4S+3PPKtmWWAwEIB/4H',
        'AwItYz56B2wwNeUvvrvksyKNTg6doelQWbzUeASV0Qg1IvZqFy20aU6E5B3z1VCt',
        'wyD4GjZjlWsp/gVVk8ZvgBx6z0T/m5a9asD0xkc49iM7iHgEGBMKACAWIQQi1GdX',
        'VRHGK/mAm7434WqYa4r5ngUCWq7fNwIbDAAKCRA34WqYa4r5np7MAQCpu4SNqhrT',
        'meZE5DpkRCyau+npz0kLXa77W0eXb84mYgD/ZlNSmo6dj1Zo9yD6XfkPhf9lPB+5',
        '60Z3aPe3Nrz6hbU=',
        '=3Dct',
        '-----END PGP PRIVATE KEY BLOCK-----'
      ].join('\n'),
      message: 'second test message\n',
      message_signed: [
        '-----BEGIN PGP SIGNED MESSAGE-----',
        'Hash: SHA512',
        '',
        'second test message',
        '',
        '-----BEGIN PGP SIGNATURE-----',
        'Version: OpenPGP.js v3.1.0',
        'Comment: https://openpgpjs.org',
        '',
        'wl4EARMKABAFAltbE34JEDfhaphrivmeAABaXQD+LzOhFxTqz8+IcaD3xzww',
        'EjEn0u7qgCFem9PHPD4wqAcA/1WQE3N7DIwRG45HFd+ZBo4vcuRkWK+Q6CHl',
        'upbAEX7k',
        '=obwy',
        '-----END PGP SIGNATURE-----'
      ].join('\n')

    }
  };
  async function load_pub_key(name) {
    if (data[name].pub_key) {
      return data[name].pub_key;
    }
    const pub = await openpgp.readKey({ armoredKey: data[name].pub });
    expect(pub.getKeyID().toHex()).to.equal(data[name].id);
    data[name].pub_key = pub;
    return pub;
  }
  async function load_priv_key(name) {
    if (data[name].priv_key) {
      return data[name].priv_key;
    }
    const pk = await openpgp.decryptKey({
      privateKey: await openpgp.readKey({ armoredKey: data[name].priv }),
      passphrase: data[name].pass
    });
    expect(pk).to.exist;
    expect(pk.getKeyID().toHex()).to.equal(data[name].id);
    data[name].priv_key = pk;
    return pk;
  }
  it('Load public key', async function () {
    await load_pub_key('romeo');
    await load_pub_key('juliet');
  });
  it('Load private key', async function () {
    await load_priv_key('romeo');
    await load_priv_key('juliet');
    return true;
  });
  it('Verify clear signed message', async function () {
    const pub = await load_pub_key('juliet');
    const msg = await openpgp.readCleartextMessage({ cleartextMessage: data.juliet.message_signed });
    return openpgp.verify({ verificationKeys: [pub], message: msg }).then(async function(result) {
      expect(result).to.exist;
      expect(result.data).to.equal(data.juliet.message);
      expect(result.signatures).to.have.length(1);
      expect(await result.signatures[0].verified).to.be.true;
    });
  });
  it('Sign message', async function () {
    const romeoPrivate = await load_priv_key('romeo');
    const signed = await openpgp.sign({ signingKeys: [romeoPrivate], message: await openpgp.createCleartextMessage({ text: data.romeo.message }) });
    const romeoPublic = await load_pub_key('romeo');
    const msg = await openpgp.readCleartextMessage({ cleartextMessage: signed });
    const result = await openpgp.verify({ verificationKeys: [romeoPublic], message: msg });

    expect(result).to.exist;
    expect(result.data).to.equal(data.romeo.message);
    expect(result.signatures).to.have.length(1);
    expect(await result.signatures[0].verified).to.be.true;
  });
  it('Decrypt and verify message', async function () {
    const juliet = await load_pub_key('juliet');
    const romeo = await load_priv_key('romeo');
    const msg = await openpgp.readMessage({ armoredMessage: data.romeo.message_encrypted });
    const result = await openpgp.decrypt({ decryptionKeys: romeo, verificationKeys: [juliet], message: msg });

    expect(result).to.exist;
    expect(result.data).to.equal(data.romeo.message);
    expect(result.signatures).to.have.length(1);
    expect(await result.signatures[0].verified).to.be.true;
  });
  it('Decrypt and verify message with leading zero in hash', async function () {
    const juliet = await load_priv_key('juliet');
    const romeo = await load_pub_key('romeo');
    const msg = await openpgp.readMessage({ armoredMessage: data.romeo.message_encrypted_with_leading_zero_in_hash });
    const result = await openpgp.decrypt({ decryptionKeys: juliet, verificationKeys: [romeo], message: msg });

    expect(result).to.exist;
    expect(result.data).to.equal(data.romeo.message_with_leading_zero_in_hash);
    expect(result.signatures).to.have.length(1);
    expect(await result.signatures[0].verified).to.be.true;
  });
  it('Decrypt and verify message with leading zero in hash signed with old elliptic algorithm', async function () {
    //this test would not work with nodeCrypto, since message is signed with leading zero stripped from the hash
    if (util.getNodeCrypto()) {
      this.skip(); // eslint-disable-line no-invalid-this
    }
    const juliet = await load_priv_key('juliet');
    const romeo = await load_pub_key('romeo');
    const msg = await openpgp.readMessage({ armoredMessage: data.romeo.message_encrypted_with_leading_zero_in_hash_signed_by_elliptic_with_old_implementation });
    const result = await openpgp.decrypt({ decryptionKeys: juliet, verificationKeys: [romeo], message: msg });
    expect(result).to.exist;
    expect(result.data).to.equal(data.romeo.message_with_leading_zero_in_hash_old_elliptic_implementation);
    expect(result.signatures).to.have.length(1);
    expect(await result.signatures[0].verified).to.be.true;
  });

  it('Encrypt and sign message', async function () {
    const romeoPrivate = await load_priv_key('romeo');
    const julietPublic = await load_pub_key('juliet');
    const encrypted = await openpgp.encrypt({ encryptionKeys: [julietPublic], signingKeys: [romeoPrivate], message: await openpgp.createMessage({ text: data.romeo.message }) });

    const message = await openpgp.readMessage({ armoredMessage: encrypted });
    const romeoPublic = await load_pub_key('romeo');
    const julietPrivate = await load_priv_key('juliet');
    const result = await openpgp.decrypt({ decryptionKeys: julietPrivate, verificationKeys: [romeoPublic], message: message });

    expect(result).to.exist;
    expect(result.data).to.equal(data.romeo.message);
    expect(result.signatures).to.have.length(1);
    expect(await result.signatures[0].verified).to.be.true;
  });

  tryTests('Brainpool Omnibus Tests @lightweight', omnibus, {
    if: openpgp.config.useIndutnyElliptic || util.getNodeCrypto()
  });
});

function omnibus() {
  it('Omnibus BrainpoolP256r1 Test', async function() {
    const { rejectCurves } = openpgp.config;
    openpgp.config.rejectCurves = new Set();

    try {
      const testData = input.createSomeMessage();
      const testData2 = input.createSomeMessage();

      const { privateKey: hi, publicKey: pubHi } = await openpgp.generateKey({ userIDs: { name: 'Hi', email: 'hi@hel.lo' }, curve: 'brainpoolP256r1', format: 'object' });
      const { privateKey: bye, publicKey: pubBye } = await openpgp.generateKey({ userIDs: { name: 'Bye', email: 'bye@good.bye' }, curve: 'brainpoolP256r1', format: 'object' });

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
    } finally {
      openpgp.config.rejectCurves = rejectCurves;
    }
  });
}

// TODO find test vectors
