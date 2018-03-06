/* globals tryTests: true */

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;

describe('Elliptic Curve Cryptography', function () {
  const data = {
    romeo: {
      id: 'c2b12389b401a43d',
      pass: 'juliet',
      pub: [
        '-----BEGIN PGP PUBLIC KEY BLOCK-----',
        'Version: OpenPGP.js 1.3+secp256k1',
        'Comment: http://openpgpjs.org',
        '',
        'xk8EVjET2xMFK4EEAAoCAwS/zT2gefLhEnISXN3rvdV3eD6MVrPwxNMAR+LM',
        'ZzFO1gdtZbf7XQSZP02CYQe3YFrNQYYuJ4CGkTvOVJSV+yrAzS5Sb21lbyBN',
        'b250YWd1ZSAoc2VjcDI1NmsxKSA8cm9tZW9AZXhhbXBsZS5uZXQ+wnIEEBMI',
        'ACQFAlYxE9sFCwkIBwMJEMKxI4m0AaQ9AxUICgMWAgECGwMCHgEAAOjHAQDM',
        'y6EJPFayCgI4ZSmZlSue3xFShj9y6hZTLZqPJquspQD+MMT00a2Cicnbhrd1',
        '8SQUIYRQ//I7oXVoxZN5MA4rmOHOUwRWMRPbEgUrgQQACgIDBLPZgGC257Ra',
        'Z9Bg3ij9OgSoJGwqIu03SfQMTnR2crHkAHqLaUImz/lwhsL/V499zXZ2gEmf',
        'oKCacroXNDM85xUDAQgHwmEEGBMIABMFAlYxE9sJEMKxI4m0AaQ9AhsMAADk',
        'gwEA4B3lysFe/3+KE/PgCSZkUfx7n7xlKqMiqrX+VNyPej8BAMQJgtMVdslQ',
        'HLr5fhoGnRots3JSC0j20UQQOKVOXaW3',
        '=VpL9',
        '-----END PGP PUBLIC KEY BLOCK-----'
      ].join('\n'),
      priv: [
        '-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'Version: OpenPGP.js 1.3+secp256k1',
        'Comment: http://openpgpjs.org',
        '',
        'xaIEVjET2xMFK4EEAAoCAwS/zT2gefLhEnISXN3rvdV3eD6MVrPwxNMAR+LM',
        'ZzFO1gdtZbf7XQSZP02CYQe3YFrNQYYuJ4CGkTvOVJSV+yrA/gkDCILD3FP2',
        'D6eRYNWhI+QTFWAGDw+pIhtXQ/p0zZgK6HSk68Fox0tH6TlGtPmtULkPExs0',
        'cnIdAVSMHI+SnZ9lIeAykAcFoqJYIO5p870XbjzNLlJvbWVvIE1vbnRhZ3Vl',
        'IChzZWNwMjU2azEpIDxyb21lb0BleGFtcGxlLm5ldD7CcgQQEwgAJAUCVjET',
        '2wULCQgHAwkQwrEjibQBpD0DFQgKAxYCAQIbAwIeAQAA6McBAMzLoQk8VrIK',
        'AjhlKZmVK57fEVKGP3LqFlMtmo8mq6ylAP4wxPTRrYKJyduGt3XxJBQhhFD/',
        '8juhdWjFk3kwDiuY4cemBFYxE9sSBSuBBAAKAgMEs9mAYLbntFpn0GDeKP06',
        'BKgkbCoi7TdJ9AxOdHZyseQAeotpQibP+XCGwv9Xj33NdnaASZ+goJpyuhc0',
        'MzznFQMBCAf+CQMIqp5StLTK+lBgqmaJ8/64E+8+OJVOgzk8EoRp8bS9IEac',
        'VYu2i8ARjAF3sqwGZ5hxxsniORcjQUghf+n+NwEm9LUWfbAGUlT4YfSIq5pV',
        'rsJhBBgTCAATBQJWMRPbCRDCsSOJtAGkPQIbDAAA5IMBAOAd5crBXv9/ihPz',
        '4AkmZFH8e5+8ZSqjIqq1/lTcj3o/AQDECYLTFXbJUBy6+X4aBp0aLbNyUgtI',
        '9tFEEDilTl2ltw==',
        '=C3TW',
        '-----END PGP PRIVATE KEY BLOCK-----'
      ].join('\n'),
      message: 'Shall I hear more, or shall I speak at this?'
    },
    juliet: {
      id: '64116021959bdfe0',
      pass: 'romeo',
      pub: [
        '-----BEGIN PGP PUBLIC KEY BLOCK-----',
        'Version: OpenPGP.js 1.3+secp256k1',
        'Comment: http://openpgpjs.org',
        '',
        'xk8EVjEUUBMFK4EEAAoCAwQRNz0sbftAv3SSE0fm7vE0pD96NDA3YtGdObaj',
        'D0DNUMBL1eoLl5/qdJUc/16xbZLkL2saMsbqtPn/iuahz6bkzS9KdWxpZXQg',
        'Q2FwdWxldCAoc2VjcDI1NmsxKSA8anVsaWV0QGV4YW1wbGUubmV0PsJyBBAT',
        'CAAkBQJWMRRRBQsJCAcDCRBkEWAhlZvf4AMVCAoDFgIBAhsDAh4BAAAr1wEA',
        '+39TqKy/tks7dPlEYw+IYkFCW99a60kiSCjLBPxEgNUA/3HeLDP/XbrgklUs',
        'DFOy20aHE7M6i/cFXLLxDJmN6BF3zlMEVjEUUBIFK4EEAAoCAwTQ02rHHP/d',
        'kR4W7y5BY4kRtoNc/HxUloOpxA8svfmxwOoP5stCS/lInD8K+7nSEiPr84z9',
        'EQ47LMjiT1zK2mHZAwEIB8JhBBgTCAATBQJWMRRRCRBkEWAhlZvf4AIbDAAA',
        '7FoA/1Y4xDYO49u21I7aqjPyTygLoObdLMAtK6xht+DDc0YKAQDNp2wv0HOJ',
        '+0kjoUNu6PRIll/jMgTVAXn0Mov6HqJ95A==',
        '=ISmy',
        '-----END PGP PUBLIC KEY BLOCK-----'
      ].join('\n'),
      priv: [
        '-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'Version: OpenPGP.js 1.3+secp256k1',
        'Comment: http://openpgpjs.org',
        '',
        'xaIEVjEUUBMFK4EEAAoCAwQRNz0sbftAv3SSE0fm7vE0pD96NDA3YtGdObaj',
        'D0DNUMBL1eoLl5/qdJUc/16xbZLkL2saMsbqtPn/iuahz6bk/gkDCD9EH0El',
        '7o9qYIbX56Ri3VlfCbpQgy1cVx9RETKI4guW9vUu6SeY2NhXASvfK+zgpLzO',
        'j+hv2a+re549UKBdFbPEcyPUQKo2YJ1AfdAfZcDNL0p1bGlldCBDYXB1bGV0',
        'IChzZWNwMjU2azEpIDxqdWxpZXRAZXhhbXBsZS5uZXQ+wnIEEBMIACQFAlYx',
        'FFEFCwkIBwMJEGQRYCGVm9/gAxUICgMWAgECGwMCHgEAACvXAQD7f1OorL+2',
        'Szt0+URjD4hiQUJb31rrSSJIKMsE/ESA1QD/cd4sM/9duuCSVSwMU7LbRocT',
        'szqL9wVcsvEMmY3oEXfHpgRWMRRQEgUrgQQACgIDBNDTascc/92RHhbvLkFj',
        'iRG2g1z8fFSWg6nEDyy9+bHA6g/my0JL+UicPwr7udISI+vzjP0RDjssyOJP',
        'XMraYdkDAQgH/gkDCA4aIC5h7thWYEM9KvwVEN4/rAYOWVNzUN2K7l25M+NZ',
        '1/mEAjEgEW9yPufKtF3hILeNdPBwh6Gcw/0gOJ/9yJwKk7tqwyS/gKF1+VDm',
        'X0LCYQQYEwgAEwUCVjEUUQkQZBFgIZWb3+ACGwwAAOxaAP9WOMQ2DuPbttSO',
        '2qoz8k8oC6Dm3SzALSusYbfgw3NGCgEAzadsL9BziftJI6FDbuj0SJZf4zIE',
        '1QF59DKL+h6ifeQ=',
        '=QvXN',
        '-----END PGP PRIVATE KEY BLOCK-----'
      ].join('\n'),
      message: 'O Romeo, Romeo! Wherefore art thou Romeo?',
      message_signed: [
        '-----BEGIN PGP SIGNED MESSAGE-----',
        'Hash: SHA256',
        '',
        'O Romeo, Romeo! Wherefore art thou Romeo?',
        '-----BEGIN PGP SIGNATURE-----',
        'Version: GnuPG v2',
        'Comment: GnuPG v2.1+libgcrypt-1.7',
        '',
        'iF4EARMIAAYFAlYxF8oACgkQZBFgIZWb3+BfTwD/b1yKtFnKrRjELuD6/gOH9/er',
        '6yc7nzn1FBYFzMz8aFIA/3FlcIvR+eLvRTVmfiEatB6IU6JviBnzxR1gA/SOdyS2',
        '=GCiR',
        '-----END PGP SIGNATURE-----'
      ].join('\n'),
      message_encrypted: [
        '-----BEGIN PGP MESSAGE-----',
        'Version: GnuPG v2',
        'Comment: GnuPG v2.1+libgcrypt-1.7',
        '',
        'hH4DDYFqRW5CSpsSAgMERfIYgKzriOCHTTQnWhM4VZ6cLjrjJbOaW1VuCfeN03d+',
        'yzhW1Sm1BYYdqxPE0rvjvGfD8VmMB6etaHQsrDQflzA+vGeVa9Mn/wyKq4+j13ur',
        'NOoUhDKX27+LEBNfho6bbEN72J7z3E5/+wVr+wEt3bLSwBcBvuNNkvGCpE19/AmL',
        'GP2lmjE6O9VfiW0o8sxfa+hPEq2A+6DxvMhxi2YPS0f9MMPqn5NFx2PCIGdC0+xY',
        'f0BXl1atBO1z6UXTC9aHH7UULKdynr4nUEkDa3DJW/feCSC6rQxTikn/Gf4341qQ',
        'aiwv66jhgJSdB+2+JrHfh6Znvv2fhl3SQl8K0CiG8Q0QubWdlQwNaNSOmgH7v3T8',
        'j5FhrMbD3Z+TPlrNjJqidAV28XwSBFvhw8Jf5WpaewOxVlxLjUHnnkUGHyvfdEr/',
        'DP/V1yLuBUZuRg==',
        '=GEAB',
        '-----END PGP MESSAGE-----'
      ].join('\n')
    }
  };
  function load_pub_key(name) {
    if (data[name].pub_key) {
      return data[name].pub_key;
    }
    const pub = openpgp.key.readArmored(data[name].pub);
    expect(pub).to.exist;
    expect(pub.err).to.not.exist;
    expect(pub.keys).to.have.length(1);
    expect(pub.keys[0].primaryKey.getKeyId().toHex()).to.equal(data[name].id);
    data[name].pub_key = pub.keys[0];
    return data[name].pub_key;
  }
  async function load_priv_key(name) {
    if (data[name].priv_key) {
      return data[name].priv_key;
    }
    const pk = openpgp.key.readArmored(data[name].priv);
    expect(pk).to.exist;
    expect(pk.err).to.not.exist;
    expect(pk.keys).to.have.length(1);
    expect(pk.keys[0].primaryKey.getKeyId().toHex()).to.equal(data[name].id);
    expect(await pk.keys[0].decrypt(data[name].pass)).to.be.true;
    data[name].priv_key = pk.keys[0];
    return data[name].priv_key;
  }
  it('Load public key', function (done) {
    load_pub_key('romeo');
    load_pub_key('juliet');
    done();
  });
  it('Load private key', async function () {
    await load_priv_key('romeo');
    await load_priv_key('juliet');
    return true;
  });
  it('Verify clear signed message', function () {
    const pub = load_pub_key('juliet');
    const msg = openpgp.cleartext.readArmored(data.juliet.message_signed);
    return openpgp.verify({publicKeys: [pub], message: msg}).then(function(result) {
      expect(result).to.exist;
      expect(result.data.trim()).to.equal(data.juliet.message);
      expect(result.signatures).to.have.length(1);
      expect(result.signatures[0].valid).to.be.true;
    });
  });
  it('Sign message', async function () {
    const romeoPrivate = await load_priv_key('romeo');
    const signed = await openpgp.sign({privateKeys: [romeoPrivate], data: data.romeo.message + "\n"});
    const romeoPublic = load_pub_key('romeo');
    const msg = openpgp.cleartext.readArmored(signed.data);
    const result = await openpgp.verify({publicKeys: [romeoPublic], message: msg});

    expect(result).to.exist;
    expect(result.data.trim()).to.equal(data.romeo.message);
    expect(result.signatures).to.have.length(1);
    expect(result.signatures[0].valid).to.be.true;
  });
  it('Decrypt and verify message', async function () {
    const juliet = load_pub_key('juliet');
    const romeo = await load_priv_key('romeo');
    const msg = openpgp.message.readArmored(data.juliet.message_encrypted);
    const result = await openpgp.decrypt({privateKeys: romeo, publicKeys: [juliet], message: msg});

    expect(result).to.exist;
    // trim required because https://github.com/openpgpjs/openpgpjs/issues/311
    expect(result.data.trim()).to.equal(data.juliet.message);
    expect(result.signatures).to.have.length(1);
    expect(result.signatures[0].valid).to.be.true;
  });
  it('Encrypt and sign message', async function () {
    const romeoPrivate = await load_priv_key('romeo');
    const julietPublic = load_pub_key('juliet');
    const encrypted = await openpgp.encrypt({publicKeys: [julietPublic], privateKeys: [romeoPrivate], data: data.romeo.message + "\n"});

    const message = openpgp.message.readArmored(encrypted.data);
    const romeoPublic = load_pub_key('romeo');
    const julietPrivate = await load_priv_key('juliet');
    const result = await openpgp.decrypt({privateKeys: julietPrivate, publicKeys: [romeoPublic], message: message});

    expect(result).to.exist;
    expect(result.data.trim()).to.equal(data.romeo.message);
    expect(result.signatures).to.have.length(1);
    expect(result.signatures[0].valid).to.be.true;
  });
  it('Generate key', function () {
    const options = {
      userIds: {name: "Hamlet (secp256k1)", email: "hamlet@example.net"},
      curve: "secp256k1",
      passphrase: "ophelia"
    };
    return openpgp.generateKey(options).then(function (key) {
      expect(key).to.exist;
      expect(key.key).to.exist;
      expect(key.key.primaryKey).to.exist;
      expect(key.privateKeyArmored).to.exist;
      expect(key.publicKeyArmored).to.exist;
    });
  });

  function omnibus() {
    it('Omnibus NIST P-256 Test', function () {
      const options = { userIds: {name: "Hi", email: "hi@hel.lo"}, curve: "p256" };
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

  tryTests('ECC Worker Tests', omnibus, {
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
