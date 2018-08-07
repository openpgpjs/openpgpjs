/* globals tryTests: true */

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const spy = require('sinon/lib/sinon/spy');
const stub = require('sinon/lib/sinon/stub');
const input = require('./testInputs.js');
const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;

const pub_key =
  ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
  'Version: GnuPG v2.0.19 (GNU/Linux)',
  '',
  'mI0EUmEvTgEEANyWtQQMOybQ9JltDqmaX0WnNPJeLILIM36sw6zL0nfTQ5zXSS3+',
  'fIF6P29lJFxpblWk02PSID5zX/DYU9/zjM2xPO8Oa4xo0cVTOTLj++Ri5mtr//f5',
  'GLsIXxFrBJhD/ghFsL3Op0GXOeLJ9A5bsOn8th7x6JucNKuaRB6bQbSPABEBAAG0',
  'JFRlc3QgTWNUZXN0aW5ndG9uIDx0ZXN0QGV4YW1wbGUuY29tPoi5BBMBAgAjBQJS',
  'YS9OAhsvBwsJCAcDAgEGFQgCCQoLBBYCAwECHgECF4AACgkQSmNhOk1uQJQwDAP6',
  'AgrTyqkRlJVqz2pb46TfbDM2TDF7o9CBnBzIGoxBhlRwpqALz7z2kxBDmwpQa+ki',
  'Bq3jZN/UosY9y8bhwMAlnrDY9jP1gdCo+H0sD48CdXybblNwaYpwqC8VSpDdTndf',
  '9j2wE/weihGp/DAdy/2kyBCaiOY1sjhUfJ1GogF49rC4jQRSYS9OAQQA6R/PtBFa',
  'JaT4jq10yqASk4sqwVMsc6HcifM5lSdxzExFP74naUMMyEsKHP53QxTF0Grqusag',
  'Qg/ZtgT0CN1HUM152y7ACOdp1giKjpMzOTQClqCoclyvWOFB+L/SwGEIJf7LSCEr',
  'woBuJifJc8xAVr0XX0JthoW+uP91eTQ3XpsAEQEAAYkBPQQYAQIACQUCUmEvTgIb',
  'LgCoCRBKY2E6TW5AlJ0gBBkBAgAGBQJSYS9OAAoJEOCE90RsICyXuqIEANmmiRCA',
  'SF7YK7PvFkieJNwzeK0V3F2lGX+uu6Y3Q/Zxdtwc4xR+me/CSBmsURyXTO29OWhP',
  'GLszPH9zSJU9BdDi6v0yNprmFPX/1Ng0Abn/sCkwetvjxC1YIvTLFwtUL/7v6NS2',
  'bZpsUxRTg9+cSrMWWSNjiY9qUKajm1tuzPDZXAUEAMNmAN3xXN/Kjyvj2OK2ck0X',
  'W748sl/tc3qiKPMJ+0AkMF7Pjhmh9nxqE9+QCEl7qinFqqBLjuzgUhBU4QlwX1GD',
  'AtNTq6ihLMD5v1d82ZC7tNatdlDMGWnIdvEMCv2GZcuIqDQ9rXWs49e7tq1NncLY',
  'hz3tYjKhoFTKEIq3y3Pp',
  '=h/aX',
  '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

const priv_key =
  ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
  'Version: GnuPG v2.0.19 (GNU/Linux)',
  '',
  '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',
  '=lw5e',
  '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

const pub_key_de =
  ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
  'Version: GnuPG v2.0.22 (GNU/Linux)',
  '',
  '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',
  'og2umGfGng==',
  '=v3+L',
  '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

const priv_key_de =
  ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
  'Version: GnuPG v2.0.22 (GNU/Linux)',
  '',
  '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',
  'DHTORVqAOdoOcu5Qh7AQg1GdSmfFAsx2',
  '=kyeP',
  '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

const priv_key_2000_2008 = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
t/ia1kMpSEiOVLlX5dfHZzhR3WNtBqU=
=C0fJ
-----END PGP PRIVATE KEY BLOCK-----`;

const priv_key_2038_2045 = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xcA8BX/oGU8BAAAARwIAjNgDw0CUQpDCNWOKR8Z6pUrEH/cdJV5U9jtSAC0L
2OfS+55nlOBlR5hQXXSb9G2anvw+i1QoftPEO08gAp9JpwARAQABAAH/Ypa3
E475+RqBh4O1AQcTRO7wGHwPH+BHUtE1VkAyAdNCE9Sk+XNIK4S6uzh6gscJ
tUwFXlk/rLV9PVAb+WgYUQEAzspBgGUzFx3wSUr31mveTE/iqDznilXam2m5
8TPwY68BAK5cSH26R/Ny+66F43UsrP2l9ckHqszEg6ueTA5QxF+JAP9dwWRa
wi9iVbBTE7zmxODSsswQZQaz0CuUteVTkHff/lNizQR0ZXN0wpIEEAEIAEYF
An/oGU8GCwkHCAMCBBUICgIDFgIBAhkBAhsDAh4HIiEFZ4vbFQK+dhO4Mq0r
CJObHi9GdWx8bzLuYsuBHQd/JUIDIgECAADJPQH9E2r1AXtohOdf3VMzA2/g
zJZIUGKvu4ccWjX2Wh8bhKepJNpf/AmSplhRar+thOMu8KpiUwZ9uvI0RckN
3d6x5sfAPAV/6BlPAQAAAEcCAINWcLsIVu4+m7VW4xj7x4xIg8SASq6QJB0G
ru/EzMJfoJCp/UnfSR/sWwtS/RdtRY1nBTSHnjaUd41zR8n00TMAEQEAAQAB
/2h2tZ2eKX7AH5th66nwgayr9Nqz7DLihUbtDPG7B95Fg3ARDNneVhqXU9W3
l2GqicBX2bKpvezQFcndKWNgwqkBAOitvd8/iG3UO8F5wNAvSaKES5QSEPG3
+tsaxWirLqCFAQCQgGiVj9JTh3XkBTrU0gKgnrIg49IPrlIr66s6aOB0VwD/
WiU+vwxv4q+/5Qlk5TjQN7O/c1fqBsSEshbH4D5IPUBYIsJ4BBgBCAAsBQJ/
6BlPAhsMIiEFZ4vbFQK+dhO4Mq0rCJObHi9GdWx8bzLuYsuBHQd/JUIAABQp
Af9CHMI05KPuo8unLj7RpB00In8vfIp3MdckIBLRwEhY3UcXQWYt09IyKYo3
l3kACyh930t1glZPPiJ8n6rOAiN2
=GIk2
-----END PGP PRIVATE KEY BLOCK-----`;

const priv_key_expires_1337 = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xcA4BAAAAAEBAgCgONc0J8rfO6cJw5YTP38x1ze2tAYIO7EcmRCNYwMkXngb
0Qdzg34Q5RW0rNiR56VB6KElPUhePRPVklLFiIvHABEBAAEAAf9qabYMzsz/
/LeRVZSsTgTljmJTdzd2ambUbpi+vt8MXJsbaWh71vjoLMWSXajaKSPDjVU5
waFNt9kLqwGGGLqpAQD5ZdMH2XzTq6GU9Ka69iZs6Pbnzwdz59Vc3i8hXlUj
zQEApHargCTsrtvSrm+hK/pN51/BHAy9lxCAw9f2etx+AeMA/RGrijkFZtYt
jeWdv/usXL3mgHvEcJv63N5zcEvDX5X4W1bND3Rlc3QxIDxhQGIuY29tPsJ7
BBABCAAvBQIAAAABBQMAAAU5BgsJBwgDAgkQzcF99nGrkAkEFQgKAgMWAgEC
GQECGwMCHgEAABAlAfwPehmLZs+gOhOTTaSslqQ50bl/REjmv42Nyr1ZBlQS
DECl1Qu4QyeXin29uEXWiekMpNlZVsEuc8icCw6ABhIZ
=/7PI
-----END PGP PRIVATE KEY BLOCK-----`;

const priv_key_1337 = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVwFAAAAARYAAAAtCSsGAQQB2kcPAQEHQPoOlWx63Q0X/8Fnp/9hBdabLpT9
NU3VFclbtTA0OQeHAAD/TCg3IheFtfDnOyw5bNmqI0fxEh4MT0OSQCpjV7SN
5QMNi80EdGVzdMKUBBAWCgBGBQIAAAABBgsJBwgDAgQVCAoCAxYCAQIZAQIb
AwIeByIhBcSXQKFZWrh2tt8Xmfk1a7IKz2lL1qkhzblQWVP22KPaAyIBAgAA
XsMA/2HhxX9PUSVaYGOUM6ERE5K+KOIDiQ+7AhkRRpNqcmuAAQC8E9AU/1zB
uHhbdYWrzNW7YhvpnyIfiH9ryV7I5A2bAsdhBQAAAAESAAAAMgorBgEEAZdV
AQUBAQdAnoXNRWAAuRNxbnMthP5WAbjhSE72mEKX0dXajdnMjnYDAQgHAAD/
UEMFmvyW0mXQ7vCAzGjIjs5QAX9yLsnuFzPO1RmDlNASlMJ6BBgWCgAsBQIA
AAABAhsMIiEFxJdAoVlauHa23xeZ+TVrsgrPaUvWqSHNuVBZU/bYo9oAAGC/
AQC62tIndYzEFSN9NcPIFF8kxO7O4HY+OONrC4f3N/L5tAD8CCPD0w5FpC2Y
whhOh8SVcRCaUR8ghroLD7yEOlKKfQo=
=tiJt
-----END PGP PRIVATE KEY BLOCK-----`;

const passphrase = 'hello world';
const plaintext = input.createSomeMessage();
const password1 = 'I am a password';
const password2 = 'I am another password';
const password3 = 'I am a third password';

const twoPasswordGPGFail = ['-----BEGIN PGP MESSAGE-----',
'Version: OpenPGP.js v3.0.0',
'Comment: https://openpgpjs.org',
'',
'wy4ECQMIWjj3WEfWxGpgrfb3vXu0TS9L8UNTBvNZFIjltGjMVkLFD+/afgs5',
'aXt0wy4ECQMIrFo3TFN5xqtgtB+AaAjBcWJrA4bvIPBpJ38PbMWeF0JQgrqg',
'j3uehxXy0mUB5i7B61g0ho+YplyFGM0s9XayJCnu40tWmr5LqqsRxuwrhJKR',
'migslOF/l6Y9F0F9xGIZWGhxp3ugQPjVKjj8fOH7ap14mLm60C8q8AOxiSmL',
'ubsd/hL7FPZatUYAAZVA0a6hmQ==',
'=cHCV',
'-----END PGP MESSAGE-----'].join('\n');

function withCompression(tests) {
  const compressionTypes = Object.keys(openpgp.enums.compression).map(k => openpgp.enums.compression[k]);

  compressionTypes.forEach(function (compression) {
    const compressionName = openpgp.enums.read(openpgp.enums.compression, compression);
    const group = `compression - ${compressionName}`;

    describe(group, function() {
      let compressSpy;
      let decompressSpy;

      beforeEach(function () {
        compressSpy = spy(openpgp.packet.Compressed.prototype, 'compress');
        decompressSpy = spy(openpgp.packet.Compressed.prototype, 'decompress');
      });

      afterEach(function () {
        compressSpy.restore();
        decompressSpy.restore();
      });

      tests(
        function(options) {
          options.compression = compression;
          return options;
        },
        function() {
          // Disable the call expectations when using the web worker because it's not possible to spy on what functions get called.
          if (openpgp.getWorker()) {
            return;
          }

          if (compression === openpgp.enums.compression.uncompressed) {
            expect(compressSpy.called).to.be.false;
            expect(decompressSpy.called).to.be.false;
            return;
          }

          expect(compressSpy.called).to.be.true;
          expect(compressSpy.thisValues[0].algorithm).to.equal(compressionName);
          expect(decompressSpy.called).to.be.true;
          expect(decompressSpy.thisValues[0].algorithm).to.equal(compressionName);
        }
      );
    });
  });
}

describe('OpenPGP.js public api tests', function() {

  describe('initWorker, getWorker, destroyWorker - unit tests', function() {
    afterEach(function() {
      openpgp.destroyWorker(); // cleanup worker in case of failure
    });

    it('should work', function() {
      const workerStub = {
        postMessage: function() {}
      };
      openpgp.initWorker({
        workers: [workerStub]
      });
      expect(openpgp.getWorker()).to.exist;
      openpgp.destroyWorker();
      expect(openpgp.getWorker()).to.not.exist;
    });
  });

  describe('generateKey - validate user ids', function() {
    let rsaGenStub;
    let rsaGenValue = openpgp.crypto.publicKey.rsa.generate(2048, "10001");

    beforeEach(function() {
      rsaGenStub = stub(openpgp.crypto.publicKey.rsa, 'generate');
      rsaGenStub.returns(rsaGenValue);
    });

    afterEach(function() {
      rsaGenStub.restore();
    });

    it('should fail for invalid user name', async function() {
      const opt = {
        userIds: [{ name: {}, email: 'text@example.com' }]
      };
      const test = openpgp.generateKey(opt);
      await expect(test).to.eventually.be.rejectedWith(/Invalid user id format/);
    });

    it('should fail for invalid user email address', async function() {
      const opt = {
        userIds: [{ name: 'Test User', email: 'textexample.com' }]
      };
      const test = openpgp.generateKey(opt);
      await expect(test).to.eventually.be.rejectedWith(/Invalid user id format/);
    });

    it('should fail for invalid user email address', async function() {
      const opt = {
        userIds: [{ name: 'Test User', email: 'text@examplecom' }]
      };
      const test = openpgp.generateKey(opt);
      await expect(test).to.eventually.be.rejectedWith(/Invalid user id format/);
    });

    it('should fail for invalid string user id', async function() {
      const opt = {
        userIds: ['Test User text@example.com>']
      };
      const test = openpgp.generateKey(opt);
      await expect(test).to.eventually.be.rejectedWith(/Invalid user id format/);
    });

    it('should fail for invalid single string user id', async function() {
      const opt = {
        userIds: 'Test User text@example.com>'
      };
      const test = openpgp.generateKey(opt);
      await expect(test).to.eventually.be.rejectedWith(/Invalid user id format/);
    });

    it('should work for valid single string user id', function() {
      const opt = {
        userIds: 'Test User <text@example.com>'
      };
      return openpgp.generateKey(opt);
    });

    it('should work for valid string user id', function() {
      const opt = {
        userIds: ['Test User <text@example.com>']
      };
      return openpgp.generateKey(opt);
    });

    it('should work for valid single user id hash', function() {
      const opt = {
        userIds: { name: 'Test User', email: 'text@example.com' }
      };
      return openpgp.generateKey(opt);
    });

    it('should work for valid single user id hash', function() {
      const opt = {
        userIds: [{ name: 'Test User', email: 'text@example.com' }]
      };
      return openpgp.generateKey(opt);
    });

    it('should work for an empty name', function() {
      const opt = {
        userIds: { email: 'text@example.com' }
      };
      return openpgp.generateKey(opt);
    });

    it('should work for an empty email address', function() {
      const opt = {
        userIds: { name: 'Test User' }
      };
      return openpgp.generateKey(opt);
    });
  });

  describe('generateKey - unit tests', function() {
    let keyGenStub;
    let keyObjStub;
    let getWebCryptoAllStub;

    beforeEach(function() {
      keyObjStub = {
        armor: function() {
          return 'priv_key';
        },
        toPublic: function() {
          return {
            armor: function() {
              return 'pub_key';
            }
          };
        },
        getRevocationCertificate: function() {}
      };
      keyGenStub = stub(openpgp.key, 'generate');
      keyGenStub.returns(resolves(keyObjStub));
      getWebCryptoAllStub = stub(openpgp.util, 'getWebCryptoAll');
    });

    afterEach(function() {
      keyGenStub.restore();
      openpgp.destroyWorker();
      getWebCryptoAllStub.restore();
    });

    it('should have default params set', function() {
      const now = openpgp.util.normalizeDate(new Date());
      const opt = {
        userIds: { name: 'Test User', email: 'text@example.com' },
        passphrase: 'secret',
        date: now,
        subkeys: []
      };
      return openpgp.generateKey(opt).then(function(newKey) {
        expect(keyGenStub.withArgs({
          userIds: [{ name: 'Test User', email: 'text@example.com' }],
          passphrase: 'secret',
          numBits: 2048,
          keyExpirationTime: 0,
          curve: "",
          date: now,
          subkeys: []
        }).calledOnce).to.be.true;
        expect(newKey.key).to.exist;
        expect(newKey.privateKeyArmored).to.exist;
        expect(newKey.publicKeyArmored).to.exist;
      });
    });

    it('should delegate to async proxy', function() {
      const workerStub = {
        postMessage: function() {}
      };
      openpgp.initWorker({
        workers: [workerStub]
      });
      const proxyGenStub = stub(openpgp.getWorker(), 'delegate');
      getWebCryptoAllStub.returns();

      const opt = {
        userIds: { name: 'Test User', email: 'text@example.com' },
        passphrase: 'secret',
        subkeys: []
      };
      openpgp.generateKey(opt);
      expect(proxyGenStub.calledOnce).to.be.true;
      expect(keyGenStub.calledOnce).to.be.false;
    });
  });

  describe('generateKey - integration tests', function() {
    let use_nativeVal;

    beforeEach(function() {
      use_nativeVal = openpgp.config.use_native;
    });

    afterEach(function() {
      openpgp.config.use_native = use_nativeVal;
      openpgp.destroyWorker();
    });

    it('should work in JS (without worker)', function() {
      openpgp.config.use_native = false;
      openpgp.destroyWorker();
      const opt = {
        userIds: [{ name: 'Test User', email: 'text@example.com' }],
        numBits: 512
      };

      return openpgp.generateKey(opt).then(function(newKey) {
        expect(newKey.key.getUserIds()[0]).to.equal('Test User <text@example.com>');
        expect(newKey.publicKeyArmored).to.match(/^-----BEGIN PGP PUBLIC/);
        expect(newKey.privateKeyArmored).to.match(/^-----BEGIN PGP PRIVATE/);
      });
    });

    it('should work in JS (with worker)', function() {
      openpgp.config.use_native = false;
      openpgp.initWorker({ path:'../dist/openpgp.worker.js' });
      const opt = {
        userIds: [{ name: 'Test User', email: 'text@example.com' }],
        numBits: 512
      };

      return openpgp.generateKey(opt).then(function(newKey) {
        expect(newKey.key.getUserIds()[0]).to.equal('Test User <text@example.com>');
        expect(newKey.publicKeyArmored).to.match(/^-----BEGIN PGP PUBLIC/);
        expect(newKey.privateKeyArmored).to.match(/^-----BEGIN PGP PRIVATE/);
      });
    });

    it('should work in with native crypto', function() {
      openpgp.config.use_native = true;
      const opt = {
        userIds: [{ name: 'Test User', email: 'text@example.com' }],
        numBits: 512
      };
      if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys

      return openpgp.generateKey(opt).then(function(newKey) {
        expect(newKey.key.getUserIds()[0]).to.equal('Test User <text@example.com>');
        expect(newKey.publicKeyArmored).to.match(/^-----BEGIN PGP PUBLIC/);
        expect(newKey.privateKeyArmored).to.match(/^-----BEGIN PGP PRIVATE/);
      });
    });
  });

  describe('encrypt, decrypt, sign, verify - integration tests', function() {
    let privateKey_2000_2008;
    let publicKey_2000_2008;
    let privateKey_2038_2045;
    let publicKey_2038_2045;
    let privateKey_1337;
    let publicKey_1337;
    let privateKey;
    let publicKey;
    let zero_copyVal;
    let use_nativeVal;
    let aead_protectVal;
    let aead_protect_versionVal;
    let aead_modeVal;
    let aead_chunk_size_byteVal;

    beforeEach(function(done) {
      publicKey = openpgp.key.readArmored(pub_key);
      expect(publicKey.keys).to.have.length(1);
      expect(publicKey.err).to.not.exist;
      publicKeyNoAEAD = openpgp.key.readArmored(pub_key);
      privateKey = openpgp.key.readArmored(priv_key);
      expect(privateKey.keys).to.have.length(1);
      expect(privateKey.err).to.not.exist;
      privateKey_2000_2008 = openpgp.key.readArmored(priv_key_2000_2008);
      expect(privateKey_2000_2008.keys).to.have.length(1);
      expect(privateKey_2000_2008.err).to.not.exist;
      publicKey_2000_2008 = { keys: [ privateKey_2000_2008.keys[0].toPublic() ] };
      privateKey_2038_2045 = openpgp.key.readArmored(priv_key_2038_2045);
      expect(privateKey_2038_2045.keys).to.have.length(1);
      expect(privateKey_2038_2045.err).to.not.exist;
      publicKey_2038_2045 = { keys: [ privateKey_2038_2045.keys[0].toPublic() ] };
      privateKey_1337 = openpgp.key.readArmored(priv_key_1337);
      expect(privateKey_1337.keys).to.have.length(1);
      expect(privateKey_1337.err).to.not.exist;
      publicKey_1337 = { keys: [ privateKey_1337.keys[0].toPublic() ] };
      zero_copyVal = openpgp.config.zero_copy;
      use_nativeVal = openpgp.config.use_native;
      aead_protectVal = openpgp.config.aead_protect;
      aead_protect_versionVal = openpgp.config.aead_protect_version;
      aead_modeVal = openpgp.config.aead_mode;
      aead_chunk_size_byteVal = openpgp.config.aead_chunk_size_byte;
      done();
    });

    afterEach(function() {
      openpgp.config.zero_copy = zero_copyVal;
      openpgp.config.use_native = use_nativeVal;
      openpgp.config.aead_protect = aead_protectVal;
      openpgp.config.aead_protect_version = aead_protect_versionVal;
      openpgp.config.aead_mode = aead_modeVal;
      openpgp.config.aead_chunk_size_byte = aead_chunk_size_byteVal;
    });

    it('Decrypting key with wrong passphrase rejected', async function () {
      await expect(privateKey.keys[0].decrypt('wrong passphrase')).to.eventually.be.rejectedWith('Incorrect key passphrase');
    });

    it('Decrypting key with correct passphrase returns true', async function () {
      expect(await privateKey.keys[0].decrypt(passphrase)).to.be.true;
    });

    tryTests('CFB mode (asm.js)', tests, {
      if: !(typeof window !== 'undefined' && window.Worker),
      beforeEach: function() {
        openpgp.config.aead_protect = false;
      }
    });

    tryTests('CFB mode (asm.js, worker)', tests, {
      if: typeof window !== 'undefined' && window.Worker,
      before: function() {
        openpgp.initWorker({ path:'../dist/openpgp.worker.js' });
      },
      beforeEach: function() {
        openpgp.config.aead_protect = false;
      },
      after: function() {
        openpgp.destroyWorker();
      }
    });

    tryTests('GCM mode', tests, {
      if: true,
      beforeEach: function() {
        openpgp.config.aead_protect = true;
        openpgp.config.aead_protect_version = 0;
      }
    });

    tryTests('GCM mode (draft04)', tests, {
      if: true,
      beforeEach: function() {
        openpgp.config.aead_protect = true;
        openpgp.config.aead_mode = openpgp.enums.aead.experimental_gcm;

        // Monkey-patch AEAD feature flag
        publicKey.keys[0].users[0].selfCertifications[0].features = [7];
        publicKey_2000_2008.keys[0].users[0].selfCertifications[0].features = [7];
        publicKey_2038_2045.keys[0].users[0].selfCertifications[0].features = [7];
      }
    });

    tryTests('EAX mode (small chunk size)', tests, {
      if: true,
      beforeEach: function() {
        openpgp.config.aead_protect = true;
        openpgp.config.aead_chunk_size_byte = 0;

        // Monkey-patch AEAD feature flag
        publicKey.keys[0].users[0].selfCertifications[0].features = [7];
        publicKey_2000_2008.keys[0].users[0].selfCertifications[0].features = [7];
        publicKey_2038_2045.keys[0].users[0].selfCertifications[0].features = [7];
      }
    });

    tryTests('OCB mode', tests, {
      if: true,
      beforeEach: function() {
        openpgp.config.aead_protect = true;
        openpgp.config.aead_mode = openpgp.enums.aead.ocb;

        // Monkey-patch AEAD feature flag
        publicKey.keys[0].users[0].selfCertifications[0].features = [7];
        publicKey_2000_2008.keys[0].users[0].selfCertifications[0].features = [7];
        publicKey_2038_2045.keys[0].users[0].selfCertifications[0].features = [7];
      }
    });

    function tests() {
      it('Configuration', function() {
        openpgp.config.show_version = false;
        openpgp.config.commentstring = 'different';
        if (openpgp.getWorker()) { // init again to trigger config event
          openpgp.initWorker({ path:'../dist/openpgp.worker.js' });
        }
        return openpgp.encrypt({ publicKeys:publicKey.keys, data:plaintext }).then(function(encrypted) {
          expect(encrypted.data).to.exist;
          expect(encrypted.data).not.to.match(/^Version:/);
          expect(encrypted.data).to.match(/Comment: different/);
        });
      });

      it('Test multiple workers', async function() {
        openpgp.config.show_version = false;
        openpgp.config.commentstring = 'different';
        if (!openpgp.getWorker()) {
          return;
        }
        const { workers } = openpgp.getWorker();
        try {
          await privateKey.keys[0].decrypt(passphrase)
          openpgp.initWorker({path: '../dist/openpgp.worker.js', workers, n: 2});

          const workerTest = (_, index) => {
            const plaintext = input.createSomeMessage() + index;
            return openpgp.encrypt({
              publicKeys: publicKey.keys,
              data: plaintext
            }).then(function (encrypted) {
              expect(encrypted.data).to.exist;
              expect(encrypted.data).not.to.match(/^Version:/);
              expect(encrypted.data).to.match(/Comment: different/);
              return openpgp.decrypt({
                privateKeys: privateKey.keys[0],
                message: openpgp.message.readArmored(encrypted.data)
              });
            }).then(function (decrypted) {
              expect(decrypted.data).to.equal(plaintext);
            });
          };
          await Promise.all(Array(10).fill(null).map(workerTest));
        } finally {
          openpgp.initWorker({path: '../dist/openpgp.worker.js', workers, n: 1 });
        }
      });

      it('Calling decrypt with not decrypted key leads to exception', function() {
        const encOpt = {
          data: plaintext,
          publicKeys: publicKey.keys
        };
        const decOpt = {
          privateKeys: privateKey.keys[0]
        };
        return openpgp.encrypt(encOpt).then(function(encrypted) {
          decOpt.message = openpgp.message.readArmored(encrypted.data);
          return openpgp.decrypt(decOpt);
        }).catch(function(error) {
          expect(error.message).to.match(/not decrypted/);
        });
      });

      describe('decryptKey', function() {
        it('should work for correct passphrase', function() {
          return openpgp.decryptKey({
            privateKey: privateKey.keys[0],
            passphrase: passphrase
          }).then(function(unlocked){
            expect(unlocked.key.getKeyId().toHex()).to.equal(privateKey.keys[0].getKeyId().toHex());
            expect(unlocked.key.isDecrypted()).to.be.true;
          });
        });

        it('should fail for incorrect passphrase', function() {
          return openpgp.decryptKey({
            privateKey: privateKey.keys[0],
            passphrase: 'incorrect'
          }).catch(function(error){
            expect(error.message).to.match(/Incorrect key passphrase/);
          });
        });
      });

      describe('encryptSessionKey, decryptSessionKeys', function() {
        const sk = new Uint8Array([0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01]);

        beforeEach(async function() {
          expect(await privateKey.keys[0].decrypt(passphrase)).to.be.true;
          return true;
        });

        it('should encrypt with public key', function() {
          return openpgp.encryptSessionKey({
            data: sk,
            algorithm: 'aes128',
            publicKeys: publicKey.keys
          }).then(function(encrypted) {
            return openpgp.decryptSessionKeys({
              message: encrypted.message,
              privateKeys: privateKey.keys[0]
            });
          }).then(function(decrypted) {
            expect(decrypted[0].data).to.deep.equal(sk);
          });
        });

        it('should encrypt with password', function() {
          return openpgp.encryptSessionKey({
            data: sk,
            algorithm: 'aes128',
            passwords: password1
          }).then(function(encrypted) {
            return openpgp.decryptSessionKeys({
              message: encrypted.message,
              passwords: password1
            });
          }).then(function(decrypted) {
            expect(decrypted[0].data).to.deep.equal(sk);
          });
        });

        it('roundtrip workflow: encrypt, decryptSessionKeys, decrypt with pgp key pair', function () {
          let msgAsciiArmored;
          return openpgp.encrypt({
            data: plaintext,
            publicKeys: publicKey.keys
          }).then(function (encrypted) {
            msgAsciiArmored = encrypted.data;
            return openpgp.decryptSessionKeys({
              message: openpgp.message.readArmored(msgAsciiArmored),
              privateKeys: privateKey.keys[0]
            });

          }).then(function (decryptedSessionKeys) {
            const message = openpgp.message.readArmored(msgAsciiArmored);
            return openpgp.decrypt({
              sessionKeys: decryptedSessionKeys[0],
              message
            });
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
          });
        });

        it('roundtrip workflow: encrypt, decryptSessionKeys, decrypt with pgp key pair -- trailing spaces', function () {
          const plaintext = 'space: \nspace and tab: \t\nno trailing space\n  \ntab:\t\ntab and space:\t ';
          let msgAsciiArmored;
          return openpgp.encrypt({
            data: plaintext,
            publicKeys: publicKey.keys
          }).then(function (encrypted) {
            msgAsciiArmored = encrypted.data;
            return openpgp.decryptSessionKeys({
              message: openpgp.message.readArmored(msgAsciiArmored),
              privateKeys: privateKey.keys[0]
            });

          }).then(function (decryptedSessionKeys) {
            const message = openpgp.message.readArmored(msgAsciiArmored);
            return openpgp.decrypt({
              sessionKeys: decryptedSessionKeys[0],
              message
            });
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
          });
        });

        it('roundtrip workflow: encrypt, decryptSessionKeys, decrypt with password', function () {
          let msgAsciiArmored;
          return openpgp.encrypt({
            data: plaintext,
            passwords: password1
          }).then(function (encrypted) {
            msgAsciiArmored = encrypted.data;
            return openpgp.decryptSessionKeys({
              message: openpgp.message.readArmored(msgAsciiArmored),
              passwords: password1
            });

          }).then(function (decryptedSessionKeys) {
            return openpgp.decrypt({
              sessionKeys: decryptedSessionKeys[0],
              message: openpgp.message.readArmored(msgAsciiArmored)
            });

          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
          });
        });

        it('roundtrip workflow: encrypt with multiple passwords, decryptSessionKeys, decrypt with multiple passwords', function () {
          let msgAsciiArmored;
          return openpgp.encrypt({
            data: plaintext,
            passwords: [password1, password2]
          }).then(function (encrypted) {
            msgAsciiArmored = encrypted.data;
            return openpgp.decryptSessionKeys({
              message: openpgp.message.readArmored(msgAsciiArmored),
              passwords: [password1, password2]
            });

          }).then(function (decryptedSessionKeys) {
            return openpgp.decrypt({
              sessionKeys: decryptedSessionKeys,
              message: openpgp.message.readArmored(msgAsciiArmored)
            });

          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
          });
        });

        it('roundtrip workflow: encrypt twice with one password, decryptSessionKeys, only one session key', function () {
          let msgAsciiArmored;
          return openpgp.encrypt({
            data: plaintext,
            passwords: [password1, password1]
          }).then(function (encrypted) {
            msgAsciiArmored = encrypted.data;
            return openpgp.decryptSessionKeys({
              message: openpgp.message.readArmored(msgAsciiArmored),
              passwords: password1
            });
          }).then(function (decryptedSessionKeys) {
            expect(decryptedSessionKeys.length).to.equal(1);
            return openpgp.decrypt({
              sessionKeys: decryptedSessionKeys,
              message: openpgp.message.readArmored(msgAsciiArmored)
            });
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
          });
        });
      });

      describe('AES / RSA encrypt, decrypt, sign, verify', function() {
        const wrong_pubkey = '-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n' +
          'Version: OpenPGP.js v0.9.0\r\n' +
          'Comment: Hoodiecrow - https://hoodiecrow.com\r\n' +
          '\r\n' +
          'xk0EUlhMvAEB/2MZtCUOAYvyLFjDp3OBMGn3Ev8FwjzyPbIF0JUw+L7y2XR5\r\n' +
          'RVGvbK88unV3cU/1tOYdNsXI6pSp/Ztjyv7vbBUAEQEAAc0pV2hpdGVvdXQg\r\n' +
          'VXNlciA8d2hpdGVvdXQudGVzdEB0LW9ubGluZS5kZT7CXAQQAQgAEAUCUlhM\r\n' +
          'vQkQ9vYOm0LN/0wAAAW4Af9C+kYW1AvNWmivdtr0M0iYCUjM9DNOQH1fcvXq\r\n' +
          'IiN602mWrkd8jcEzLsW5IUNzVPLhrFIuKyBDTpLnC07Loce1\r\n' +
          '=6XMW\r\n' +
          '-----END PGP PUBLIC KEY BLOCK-----\r\n\r\n';

        beforeEach(async function () {
          expect(await privateKey.keys[0].decrypt(passphrase)).to.be.true;
          return true;
        });

        it('should encrypt then decrypt', function () {
          const encOpt = {
            data: plaintext,
            publicKeys: publicKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            expect(encrypted.data).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures).to.exist;
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt then decrypt with multiple private keys', async function () {
          const privKeyDE = openpgp.key.readArmored(priv_key_de).keys[0];
          await privKeyDE.decrypt(passphrase);

          const encOpt = {
            data: plaintext,
            publicKeys: publicKey.keys
          };
          const decOpt = {
            privateKeys: [privKeyDE, privateKey.keys[0]]
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            expect(encrypted.data).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures).to.exist;
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt then decrypt with wildcard', function () {
          const encOpt = {
            data: plaintext,
            publicKeys: publicKey.keys,
            wildcard: true
          };
          const decOpt = {
            privateKeys: privateKey.keys
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            expect(encrypted.data).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures).to.exist;
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt then decrypt with wildcard with multiple private keys', async function () {
          const privKeyDE = openpgp.key.readArmored(priv_key_de).keys[0];
          await privKeyDE.decrypt(passphrase);

          const encOpt = {
            data: plaintext,
            publicKeys: publicKey.keys,
            wildcard: true
          };
          const decOpt = {
            privateKeys: [privKeyDE, privateKey.keys[0]]
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            expect(encrypted.data).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures).to.exist;
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt then decrypt using returned session key', function () {
          const encOpt = {
            data: plaintext,
            publicKeys: publicKey.keys,
            returnSessionKey: true
          };

          return openpgp.encrypt(encOpt).then(function (encrypted) {
            expect(encrypted.data).to.match(/^-----BEGIN PGP MESSAGE/);
            const decOpt = {
              sessionKeys: encrypted.sessionKey,
              message: openpgp.message.readArmored(encrypted.data)
            };
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures).to.exist;
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt using custom session key and decrypt using session key', async function () {
          const sessionKey = {
            data: await openpgp.crypto.generateSessionKey('aes256'),
            algorithm: 'aes256'
          };
          const encOpt = {
            data: plaintext,
            sessionKey: sessionKey,
            publicKeys: publicKey.keys
          };
          const decOpt = {
            sessionKeys: sessionKey
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            expect(encrypted.data).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            expect(!!decOpt.message.packets.findPacket(openpgp.enums.packet.symEncryptedAEADProtected)).to.equal(openpgp.config.aead_protect && openpgp.config.aead_protect_version !== 4);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
          });
        });

        it('should encrypt using custom session key and decrypt using private key', async function () {
          const sessionKey = {
            data: await openpgp.crypto.generateSessionKey('aes128'),
            algorithm: 'aes128'
          };
          const encOpt = {
            data: plaintext,
            sessionKey: sessionKey,
            publicKeys: publicKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys[0]
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            expect(encrypted.data).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            expect(!!decOpt.message.packets.findPacket(openpgp.enums.packet.symEncryptedAEADProtected)).to.equal(openpgp.config.aead_protect && openpgp.config.aead_protect_version !== 4);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
          });
        });

        it('should encrypt/sign and decrypt/verify', function () {
          const encOpt = {
            data: plaintext,
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: publicKey.keys
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            expect(!!decOpt.message.packets.findPacket(openpgp.enums.packet.symEncryptedAEADProtected)).to.equal(openpgp.config.aead_protect);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.true;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should encrypt/sign and decrypt/verify with signatureExpirationTime', async function () {
          const encOpt = {
            signatureExpirationTime: 1,
            data: plaintext,
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: publicKey.keys
          };

          const encrypted = await openpgp.encrypt(encOpt);
          decOpt.message = openpgp.message.readArmored(encrypted.data);
          expect(!!decOpt.message.packets.findPacket(openpgp.enums.packet.symEncryptedAEADProtected)).to.equal(openpgp.config.aead_protect);
          await timeout(1500);
          const decrypted = await openpgp.decrypt(decOpt);
          expect(decrypted.data).to.equal(plaintext);
          expect(decrypted.signatures[0].valid).to.be.false;
          const signingKey = await privateKey.keys[0].getSigningKey();
          expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
        });

        it('should encrypt/sign and decrypt/verify (no AEAD support)', function () {
          const encOpt = {
            data: plaintext,
            publicKeys: publicKeyNoAEAD.keys,
            privateKeys: privateKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: publicKeyNoAEAD.keys
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            expect(!!decOpt.message.packets.findPacket(openpgp.enums.packet.symEncryptedAEADProtected)).to.equal(openpgp.config.aead_protect && openpgp.config.aead_protect_version !== 4);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.true;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should encrypt/sign and decrypt/verify (no AEAD support) with signatureExpirationTime', function () {
          const encOpt = {
            signatureExpirationTime: 1,
            data: plaintext,
            publicKeys: publicKeyNoAEAD.keys,
            privateKeys: privateKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: publicKeyNoAEAD.keys
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            expect(!!decOpt.message.packets.findPacket(openpgp.enums.packet.symEncryptedAEADProtected)).to.equal(openpgp.config.aead_protect && openpgp.config.aead_protect_version !== 4);
            return timeout(1500);
          }).then(async function () {
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.false;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should encrypt/sign and decrypt/verify with generated key', function () {
          const genOpt = {
            userIds: [{ name: 'Test User', email: 'text@example.com' }],
            numBits: 512
          };
          if (openpgp.util.getWebCryptoAll()) { genOpt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys

          return openpgp.generateKey(genOpt).then(function(newKey) {
            const newPublicKey = openpgp.key.readArmored(newKey.publicKeyArmored);
            const newPrivateKey = openpgp.key.readArmored(newKey.privateKeyArmored);

            const encOpt = {
              data: plaintext,
              publicKeys: newPublicKey.keys,
              privateKeys: newPrivateKey.keys
            };
            const decOpt = {
              privateKeys: newPrivateKey.keys[0],
              publicKeys: newPublicKey.keys
            };
            return openpgp.encrypt(encOpt).then(function (encrypted) {
              decOpt.message = openpgp.message.readArmored(encrypted.data);
              expect(!!decOpt.message.packets.findPacket(openpgp.enums.packet.symEncryptedAEADProtected)).to.equal(openpgp.config.aead_protect);
              return openpgp.decrypt(decOpt);
            }).then(async function (decrypted) {
              expect(decrypted.data).to.equal(plaintext);
              expect(decrypted.signatures[0].valid).to.be.true;
              const signingKey = await newPrivateKey.keys[0].getSigningKey();
              expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
              expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
            });
          });
        });

        it('should encrypt/sign and decrypt/verify with null string input', function () {
          const encOpt = {
            data: '',
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: publicKey.keys
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal('');
            expect(decrypted.signatures[0].valid).to.be.true;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should encrypt/sign and decrypt/verify with detached signatures', function () {
          const encOpt = {
            data: plaintext,
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys,
            detached: true
          };
          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: publicKey.keys
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            decOpt.signature = openpgp.signature.readArmored(encrypted.signature);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.true;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should encrypt and decrypt/verify with detached signature input and detached flag set for encryption', function () {
          const signOpt = {
            data: plaintext,
            privateKeys: privateKey.keys[0],
            detached: true
          };

          const encOpt = {
            data: plaintext,
            publicKeys: publicKey.keys,
            detached: true
          };

          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: publicKey.keys[0]
          };

          return openpgp.sign(signOpt).then(function (signed) {
            encOpt.signature = openpgp.signature.readArmored(signed.signature);
            return openpgp.encrypt(encOpt);
          }).then(function (encrypted) {
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            decOpt.signature = openpgp.signature.readArmored(encrypted.signature);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.true;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should encrypt and decrypt/verify with detached signature as input and detached flag not set for encryption', async function () {
          const privKeyDE = openpgp.key.readArmored(priv_key_de).keys[0];
          await privKeyDE.decrypt(passphrase);

          const pubKeyDE = openpgp.key.readArmored(pub_key_de).keys[0];

          const signOpt = {
            data: plaintext,
            privateKeys: privKeyDE,
            detached: true
          };

          const encOpt = {
            data: plaintext,
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys[0]
          };

          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: [publicKey.keys[0], pubKeyDE]
          };

          return openpgp.sign(signOpt).then(function (signed) {
            encOpt.signature = openpgp.signature.readArmored(signed.signature);
            return openpgp.encrypt(encOpt);
          }).then(function (encrypted) {
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            let signingKey;
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.true;
            signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
            expect(decrypted.signatures[1].valid).to.be.true;
            signingKey = await privKeyDE.getSigningKey();
            expect(decrypted.signatures[1].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[1].signature.packets.length).to.equal(1);
          });
        });

        it('should fail to encrypt and decrypt/verify with detached signature input and detached flag set for encryption with wrong public key', function () {
          const signOpt = {
            data: plaintext,
            privateKeys: privateKey.keys,
            detached: true
          };

          const encOpt = {
            data: plaintext,
            publicKeys: publicKey.keys,
            detached: true
          };

          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: openpgp.key.readArmored(wrong_pubkey).keys
          };

          return openpgp.sign(signOpt).then(function (signed) {
            encOpt.signature = openpgp.signature.readArmored(signed.signature);
            return openpgp.encrypt(encOpt);
          }).then(function (encrypted) {
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            decOpt.signature = openpgp.signature.readArmored(encrypted.signature);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should fail to encrypt and decrypt/verify with detached signature as input and detached flag not set for encryption with wrong public key', function () {
          const signOpt = {
            data: plaintext,
            privateKeys: privateKey.keys,
            detached: true
          };

          const encOpt = {
            data: plaintext,
            publicKeys: publicKey.keys
          };

          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: openpgp.key.readArmored(wrong_pubkey).keys
          };

          return openpgp.sign(signOpt).then(function (signed) {
            encOpt.signature = openpgp.signature.readArmored(signed.signature);
            return openpgp.encrypt(encOpt);
          }).then(function (encrypted) {
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should fail to verify decrypted data with wrong public pgp key', function () {
          const encOpt = {
            data: plaintext,
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: openpgp.key.readArmored(wrong_pubkey).keys
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should fail to verify decrypted null string with wrong public pgp key', function () {
          const encOpt = {
            data: '',
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: openpgp.key.readArmored(wrong_pubkey).keys
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal('');
            expect(decrypted.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should successfully decrypt signed message without public keys to verify', function () {
          const encOpt = {
            data: plaintext,
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys[0]
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should fail to verify decrypted data with wrong public pgp key with detached signatures', function () {
          const encOpt = {
            data: plaintext,
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys,
            detached: true
          };
          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: openpgp.key.readArmored(wrong_pubkey).keys
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            decOpt.signature = openpgp.signature.readArmored(encrypted.signature);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should encrypt and decrypt/verify both signatures when signed with two private keys', async function () {
          const privKeyDE = openpgp.key.readArmored(priv_key_de).keys[0];
          await privKeyDE.decrypt(passphrase);

          const pubKeyDE = openpgp.key.readArmored(pub_key_de).keys[0];

          const encOpt = {
            data: plaintext,
            publicKeys: publicKey.keys,
            privateKeys: [privateKey.keys[0], privKeyDE]
          };

          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: [publicKey.keys[0], pubKeyDE]
          };

          return openpgp.encrypt(encOpt).then(function (encrypted) {
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            let signingKey;
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.true;
            signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
            expect(decrypted.signatures[1].valid).to.be.true;
            signingKey = await privKeyDE.getSigningKey();
            expect(decrypted.signatures[1].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[1].signature.packets.length).to.equal(1);
          });
        });

        it('should sign and verify cleartext data', function () {
          const signOpt = {
            data: plaintext,
            privateKeys: privateKey.keys
          };
          const verifyOpt = {
            publicKeys: publicKey.keys
          };
          return openpgp.sign(signOpt).then(function (signed) {
            expect(signed.data).to.match(/-----BEGIN PGP SIGNED MESSAGE-----/);
            verifyOpt.message = openpgp.cleartext.readArmored(signed.data);
            return openpgp.verify(verifyOpt);
          }).then(async function (verified) {
            expect(verified.data).to.equal(plaintext);
            expect(verified.signatures[0].valid).to.be.true;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(verified.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should sign and verify cleartext data with multiple private keys', async function () {
          const privKeyDE = openpgp.key.readArmored(priv_key_de).keys[0];
          await privKeyDE.decrypt(passphrase);

          const signOpt = {
            data: plaintext,
            privateKeys: [privateKey.keys[0], privKeyDE]
          };
          const verifyOpt = {
            publicKeys: [publicKey.keys[0], privKeyDE.toPublic()]
          };
          return openpgp.sign(signOpt).then(function (signed) {
            expect(signed.data).to.match(/-----BEGIN PGP SIGNED MESSAGE-----/);
            verifyOpt.message = openpgp.cleartext.readArmored(signed.data);
            return openpgp.verify(verifyOpt);
          }).then(async function (verified) {
            let signingKey;
            expect(verified.data).to.equal(plaintext);
            expect(verified.signatures[0].valid).to.be.true;
            signingKey = await privateKey.keys[0].getSigningKey();
            expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(verified.signatures[0].signature.packets.length).to.equal(1);
            expect(verified.signatures[1].valid).to.be.true;
            signingKey = await privKeyDE.getSigningKey();
            expect(verified.signatures[1].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(verified.signatures[1].signature.packets.length).to.equal(1);
          });
        });

        it('should sign and verify cleartext data with detached signatures', function () {
          const signOpt = {
            data: plaintext,
            privateKeys: privateKey.keys,
            detached: true
          };
          const verifyOpt = {
            publicKeys: publicKey.keys
          };
          return openpgp.sign(signOpt).then(function (signed) {
            verifyOpt.message = new openpgp.cleartext.CleartextMessage(plaintext);
            verifyOpt.signature = openpgp.signature.readArmored(signed.signature);
            return openpgp.verify(verifyOpt);
          }).then(async function (verified) {
            expect(verified.data).to.equal(plaintext);
            expect(verified.signatures[0].valid).to.be.true;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(verified.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should sign and fail to verify cleartext data with wrong public pgp key', function () {
          const signOpt = {
            data: plaintext,
            privateKeys: privateKey.keys
          };
          const verifyOpt = {
            publicKeys: openpgp.key.readArmored(wrong_pubkey).keys
          };
          return openpgp.sign(signOpt).then(function (signed) {
            verifyOpt.message = openpgp.cleartext.readArmored(signed.data);
            return openpgp.verify(verifyOpt);
          }).then(async function (verified) {
            expect(verified.data).to.equal(plaintext);
            expect(verified.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(verified.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should sign and fail to verify cleartext data with wrong public pgp key with detached signature', function () {
          const signOpt = {
            data: plaintext,
            privateKeys: privateKey.keys,
            detached: true
          };
          const verifyOpt = {
            publicKeys: openpgp.key.readArmored(wrong_pubkey).keys
          };
          return openpgp.sign(signOpt).then(function (signed) {
            verifyOpt.message = new openpgp.cleartext.CleartextMessage(plaintext);
            verifyOpt.signature = openpgp.signature.readArmored(signed.signature);
            return openpgp.verify(verifyOpt);
          }).then(async function (verified) {
            expect(verified.data).to.equal(plaintext);
            expect(verified.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(verified.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should sign and verify cleartext data and not armor', function () {
          const signOpt = {
            data: plaintext,
            privateKeys: privateKey.keys,
            armor: false
          };
          const verifyOpt = {
            publicKeys: publicKey.keys
          };
          return openpgp.sign(signOpt).then(function (signed) {
            verifyOpt.message = signed.message;
            return openpgp.verify(verifyOpt);
          }).then(async function (verified) {
            expect(verified.data).to.equal(plaintext);
            expect(verified.signatures[0].valid).to.be.true;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(verified.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should sign and verify cleartext data and not armor with detached signatures', function () {
            const start = openpgp.util.normalizeDate();
            const signOpt = {
                data: plaintext,
                privateKeys: privateKey.keys,
                detached: true,
                armor: false
            };
            const verifyOpt = {
                publicKeys: publicKey.keys
            };
            return openpgp.sign(signOpt).then(function (signed) {
                verifyOpt.message = new openpgp.cleartext.CleartextMessage(plaintext);
                verifyOpt.signature = signed.signature;
                return openpgp.verify(verifyOpt);
            }).then(async function (verified) {
                expect(verified.data).to.equal(plaintext);
                expect(+verified.signatures[0].signature.packets[0].created).to.be.lte(+openpgp.util.normalizeDate());
                expect(+verified.signatures[0].signature.packets[0].created).to.be.gte(+start);
                expect(verified.signatures[0].valid).to.be.true;
                const signingKey = await privateKey.keys[0].getSigningKey();
                expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
                expect(verified.signatures[0].signature.packets.length).to.equal(1);
            });
        });

        it('should sign and verify cleartext data with a date in the past', function () {
            // the privateKey_1337 created date is Date(1000).
            const past = new Date(2000);
            const signOpt = {
                data: plaintext,
                privateKeys: privateKey_1337.keys,
                detached: true,
                date: past,
                armor: false
            };
            const verifyOpt = {
                publicKeys: publicKey_1337.keys,
                date: past
            };
            return openpgp.sign(signOpt).then(function (signed) {
                verifyOpt.message = new openpgp.cleartext.CleartextMessage(plaintext);
                verifyOpt.signature = signed.signature;
                return openpgp.verify(verifyOpt).then(function (verified) {
                  expect(+verified.signatures[0].signature.packets[0].created).to.equal(+past);
                  expect(verified.data).to.equal(plaintext);
                  expect(verified.signatures[0].valid).to.be.true;
                  expect(signOpt.privateKeys[0].getSigningKey(verified.signatures[0].keyid, past))
                      .to.be.not.null;
                  expect(verified.signatures[0].signature.packets.length).to.equal(1);
                  // now check with expiration checking disabled
                  verifyOpt.date = null;
                  return openpgp.verify(verifyOpt);
                }).then(function (verified) {
                  expect(+verified.signatures[0].signature.packets[0].created).to.equal(+past);
                  expect(verified.data).to.equal(plaintext);
                  expect(verified.signatures[0].valid).to.be.true;
                  expect(signOpt.privateKeys[0].getSigningKey(verified.signatures[0].keyid, null))
                      .to.be.not.null;
                  expect(verified.signatures[0].signature.packets.length).to.equal(1);
                });
            });
        });

        it('should sign and verify binary data with a date in the future', function () {
    // let pubKey = await openpgp.generateKey({
    //   userIds:[{name:'test'}],
    //   date: new Date('2038-01-01T00:07:43.000Z'),
    //   // keyExpirationTime: 1,
    //   numBits: 512
    // });
    // console.log(pubKey.privateKeyArmored);
    // return;
    // return console.log(privateKey_2038_2045.keys[0].users[0]);

            const future = new Date(2040, 5, 5, 5, 5, 5, 0);
            const data = new Uint8Array([3, 14, 15, 92, 65, 35, 59]);
            const signOpt = {
              data,
              privateKeys: privateKey_2038_2045.keys,
              detached: true,
              date: future,
              armor: false
            };
            const verifyOpt = {
              publicKeys: publicKey_2038_2045.keys,
              date: future
            };
            return openpgp.sign(signOpt).then(function (signed) {
              verifyOpt.message = openpgp.message.fromBinary(data);
              verifyOpt.signature = signed.signature;
              return openpgp.verify(verifyOpt);
            }).then(function (verified) {
              expect(+verified.signatures[0].signature.packets[0].created).to.equal(+future);
              expect([].slice.call(verified.data)).to.deep.equal([].slice.call(data));
              expect(verified.signatures[0].valid).to.be.true;
              expect(signOpt.privateKeys[0].getSigningKey(verified.signatures[0].keyid, future))
                  .to.be.not.null;
              expect(verified.signatures[0].signature.packets.length).to.equal(1);
            });
        });

        it('should encrypt and decrypt cleartext data with a date in the future', function () {
            const future = new Date(2040, 5, 5, 5, 5, 5, 0);
            const encryptOpt = {
                data: plaintext,
                publicKeys: publicKey_2038_2045.keys,
                date: future,
                armor: false
            };
            const decryptOpt = {
                privateKeys: privateKey_2038_2045.keys,
                date: future
            };

            return openpgp.encrypt(encryptOpt).then(function (encrypted) {
                decryptOpt.message = encrypted.message;
                return encrypted.message.decrypt(decryptOpt.privateKeys);
            }).then(function (packets) {
                const literals = packets.packets.filterByTag(openpgp.enums.packet.literal);
                expect(literals.length).to.equal(1);
                expect(+literals[0].date).to.equal(+future);
                expect(packets.getText()).to.equal(plaintext);
            });
        });

        it('should encrypt and decrypt binary data with a date in the past', function () {
            const past = new Date(2005, 5, 5, 5, 5, 5, 0);
            const data = new Uint8Array([3, 14, 15, 92, 65, 35, 59]);
            const encryptOpt = {
                data,
                publicKeys: publicKey_2000_2008.keys,
                date: past,
                armor: false
            };
            const decryptOpt = {
                privateKeys: privateKey_2000_2008.keys,
                date: past
            };

            return openpgp.encrypt(encryptOpt).then(function (encrypted) {
                decryptOpt.message = encrypted.message;
                return encrypted.message.decrypt(decryptOpt.privateKeys);
            }).then(function (packets) {
                const literals = packets.packets.filterByTag(openpgp.enums.packet.literal);
                expect(literals.length).to.equal(1);
                expect(+literals[0].date).to.equal(+past);
                expect(packets.getLiteralData()).to.deep.equal(data);
            });
        });

        it('should sign, encrypt and decrypt, verify cleartext data with a date in the past', function () {
            const past = new Date(2005, 5, 5, 5, 5, 5, 0);
            const encryptOpt = {
                data: plaintext,
                publicKeys: publicKey_2000_2008.keys,
                privateKeys: privateKey_2000_2008.keys,
                date: past,
                armor: false
            };

            return openpgp.encrypt(encryptOpt).then(function (encrypted) {
                return encrypted.message.decrypt(encryptOpt.privateKeys);
            }).then(function (packets) {
                const literals = packets.packets.filterByTag(openpgp.enums.packet.literal);
                expect(literals.length).to.equal(1);
                expect(+literals[0].date).to.equal(+past);
                expect(packets.getText()).to.equal(plaintext);
                return packets.verify(encryptOpt.publicKeys, past);
            }).then(function (signatures) {
                expect(+signatures[0].signature.packets[0].created).to.equal(+past);
                expect(signatures[0].valid).to.be.true;
                expect(encryptOpt.privateKeys[0].getSigningKey(signatures[0].keyid, past))
                    .to.be.not.null;
                expect(signatures[0].signature.packets.length).to.equal(1);
            });
        });

        it('should sign, encrypt and decrypt, verify binary data with a date in the future', function () {
            const future = new Date(2040, 5, 5, 5, 5, 5, 0);
            const data = new Uint8Array([3, 14, 15, 92, 65, 35, 59]);
            const encryptOpt = {
                data,
                publicKeys: publicKey_2038_2045.keys,
                privateKeys: privateKey_2038_2045.keys,
                date: future,
                armor: false
            };

            return openpgp.encrypt(encryptOpt).then(function (encrypted) {
                return encrypted.message.decrypt(encryptOpt.privateKeys);
            }).then(function (packets) {
                const literals = packets.packets.filterByTag(openpgp.enums.packet.literal);
                expect(literals.length).to.equal(1);
                expect(literals[0].format).to.equal('binary');
                expect(+literals[0].date).to.equal(+future);
                expect(packets.getLiteralData()).to.deep.equal(data);
                return packets.verify(encryptOpt.publicKeys, future);
            }).then(function (signatures) {
                expect(+signatures[0].signature.packets[0].created).to.equal(+future);
                expect(signatures[0].valid).to.be.true;
                expect(encryptOpt.privateKeys[0].getSigningKey(signatures[0].keyid, future))
                    .to.be.not.null;
                expect(signatures[0].signature.packets.length).to.equal(1);
            });
        });

        it('should sign, encrypt and decrypt, verify mime data with a date in the future', function () {
            const future = new Date(2040, 5, 5, 5, 5, 5, 0);
            const data = new Uint8Array([3, 14, 15, 92, 65, 35, 59]);
            const encryptOpt = {
                data,
                dataType: 'mime',
                publicKeys: publicKey_2038_2045.keys,
                privateKeys: privateKey_2038_2045.keys,
                date: future,
                armor: false
            };

            return openpgp.encrypt(encryptOpt).then(function (encrypted) {
                return encrypted.message.decrypt(encryptOpt.privateKeys);
            }).then(function (packets) {
                const literals = packets.packets.filterByTag(openpgp.enums.packet.literal);
                expect(literals.length).to.equal(1);
                expect(literals[0].format).to.equal('mime');
                expect(+literals[0].date).to.equal(+future);
                expect(packets.getLiteralData()).to.deep.equal(data);
                return packets.verify(encryptOpt.publicKeys, future);
            }).then(function (signatures) {
                expect(+signatures[0].signature.packets[0].created).to.equal(+future);
                expect(signatures[0].valid).to.be.true;
                expect(encryptOpt.privateKeys[0].getSigningKey(signatures[0].keyid, future))
                    .to.be.not.null;
                expect(signatures[0].signature.packets.length).to.equal(1);
            });
        });

        it('should fail to encrypt with revoked key', function() {
          return openpgp.revokeKey({
            key: privateKey.keys[0]
          }).then(function(revKey) {
            return openpgp.encrypt({
              data: plaintext,
              publicKeys: revKey.publicKey
            }).then(function(encrypted) {
              throw new Error('Should not encrypt with revoked key');
            }).catch(function(error) {
              expect(error.message).to.match(/Could not find valid key packet for encryption/);
            });
          });
        });

        it('should fail to encrypt with revoked subkey', async function() {
          const pubKeyDE = openpgp.key.readArmored(pub_key_de).keys[0];
          const privKeyDE = openpgp.key.readArmored(priv_key_de).keys[0];
          await privKeyDE.decrypt(passphrase);
          return privKeyDE.subKeys[0].revoke(privKeyDE.primaryKey).then(function(revSubKey) {
            pubKeyDE.subKeys[0] = revSubKey;
            return openpgp.encrypt({
              data: plaintext,
              publicKeys: pubKeyDE
            }).then(function(encrypted) {
              throw new Error('Should not encrypt with revoked subkey');
            }).catch(function(error) {
              expect(error.message).to.match(/Could not find valid key packet for encryption/);
            });
          });
        });
      });

      describe('ELG / DSA encrypt, decrypt, sign, verify', function() {

        it('round trip test', async function () {
          const pubKeyDE = openpgp.key.readArmored(pub_key_de).keys[0];
          const privKeyDE = openpgp.key.readArmored(priv_key_de).keys[0];
          await privKeyDE.decrypt(passphrase);
          pubKeyDE.users[0].selfCertifications[0].features = [7]; // Monkey-patch AEAD feature flag
          return openpgp.encrypt({
            publicKeys: pubKeyDE,
            privateKeys: privKeyDE,
            data: plaintext
          }).then(function (encrypted) {
            return openpgp.decrypt({
              privateKeys: privKeyDE,
              publicKeys: pubKeyDE,
              message: openpgp.message.readArmored(encrypted.data)
            });
          }).then(async function (decrypted) {
            expect(decrypted.data).to.exist;
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.true;
            const signingKey = await privKeyDE.getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });
      });

      describe("3DES decrypt", function() {
        const pgp_msg =
            ['-----BEGIN PGP MESSAGE-----',
            'Version: GnuPG/MacGPG2 v2.0.19 (Darwin)',
            'Comment: GPGTools - https://gpgtools.org',
            '',
            'hIwDBU4Dycfvp2EBA/9tuhQgOrcATcm2PRmIOcs6q947YhlsBTZZdVJDfVjkKlyM',
            'M0yE+lnNplWb041Cpfkkl6IvorKQd2iPbAkOL0IXwmVN41l+PvVgMcuFvvzetehG',
            'Ca0/VEYOaTZRNqyr9FIzcnVy1I/PaWT3iqVAYa+G8TEA5Dh9RLfsx8ZA9UNIaNI+',
            'ASm9aZ3H6FerNhm8RezDY5vRn6xw3o/wH5YEBvV2BEmmFKZ2BlqFQxqChr8UNwd1',
            'Ieebnq0HtBPE8YU/L0U=',
            '=JyIa',
            '-----END PGP MESSAGE-----'].join('\n');

        const priv_key =
            ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'Version: GnuPG/MacGPG2 v2.0.19 (Darwin)',
            'Comment: GPGTools - https://gpgtools.org',
            '',
            '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',
            '22q10ausyQXoOxXfDWVwKA==',
            '=IkKW',
            '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

        it('Decrypt message', async function() {
          const privKey = openpgp.key.readArmored(priv_key).keys[0];
          await privKey.decrypt('1234');
          const message = openpgp.message.readArmored(pgp_msg);

          return openpgp.decrypt({ privateKeys:privKey, message:message }).then(function(decrypted) {
            expect(decrypted.data).to.equal('hello 3des\n');
            expect(decrypted.signatures.length).to.equal(0);
          });
        });
      });

      describe('AES encrypt, decrypt', function() {

        it('should encrypt and decrypt with one password', function () {
          const encOpt = {
            data: plaintext,
            passwords: password1
          };
          const decOpt = {
            passwords: password1
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt and decrypt with two passwords', function () {
          const encOpt = {
            data: plaintext,
            passwords: [password1, password2]
          };
          const decOpt = {
            passwords: password2
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            decOpt.message = openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should decrypt with two passwords message which GPG fails on', function () {

          const decOpt = {
            message: openpgp.message.readArmored(twoPasswordGPGFail),
            passwords: password2
          };
          return openpgp.decrypt(decOpt).then(function (decrypted) {
            expect(decrypted.data).to.equal('short message\nnext line\n한국어/조선말');
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt and decrypt with password and not ascii armor', function () {
          const encOpt = {
            data: plaintext,
            passwords: password1,
            armor: false
          };
          const decOpt = {
            passwords: password1
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            decOpt.message = encrypted.message;
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt and decrypt with binary data and transferable objects', function () {
          openpgp.config.zero_copy = true; // activate transferable objects
          const encOpt = {
            data: new Uint8Array([0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]),
            passwords: password1,
            armor: false
          };
          const decOpt = {
            passwords: password1,
            format: 'binary'
          };
          return openpgp.encrypt(encOpt).then(function (encrypted) {
            decOpt.message = encrypted.message;
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            if (openpgp.getWorker()) {
              expect(encOpt.data.byteLength).to.equal(0); // transferred buffer should be empty
            }
            expect(decrypted.data).to.deep.equal(new Uint8Array([0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]));
            expect(decrypted.signatures.length).to.equal(0);
          });
        });
      });

      describe('Encrypt, decrypt with compression', function() {
        withCompression(function (modifyCompressionEncryptOptions, verifyCompressionDecrypted) {
          it('should encrypt and decrypt with one password', function () {
            const encOpt = modifyCompressionEncryptOptions({
              data: plaintext,
              passwords: password1
            });
            const decOpt = {
              passwords: password1
            };
            return openpgp.encrypt(encOpt).then(function (encrypted) {
              decOpt.message = openpgp.message.readArmored(encrypted.data);
              return openpgp.decrypt(decOpt);
            }).then(function (decrypted) {
              expect(decrypted.data).to.equal(plaintext);
              expect(decrypted.signatures.length).to.equal(0);
              verifyCompressionDecrypted(decrypted);
            });
          });
        });
      });

      describe('Errors', function() {

        it('Error message should contain the original error message', function() {
          return openpgp.encrypt({
            data: new Uint8Array([0x01, 0x01, 0x01]),
            passwords: null
          })
          .then(function() {
            throw new Error('Error expected.');
          })
          .catch(function(error) {
            expect(error.message).to.match(/No keys, passwords, or session key provided/);
          });
        });

      });

    }

  });

});

function timeout(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
