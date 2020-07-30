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
  'mQMuBFLVgdQRCACOlpq0cd1IazNjOEpWPZvx/O3JMbdDs3B3iCG0Mo5OUZ8lpKU5',
  'EslVgTd8IcUU14ZMOO7y91dw0KP4q61b4OIy7oVxzfFfKCC1s0Dc7GTay+qo5afJ',
  'wbWcgTyCIahTRmi5UepU7xdRHRMlqAclOwY2no8fw0JRQfFwRFCjbMdmvzC/k+Wo',
  'A42nn8YaSAG2v7OqF3rkYjkv/7iak48PO/l0Q13USAJLIWdHvRTir78mQUsEY0qR',
  'VoNqz5sMqakzhTvTav07EVy/1xC6GKoWXA9sdB/4r7+blVuu9M4yD40GkE69oAXO',
  'mz6tG3lRq41S0OSzNyDWtUQgMVF6wYqVxUGrAQDJM5A1rF1RKzFiHdkyy57E8LC1',
  'SIJyIXWJ0c5b8/olWQf9G5a17fMjkRTC3FO+ZHwFE1jIM6znYOF2GltDToLuJPq9',
  'lWrI7zVP9AJPwrUt7FK2MBNAvd1jKyIhdU98PBQ2pr+jmyqIycl9iDGXLDO7D7E/',
  'TBnxwQzoL/5b7UnPImuXOwv5JhVmyV2t003xjzb1EGggOnpKugUtVLps8JiLl9n+',
  'Nkj5wpU7NXbuHj2XGkkGmKkCIz4l0dJQR9V6svJV9By0RPgfGPXlN1VR6f2ounNy',
  '6REnDCQP9S3Li5eNcxlSGDIxIZL22j63sU/68GVlzqhVdGXxofv5jGtajiNSpPot',
  'ElZU0dusna4PzYmiBCsyN8jENWSzHLJ37N4ScN4b/gf6Axf9FU0PjzPBN1o9W6zj',
  'kpfhlSWDjE3BK8jJ7KvzecM2QE/iJsbuyKEsklw1v0MsRDsox5QlQJcKOoUHC+OT',
  'iKm8cnPckLQNPOw/kb+5Auz7TXBQ63dogDuqO8QGGOpjh8SIYbblYQI5ueo1Tix3',
  'PlSU36SzOQfxSOCeIomEmaFQcU57O1CLsRl//+5lezMFDovJyQHQZfiTxSGfPHij',
  'oQzEUyEWYHKQhIRV6s5VGvF3hN0t8fo0o57bzhV6E7IaSz2Cnm0O0S2PZt8DBN9l',
  'LYNw3cFgzMb/qdFJGR0JXz+moyAYh/fYMiryb6d8ghhvrRy0CrRlC3U5K6qiYfKu',
  'lLQURFNBL0VMRyA8ZHNhQGVsZy5qcz6IewQTEQgAIwUCUtWB1AIbAwcLCQgHAwIB',
  'BhUIAgkKCwQWAgMBAh4BAheAAAoJELqZP8Ku4Yo6Aa0A/1Kz5S8d9czLiDbrhSa/',
  'C1rQ5qiWpFq9UNTFg2P/gASvAP92TzUMLK2my8ew1xXShtrfXked5fkSuFrPlZBs',
  'b4Ta67kCDQRS1YHUEAgAxOKx4y5QD78uPLlgNBHXrcncUNBIt4IXBGjQTxpFcn5j',
  'rSuj+ztvXJQ8wCkx+TTb2yuL5M+nXd7sx4s+M4KZ/MZfI6ZX4lhcoUdAbB9FWiV7',
  'uNntyeFo8qgGM5at/Q0EsyzMSqbeBxk4bpd5MfYGThn0Ae2xaw3X94KaZ3LjtHo2',
  'V27FD+jvmmoAj9b1+zcO/pJ8SuojQmcnS4VDVV+Ba5WPTav0LzDdQXyGMZI9PDxC',
  'jAI2f1HjTuxIt8X8rAQSQdoMIcQRYEjolsXS6iob1eVigyL86hLJjI3VPn6kBCv3',
  'Tb+WXX+9LgSAt9yvv4HMwBLK33k6IH7M72SqQulZywADBQgAt2xVTMjdVyMniMLj',
  'Ed4HbUgwyCPkVkcA4zTXqfKu+dAe4dK5tre0clkXZVtR1V8RDAD0zaVyM030e2zb',
  'zn4cGKDL2dmwk2ZBeXWZDgGKoKvGKYf8PRpTAYweFzol3OUdfXH5SngOylCD4OCL',
  's4RSVkSsllIWqLpnS5IJFgt6PDVcQgGXo2ZhVYkoLNhWTIEBuJWIyc4Vj20YpTms',
  'lgHnjeq5rP6781MwAJQnViyJ2SziGK4/+3CoDiQLO1zId42otXBvsbUuLSL5peX4',
  'v2XNVMLJMY5iSfzbBWczecyapiQ3fbVtWgucgrqlrqM3546v+GdATBhGOu8ppf5j',
  '7d1A7ohhBBgRCAAJBQJS1YHUAhsMAAoJELqZP8Ku4Yo6SgoBAIVcZstwz4lyA2et',
  'y61IhKbJCOlQxyem+kepjNapkhKDAQDIDL38bZWU4Rm0nq82Xb4yaI0BCWDcFkHV',
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

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
0uyeibPdgJTjARMuQzDFA8bdbM540vBf5Q==
=WLIN
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

const ecdh_msg_bad = `-----BEGIN PGP MESSAGE-----
Version: ProtonMail
Comment: https://protonmail.com

wV4DlF328rtCW+wSAQdA9FsAz4rCdoxY/oZaa68WMPMXbO+wtHs4ZXtAOJOs
SlwwDaABXYC2dt0hUS2zRAL3gBGf4udH/CKJ1vPE58sNeh0ERYLxPHgwrpqI
oNVWOWH50kUBIdqd7by8RwLOk9GyV6008iFOlOG90mfjvt2g5DsnSB4wEeMg
pVu3fXj8iAKvFxvihwv1M7gNtP14StP6CngvyGVVEHQ=
=mvcB
-----END PGP MESSAGE-----`;

const ecdh_dec_key = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.4.6
Comment: https://openpgpjs.org

xYYEXEBTPxYJKwYBBAHaRw8BAQdAbXBY+2lpOatB+ZLokS/JIWqrVOseja9S
ewQxMKN6ueT+CQMIuUXr0XofC6VgJvFLyLwDlyyvT4I1HWGKZ6W9HUaslKvS
rw362rbMZKKfUtfjRJvpqiIU3Dr7iDkHB5vT7Tp5S7AZ2tNKoh/bwfTKdHsT
1803InFhX3Rlc3RlcjJAcHJvdG9ubWFpbC5jb20iIDxxYV90ZXN0ZXIyQHBy
b3Rvbm1haWwuY29tPsJ3BBAWCgAfBQJcQFM/BgsJBwgDAgQVCAoCAxYCAQIZ
AQIbAwIeAQAKCRClzcrGJTMHyTpjAQCJZ7p0TJBZyPQ8m64N24glaM6oM78q
2Ogpc0e9LcrPowD6AssY2YfUwJNzVFVzR+Lulzu6XVPjn0pXGMhOl03SrQ3H
iwRcQFM/EgorBgEEAZdVAQUBAQdAAgJJUhKvjGWMq1sDhrJgvqbHK1t1W5RF
Xoet5noIlAADAQgH/gkDCOFdJ7Yv2cTZYETRT5+ak/ntmslcAqtk3ebd7Ok3
tQIjO3TYUbkV1eqrpA4I42kGCUkU4Dy26wxuaLRSsO1u/RgXjExZLP9FlWFI
h6lLS1bCYQQYFggACQUCXEBTPwIbDAAKCRClzcrGJTMHyfNBAP9sdyU3GHNR
7+QdwYvQp7wN+2VUd8vIf7iwAHOK1Cj4ywD+NhzjFfGYESJ68nnkrYlYdf+u
OBqYz6mzZAWQZqsjbg4=
=zrks
-----END PGP PRIVATE KEY BLOCK-----`;

const ecdh_msg_bad_2 = `-----BEGIN PGP MESSAGE-----
Version: ProtonMail
Comment: https://protonmail.com

wV4DtM+8giJEGNISAQhA2rYu8+B41rJi6Gsr4TVeKyDtI0KjhhlLZs891rCG
6X4wxNkxCuTJZax7gQZbDKh2kETK/RH75s9g7H/WV9kZ192NTGmMFiKiautH
c5BGRGxM0sDfAQZb3ZsAUORHKPP7FczMv5aMU2Ko7O2FHc06bMdnZ/ag7GMF
Bdl4EizttNTQ5sNCAdIXUoA8BJLHPgPiglnfTqqx3ynkBNMzfH46oKf08oJ+
6CAQhJdif67/iDX8BRtaKDICBpv3b5anJht7irOBqf9XX13SGkmqKYF3T8eB
W7ZV5EdCTC9KU+1BBPfPEi93F4OHsG/Jo80e5MDN24/wNxC67h7kUQiy3H4s
al+5mSAKcIfZJA4NfPJg9zSoHgfRNGI8Q7ao+c8CLPiefGcMsakNsWUdRyBT
SSLH3z/7AH4GxBvhDEEG3cZwmXzZAJMZmzTa+SrsxZzRpGB/aawyRntOWm8w
6Lq9ntq4S8suj/YK62dJpJxFl8xs+COngpMDvCexX9lYlh/r/y4JRQl06oUK
wv7trvi89TkK3821qHxr7XwI1Ncr2qDJVNlN4W+b6WFyLXnXaJAUMyZ/6inm
RR8BoR2KkEAku3Ne/G5QI51ktNJ7cCodeVOkZj8+iip1/AGyjxZCybq/N8rc
bpOWdMhJ6Hy+JzGNY1qNXcHJPw==
=99Fs
-----END PGP MESSAGE-----`;

const ecdh_dec_key_2 = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.4.9
Comment: https://openpgpjs.org

xYYEXEg93hYJKwYBBAHaRw8BAQdAeoA+T4vr3P0hFFsbzJpgy7/ZnKCrlehr
Myk5QAsBYgf+CQMIQ76YL5sEx+Zgr7DLZ5fhQn1U9+8aLIQaIbaT51nEjEMD
7h6mrJmp7oIr4PyijsIU+0LasXh/qlNeVQVWSygDq9L4nXDEGQhlMq3oH1FN
NM07InBha292c2thdGVzdEBwcm90b25tYWlsLmNvbSIgPHBha292c2thdGVz
dEBwcm90b25tYWlsLmNvbT7CdwQQFgoAHwUCXEg93gYLCQcIAwIEFQgKAgMW
AgECGQECGwMCHgEACgkQp7+eOYEhwd6x5AD9E0LA62odFFDH76wjEYrPCvOH
cYM56/5ZqZoGPPmbE98BAKCz/SQ90tiCMmlLEDXGX+a1bi6ttozqrnSQigic
DI4Ix4sEXEg93hIKKwYBBAGXVQEFAQEHQPDXy2mDfbMKOpCBZB2Ic5bfoWGV
iXvCFMnTLRWfGHUkAwEIB/4JAwhxMnjHjyALomBWSsoYxxB6rj6JKnWeikyj
yjXZdZqdK5F+0rk4M0l7lF0wt5PhT2uMCLB7aH/mSFN1cz7sBeJl3w2soJsT
ve/fP/8NfzP0wmEEGBYIAAkFAlxIPd4CGwwACgkQp7+eOYEhwd5MWQEAp0E4
QTnEnG8lYXhOqnOw676oV2kEU6tcTj3DdM+cW/sA/jH3FQQjPf+mA/7xqKIv
EQr2Mx42THr260IFYp5E/rIA
=oA0b
-----END PGP PRIVATE KEY BLOCK-----`;

function withCompression(tests) {
  const compressionTypes = Object.keys(openpgp.enums.compression).map(k => openpgp.enums.compression[k]);

  compressionTypes.forEach(function (compression) {
    const compressionName = openpgp.enums.read(openpgp.enums.compression, compression);
    if (compressionName === 'bzip2') {
      return; // bzip2 compression is not supported.
    }
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

  let rsaGenStub;
  let rsaGenValue = openpgp.crypto.publicKey.rsa.generate(openpgp.util.getWebCryptoAll() ? 2048 : 512, "10001");

  beforeEach(function() {
    rsaGenStub = stub(openpgp.crypto.publicKey.rsa, 'generate');
    rsaGenStub.returns(rsaGenValue);
  });

  afterEach(function() {
    rsaGenStub.restore();
  });

  describe('initWorker, getWorker, destroyWorker - unit tests', function() {
    afterEach(function() {
      openpgp.destroyWorker(); // cleanup worker in case of failure
    });

    it('should work', async function() {
      const workerStub = {
        postMessage: function() {},
        terminate: function() {}
      };
      await Promise.all([
        openpgp.initWorker({
          workers: [workerStub]
        }),
        workerStub.onmessage({ data: { event: 'loaded' } })
      ]);
      expect(openpgp.getWorker()).to.exist;
      openpgp.destroyWorker();
      expect(openpgp.getWorker()).to.not.exist;
    });
  });

  describe('generateKey - validate user ids', function() {
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
          rsaBits: 2048,
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

    it('should delegate to async proxy', async function() {
      const workerStub = {
        postMessage: function() {},
        terminate: function() {}
      };
      await Promise.all([
        openpgp.initWorker({
          workers: [workerStub]
        }),
        workerStub.onmessage({ data: { event: 'loaded' } })
      ]);
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

    it('should work in JS (with worker)', async function() {
      openpgp.config.use_native = false;
      await openpgp.initWorker({ path:'../dist/openpgp.worker.js' });
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
    let publicKeyNoAEAD;
    let zero_copyVal;
    let use_nativeVal;
    let aead_protectVal;
    let aead_modeVal;
    let aead_chunk_size_byteVal;
    let v5_keysVal;

    beforeEach(async function() {
      publicKey = await openpgp.key.readArmored(pub_key);
      expect(publicKey.keys).to.have.length(1);
      expect(publicKey.err).to.not.exist;
      publicKeyNoAEAD = await openpgp.key.readArmored(pub_key);
      privateKey = await openpgp.key.readArmored(priv_key);
      expect(privateKey.keys).to.have.length(1);
      expect(privateKey.err).to.not.exist;
      privateKey_2000_2008 = await openpgp.key.readArmored(priv_key_2000_2008);
      expect(privateKey_2000_2008.keys).to.have.length(1);
      expect(privateKey_2000_2008.err).to.not.exist;
      publicKey_2000_2008 = { keys: [ privateKey_2000_2008.keys[0].toPublic() ] };
      privateKey_2038_2045 = await openpgp.key.readArmored(priv_key_2038_2045);
      expect(privateKey_2038_2045.keys).to.have.length(1);
      expect(privateKey_2038_2045.err).to.not.exist;
      publicKey_2038_2045 = { keys: [ privateKey_2038_2045.keys[0].toPublic() ] };
      privateKey_1337 = await openpgp.key.readArmored(priv_key_expires_1337);
      expect(privateKey_1337.keys).to.have.length(1);
      expect(privateKey_1337.err).to.not.exist;
      publicKey_1337 = { keys: [ privateKey_1337.keys[0].toPublic() ] };
      zero_copyVal = openpgp.config.zero_copy;
      use_nativeVal = openpgp.config.use_native;
      aead_protectVal = openpgp.config.aead_protect;
      aead_modeVal = openpgp.config.aead_mode;
      aead_chunk_size_byteVal = openpgp.config.aead_chunk_size_byte;
      v5_keysVal = openpgp.config.v5_keys;
    });

    afterEach(function() {
      openpgp.config.zero_copy = zero_copyVal;
      openpgp.config.use_native = use_nativeVal;
      openpgp.config.aead_protect = aead_protectVal;
      openpgp.config.aead_mode = aead_modeVal;
      openpgp.config.aead_chunk_size_byte = aead_chunk_size_byteVal;
      openpgp.config.v5_keys = v5_keysVal;
    });

    it('Configuration', async function() {
      openpgp.config.show_version = false;
      openpgp.config.commentstring = 'different';
      if (openpgp.getWorker()) { // init again to trigger config event
        await openpgp.initWorker({ path:'../dist/openpgp.worker.js' });
      }
      return openpgp.encrypt({ publicKeys:publicKey.keys, message:openpgp.message.fromText(plaintext) }).then(function(encrypted) {
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
        await openpgp.initWorker({path: '../dist/openpgp.worker.js', workers, n: 2});

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
        await openpgp.initWorker({path: '../dist/openpgp.worker.js', workers, n: 1 });
      }
    });

    it('Decrypting key with wrong passphrase rejected', async function () {
      await expect(privateKey.keys[0].decrypt('wrong passphrase')).to.eventually.be.rejectedWith('Incorrect key passphrase');
    });

    it('Decrypting key with correct passphrase returns true', async function () {
      expect(await privateKey.keys[0].decrypt(passphrase)).to.be.true;
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
        }).then(function() {
          throw new Error('Should not decrypt with incorrect passphrase');
        }).catch(function(error){
          expect(error.message).to.match(/Incorrect key passphrase/);
        });
      });
    });

    it('Calling decrypt with not decrypted key leads to exception', async function() {
      const encOpt = {
        message: openpgp.message.fromText(plaintext),
        publicKeys: publicKey.keys
      };
      const decOpt = {
        privateKeys: privateKey.keys[0]
      };
      const encrypted = await openpgp.encrypt(encOpt);
      decOpt.message = await openpgp.message.readArmored(encrypted.data);
      await expect(openpgp.decrypt(decOpt)).to.be.rejectedWith('Error decrypting message: Private key is not decrypted.');
    });

    tryTests('CFB mode (asm.js)', tests, {
      if: !(typeof window !== 'undefined' && window.Worker),
      beforeEach: function() {
        openpgp.config.aead_protect = false;
      }
    });

    tryTests('CFB mode (asm.js, worker)', tests, {
      if: typeof window !== 'undefined' && window.Worker,
      before: async function() {
        await openpgp.initWorker({ path:'../dist/openpgp.worker.js' });
      },
      beforeEach: function() {
        openpgp.config.aead_protect = false;
      },
      after: function() {
        openpgp.destroyWorker();
      }
    });

    tryTests('GCM mode (V5 keys)', tests, {
      if: true,
      beforeEach: function() {
        openpgp.config.aead_protect = true;
        openpgp.config.aead_mode = openpgp.enums.aead.experimental_gcm;
        openpgp.config.v5_keys = true;

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
      if: !openpgp.config.ci,
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
      describe('encryptSessionKey, decryptSessionKeys', function() {
        const sk = new Uint8Array([0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01]);

        let decryptedPrivateKey;
        beforeEach(async function() {
          if (!decryptedPrivateKey) {
            expect(await privateKey.keys[0].decrypt(passphrase)).to.be.true;
            decryptedPrivateKey = privateKey;
          }
          privateKey = decryptedPrivateKey;
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

        it('should not decrypt with a key without binding signatures', function() {
          return openpgp.encryptSessionKey({
            data: sk,
            algorithm: 'aes128',
            publicKeys: publicKey.keys
          }).then(async function(encrypted) {
            const invalidPrivateKey = (await openpgp.key.readArmored(priv_key)).keys[0];
            invalidPrivateKey.subKeys[0].bindingSignatures = [];
            return openpgp.decryptSessionKeys({
              message: encrypted.message,
              privateKeys: invalidPrivateKey
            }).then(() => {
              throw new Error('Should not decrypt with invalid key');
            }).catch(error => {
              expect(error.message).to.match(/Error decrypting session keys: Session key decryption failed./);
            });
          });
        });

        it('roundtrip workflow: encrypt, decryptSessionKeys, decrypt with pgp key pair', function () {
          let msgAsciiArmored;
          return openpgp.encrypt({
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys
          }).then(async function (encrypted) {
            msgAsciiArmored = encrypted.data;
            return openpgp.decryptSessionKeys({
              message: await openpgp.message.readArmored(msgAsciiArmored),
              privateKeys: privateKey.keys[0]
            });

          }).then(async function (decryptedSessionKeys) {
            const message = await openpgp.message.readArmored(msgAsciiArmored);
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
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys
          }).then(async function (encrypted) {
            msgAsciiArmored = encrypted.data;
            return openpgp.decryptSessionKeys({
              message: await openpgp.message.readArmored(msgAsciiArmored),
              privateKeys: privateKey.keys[0]
            });

          }).then(async function (decryptedSessionKeys) {
            const message = await openpgp.message.readArmored(msgAsciiArmored);
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
            message: openpgp.message.fromText(plaintext),
            passwords: password1
          }).then(async function (encrypted) {
            msgAsciiArmored = encrypted.data;
            return openpgp.decryptSessionKeys({
              message: await openpgp.message.readArmored(msgAsciiArmored),
              passwords: password1
            });

          }).then(async function (decryptedSessionKeys) {
            return openpgp.decrypt({
              sessionKeys: decryptedSessionKeys[0],
              message: await openpgp.message.readArmored(msgAsciiArmored)
            });

          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
          });
        });

        it('roundtrip workflow: encrypt with multiple passwords, decryptSessionKeys, decrypt with multiple passwords', function () {
          let msgAsciiArmored;
          return openpgp.encrypt({
            message: openpgp.message.fromText(plaintext),
            passwords: [password1, password2]
          }).then(async function (encrypted) {
            msgAsciiArmored = encrypted.data;
            return openpgp.decryptSessionKeys({
              message: await openpgp.message.readArmored(msgAsciiArmored),
              passwords: [password1, password2]
            });

          }).then(async function (decryptedSessionKeys) {
            return openpgp.decrypt({
              sessionKeys: decryptedSessionKeys,
              message: await openpgp.message.readArmored(msgAsciiArmored)
            });

          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
          });
        });

        it('roundtrip workflow: encrypt twice with one password, decryptSessionKeys, only one session key', function () {
          let msgAsciiArmored;
          return openpgp.encrypt({
            message: openpgp.message.fromText(plaintext),
            passwords: [password1, password1]
          }).then(async function (encrypted) {
            msgAsciiArmored = encrypted.data;
            return openpgp.decryptSessionKeys({
              message: await openpgp.message.readArmored(msgAsciiArmored),
              passwords: password1
            });
          }).then(async function (decryptedSessionKeys) {
            expect(decryptedSessionKeys.length).to.equal(1);
            return openpgp.decrypt({
              sessionKeys: decryptedSessionKeys,
              message: await openpgp.message.readArmored(msgAsciiArmored)
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

        let decryptedPrivateKey;
        beforeEach(async function() {
          if (!decryptedPrivateKey) {
            expect(await privateKey.keys[0].decrypt(passphrase)).to.be.true;
            decryptedPrivateKey = privateKey;
          }
          privateKey = decryptedPrivateKey;
        });

        it('should encrypt then decrypt', function () {
          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            expect(encrypted.data).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures).to.exist;
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt then decrypt with multiple private keys', async function () {
          const privKeyDE = (await openpgp.key.readArmored(priv_key_de)).keys[0];
          await privKeyDE.decrypt(passphrase);

          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys
          };
          const decOpt = {
            privateKeys: [privKeyDE, privateKey.keys[0]]
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            expect(encrypted.data).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures).to.exist;
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt then decrypt with wildcard', function () {
          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys,
            wildcard: true
          };
          const decOpt = {
            privateKeys: privateKey.keys
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            expect(encrypted.data).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures).to.exist;
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt then decrypt with wildcard with multiple private keys', async function () {
          const privKeyDE = (await openpgp.key.readArmored(priv_key_de)).keys[0];
          await privKeyDE.decrypt(passphrase);

          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys,
            wildcard: true
          };
          const decOpt = {
            privateKeys: [privKeyDE, privateKey.keys[0]]
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            expect(encrypted.data).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures).to.exist;
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt then decrypt using returned session key', function () {
          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys,
            returnSessionKey: true
          };

          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            expect(encrypted.data).to.match(/^-----BEGIN PGP MESSAGE/);
            const decOpt = {
              sessionKeys: encrypted.sessionKey,
              message: await openpgp.message.readArmored(encrypted.data)
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
            message: openpgp.message.fromText(plaintext),
            sessionKey: sessionKey,
            publicKeys: publicKey.keys
          };
          const decOpt = {
            sessionKeys: sessionKey
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            expect(encrypted.data).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            expect(!!decOpt.message.packets.findPacket(openpgp.enums.packet.symEncryptedAEADProtected)).to.equal(false);
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
            message: openpgp.message.fromText(plaintext),
            sessionKey: sessionKey,
            publicKeys: publicKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys[0]
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            expect(encrypted.data).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            expect(!!decOpt.message.packets.findPacket(openpgp.enums.packet.symEncryptedAEADProtected)).to.equal(false);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
          });
        });

        it('should encrypt/sign and decrypt/verify', function () {
          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: publicKey.keys
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
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

        it('should encrypt/sign and decrypt/verify (no AEAD support)', function () {
          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKeyNoAEAD.keys,
            privateKeys: privateKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: publicKeyNoAEAD.keys
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            expect(!!decOpt.message.packets.findPacket(openpgp.enums.packet.symEncryptedAEADProtected)).to.equal(false);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.true;
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

          return openpgp.generateKey(genOpt).then(async function(newKey) {
            const newPublicKey = await openpgp.key.readArmored(newKey.publicKeyArmored);
            const newPrivateKey = await openpgp.key.readArmored(newKey.privateKeyArmored);

            const encOpt = {
              message: openpgp.message.fromText(plaintext),
              publicKeys: newPublicKey.keys,
              privateKeys: newPrivateKey.keys
            };
            const decOpt = {
              privateKeys: newPrivateKey.keys[0],
              publicKeys: newPublicKey.keys
            };
            return openpgp.encrypt(encOpt).then(async function (encrypted) {
              decOpt.message = await openpgp.message.readArmored(encrypted.data);
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

        it('should encrypt/sign and decrypt/verify with generated key and detached signatures', function () {
          const genOpt = {
            userIds: [{ name: 'Test User', email: 'text@example.com' }],
            numBits: 512
          };
          if (openpgp.util.getWebCryptoAll()) { genOpt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys

          return openpgp.generateKey(genOpt).then(async function(newKey) {
            const newPublicKey = await openpgp.key.readArmored(newKey.publicKeyArmored);
            const newPrivateKey = await openpgp.key.readArmored(newKey.privateKeyArmored);

            const encOpt = {
              message: openpgp.message.fromText(plaintext),
              publicKeys: newPublicKey.keys,
              privateKeys: newPrivateKey.keys,
              detached: true
            };
            const decOpt = {
              privateKeys: newPrivateKey.keys[0],
              publicKeys: newPublicKey.keys
            };
            return openpgp.encrypt(encOpt).then(async function (encrypted) {
              decOpt.message = await openpgp.message.readArmored(encrypted.data);
              decOpt.signature = await openpgp.signature.readArmored(encrypted.signature);
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
            message: openpgp.message.fromText(''),
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: publicKey.keys
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
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
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys,
            detached: true
          };
          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: publicKey.keys
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            decOpt.signature = await openpgp.signature.readArmored(encrypted.signature);
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
            message: openpgp.message.fromText(plaintext),
            privateKeys: privateKey.keys[0],
            detached: true
          };

          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys,
            detached: true
          };

          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: publicKey.keys[0]
          };

          return openpgp.sign(signOpt).then(async function (signed) {
            encOpt.signature = await openpgp.signature.readArmored(signed.signature);
            return openpgp.encrypt(encOpt);
          }).then(async function (encrypted) {
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            decOpt.signature = await openpgp.signature.readArmored(encrypted.signature);
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
          const plaintext = "  \t┍ͤ޵၂༫዇◧˘˻ᙑ᎚⏴ំந⛑nٓኵΉⅶ⋋ŵ⋲΂ͽᣏ₅ᄶɼ┋⌔û᬴Ƚᔡᧅ≃ṱἆ⃷݂૿ӌ᰹෇ٹჵ⛇໶⛌  \t\n한국어/조선말";

          const privKeyDE = (await openpgp.key.readArmored(priv_key_de)).keys[0];
          await privKeyDE.decrypt(passphrase);

          const pubKeyDE = (await openpgp.key.readArmored(pub_key_de)).keys[0];

          const signOpt = {
            message: openpgp.message.fromText(plaintext),
            privateKeys: privKeyDE,
            detached: true
          };

          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys[0]
          };

          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: [publicKey.keys[0], pubKeyDE]
          };

          return openpgp.sign(signOpt).then(async function (signed) {
            encOpt.signature = await openpgp.signature.readArmored(signed.signature);
            return openpgp.encrypt(encOpt);
          }).then(async function (encrypted) {
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
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

        it('should fail to encrypt and decrypt/verify with detached signature input and detached flag set for encryption with wrong public key', async function () {
          const signOpt = {
            message: openpgp.message.fromText(plaintext),
            privateKeys: privateKey.keys,
            detached: true
          };

          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys,
            detached: true
          };

          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: (await openpgp.key.readArmored(wrong_pubkey)).keys
          };

          return openpgp.sign(signOpt).then(async function (signed) {
            encOpt.signature = await openpgp.signature.readArmored(signed.signature);
            return openpgp.encrypt(encOpt);
          }).then(async function (encrypted) {
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            decOpt.signature = await openpgp.signature.readArmored(encrypted.signature);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should fail to encrypt and decrypt/verify with detached signature as input and detached flag not set for encryption with wrong public key', async function () {
          const signOpt = {
            message: openpgp.message.fromText(plaintext),
            privateKeys: privateKey.keys,
            detached: true
          };

          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys
          };

          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: (await openpgp.key.readArmored(wrong_pubkey)).keys
          };

          return openpgp.sign(signOpt).then(async function (signed) {
            encOpt.signature = await openpgp.signature.readArmored(signed.signature);
            return openpgp.encrypt(encOpt);
          }).then(async function (encrypted) {
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should fail to verify decrypted data with wrong public pgp key', async function () {
          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: (await openpgp.key.readArmored(wrong_pubkey)).keys
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should fail to verify decrypted null string with wrong public pgp key', async function () {
          const encOpt = {
            message: openpgp.message.fromText(''),
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: (await openpgp.key.readArmored(wrong_pubkey)).keys
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal('');
            expect(decrypted.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should successfully decrypt signed message without public keys to verify', async function () {
          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys
          };
          const decOpt = {
            privateKeys: privateKey.keys[0]
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.keys[0].getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should fail to verify decrypted data with wrong public pgp key with detached signatures', async function () {
          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys,
            privateKeys: privateKey.keys,
            detached: true
          };
          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: (await openpgp.key.readArmored(wrong_pubkey)).keys
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            decOpt.signature = await openpgp.signature.readArmored(encrypted.signature);
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
          const privKeyDE = (await openpgp.key.readArmored(priv_key_de)).keys[0];
          await privKeyDE.decrypt(passphrase);

          const pubKeyDE = (await openpgp.key.readArmored(pub_key_de)).keys[0];

          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            publicKeys: publicKey.keys,
            privateKeys: [privateKey.keys[0], privKeyDE]
          };

          const decOpt = {
            privateKeys: privateKey.keys[0],
            publicKeys: [publicKey.keys[0], pubKeyDE]
          };

          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
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

        it('should fail to decrypt modified message', async function() {
          const { privateKeyArmored } = await openpgp.generateKey({ curve: 'curve25519', userIds: [{ email: 'test@email.com' }] });
          const { keys: [key] } = await openpgp.key.readArmored(privateKeyArmored);
          const { data } = await openpgp.encrypt({ message: openpgp.message.fromBinary(new Uint8Array(500)), publicKeys: [key.toPublic()] });
          let badSumEncrypted = data.replace(/\n=[a-zA-Z0-9/+]{4}/, '\n=aaaa');
          if (badSumEncrypted === data) { // checksum was already =aaaa
            badSumEncrypted = data.replace(/\n=[a-zA-Z0-9/+]{4}/, '\n=bbbb');
          }
          if (badSumEncrypted === data) {
            throw new Error("Was not able to successfully modify checksum");
          }
          const badBodyEncrypted = data.replace(/\n=([a-zA-Z0-9/+]{4})/, 'aaa\n=$1');
          for (let allow_streaming = 1; allow_streaming >= 0; allow_streaming--) {
            openpgp.config.allow_unauthenticated_stream = !!allow_streaming;
            if (openpgp.getWorker()) {
              openpgp.getWorker().workers.forEach(worker => {
                worker.postMessage({ event: 'configure', config: openpgp.config });
              });
            }
            await Promise.all([badSumEncrypted, badBodyEncrypted].map(async (encrypted, i) => {
              await Promise.all([
                encrypted,
                openpgp.stream.toStream(encrypted),
                new ReadableStream({
                  start() {
                    this.remaining = encrypted.split('\n');
                  },
                  async pull(controller) {
                    if (this.remaining.length) {
                      await new Promise(res => setTimeout(res));
                      controller.enqueue(this.remaining.shift() + '\n');
                    } else {
                      controller.close();
                    }
                  }
                })
              ].map(async (encrypted, j) => {
                let stepReached = 0;
                try {
                  const message = await openpgp.message.readArmored(encrypted);
                  stepReached = 1;
                  const { data: decrypted } = await openpgp.decrypt({ message: message, privateKeys: [key] });
                  stepReached = 2;
                  await openpgp.stream.readToEnd(decrypted);
                } catch (e) {
                  expect(e.message).to.match(/Ascii armor integrity check on message failed/);
                  expect(stepReached).to.equal(
                    j === 0 ? 0 :
                      (openpgp.config.aead_chunk_size_byte === 0 && (j === 2 || openpgp.util.detectNode() || openpgp.util.getHardwareConcurrency() < 8)) || (!openpgp.config.aead_protect && openpgp.config.allow_unauthenticated_stream) ? 2 :
                      1
                  );
                  return;
                }
                throw new Error(`Expected "Ascii armor integrity check on message failed" error in subtest ${i}.${j}`);
              }));
            }));
          }
        });
      });

      describe('ELG / DSA encrypt, decrypt, sign, verify', function() {

        it('round trip test', async function () {
          const pubKeyDE = (await openpgp.key.readArmored(pub_key_de)).keys[0];
          const privKeyDE = (await openpgp.key.readArmored(priv_key_de)).keys[0];
          await privKeyDE.decrypt(passphrase);
          pubKeyDE.users[0].selfCertifications[0].features = [7]; // Monkey-patch AEAD feature flag
          return openpgp.encrypt({
            publicKeys: pubKeyDE,
            privateKeys: privKeyDE,
            message: openpgp.message.fromText(plaintext)
          }).then(async function (encrypted) {
            return openpgp.decrypt({
              privateKeys: privKeyDE,
              publicKeys: pubKeyDE,
              message: await openpgp.message.readArmored(encrypted.data)
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
          const privKey = (await openpgp.key.readArmored(priv_key)).keys[0];
          await privKey.decrypt('1234');
          const message = await openpgp.message.readArmored(pgp_msg);

          return openpgp.decrypt({ privateKeys:privKey, message:message }).then(function(decrypted) {
            expect(decrypted.data).to.equal('hello 3des\n');
            expect(decrypted.signatures.length).to.equal(0);
          });
        });
      });

      describe('AES encrypt, decrypt', function() {

        it('should encrypt and decrypt with one password', function () {
          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            passwords: password1
          };
          const decOpt = {
            passwords: password1
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt and decrypt with two passwords', function () {
          const encOpt = {
            message: openpgp.message.fromText(plaintext),
            passwords: [password1, password2]
          };
          const decOpt = {
            passwords: password2
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.message.readArmored(encrypted.data);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt and decrypt with password and not ascii armor', function () {
          const encOpt = {
            message: openpgp.message.fromText(plaintext),
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
            message: openpgp.message.fromBinary(new Uint8Array([0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01])),
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
              if (navigator.userAgent.indexOf('Safari') !== -1 && (navigator.userAgent.indexOf('Version/11.1') !== -1 || (navigator.userAgent.match(/Chrome\/(\d+)/) || [])[1] < 56)) {
                expect(encOpt.message.packets[0].data.byteLength).to.equal(8); // browser doesn't support transfering buffers
              } else {
                expect(encOpt.message.packets[0].data.byteLength).to.equal(0); // transferred buffer should be empty
              }
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
              message: openpgp.message.fromText(plaintext),
              passwords: password1
            });
            const decOpt = {
              passwords: password1
            };
            return openpgp.encrypt(encOpt).then(async function (encrypted) {
              decOpt.message = await openpgp.message.readArmored(encrypted.data);
              return openpgp.decrypt(decOpt);
            }).then(function (decrypted) {
              expect(decrypted.data).to.equal(plaintext);
              expect(decrypted.signatures.length).to.equal(0);
              verifyCompressionDecrypted(decrypted);
            });
          });

          it('Streaming encrypt and decrypt small message roundtrip', async function() {
            let plaintext = [];
            let i = 0;
            const data = new ReadableStream({
              async pull(controller) {
                if (i++ < 4) {
                  let randomBytes = await openpgp.crypto.random.getRandomBytes(10);
                  controller.enqueue(randomBytes);
                  plaintext.push(randomBytes.slice());
                } else {
                  controller.close();
                }
              }
            });
            const encrypted = await openpgp.encrypt(modifyCompressionEncryptOptions({
              message: openpgp.message.fromBinary(data),
              passwords: ['test'],
            }));

            const msgAsciiArmored = encrypted.data;
            const message = await openpgp.message.readArmored(msgAsciiArmored);
            const decrypted = await openpgp.decrypt({
              passwords: ['test'],
              message,
              format: 'binary'
            });
            expect(openpgp.util.isStream(decrypted.data)).to.equal('web');
            expect(await openpgp.stream.readToEnd(decrypted.data)).to.deep.equal(openpgp.util.concatUint8Array(plaintext));
          });
        });
      });

    }

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

      let decryptedPrivateKey;
      beforeEach(async function() {
        if (!decryptedPrivateKey) {
          expect(await privateKey.keys[0].decrypt(passphrase)).to.be.true;
          decryptedPrivateKey = privateKey;
        }
        privateKey = decryptedPrivateKey;
      });

      it('should sign and verify cleartext data', function () {
        const message = openpgp.cleartext.fromText(plaintext);
        const signOpt = {
          message,
          privateKeys: privateKey.keys
        };
        const verifyOpt = {
          publicKeys: publicKey.keys
        };
        return openpgp.sign(signOpt).then(async function (signed) {
          expect(signed.data).to.match(/-----BEGIN PGP SIGNED MESSAGE-----/);
          verifyOpt.message = await openpgp.cleartext.readArmored(signed.data);
          return openpgp.verify(verifyOpt);
        }).then(async function (verified) {
          expect(verified.data).to.equal(plaintext.replace(/[ \t]+$/mg, ''));
          expect(verified.signatures[0].valid).to.be.true;
          const signingKey = await privateKey.keys[0].getSigningKey();
          expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(verified.signatures[0].signature.packets.length).to.equal(1);
        });
      });

      it('should sign and verify cleartext data with multiple private keys', async function () {
        const privKeyDE = (await openpgp.key.readArmored(priv_key_de)).keys[0];
        await privKeyDE.decrypt(passphrase);

        const message = openpgp.cleartext.fromText(plaintext);
        const signOpt = {
          message,
          privateKeys: [privateKey.keys[0], privKeyDE]
        };
        const verifyOpt = {
          publicKeys: [publicKey.keys[0], privKeyDE.toPublic()]
        };
        return openpgp.sign(signOpt).then(async function (signed) {
          expect(signed.data).to.match(/-----BEGIN PGP SIGNED MESSAGE-----/);
          verifyOpt.message = await openpgp.cleartext.readArmored(signed.data);
          return openpgp.verify(verifyOpt);
        }).then(async function (verified) {
          let signingKey;
          expect(verified.data).to.equal(plaintext.replace(/[ \t]+$/mg, ''));
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
        const message = openpgp.cleartext.fromText(plaintext);
        const signOpt = {
          message,
          privateKeys: privateKey.keys,
          detached: true
        };
        const verifyOpt = {
          message,
          publicKeys: publicKey.keys
        };
        return openpgp.sign(signOpt).then(async function (signed) {
          verifyOpt.signature = await openpgp.signature.readArmored(signed.signature);
          return openpgp.verify(verifyOpt);
        }).then(async function (verified) {
          expect(verified.data).to.equal(plaintext.replace(/[ \t]+$/mg, ''));
          expect(verified.signatures[0].valid).to.be.true;
          const signingKey = await privateKey.keys[0].getSigningKey();
          expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(verified.signatures[0].signature.packets.length).to.equal(1);
        });
      });

      it('should sign and fail to verify cleartext data with wrong public pgp key', async function () {
        const message = openpgp.cleartext.fromText(plaintext);
        const signOpt = {
          message,
          privateKeys: privateKey.keys
        };
        const verifyOpt = {
          publicKeys: (await openpgp.key.readArmored(wrong_pubkey)).keys
        };
        return openpgp.sign(signOpt).then(async function (signed) {
          verifyOpt.message = await openpgp.cleartext.readArmored(signed.data);
          return openpgp.verify(verifyOpt);
        }).then(async function (verified) {
          expect(verified.data).to.equal(plaintext.replace(/[ \t]+$/mg, ''));
          expect(verified.signatures[0].valid).to.be.null;
          const signingKey = await privateKey.keys[0].getSigningKey();
          expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(verified.signatures[0].signature.packets.length).to.equal(1);
        });
      });

      it('should sign and fail to verify cleartext data with wrong public pgp key with detached signature', async function () {
        const message = openpgp.cleartext.fromText(plaintext);
        const signOpt = {
          message,
          privateKeys: privateKey.keys,
          detached: true
        };
        const verifyOpt = {
          message,
          publicKeys: (await openpgp.key.readArmored(wrong_pubkey)).keys
        };
        return openpgp.sign(signOpt).then(async function (signed) {
          verifyOpt.signature = await openpgp.signature.readArmored(signed.signature);
          return openpgp.verify(verifyOpt);
        }).then(async function (verified) {
          expect(verified.data).to.equal(plaintext.replace(/[ \t]+$/mg, ''));
          expect(verified.signatures[0].valid).to.be.null;
          const signingKey = await privateKey.keys[0].getSigningKey();
          expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(verified.signatures[0].signature.packets.length).to.equal(1);
        });
      });

      it('should sign and verify cleartext data and not armor', function () {
        const message = openpgp.cleartext.fromText(plaintext);
        const signOpt = {
          message,
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
          expect(verified.data).to.equal(plaintext.replace(/[ \t]+$/mg, ''));
          expect(verified.signatures[0].valid).to.be.true;
          const signingKey = await privateKey.keys[0].getSigningKey();
          expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(verified.signatures[0].signature.packets.length).to.equal(1);
        });
      });

      it('should sign and verify cleartext data and not armor with detached signatures', function () {
          const start = openpgp.util.normalizeDate();
          const message = openpgp.cleartext.fromText(plaintext);
          const signOpt = {
              message,
              privateKeys: privateKey.keys,
              detached: true,
              armor: false
          };
          const verifyOpt = {
              message,
              publicKeys: publicKey.keys
          };
          return openpgp.sign(signOpt).then(function (signed) {
              verifyOpt.signature = signed.signature;
              return openpgp.verify(verifyOpt);
          }).then(async function (verified) {
              expect(verified.data).to.equal(plaintext.replace(/[ \t]+$/mg, ''));
              expect(+verified.signatures[0].signature.packets[0].created).to.be.lte(+openpgp.util.normalizeDate());
              expect(+verified.signatures[0].signature.packets[0].created).to.be.gte(+start);
              expect(verified.signatures[0].valid).to.be.true;
              const signingKey = await privateKey.keys[0].getSigningKey();
              expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
              expect(verified.signatures[0].signature.packets.length).to.equal(1);
          });
      });

      it('should sign and verify cleartext data with a date in the past', function () {
          const message = openpgp.cleartext.fromText(plaintext);
          const past = new Date(2000);
          const signOpt = {
              message,
              privateKeys: privateKey_1337.keys,
              detached: true,
              date: past,
              armor: false
          };
          const verifyOpt = {
              message,
              publicKeys: publicKey_1337.keys,
              date: past
          };
          return openpgp.sign(signOpt).then(function (signed) {
              verifyOpt.signature = signed.signature;
              return openpgp.verify(verifyOpt).then(async function (verified) {
                expect(+verified.signatures[0].signature.packets[0].created).to.equal(+past);
                expect(verified.data).to.equal(plaintext.replace(/[ \t]+$/mg, ''));
                expect(verified.signatures[0].valid).to.be.true;
                expect(await signOpt.privateKeys[0].getSigningKey(verified.signatures[0].keyid, past))
                    .to.be.not.null;
                expect(verified.signatures[0].signature.packets.length).to.equal(1);
                // now check with expiration checking disabled
                verifyOpt.date = null;
                return openpgp.verify(verifyOpt);
              }).then(async function (verified) {
                expect(+verified.signatures[0].signature.packets[0].created).to.equal(+past);
                expect(verified.data).to.equal(plaintext.replace(/[ \t]+$/mg, ''));
                expect(verified.signatures[0].valid).to.be.true;
                expect(await signOpt.privateKeys[0].getSigningKey(verified.signatures[0].keyid, null))
                    .to.be.not.null;
                expect(verified.signatures[0].signature.packets.length).to.equal(1);
              });
          });
      });

      it('should sign and verify binary data with a date in the future', function () {
          const future = new Date(2040, 5, 5, 5, 5, 5, 0);
          const data = new Uint8Array([3, 14, 15, 92, 65, 35, 59]);
          const signOpt = {
            message: openpgp.message.fromBinary(data),
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
          }).then(async function (verified) {
            expect(+verified.signatures[0].signature.packets[0].created).to.equal(+future);
            expect([].slice.call(verified.data)).to.deep.equal([].slice.call(data));
            expect(verified.signatures[0].valid).to.be.true;
            expect(await signOpt.privateKeys[0].getSigningKey(verified.signatures[0].keyid, future))
                .to.be.not.null;
            expect(verified.signatures[0].signature.packets.length).to.equal(1);
          });
      });

      it('should sign and verify binary data without one-pass signature', function () {
          const data = new Uint8Array([3, 14, 15, 92, 65, 35, 59]);
          const signOpt = {
            message: openpgp.message.fromBinary(data),
            privateKeys: privateKey.keys,
            armor: false
          };
          const verifyOpt = {
            publicKeys: publicKey.keys
          };
          return openpgp.sign(signOpt).then(function (signed) {
            const packets = new openpgp.packet.List();
            packets.push(signed.message.packets.findPacket(openpgp.enums.packet.signature));
            packets.push(signed.message.packets.findPacket(openpgp.enums.packet.literal));
            verifyOpt.message = new openpgp.message.Message(packets);
            return openpgp.verify(verifyOpt);
          }).then(async function (verified) {
            expect([].slice.call(verified.data)).to.deep.equal([].slice.call(data));
            expect(verified.signatures[0].valid).to.be.true;
            expect(await signOpt.privateKeys[0].getSigningKey(verified.signatures[0].keyid))
                .to.be.not.null;
            expect(verified.signatures[0].signature.packets.length).to.equal(1);
          });
      });

      it('should streaming sign and verify binary data without one-pass signature', function () {
          const data = new Uint8Array([3, 14, 15, 92, 65, 35, 59]);
          const signOpt = {
            message: openpgp.message.fromBinary(data),
            privateKeys: privateKey.keys,
            armor: false,
            streaming: 'web'
          };
          const verifyOpt = {
            publicKeys: publicKey.keys,
            streaming: 'web'
          };
          return openpgp.sign(signOpt).then(function (signed) {
            const packets = new openpgp.packet.List();
            packets.push(signed.message.packets.findPacket(openpgp.enums.packet.signature));
            packets.push(signed.message.packets.findPacket(openpgp.enums.packet.literal));
            verifyOpt.message = new openpgp.message.Message(packets);
            return openpgp.verify(verifyOpt);
          }).then(async function (verified) {
            expect(openpgp.stream.isStream(verified.data)).to.equal('web');
            expect([].slice.call(await openpgp.stream.readToEnd(verified.data))).to.deep.equal([].slice.call(data));
            expect(await verified.signatures[0].verified).to.be.true;
            expect(await signOpt.privateKeys[0].getSigningKey(verified.signatures[0].keyid))
                .to.be.not.null;
            expect((await verified.signatures[0].signature).packets.length).to.equal(1);
          });
      });

      it('should encrypt and decrypt cleartext data with a date in the future', function () {
          const future = new Date(2040, 5, 5, 5, 5, 5, 0);
          const encryptOpt = {
              message: openpgp.message.fromText(plaintext, undefined, future),
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
          }).then(async function (packets) {
              const literals = packets.packets.filterByTag(openpgp.enums.packet.literal);
              expect(literals.length).to.equal(1);
              expect(+literals[0].date).to.equal(+future);
              expect(await openpgp.stream.readToEnd(packets.getText())).to.equal(plaintext);
          });
      });

      it('should encrypt and decrypt binary data with a date in the past', function () {
          const past = new Date(2005, 5, 5, 5, 5, 5, 0);
          const data = new Uint8Array([3, 14, 15, 92, 65, 35, 59]);
          const encryptOpt = {
              message: openpgp.message.fromBinary(data, undefined, past),
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
          }).then(async function (packets) {
              const literals = packets.packets.filterByTag(openpgp.enums.packet.literal);
              expect(literals.length).to.equal(1);
              expect(+literals[0].date).to.equal(+past);
              expect(await openpgp.stream.readToEnd(packets.getLiteralData())).to.deep.equal(data);
          });
      });

      it('should sign, encrypt and decrypt, verify cleartext data with a date in the past', function () {
          const past = new Date(2005, 5, 5, 5, 5, 5, 0);
          const encryptOpt = {
              message: openpgp.message.fromText(plaintext, undefined, past),
              publicKeys: publicKey_2000_2008.keys,
              privateKeys: privateKey_2000_2008.keys,
              date: past,
              armor: false
          };

          return openpgp.encrypt(encryptOpt).then(function (encrypted) {
              return encrypted.message.decrypt(encryptOpt.privateKeys);
          }).then(async function (packets) {
              const literals = packets.packets.filterByTag(openpgp.enums.packet.literal);
              expect(literals.length).to.equal(1);
              expect(+literals[0].date).to.equal(+past);
              const signatures = await packets.verify(encryptOpt.publicKeys, past);
              expect(await openpgp.stream.readToEnd(packets.getText())).to.equal(plaintext);
              expect(+(await signatures[0].signature).packets[0].created).to.equal(+past);
              expect(await signatures[0].verified).to.be.true;
              expect(await encryptOpt.privateKeys[0].getSigningKey(signatures[0].keyid, past))
                  .to.be.not.null;
              expect((await signatures[0].signature).packets.length).to.equal(1);
          });
      });

      it('should sign, encrypt and decrypt, verify binary data with a date in the future', function () {
          const future = new Date(2040, 5, 5, 5, 5, 5, 0);
          const data = new Uint8Array([3, 14, 15, 92, 65, 35, 59]);
          const encryptOpt = {
              message: openpgp.message.fromBinary(data, undefined, future),
              publicKeys: publicKey_2038_2045.keys,
              privateKeys: privateKey_2038_2045.keys,
              date: future,
              armor: false
          };

          return openpgp.encrypt(encryptOpt).then(function (encrypted) {
              return encrypted.message.decrypt(encryptOpt.privateKeys);
          }).then(async function (packets) {
              const literals = packets.packets.filterByTag(openpgp.enums.packet.literal);
              expect(literals.length).to.equal(1);
              expect(literals[0].format).to.equal('binary');
              expect(+literals[0].date).to.equal(+future);
              const signatures = await packets.verify(encryptOpt.publicKeys, future);
              expect(await openpgp.stream.readToEnd(packets.getLiteralData())).to.deep.equal(data);
              expect(+(await signatures[0].signature).packets[0].created).to.equal(+future);
              expect(await signatures[0].verified).to.be.true;
              expect(await encryptOpt.privateKeys[0].getSigningKey(signatures[0].keyid, future))
                  .to.be.not.null;
              expect((await signatures[0].signature).packets.length).to.equal(1);
          });
      });

      it('should sign, encrypt and decrypt, verify mime data with a date in the future', function () {
          const future = new Date(2040, 5, 5, 5, 5, 5, 0);
          const data = new Uint8Array([3, 14, 15, 92, 65, 35, 59]);
          const encryptOpt = {
              message: openpgp.message.fromBinary(data, undefined, future, 'mime'),
              publicKeys: publicKey_2038_2045.keys,
              privateKeys: privateKey_2038_2045.keys,
              date: future,
              armor: false
          };

          return openpgp.encrypt(encryptOpt).then(function (encrypted) {
              return encrypted.message.decrypt(encryptOpt.privateKeys);
          }).then(async function (packets) {
              const literals = packets.packets.filterByTag(openpgp.enums.packet.literal);
              expect(literals.length).to.equal(1);
              expect(literals[0].format).to.equal('mime');
              expect(+literals[0].date).to.equal(+future);
              const signatures = await packets.verify(encryptOpt.publicKeys, future);
              expect(await openpgp.stream.readToEnd(packets.getLiteralData())).to.deep.equal(data);
              expect(+(await signatures[0].signature).packets[0].created).to.equal(+future);
              expect(await signatures[0].verified).to.be.true;
              expect(await encryptOpt.privateKeys[0].getSigningKey(signatures[0].keyid, future))
                  .to.be.not.null;
              expect((await signatures[0].signature).packets.length).to.equal(1);
          });
      });

      it('should fail to encrypt with revoked key', function() {
        return openpgp.revokeKey({
          key: privateKey.keys[0]
        }).then(function(revKey) {
          return openpgp.encrypt({
            message: openpgp.message.fromText(plaintext),
            publicKeys: revKey.publicKey
          }).then(function() {
            throw new Error('Should not encrypt with revoked key');
          }).catch(function(error) {
            expect(error.message).to.match(/Error encrypting message: Primary key is revoked/);
          });
        });
      });

      it('should fail to encrypt with revoked subkey', async function() {
        const pubKeyDE = (await openpgp.key.readArmored(pub_key_de)).keys[0];
        const privKeyDE = (await openpgp.key.readArmored(priv_key_de)).keys[0];
        await privKeyDE.decrypt(passphrase);
        return privKeyDE.subKeys[0].revoke(privKeyDE.primaryKey).then(function(revSubKey) {
          pubKeyDE.subKeys[0] = revSubKey;
          return openpgp.encrypt({
            message: openpgp.message.fromText(plaintext),
            publicKeys: pubKeyDE
          }).then(function() {
            throw new Error('Should not encrypt with revoked subkey');
          }).catch(function(error) {
            expect(error.message).to.match(/Could not find valid encryption key packet/);
          });
        });
      });

      it('should decrypt with revoked subkey', async function() {
        const pubKeyDE = (await openpgp.key.readArmored(pub_key_de)).keys[0];
        const privKeyDE = (await openpgp.key.readArmored(priv_key_de)).keys[0];
        await privKeyDE.decrypt(passphrase);
        const encrypted = await openpgp.encrypt({
          message: openpgp.message.fromText(plaintext),
          publicKeys: pubKeyDE
        });
        privKeyDE.subKeys[0] = await privKeyDE.subKeys[0].revoke(privKeyDE.primaryKey);
        const decOpt = {
          message: await openpgp.message.readArmored(encrypted.data),
          privateKeys: privKeyDE
        };
        const decrypted = await openpgp.decrypt(decOpt);
        expect(decrypted.data).to.equal(plaintext);
      });

      it('should not decrypt with corrupted subkey', async function() {
        const pubKeyDE = (await openpgp.key.readArmored(pub_key_de)).keys[0];
        const privKeyDE = (await openpgp.key.readArmored(priv_key_de)).keys[0];
        // corrupt the public key params
        privKeyDE.subKeys[0].keyPacket.params[0].data[0]++;
        // validation will not check the decryption subkey and will succeed
        await privKeyDE.decrypt(passphrase);
        const encrypted = await openpgp.encrypt({
          message: openpgp.message.fromText(plaintext),
          publicKeys: pubKeyDE
        });
        const decOpt = {
          message: await openpgp.message.readArmored(encrypted.data),
          privateKeys: privKeyDE
        };
        // binding signature is invalid
        await expect(openpgp.decrypt(decOpt)).to.be.rejectedWith(/Session key decryption failed/);
      });

      it('should decrypt with two passwords message which GPG fails on', async function() {
        const decOpt = {
          message: await openpgp.message.readArmored(twoPasswordGPGFail),
          passwords: password2
        };
        return openpgp.decrypt(decOpt).then(function(decrypted) {
          expect(decrypted.data).to.equal('short message\nnext line\n한국어/조선말');
          expect(decrypted.signatures.length).to.equal(0);
        });
      });

      it('should decrypt with three passwords', async function() {
        const messageBinary = openpgp.util.b64_to_Uint8Array('wy4ECQMIElIx/jiwJV9gp/MZ/ElZwUfHrzOBfOtM8VmgDy76F7eSGWH26tAlx3WI0kMBZv6Tlc1Y6baaZ6MEcOLTG/C7uzHH7KMfuQFd3fcMaVcDawk9EEy/CybiGBE+acT6id2pemHQy6Nk76d9UUTFubcB');
        const message = await openpgp.message.read(messageBinary);
        const passwords = ['Test', 'Pinata', 'a'];
        const decrypted = await openpgp.decrypt({ message, passwords });
        expect(decrypted.data).to.equal('Hello world');
      });

      it('should decrypt broken ECC message from old OpenPGP.js', async function() {
        const { keys: [key] } = await openpgp.key.readArmored(ecdh_dec_key);
        const message = await openpgp.message.readArmored(ecdh_msg_bad);
        await key.decrypt('12345');
        const decrypted = await openpgp.decrypt({ message, privateKeys: [key] });
        expect(decrypted.data).to.equal('\n');
      });

      it('should decrypt broken ECC message from old go crypto', async function() {
        const { keys: [key] } = await openpgp.key.readArmored(ecdh_dec_key_2);
        const message = await openpgp.message.readArmored(ecdh_msg_bad_2);
        await key.decrypt('12345');
        const decrypted = await openpgp.decrypt({ message, privateKeys: [key] });
        expect(decrypted.data).to.equal('Tesssst<br><br><br>Sent from ProtonMail mobile<br><br><br>');
      });

      it('should decrypt broken Blowfish message from old OpenPGP.js', async function() {
        openpgp.crypto.cipher.blowfish.blockSize = 16;
        openpgp.crypto.cipher.blowfish.prototype.blockSize = 16;
        const use_nativeVal = openpgp.config.use_native;
        openpgp.config.use_native = false;
        try {
          const { data } = await openpgp.decrypt({
            passwords: 'test',
            message: await openpgp.message.readArmored(`-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.8.1
Comment: https://openpgpjs.org

wx4EBAMI0eHVbTnl2iLg6pIJ4sWw2K7OwfxFP8bmaUvSRAGiSDGJSFNUuB4v
SU69Z1XyXiuTpD3780FnLnR4dF41nhbrTXaDG+X1b3JsZCHTFMGF7Eb+YVhh
YCXOZwd3z5lxcj/M
=oXcN
-----END PGP MESSAGE-----`)
          });
          expect(data).to.equal('Hello World!');
        } finally {
          openpgp.crypto.cipher.blowfish.blockSize = 8;
          openpgp.crypto.cipher.blowfish.prototype.blockSize = 8;
          openpgp.config.use_native = use_nativeVal;
        }
      });

      it('should decrypt correct Blowfish message from new OpenPGP.js', async function() {
        const { data } = await openpgp.decrypt({
          passwords: 'test',
          message: await openpgp.message.readArmored(`-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.9.0
Comment: https://openpgpjs.org

wx4EBAMI7Di70u7hoDfgBUJQ2+1ig6ym3KMjRS9kAovSPAGRQLIPv2DgkINL
3DUgMNqtQCA23xWhq7Ly6o9H1lRfoAo7V5UElVCqGEX7cgyZjI97alY6Je3o
amnR6g==
=rPIK
-----END PGP MESSAGE-----`)
        });
        expect(data).to.equal('Hello World!');
      });

      it('should normalize newlines in encrypted text message', async function() {
        const message = openpgp.message.fromText('"BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\r\nUID:123\r\nDTSTART:20191211T121212Z\r\nDTEND:20191212T121212Z\r\nEND:VEVENT\nEND:VCALENDAR"');
        const encrypted = await openpgp.encrypt({
          passwords: 'test',
          message
        });
        const decrypted = await openpgp.decrypt({
          passwords: 'test',
          message: await openpgp.message.readArmored(encrypted.data),
          format: 'binary'
        });
        expect(openpgp.util.decode_utf8(decrypted.data)).to.equal('"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:123\r\nDTSTART:20191211T121212Z\r\nDTEND:20191212T121212Z\r\nEND:VEVENT\r\nEND:VCALENDAR"');
      });

    });

    describe('Errors', function() {

      it('Error message should contain the original error message', function() {
        return openpgp.encrypt({
          message: openpgp.message.fromBinary(new Uint8Array([0x01, 0x01, 0x01])),
          passwords: null
        }).then(function() {
          throw new Error('Error expected.');
        }).catch(function(error) {
          expect(error.message).to.match(/No keys, passwords, or session key provided/);
        });
      });

    });

  });

});
