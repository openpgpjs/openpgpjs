const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const stub = require('sinon/lib/sinon/stub');
const chai = require('chai');
chai.use(require('chai-as-promised'));

const { expect } = chai;

describe('Key', function() {
  let webCrypto = openpgp.util.getWebCryptoAll();

  if (webCrypto) {
    let generateKey = webCrypto.generateKey;
    let keyGenStub;
    let keyGenValue;

    beforeEach(function() {
      keyGenStub = stub(webCrypto, 'generateKey');
      keyGenStub.callsFake(function() {
        if (!keyGenValue) {
          keyGenValue = generateKey.apply(webCrypto, arguments);
        }
        return keyGenValue;
      });
    });

    afterEach(function() {
      keyGenStub.restore();
    });
  }

  describe('V4', tests);

  describe('V5', function() {
    let aead_protectVal;
    let aead_protect_versionVal;
    beforeEach(function() {
      aead_protectVal = openpgp.config.aead_protect;
      aead_protect_versionVal = openpgp.config.aead_protect_version;
      openpgp.config.aead_protect = true;
      openpgp.config.aead_protect_version = 4;
    });
    afterEach(function() {
      openpgp.config.aead_protect = aead_protectVal;
      openpgp.config.aead_protect_version = aead_protect_versionVal;
    });

    tests();
  });
});

function tests() {
  const priv_key_arm2 =
    ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
      'Version: GnuPG v2.0.19 (GNU/Linux)',
      '',
      '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',
      '=lw5e',
      '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

  const pub_key_arm2 =
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

  const pub_key_arm4 = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG 2.1.15 (GNU/Linux)

mI0EWpoNLAEEAMoO8dfnLvvCze1hjWcr8t1fMdndFQc1fAM7dm6sbqrdlaAz+Dab
zF3F9UhIOCcABRm+QHyZlgEsoQpHF/7sWflUK1FpoxdORINtIDilukUkMZ0NnIaD
+8pRutdSczPNFvSImSzZNCyLzvDCGMO3+Xeaa6pViSPEeBwhXWJUuHYtABEBAAG0
IkpvZSBVc2VyIDxqb2UudXNlckBwcm90b25tYWlsLmNvbT6ItwQTAQgAIQUCWpoN
LAIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRBYtrN4WUnCtoUjBACi6qVb
noQJ1aOaOyoBZscDIO5XZHZK4L9V9uJJhD9v1qRF5s0PRiG969EwFlvjqIlLiRej
KSxvE/1rcym4GwBUndku1fMM+weTWHNtRn9+BPzN/4eKZbUbY3fHtlk+Lde3N+CZ
vrGKS/ICtbtuAfZL0LdzzqnNuBUXlO6EpG5C3riNBFqaDSwBBADDURzGkpTn/FTT
xHyheai+zTOUmy7N1ViCRPkErIeD606tZf/sKqAnEChfECeZJReYydN1B3O8QOyI
Ly/rH0DS2bt/6juhknPVGHPUAyNxHmiHYXTUgGPEX1QfusjzBcfIk6vHjYBiRm/I
u9iwrzCwypA4dWDZSTZuFrVsf4n+twARAQABiJ8EGAEIAAkFAlqaDSwCGwwACgkQ
WLazeFlJwrZQEAQAuUrp9Qp76CnKqUsUjcVxq7DJBi/lewyGGYSVAFt6/0Xyg/8Y
TEa/c4Dri/HMOtrfbgjp/doIVaZLOXZYfqRcpy3z0M6BierOPB3D+fdaTfd7gIrQ
nGHIp2NmbJZnYgl8Ps23qF+LKTa1eE+AmMQYzUHSGuka2lp6OglwWzg/dEw=
=/vbH
-----END PGP PUBLIC KEY BLOCK-----`;

  const priv_key_arm4 = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG 2.1.15 (GNU/Linux)

lQIGBFqaDSwBBADKDvHX5y77ws3tYY1nK/LdXzHZ3RUHNXwDO3ZurG6q3ZWgM/g2
m8xdxfVISDgnAAUZvkB8mZYBLKEKRxf+7Fn5VCtRaaMXTkSDbSA4pbpFJDGdDZyG
g/vKUbrXUnMzzRb0iJks2TQsi87wwhjDt/l3mmuqVYkjxHgcIV1iVLh2LQARAQAB
/gcDAoZ8RULY7umS4fVGPmTuETCnOOTGancXT5r7chKyfFXlyVU4ULvTdLwdFtqx
Vl9tNyED31nIiRP1CTmZLeaVScNGfVLjo8nvpMZUVopw5UdaFADeVTpwVdtp7ru+
IgH4ynrRMgMGh7/dgBzIP8WN4w8uBPK5G4bS34NNiREkVoZ3oh4dA/6aeYfW7lVV
cYRl2F7++AGfqS+FpLsE8KjFU2z8POJjWMN1nYKwjNa+beEO0BFYdUFvMzU7eUHA
/G0xWAhYvNyuJHE4imgYmCy1OZeawc9h8YGeaQJCh2NTVzaD9HRu0xmz93bNF19q
bfUZJC7mC6WzKsRXHX0JmzH+9DShUqGnkRl5fMo2UhQMpSxsMT4dU/Ji4q+t96oy
K6g3DMJr5OtZML3XKxGmdy0CgepkG1aikrC9qLfBgxjqi+uTewcbrS9lAOfrZg4N
jwt1FLEK8gu7aOeczdW/pFOHOCrX1DnpF81JKJ1a7hz5JRP1m+ffqwm0IkpvZSBV
c2VyIDxqb2UudXNlckBwcm90b25tYWlsLmNvbT6ItwQTAQgAIQUCWpoNLAIbAwUL
CQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRBYtrN4WUnCtoUjBACi6qVbnoQJ1aOa
OyoBZscDIO5XZHZK4L9V9uJJhD9v1qRF5s0PRiG969EwFlvjqIlLiRejKSxvE/1r
cym4GwBUndku1fMM+weTWHNtRn9+BPzN/4eKZbUbY3fHtlk+Lde3N+CZvrGKS/IC
tbtuAfZL0LdzzqnNuBUXlO6EpG5C3p0CBgRamg0sAQQAw1EcxpKU5/xU08R8oXmo
vs0zlJsuzdVYgkT5BKyHg+tOrWX/7CqgJxAoXxAnmSUXmMnTdQdzvEDsiC8v6x9A
0tm7f+o7oZJz1Rhz1AMjcR5oh2F01IBjxF9UH7rI8wXHyJOrx42AYkZvyLvYsK8w
sMqQOHVg2Uk2bha1bH+J/rcAEQEAAf4HAwLwNvRIoBFS3OHTIYirkr4sHzSkWFJx
xDPozovXgCq7BoCXDMaSIQLwZqEfb+SabYtk7nLSnG2Y2mgwb9swZuBZEWuQjZk7
lX1MvuZ0Ih2QdQSMEJk8sEsMoBGHHdHh/MZO4a27+5B9OceDfnEZZcGSOweUuu1n
IlgWcgrM40q4S3Mt39FXFgdJWnpd93hAokKDHklUGMdMLw/02dGVRkJmvUp9qdhe
c2njq9HSeYwqbY2rYgcNsF2ZcCLt9UXA2dOG4X2c2mPfjKuTRZUPxNKh6JfL3mlu
rBdd/z8gQHoKObyaarVwN3HAbtP0+6Z8a9/wDYj1K9ZCoHuEtKq1qq5J2Ec8+Yzl
K0Zlcs760LiYUr69CninMrnbDNnAhrYAcyJS42viUADPv9g+CBbyanB4KyE4UNrZ
BCB296lOEW4v1IZVNrNvqrbka3/p0qqBJiFTh7eT3zXpRNArFZDmLCUEEm53qT1a
PO/MyYUGTTMRAzTmNTiPiJ8EGAEIAAkFAlqaDSwCGwwACgkQWLazeFlJwrZQEAQA
uUrp9Qp76CnKqUsUjcVxq7DJBi/lewyGGYSVAFt6/0Xyg/8YTEa/c4Dri/HMOtrf
bgjp/doIVaZLOXZYfqRcpy3z0M6BierOPB3D+fdaTfd7gIrQnGHIp2NmbJZnYgl8
Ps23qF+LKTa1eE+AmMQYzUHSGuka2lp6OglwWzg/dEw=
=mr3M
-----END PGP PRIVATE KEY BLOCK-----`;

  const revocation_certificate_arm4 = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG 2.1.15 (GNU/Linux)
Comment: This is a revocation certificate

iJ8EIAEIAAkFAlqaDT0CHQAACgkQWLazeFlJwrbOaAP/V38FhBrUy4XYgt8ZX22G
ov6IFDNoyRKafSuz7Rg+8K8cf+0MAsSi52ueKfsbPxQ+I1vPeaEuEYbwTjtbvM+M
vZcX+VNYdsc1iZeNaT4ayA+2LrCN/xgFj0nrExHqcZAjgBZ9pvKghAqdK4Zb2Ghb
7chPiLLNWJCMtL4bo7a1X84=
=HcWg
-----END PGP PUBLIC KEY BLOCK-----`;

  const revoked_key_arm4 = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG 2.1.15 (GNU/Linux)

mI0EWpoNLAEEAMoO8dfnLvvCze1hjWcr8t1fMdndFQc1fAM7dm6sbqrdlaAz+Dab
zF3F9UhIOCcABRm+QHyZlgEsoQpHF/7sWflUK1FpoxdORINtIDilukUkMZ0NnIaD
+8pRutdSczPNFvSImSzZNCyLzvDCGMO3+Xeaa6pViSPEeBwhXWJUuHYtABEBAAGI
nwQgAQgACQUCWpoNPQIdAAAKCRBYtrN4WUnCts5oA/9XfwWEGtTLhdiC3xlfbYai
/ogUM2jJEpp9K7PtGD7wrxx/7QwCxKLna54p+xs/FD4jW895oS4RhvBOO1u8z4y9
lxf5U1h2xzWJl41pPhrID7YusI3/GAWPSesTEepxkCOAFn2m8qCECp0rhlvYaFvt
yE+Iss1YkIy0vhujtrVfzrQiSm9lIFVzZXIgPGpvZS51c2VyQHByb3Rvbm1haWwu
Y29tPoi3BBMBCAAhBQJamg0sAhsDBQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJ
EFi2s3hZScK2hSMEAKLqpVuehAnVo5o7KgFmxwMg7ldkdkrgv1X24kmEP2/WpEXm
zQ9GIb3r0TAWW+OoiUuJF6MpLG8T/WtzKbgbAFSd2S7V8wz7B5NYc21Gf34E/M3/
h4pltRtjd8e2WT4t17c34Jm+sYpL8gK1u24B9kvQt3POqc24FReU7oSkbkLeuI0E
WpoNLAEEAMNRHMaSlOf8VNPEfKF5qL7NM5SbLs3VWIJE+QSsh4PrTq1l/+wqoCcQ
KF8QJ5klF5jJ03UHc7xA7IgvL+sfQNLZu3/qO6GSc9UYc9QDI3EeaIdhdNSAY8Rf
VB+6yPMFx8iTq8eNgGJGb8i72LCvMLDKkDh1YNlJNm4WtWx/if63ABEBAAGInwQY
AQgACQUCWpoNLAIbDAAKCRBYtrN4WUnCtlAQBAC5Sun1CnvoKcqpSxSNxXGrsMkG
L+V7DIYZhJUAW3r/RfKD/xhMRr9zgOuL8cw62t9uCOn92ghVpks5dlh+pFynLfPQ
zoGJ6s48HcP591pN93uAitCcYcinY2ZslmdiCXw+zbeoX4spNrV4T4CYxBjNQdIa
6RraWno6CXBbOD90TA==
=8d2d
-----END PGP PUBLIC KEY BLOCK-----`;

  const twoKeys =
       ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
        'Version: GnuPG v2.0.19 (GNU/Linux)',
        '',
        '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',
        'PepQmgsu',
        '=w6wd',
        '-----END PGP PUBLIC KEY BLOCK-----'].join("\n");

  const pub_revoked_subkeys =
      ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
      'Version: GnuPG v2.0.19 (GNU/Linux)',
      '',
      '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',
      'pMiJM+NJAQ==',
      '=ok+o',
      '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  const pub_revoked_with_cert =
      ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
      'Comment: GPGTools - https://gpgtools.org',
      '',
      'mQENBFqm7EoBCAC9MNVwQqdpz9bQK9fpKGLSPk20ckRvvTwq7oDUM1IMZGb4bd/A',
      '3KDi9SoBU4oEFRbCAk3rxj8iGL9pxvsX3szyCEXuWfzilAQ/1amRe2woMst+YkTt',
      'x9rzkRiQta4T1fNlqQsJyIIpHrKAFGPp0UjBTr6Vs+Ti6JkF5su4ea+yEiuBHtY4',
      'NjFb1xuV7OyAsZToh0B5fah4/WZ5Joyt9h8gp4WGSvdhLbdsoo8Tjveh2G+Uy2qC',
      'mM8h5v9qGBBRyGM9QmAlhn9XtvEODGbSPYVijEUu8QmbUwHqONAN4fCKAM+jHPuA',
      'rFG+si6QNEk3SOhXX3nvu9ThXg/gKZmmX5ABABEBAAGJATYEIAEKACAWIQQuQVvj',
      'r/N2jaYeuSDeEOPy1UVxbwUCWqbs0wIdAQAKCRDeEOPy1UVxb8CyCACyEagyyvmg',
      'kmS8pEI+iJQU/LsfnNPHwYrDOm0NodGw8HYkil2kfWJim60vFPC3jozzFmvlfy5z',
      'VAge9sVUl3sk7HxnYdPmK767h5Skp6dQSBeeh5WfH4ZK+hhJt9vJTstzaAhVNkX1',
      '5OPBfkpy9pbYblQj56g0ECF4UhUxGFVZfycy+i6jvTpk+ABHWDKdqoKj9pTOzwDV',
      'JVa6Y0UT76PMIDjkeDKUYTU6MHexN1oyC07IYh+HsZtlsPTs/zo1JsrO+D6aEkEg',
      'yoLStyg0uemr6LRQ5YuhpG7OMeGRgJstCSo22JHJEtpSUR688aHKN35KNmxjkJDi',
      'fL7cRKHLlqqKtBlTdW5ueSA8c3VubnlAc3Vubnkuc3Vubnk+iQFUBBMBCgA+FiEE',
      'LkFb46/zdo2mHrkg3hDj8tVFcW8FAlqm7EoCGwMFCQeGH4AFCwkIBwMFFQoJCAsF',
      'FgIDAQACHgECF4AACgkQ3hDj8tVFcW83pgf6Auezf0G4MR8/jfHTshYRO8uGdTVR',
      'PjSmczyk4UAk3xy2dZuVc4CathVs/ID3QhycurL33fiZntx+p3JKUrypnp2Y+ZXW',
      'q4xjL05yirDFq4WGgksovmP4q1NfNB3YIsNulHMJ/qCOHl6d+oIDIKF/udwr0+qf',
      'rhd1rMFqO5lAF5/kSBbRdCCLpvMIWKxvDkbZrsqvWcchP5nuymhVHn9cCVGdxsZ8',
      'a/1iODFsBTDF4LISX2Tk1AW5thT96erbvq9XOluDFNjZY9dc6/JWmyWBvLTNguGV',
      'rx0bydeGaddfZc+3XkpImKrpckz5gwYvkgu6bm7GroERjEeYzQDLsg2L07kBDQRa',
      'puxKAQgApxDXRk9YUQ2Ba9QVe8WW/NSmyYQEvtSuvG86nZn5aMiZkEuDpVcmePOS',
      '1u6Pz0RB9k1WzAi6Az2l/fS7xSbzjDPV+VXV704t9r0M3Zr5RMzIRjbGoxaZp7Tv',
      'Da3QGN4VIZN6o4oAJM7G2FeZMstnCDxrT3wyKXaEdOn5Uc6hxl2Bhx2gTCpsTFn8',
      'AaBnSY6+kge6rCkeufndXQUhTVy8dYsaSqGwpQHVtk1X4nDoZlCC929F9d3I2/WV',
      'OGlfHqbpbO+8tprvQS0JSzsa9w7xaGJcYUA2tOWV8ZZgC8/1MHMsj5HhHKmmWPsS',
      's6k6RLg3nP+CV9zkKn4sI+l/erOEaQARAQABiQE8BBgBCgAmFiEELkFb46/zdo2m',
      'Hrkg3hDj8tVFcW8FAlqm7EoCGwwFCQeGH4AACgkQ3hDj8tVFcW/lmwgAs3o/b24U',
      't2jioTzjZNFMrqjc99PpURJ9BhKPqa9RF7HrpM4x2mJEFw0fUZGQpQmL5NP0ZazE',
      'N47YHwZH1O5i4t5HtFmjtmMkJUFPlwy0MrClW+OVu6Wl7rtYuXIBqFouUx1YBZtQ',
      'isAmwBeB6DS8Oc39raZpoHh9lGPN1Kmp6iLX3xq+6IqUEV567vSAAR6N2m18GH79',
      '365Dq88eZKS/NtlzFnEzoThYlIVt/dknuQsUSdZHtuBbNXaJ816byVZQQWdqnXd5',
      'BIDZSFjrJY/gm2kgQX2Pn9hGqDdGhxiALjxhA0+OJQNw4v11y0zVGdofh0IHjkcZ',
      'onCOcv4DKguN2w==',
      '=OqO3',
      '-----END PGP PUBLIC KEY BLOCK----'].join('\n');

  const pub_v3 =
      ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
      'Version: SKS 1.1.3',
      '',
      'mQENAy9J/w4AAAEIALBDDD4vWqG/Jg59ghhMYAa+E7ECCTv2At8hxsM5cMP8P9sMLjs+GMfD',
      'IdQSOqlQXbunYADvM1l/h2fOuUMoYFIIGaUsO5Daxvd9uWceM4DVzhXMeJZb9wc5jEJEF21+',
      'qidKj5OGsMyTrg++mn4Gh/aFXvvy3N3KWaQpPfNi3NRZUpNLz0IlfbXVBQGD6reLoxPptJun',
      'NqpClyRiesgq8HCscmB2oQo+b9KzSSgzU9qQJA4SljMYVmJ2sDE/sjREI8iKL8lIgUMhJG9q',
      'NggWjuxFTpVcGKkuQFJIvdL+UhTVvEBuqw6n4cmFAzfZ/AInJM032qLtsaIf5begFKI3up0A',
      'BRGJARUDBSAxm7HC5begFKI3up0BAbdDB/0TOcI0ec+OPxC5RTZAltgIgyUc0yOjHoTD/yBh',
      'WjZdQ9YVrLGMWTW4fjhm4rFnppVZKS/N71bwI76SnN9zO4pPfx86aQPR7StmSLJxB+cfh2GL',
      'gudJoG9ifhJWdNYMUD/yhA0TpJkdHMD5yTDE5Ce/PqKLviiX9C5MPW0AT1MDvafQlzeUXfb5',
      '1a71vQNPw7W1NBAVZRwztm7TNUaxWMFuOmUtOJpq4F/qDQTIHW2zGPJvl47rpf6JSiyIyU70',
      'l0deiQcZOXPC80tgInhNoBrz3zbEXhXRJo1fHkr2YSLclpJaoUOHsPxoyrNB28ASL5ZknPwI',
      'Zx3+cFxaGpRprfSdtCFKb2huIEEuIFBlcnJ5IDxwZXJyeUBwaG9lbml4Lm5ldD6JARUDBRAv',
      'Sf8k5begFKI3up0BAcbGB/0eLod2qrQxoE2/RUWQtqklOPUj/p/ZTmvZm8BgsdIflb0AMeey',
      '9o8AbxyAgA3pcrcCjcye79M1Ma2trEvRksvs8hViuq3BXXjDbjPZi3wTtKSvbAC022OV52Sb',
      '8/sgiTGp7xC8QMqS8w4ZeKoxJGh1TVMYrevUA8a2Rr5aDqrR3EA4rifSHwkVjJWOPF69xiKt',
      'IVA0LcYJvGsPOQCf2ag+nOcnDrF4dvcmg6XZ/RyLepve+1qkhXsA/oq+yHoaqWfe+bwgssk/',
      'qw1aEUk7Di8x7vY+cfjvWaazcYGw8kkIwSSqqIq0pkKFz2xDDfSaDJl6OW/2GUK0wDpJmYZo',
      'PN40iJUDBRAvSgDsU5OkROGu2G8BAeUqBACbC45t4+wYxWCxxp81pkFRb8RWBvEvbXI+Spwd',
      '4NcKs8jc5OVC8V02yiq4KbKFDRxdw2OWpUCSRAJe1gjsfFrZ+2RivpKk06kbAYthES03MjXg',
      'cfcV3z2d7IWanJzdcOlzsHzPe1+RoUAaqBjvcqPRCGRlk0ogkYHyWYxElc6574iVAwUQL9iL',
      'CXr7ES8bepftAQGPywP/d9GSpEmS7LLIqazl4rgN1nkXN5KqduiH8Whu3xcBrdOAn7IYnGTp',
      'O+Ag4qwKKH+y/ke9CeZL6AnrU9c0pux150dHsDeHtpTPyInkjgKI7BofprydvpiFNd0nlAi4',
      'J4SAEYr3q92Qn/IiKpnLgo6Ls/GFb7q6y1O/2LL8PC2zrYU=',
      '=eoGb',
      '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  const pub_sig_test =
   ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
    'Version: GnuPG v2.0.19 (GNU/Linux)',
    '',
    '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',
    'yeSTTh8ZnzRiwuUH1t90E7w=',
    '=e8xo',
    '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  const priv_key_rsa =
    ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'Version: GnuPG v2.0.19 (GNU/Linux)',
    '',
    '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',
    '=lw5e',
    '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

  const user_attr_key =
    ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
    'Version: GnuPG v2.0.22 (GNU/Linux)',
    '',
    'mI0EUmEvTgEEANyWtQQMOybQ9JltDqmaX0WnNPJeLILIM36sw6zL0nfTQ5zXSS3+',
    'fIF6P29lJFxpblWk02PSID5zX/DYU9/zjM2xPO8Oa4xo0cVTOTLj++Ri5mtr//f5',
    'GLsIXxFrBJhD/ghFsL3Op0GXOeLJ9A5bsOn8th7x6JucNKuaRB6bQbSPABEBAAG0',
    'JFRlc3QgTWNUZXN0aW5ndG9uIDx0ZXN0QGV4YW1wbGUuY29tPoi5BBMBAgAjBQJS',
    'YS9OAhsvBwsJCAcDAgEGFQgCCQoLBBYCAwECHgECF4AACgkQSmNhOk1uQJQwDAP6',
    'AgrTyqkRlJVqz2pb46TfbDM2TDF7o9CBnBzIGoxBhlRwpqALz7z2kxBDmwpQa+ki',
    'Bq3jZN/UosY9y8bhwMAlnrDY9jP1gdCo+H0sD48CdXybblNwaYpwqC8VSpDdTndf',
    '9j2wE/weihGp/DAdy/2kyBCaiOY1sjhUfJ1GogF49rDRwc7BzAEQAAEBAAAAAAAA',
    'AAAAAAAA/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQN',
    'DAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/',
    '2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy',
    'MjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAAFABQDASIAAhEBAxEB/8QAHwAAAQUB',
    'AQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQID',
    'AAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0',
    'NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKT',
    'lJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl',
    '5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL',
    '/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHB',
    'CSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpj',
    'ZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3',
    'uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIR',
    'AxEAPwD3+iiigAooooA//9mIuQQTAQIAIwUCUzxDqQIbLwcLCQgHAwIBBhUIAgkK',
    'CwQWAgMBAh4BAheAAAoJEEpjYTpNbkCU9PEEAKMMaXjhGdgDISBXAAEVXL6MB3x1',
    'd/7zBdnUljh1gM34TSKvbeZf7h/1DNgLbJFfSF3KiLViiqRVOumIkjwNIMZPqYtu',
    'WoEcElY50mvTETzOKemCt1GYI0GhOY2uZOVRtQLrkX0CB9r5hEQalkrnjNKlbghj',
    'LfOYu1uARF16cZUWuI0EUmEvTgEEAOkfz7QRWiWk+I6tdMqgEpOLKsFTLHOh3Inz',
    'OZUnccxMRT++J2lDDMhLChz+d0MUxdBq6rrGoEIP2bYE9AjdR1DNedsuwAjnadYI',
    'io6TMzk0ApagqHJcr1jhQfi/0sBhCCX+y0ghK8KAbiYnyXPMQFa9F19CbYaFvrj/',
    'dXk0N16bABEBAAGJAT0EGAECAAkFAlJhL04CGy4AqAkQSmNhOk1uQJSdIAQZAQIA',
    'BgUCUmEvTgAKCRDghPdEbCAsl7qiBADZpokQgEhe2Cuz7xZIniTcM3itFdxdpRl/',
    'rrumN0P2cXbcHOMUfpnvwkgZrFEcl0ztvTloTxi7Mzx/c0iVPQXQ4ur9Mjaa5hT1',
    '/9TYNAG5/7ApMHrb48QtWCL0yxcLVC/+7+jUtm2abFMUU4PfnEqzFlkjY4mPalCm',
    'o5tbbszw2VwFBADDZgDd8Vzfyo8r49jitnJNF1u+PLJf7XN6oijzCftAJDBez44Z',
    'ofZ8ahPfkAhJe6opxaqgS47s4FIQVOEJcF9RgwLTU6uooSzA+b9XfNmQu7TWrXZQ',
    'zBlpyHbxDAr9hmXLiKg0Pa11rOPXu7atTZ3C2Ic97WIyoaBUyhCKt8tz6Q==',
    '=MVfN',
    '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  const pgp_desktop_pub =
    ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
    'Version: Encryption Desktop 10.3.0 (Build 9307)',
    '',
    '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',
    '=dVeR',
    '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  const pgp_desktop_priv =
    ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'Version: Encryption Desktop 10.3.0 (Build 9307)',
    '',
    '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',
    '5g==',
    '=63Nq',
    '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

    const rsa_ecc_pub =
    ['pub   rsa4096/C9DEDC77 2015-10-17 [expires: 2018-10-16]',
    'uid         Google Security Team <security@google.com>',
    'sub   nistp384/70C16E3C 2015-10-17 [expires: 2018-10-16]',
    'sub   rsa4096/50CB43FB 2015-10-17 [expires: 2018-10-16]',
    'sub   nistp384/102D9086 2015-10-17 [expires: 2018-10-16]',
    'sub   rsa4096/DFC40367 2015-10-17 [expires: 2018-10-16]',
    '',
    '-----BEGIN PGP PUBLIC KEY BLOCK-----',
    'Version: GnuPG v2',
    '',
    'mQINBFYiIB8BEACxs55+7GG6ONQV3UFYf36UDSVFbuvNB5V1NaEnkY0t+RVMigLR',
    'Zdl0HHsiaTKfKs4jqjLQAoR6Fcre9jlEhatotRg3AvHV1XYebxRlzdfXxyD0d6i9',
    'Quc1zbca0T8F1C5c7xfYP5g9iKWn5yFtHC3S7mLeOg7Ltx84bTo8AF7bHGA3uIQf',
    'uCtE8l6Z57HTeaf2IR/893jLOir8lvmTef83m/+e1j6ZwmKxxZO2s+aGKre6Fqsz',
    'Oo89CpWKNrdZ3IN8+Y4udZNlr7u0os7ffY0shfbLrqt+eVEu4EHfbpQTJxvalZJK',
    'tEnGtV8S7Z3dcPcimxvO7HZu7Wz8VnRzY/AZtee4fC+i2yBu1rWKgY3V1tFKdxVr',
    'KDnmS5MBgBAxv69mM3bf8QPinL4mtIQ65/Dt4ksJuysRmGwQ8LkjSLQCMMepnjBs',
    '/63wJ3e4wN1LCwnJonA2f8gZQHNeGPUhVVd/dWFDtmQaLwKFcI0GS/DiUPBIJir5',
    'DWnrEedtlcSLlwwcUglFsG4Sds/tLr+z5yE88ZrDrIlX9fb9cCAsDq7c8/NCzgvw',
    'kFez14sXgGhMz6ZfFzM49o0XwlvAeuSJRWBvnKonxM7/laqv4gK0zur3a6+D6qCN',
    'vt9iWO/YG+0Fvhmyxe34/Q71nXWc9t5aLcokmYLGY1Dpzf9oB8hDRdMCAQARAQAB',
    'tCpHb29nbGUgU2VjdXJpdHkgVGVhbSA8c2VjdXJpdHlAZ29vZ2xlLmNvbT6JAjwE',
    'EwEIACYFAlYiIB8CGwEFCQWjmoAFCwkIBwIGFQgJCgsCAxYCAQIeAQIXgAAKCRC4',
    '5BBcyd7cd8MzD/9YdMVZniQH4qBKxLFIoYGfLzCEI0S9IVUA37wrZ4YiRODSJRMf',
    'El6oVfTO/g8xpeQlDgHj1w2IDoSkeQrY+7rf9H41sGGOBDGXSQT+7Z7XFH2mPPvC',
    'cqYqR32BDNDkO/LL1BzzRlQvNmnGHxo098sqTgb7hoVsP+qFoem7JUMpcAV1KrUo',
    'P81haV8a/25ouWFZu5P68WFh861TyIjIYLQCns2fG+zlKFGN9Uynv6E5+Qk7dmni',
    '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',
    '=Q/kB',
    '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  const valid_binding_sig_among_many_expired_sigs_pub = [
    '-----BEGIN PGP PUBLIC KEY BLOCK-----',
    '',
    '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',
    '4z6aN5G1sT5159GF',
    '=yzZh',
    '-----END PGP PUBLIC KEY BLOCK-----'
].join('\n');

  const key_without_subkey = [
    '-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'Version: OpenPGP.js v2.6.2',
    'Comment: https://openpgpjs.org',
    '',
    'xcLYBFp9nCsBCACXTmLI9bJzaAanrD7r6j7gNDS7PsebJr0e182hgHVnGkr3',
    '8XCsCdWSllUNfBRln4MI8GfWVO5Bhhx5en6ntCptJVeSsohAHfBzmdoauSGW',
    'y+M+3dlSGeVqgqmDukQSxuNgKBC/ELDhKvAb8uKWnS/MUOapk/6aF8mf9Vqm',
    'eG/1RHrIvxfeOsRCEFH0OqB2tOeCWPXohxpzv2AvFxWviwzpedwNGDhN/XjZ',
    'JzI4LyBKlorHJvwe4KLKtaLuOq0jmNkT6AcsniyhvqN8QRP4OK7084Uc/7Yd',
    '6Qrcnw/6plqMB5J2PyYkB6eTptp28bwIxUGzfGQ6qfDyHHQBIbAVt3m5ABEB',
    'AAEAB/9uDdjynSvon5C/oxy9Ukvbnn2AeOCNLLdA2O07/Ijoroo7IIW4zQpo',
    'rio9PbREWqrf9KVCk9IdHORXQ88eQoDdlNzG2k8ae+xq2Ux4RZJ18eVf09P/',
    '0NA7EcElDHX5RmsahOnxX72YejfdzGQd80VSEsJENF5rTMQeMkN2dIHS3pFM',
    '9ar2nJe9dc/L9ND0P79X8twZvvfh287Tm23fs384nRedcUwELm43kNV7Us3t',
    'ub1ORmAzHhVCa8dWev7Zca7FqiZxa0u3X/QHvVMMpr0ewTBulr/mEjaglfYf',
    'dNp1PxduWYPWU54/XLG3G4nqLUS++qjd3O46VhMMCIigGf01BACgrkPwdrTJ',
    'EGCfgIq48IGoMU//wS1P0g7EIzplwGAzGAJQw6LhGqKrDONcyKGqHzRgn8oz',
    'dF8iezGjlVq7oiyrrB4ez1gDG4RRDC+6+PTn/TXBTZ21krUgPUrB0jcqV7SQ',
    'IIWZost7zNcbEqiPI91SPAMwYJZbJrSL4pTnDVLfewQA8RB1y3IzuK/rT+gs',
    'JfcSHqZ12G+sUIgpK6yv4pN7hQDhWC3+qe8ULnLLXYv+FQslnRW7tTkAbCRl',
    'kJvbibRqrYj+fQS2d3Hau5HYcGKcv9KPgOhB49yRkQpWCT+fqsQwJByyeZ47',
    'iiJRR8t0X92nr0zbf0f+LalmK4cQnQ6LS1sEAN2R8RiamrNcbsdmre0v6QVL',
    'WUOIwRWABRWFOm9QbSr80ji1q9pHlS5WbIw4LVeiO8V6H21QTL2fqDA9yWOK',
    'mNsOgIi+1PMkC4lwPu60VR7yBtLFWFF2SuuqPuDG8TFA2PBQFisrxcq63E38',
    'kroxpqxNCXXuB3E0uNL2fO6dqWbaRPzNF2dpYm9saW5AcHJvdG9ubWFpbC5i',
    'bHVlwsBcBBABAgAGBQJafZwrAAoJEFu1JX+Hv3FrMWEH/jE6HN5MayB6RHe7',
    'FTrfMlMEh54BqsiugmAIgtKYcxUcNsPw/hC53lJ6tDzo3/zk/2shvfItafh5',
    'ldUsERj1y5e7OMR+2GgfgMdddLddBuV8sXv2HwQgMtykeXOIPuH+7CZDwV7F',
    'lUyrykwpIjGGPkK+fG64fVt0cfWprdEsqcGZmHf/lHtoGprG8syfF+Ao3beI',
    'g6HJ61NHIBy4ewueKMBZ58/9VF2MQ7YgBQCtQNAnQKKrDFmxjZw3J4zBl83i',
    '3LrYpnYepvMUitQ/Y2pBAYygUExZ0dPC2uGFdPISbDGLg3DhGcyy1MvbLuNh',
    'EyjB8RncAfSIwK4dSGVh+PD5dkc=',
    '=w6Dj',
    '-----END PGP PRIVATE KEY BLOCK-----'
].join('\n');

  it('Parsing armored text with RSA key and ECC subkey', function(done) {
    openpgp.config.tolerant = true;
    const pubKeys = openpgp.key.readArmored(rsa_ecc_pub);
    expect(pubKeys).to.exist;
    expect(pubKeys.err).to.not.exist;
    expect(pubKeys.keys).to.have.length(1);
    expect(pubKeys.keys[0].getKeyId().toHex()).to.equal('b8e4105cc9dedc77');
    done();
  });

  const multi_uid_key =
    ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
    'Version: GnuPG v1',
    '',
    'mQENBFbqatUBCADmeA9CjMfzLt3TrplzDxroVisCWO7GRErUXiozULZd5S8p/rHS',
    'kuclUsQzraSuQ+Q7RhpOWdJt9onf5ro0dCC3i+AEWBrS0nyXGAtpgxJmZ618Cwzz',
    'RKrYstce4Hsyg0NS1KCbzCxpfIbyU/GOx4AzsvP3BcbRMvJ6fvrKy6zrhyVq5to3',
    'c6MayKm3cTW0+iDvqbQCMXeKH1MgAj1eOBNrbgQZhTBMhAaIFUb5l9lXUXUmZmSj',
    'r4pjjVZjWudFswXPoVRGpCOU+ahJFZLeIca99bHOl3Hu+fEbVExHdoaVq5W9R/QJ',
    '/0bHQrd+Th8e1qpIP2/ABb6P/7SGUKw6ZUvbABEBAAG0E1Rlc3QgVXNlciA8YUBi',
    'LmNvbT6JATgEEwECACIFAlbqatUCGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheA',
    'AAoJEPhuIdU05lVRgtoH/ioJdP34cHIdSu2Ofsm6FoWc/nk2QEughNn2AyaxZAKO',
    'pWy9o9/+KlVD3SoV5fzl6tCsFz1MqLFBsHSj2wKoQqkU6S9MnrG12HgnirqcjOa0',
    '1uPB0aAqF3ptNScPqcD44bZ4p58TAeU5H7UlrwPUn4gypotAnu+zocNaqe0tKWVo',
    'f+GAZG/FuXJc5OK2J6OmKIABJCuRchXbkyfsXZYE3f+1U9mLse4wHQhGRiSlgqG4',
    'CCSIjeIkqeIvLCj/qGXJGyJ0XeMwMVhajylhEtDmMRlc32Jt8btlTJzcQ/3NPuQd',
    'EryD92vGp/fXwP1/rLtD49o/0UbDeXT4KQphs2DuG/60E1Rlc3QgVXNlciA8YkBj',
    'LmNvbT6JATgEEwECACIFAlbqeUACGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheA',
    'AAoJEPhuIdU05lVRuPkIAK+ieYXEflVHY1bKeptYZ+UfHJhsBdM29WYmuHhAbWe9',
    'mb741n8YXbPENoCSYD4jq7cYOvrduz5QLmXKL57D9rXvu/dWhpLaSjGf4LDrSf+9',
    'bYw0U2BStjPzjnyxZSQDU60KFRIjZPWxF/VqRFp3QIp/r3vjEGuiE6JdzbT4EWwO',
    'rltkMzPYgx7cx63EhjrM3kybylL+wBX3T2JNCzLPfZBsdiWmQcypLgOPLrW/4fxQ',
    'zfAsDyEYlRj7xhVKAc+nMcXo8Hw46AecS8N3htZHM6WeekZYdoJ4DlDeE5RL76xZ',
    'hVEOziY5UnBT/F8dfZoVcyY/5FiSUuL19Cpwoc+dpWm5AQ0EVupq1QEIAMLfhMdk',
    'OoIl1J3J8F89My2u7qwKrw1WLWawBacZH2jsGZrjZlUJEIQpaIyvqHSPSgLJ+Yco',
    'YmCMj/ElNVBKBzaUpfdftW+5/S5OaJVq/j7J1OKMQqXQALgwh8GM/AThO5G4B27c',
    'HZ/+bkbldYJJK0y5ZONEj7gkch7w6cr1+6NCL7jMWIDar3HpchddOproxAMuZa9D',
    '2RjOvl+OMb6JMO5zTFbh37o5fAw3YWbmeX/tp2bD5W4lSUGD/Xwf2zS2r7vwGVZO',
    'C+zx1aaSNllcRvSWkg8zRY5FjL9AOl4l52JFfz8G63EuHrR9dXmsYA9IHunk0UNy',
    '/GGCcIJ6rXKTMCUAEQEAAYkBHwQYAQIACQUCVupq1QIbDAAKCRD4biHVNOZVUUFY',
    'CADkAAtvIiJLoiYyWBx4qdTuHecuBC8On64Ln2PqImowpMb8r5JzMP6aAIBxgfEt',
    'LezjJQbIM6Tcr6nTr1FunbAznrji1s4T6YcrRCS2QLq2j1aDUnLBFPrlAbuRnmZj',
    'o8miZXTSasZw4O8R56jmsbcebivekg0JQMiEsf3TfxmeFQrjSGKGBarn0aklfwDS',
    'JuhA5hs46N+HGvngXVZNAM9grFNxusp2YhC+DVDtcvR3SCVnVRfQojyaUKDEofHw',
    'YD+tjFrH9uxzUEF+0p6he6DJ5KrQuy5Zq4Yc4X2rNvtjsIzww0Byymvo6eRO0Gxk',
    'ljIYQms3pCv1ja6bLlNKpPII',
    '=qxBI',
    '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  const wrong_key =
    ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
    'Version: OpenPGP.js v0.9.0',
    '',
    'xk0EUlhMvAEB/2MZtCUOAYvyLFjDp3OBMGn3Ev8FwjzyPbIF0JUw+L7y2XR5',
    'RVGvbK88unV3cU/1tOYdNsXI6pSp/Ztjyv7vbBUAEQEAAc0pV2hpdGVvdXQg',
    'VXNlciA8d2hpdGVvdXQudGVzdEB0LW9ubGluZS5kZT7CXAQQAQgAEAUCUlhM',
    'vQkQ9vYOm0LN/0wAAAW4Af9C+kYW1AvNWmivdtr0M0iYCUjM9DNOQH1fcvXq',
    'IiN602mWrkd8jcEzLsW5IUNzVPLhrFIuKyBDTpLnC07Loce1',
    '=6XMW',
    '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

    const expiredKey =
    `-----BEGIN PGP PRIVATE KEY BLOCK-----

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

  const multipleBindingSignatures =
`-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mQINBFQNRrkBEAChLrYuYjiy1jq7smQtYPln6XGJjMiJ1PbZwGK2CKQaIW6u4EUJ
Dhy6j/vbApZUJbH0krnY3KY0wWjGkAjPa32J5uIU3ldKqcZEg4mavJlsnFqwGJtB
txsDVl+2qr6BNLXSHuv/xyDHOOwWv2Hij6uPup4demscvQzNkwL08KnjJyJj/uw4
QQgXwhYBsNeHfqJN+qLuSN1hJyzGRCXCsw/QjjCjtTqns25pFFYI5viNl5bRogDx
3/FiMKJEcs3U3Gzn4XECjolRiETmGB61VZuwFatvUqEnWsz6NjsvHYkILplpOoE0
Ittk9P9/RIoBaKpvArN0NzkPPY+/HIx6h7pEyx2/IaH7IknDNAhc3jX+dgF33+tl
h4CsiUg5ra1Jg20+FXcu8F67ie21lRWXZJ+St16o4cXlQ5JCmy4qiekpN03zGW92
Gpk6tpMdAMZIH6LQPea+Cjfbu2OMkSxokQ+7MSj7CXa/vu64qq3O1/34IC1fcnek
QxoI4ses4fnyoMWDFR6v+zsyptA4v8gZGU3OliLrgRokEJYbavtU54yDVyu5peM5
iJlriNun5YnHCm7AclmrhOuKv12VfDLO6pIsb/gDpGemjcEIVj7/WhlTxr5YglXT
LikCbEiIm2YJxw5j4Z2Tj11dXK4RpBpTqvY/MEmSLRjxsr3mlP5KFBDZBwARAQAB
tB1UaG9tYXMgR3JpZXMgPG1haWxAdGdyaWVzLmRlPohGBBMRAgAGBQJUO/8GAAoJ
ECuuPPba/7AAkpIAnjC4ApIaLN2cBV2phfqOMsjFNvrTAJ9+KDMEAGkgU2fPm5Dz
xKYsNY87g4hrBBARAgArBQJUSRZuBYMB4oUAHhpodHRwOi8vd3d3LmNhY2VydC5v
cmcvY3BzLnBocAAKCRDSuw0BZdD9WBqPAJ9RqDJ2ANbegApkOWMQaS+XpY8McgCg
jPuffq5cUqBBJljqyguekUfktsKJARwEEAEIAAYFAlRJI1kACgkQPDI5e2lh0zCg
Ywf+OUUuk0mgcZYv8uieAPcfWulG6oq6wGKbtDNfRH+JnwPF/lyaLUBRyLUlVbgG
diQNJoTotqJyCqWoGHU/1ssI46pnt7bVb0lUa4kkrFRzqTsN6QcwXI9QRLXp1Hje
bk5x2+E1uQ8FUVppjznSI8GbQofYEoIesxlRee54UD+8iAlyH5JNckLHPVeOr7Cc
JTmBqic9B3RK9yZm9TfiGCyRoB3/jV/FBwzQ1QZrBbdRyEU5ai1x3Q4MxRL74nJp
OSFW3oSY+P1jSlFB0v3HZW00z4xwDzrlCKbn79wHhNAvh10chF9LwreMBedKnuw6
qI1pC40VPktPN/4cmGyHC6pgl4kCHAQQAQgABgUCVQSWmQAKCRAodzh7/xuV5oLY
D/sGwQe1LpVOoEcudTsVqpC6T08cNSZWLRCeokxtxa1Yk/r8MIq8t/fijk0Dh/dE
j9QcvQ9NfypAwOVelse1MXlbL/J/gNAgG92/NbXu3+Oqy/bCOSSPJzWrnYhC1GeX
Khu8xOE+mYkxwcPEiMcfwo0NBSLVJL981Z3pRw7PFj+eSE+4JM+DxJaBP//pMiFa
Aac0Y42NXCJRRcmNPED55HnDDhUZ+sbbl2mWsHq9NkStul1qtWx1JgVLdHsFHgPo
dcx2G611/WYUOvsNl16QIuxiW+xv3HhxkPij5Dv8XpCPOM/LeGWjL7hPdbWIIXGh
eKASEeS89aKDZSQsj7LhE/ds2GSEifj0VscxLZRq/UiFChDMImydTuAxeAGsRtb2
u1Po0ww2s6sZcNzz3zISHNtO8hewV/vDhCav3gDw1f5LFA58waiVihIkYWa5JJ40
FMdnWLeODTzciCdRbx5KZtHKebKI77AWr+fXH9M7sRDVuN5XKCHRZOO76qkymmen
jSrS8j7dtrWP37spJ8/T68pVb3LLsYsVxp5U6DV4Av+hPToBy0/ux0iICQa3QsbY
iZvsx7JzZhsKdt2S+ItEY+cqdsFrLxS4jE8xoUDXIZvOOlEyxQOQ2O6nsHRjSVSQ
7imZ88U9/Yl686GIpiDpP4+/AKn7qdgWmZBqcBI7QTww1IkCPQQTAQgAJwUCVA1G
uQIbAwUJB4TOAAULCQgHAwUVCgkICwUWAgMBAAIeAQIXgAAKCRCCk/uBsYKD9ap6
D/9tDUpaulHdyJoT4LjdmR5Twlen6D/WRxIAK63Avad0gZa3y7chj3eED9HH6gw4
UmqQvpR8kfgnaJJVVPtPZBKUU0+UvnP6SH2i+thwAoGUjxWFa+cIaH41GAc3Buo2
WUOqYF+o6W0o+2ly6gICqP8FTNZllIlIsMn65ksN0290zUHUt2QDydzGVIA5OiOS
nkBr/0Cwe6ZF7VAUlF5MGsZdLMgAHbKmyQTX1FAn45xEigtOb8tmDobryW/Ga+sM
kYGC91ttTR/AYtNvb57x2aepm3vePfMtZ0YCHiyZexcLv5lqmjspRgHtRn/+/Fs/
OGHL70mHfPH1zp3k8zHbaEVMVHwBzLT+Du96Eom+jL4PiBNXOnGyQuPeRrP18QHk
kANqufLEB16ZeeHFa0/zKCILarxwV8G8zM8dbQbwNv8e5fAUbNP7LkMKbvDm2woB
LJqOGu8mF8js5JEUIgtYMI4FAuhB4DtX3yH98af7TZyEGHIJUxcasbg829qmYnrU
NoPL8qBV8trirU3D7iYvf1NTe15+9agtsdUkoBIUrzgzLQkkHVbbvydbZrwNebe8
WFLfOrAb8CN6WeC0sI+Tahqn10V15kF2quZU5jVu5gd+XXNzuuQCV8VLF8Q3S6O+
zJPHZGpjExxgFwMm25hBQ7CrtVlKVH/crP6KuKi4iI16D4hrBBARAgArBQJWIsfE
BYMB4oUAHhpodHRwOi8vd3d3LmNhY2VydC5vcmcvY3BzLnBocAAKCRDSuw0BZdD9
WHZQAJ9v6PgK/zwn1+ZHCnTU7z+10rMsUgCaA9+Pa31VBCsdqtAca8pZJP35YFaI
awQQEQIAKwUCWAO/3QWDAeKFAB4aaHR0cDovL3d3dy5jYWNlcnQub3JnL2Nwcy5w
aHAACgkQ0rsNAWXQ/Vir0wCeMYJjvyYTq+X2z26Gw9YYA0qM5GMAn2KFAJcap4Vp
3umZUAsRWq7KaFzFuQINBFQNRrkBEADFYg1yIZ4p2ncZdphG0bnTm/6Ng4RlgiZl
DRSGNM1gqckn30wKcNteqUUyEQMkw97fCfqYJads3/j+BpMHW8h7AVsbezSHuv+c
DljMaeGjYHZc3uRa0lxXTfi+8aEAKRqka0w1wyEkiO0YVXyuz7/o3vDd9pGoCIX3
g6l/z1doSzVKGrQQr384/hhLpBgZN4uxtrbVypx+Aq8yN+l4n5ELuOmCh69tI6h4
jnIwfKgnebpjB0OOnyZ/Taq219wZ4Mmjfn3WI+PxnUe0Sswp0KvXHyOoN6X8rgcK
NpTPzxkJ02VA4m9laZpDOHnysBcafM4uHwpzQ4izKq31bUPDm2hBHzSgMtLNfG7C
OmMEf01mwPkbuOKMVid85TVrmJeQEMPd0Fad5Zr81deRUHuUZD+1xsRY1SUtL4u3
OrVaVV6DkbjIPeaWiSqng0dyxdydzZwkUSHEmf8fMtCawVB13RR4sUdOwK0IIn0n
bBcYFnyE3KwUsekfDe2ejP2AF6XbFoSHJKBKaUMl5qqfEoPMRefdfjJikfPzrGXa
vOBVLiEuWmR1pif0r4OCfssHF6dJsR5lnO9p0owxDuKE5gqYwaRC9VbM4FEGM80l
ORTsdhIlm7R/oATfAhYPyj49ResvOifgQ2UfTR3hCxEYlme8SRBmb187kFQHEfS7
g85R/DGA3QARAQABiQIlBBgBCAAPBQJUDUa5AhsMBQkHhM4AAAoJEIKT+4GxgoP1
pUoP/1dhADAsm8vOdu5bSqs2O25g3Ib67FaKdgZxbsApy++1sXScy7BodnfOIvhc
el6EYYqtNmCfdxI87X2nNcJcsYWtxU5DKSKlDIG40RJL2aGG2pJ8QT3MgWgibCLW
uAdkfx8RNlSnpb9L3bUULwsbCd+muYk6en2TpiqxCRgI5Ypea+sfJf2ho327F9eQ
iW9QB+4ZhSQv/FdbZYWoVhPVo2PkJaIWbK1txMA5xCKjL/F4jcNiNHYU0uLAdgmQ
4IiUXNEygqJK14Nr/8O6nsJlVgQ9u0y7TO37KkBd0LWJRTuepcgaCawyzWV0tfXq
+64QQ1GSRMPNbaVeqi+LU/Hc3bBWX1m9Ox7Zs6ocL6ScPGIUHapp45IAEMLfCu5H
gJQN5ZanJAf2RDYn3owpZWYCmxV97y2HMfQotqPWvzlPJtLXmpgDnRS7JOwZn8CE
DJXudGK27xbAvNyRuVzK8XEVnc5+H6zFWiPtzAN8NepiJy56hNuu52/y8Eh35oVt
3OpOb6aGkUYzY45uQvhCtvG6X2CvJiy+31+pkfXTzRk2FhTeyWbVm+2M1ft7cHv+
fW8WQmmDD/cs3sdVpGstDbKVwCALGO6RUKjJDSXiZQUuB/ufjA5FRNzT2vfO7bX7
LDz4ZOY+PHS76ihek7a8HdMrSidBetiCG6to4OQ3PySjQYdkiQIlBBgBCAAPAhsM
BQJWIfuxBQkCFgZxAAoJEIKT+4GxgoP1V/cQAJCQEqMi1URwd7ODEgIpJ4/LQg+E
R3nDRiYzG9yVzKw9c7TfMJgpjoDqom+wxW4jt8doNCTl0UOer3WQkazKB75hrbCM
mzRVyUpyG6yQYErg7MAsl60x5Y+odxrN+idY45erlNbLoIIXokEb7VZoE3YFxs89
Ez6YuXwVGkTmr30HkMMlpX+psd1N46vcaeDJhcZpUmdxgi1kBBpinAZFhsSY1fhA
g3hVZI91EzsCeFwNfGVVNK0+Ph5erwB1kF3JSXTp+4pCGD0pQwj79O4USKLbaU9m
MnyLsg5HSDx6YLKD9vjQYWNbnJkmVSqBjXlaOI4ttj+8Z+7sMj4PXbSq6gMIB0Ba
4szEqd4EVxJhYATQl0KYu/YzDeHSEXfkguhIazDVXrWszXmcVpYQbvA1ADalpxdV
tvexJgnNYv+wkUauosSjkMhLG2WVLGQ5fg+AdBPeMhEb/aTTtn4aZ7Tkc/vXFWV9
Mb0n/Fo96mcCEOK28+w6z/HkBIG8KgX6+GTCTTI+5ix1HL8Jjs4qM/cZupHIxBQJ
SzFRPrm/JzbYNzus0qnpcUoLQPbAPwywOQfZnN4+1/piy1t0lRPrJh6NL0YvEtuM
5bIxEtmu4V4Mm+j1i/oieeAuJyj4lIWMZgh5uesS8yBBNu4c1BiSGBe5xb6x0uyd
b1+K7XlqT1/U+WFbuQINBFRJJmoBEADqbDxtQTD3TWQqZQzPqhGiCLxOONjNG7RS
hMR3LDn0DBMTtw8rUG6qSGefxv6xqkiYNFi6WX2nJ6JATqMrIkXDCkhzLKU4JSMg
4VYqIej0+1ETymjJBo+9Cp/YjjWBfCnXW1Xy1Bkiovx16XiFz9zI+L4Y89ziYuWk
GdzJQpM9pezZNlwVJ6fxYBFt0Xmi3cDywzVi3TuZ1kzRBQbkKyzlWJPlzrXHTW3x
fGZkw1R4A2oBvyRoTnSeNYMYJrgFKcWunTrgN4MUKZzWsw2imZJWRvBIUCAxm+wf
tMPIAEi9XhQEXSOKVOsyRDypTv9Q+b98TqabCIFpFjOCCsCZVyqJbVlD8tebCTzB
KW7y9GcKsUg/8NwgWZeOO/uWwear+2dahFO/rrHEooyjP5J8TfF0rsU6uZ0vjSMq
OJ6Qi/PYE+dSQl7dwZMdj0JhToNq64M3KX7H1mlLSoGJNMpsdT5s2+0HAkaQirVH
zmqk2PiG9ofNZHSQwlwn3bxfO7WMenTmtqRJ8f5ZsezvMLAm6NfCZ2UgfoLIUfCS
65Fq7jFdUntO6TmWocnBslAwczMbTNQ7+c5YtAP6yAihpScORuV9G2aHpg3pG3vy
yD1jYFVno1GYsDbT26DY8eGAWXMioFxNx31HVJh1hwq/tIaKk9skWIZyAUjmTKEJ
HTis7ixMXwARAQABiQQ+BBgBCAAJBQJUSSZqAhsCAikJEIKT+4GxgoP1wV0gBBkB
CAAGBQJUSSZqAAoJEOAAT9SU7ImVBS4P/0OSwomCkw2aZROmJS9CPu9jfjwgqMdY
33VcHs1SqdXdCJBdRVIu3zs4/AB/bksPeRn4UfQoJ6xQXMoG6vRisZxPexpsIOw4
cvZF7tYofOzUUnm7qF1HS0lC94KUrvJK52FLfFZu+BQB8zgBrR4p7Y5Gs/jvLUIC
OEUkXowijLJ7BPO76i7FG9ibynrei7c9RFp8DL5kEYmfSARoTb0hR875zi0a8/uh
YMWmXcRvUtq6SC6q+bhMD5CmS9s8UfnNjVhOYR501M8expCQJsbyM+r49xCUxMLz
OYkJOWgKnbyIxFFj6SFdV9oABh7r6Oqgnz8On8kEg2Qosdz87tlr0ZhG6PasMHet
L1hGSy8VBMWAHLPwtScVLr5KOuZ6S7ao+lhe2lcGEdzBkRw75lqhaCaRkJXLlBbK
ecEL4QWcoAATwFasiioBkrZhJEFay+tAZx7SrUKdxrh936XYOj4yXvwNRQshIDRG
rMyunG3fsR9DraR8/tzNdu+2HLzaWwZl2AnegcSmj0y6K5RvTQy4qO74afFBrHml
uhoTRpXt3YYoja7ql7bfZGBg5cdzoMEpJiEVXpmiKnd92JHeiiXNygSCVpBLFZl9
z/6U4m051fd/+nnC7Y1rs0AwmHzEFHwyMMHf98MjJxk9L6wH0BvcJL3yBMPOHUat
idDV4/pGzi5VFzoP/0GyypLfaj5xgfIbjSyyK+LLueZXyNpA8Qpn9jHUrI03R/AC
Rx0C5k/vlGR9ac1BqQjafhgQlmRNI/JK6lz41VPyomWE4atBeluq9KP8ijBcxY8M
nMyyxtt8kKm51pKyseXzFiUEaH9De71Gz9CcmLYyYAlsGPE2gV7AEnzG09cSya3t
sIA+sKZ6qQT8A7gspy3Kigv2IaoOpWyQFzHYDAmKkV0u77+Nf9K86GNFcS9rP2/y
aes09MwIQ3j1PEh2/EK3kf1ViJU/DvIdPSTxWS02/YcXDDSExai6HqTsxnS7OUMo
Sug754F1BFdN1D9vROaMxZBJHM+OoLtRXoIGy+3YLSScLW6xOrZ2zfD3dJD0H4jm
IbGlMjq8llftLx7gLcVL1khlFKHjHuRqcTnDtvDBJTg0fIlpi+5PXNfm33dINuOH
cWnqmxGcPY6ES0wurgz13NCYZL/G0x//LPoPSneJPb7G5ZtPN2jseGHA5zBV/kb6
3YU84twmEnbZ0gZbCm89uvmulMUIaX8Z2iy7Tig6tEC/LqT26RwuWihGpXv3HlId
2FFAZ5HOtKWR7PQDgf8nOma/en5g3n3VOa5w7JgXdK0GaKRuo8EL5C2ocVknJ7/o
o5s4nJb0841kHuAmY1Vv4AkwChTCFP77z5OOzSrlTMAQXsootYGV/Uw/Qa9wuQIN
BFRJJugBEADJSsQfPqDSle4AS/jx9R5494mL7aRQ78WrRYNADyofHw1I7Ty4EXZ+
DloSZzNM0nJkWKycgalnBa67kTOg9FhD2y+8aISUpFIiWeeBV2IDlf8bLzqi73/u
+oI6x7LNmKRl9Ei+cbyU68b6exjMIuwl6R2pxN14bgAQAzGYOnYxke8Ub9G5ANs4
9VxFlpE0AajckjW7dZu3404SJhYAUNkurK9xg5MlvTLMr55k+8hsUZaXdUQeUsiW
+qadSe4qfy7g8tzf31yAKICr8udXgdHa3zLBhRu1gUOo3pRDIcMcBID/iCVXexPD
VYqljiny8AZKvMWRhT9NzDLhJntGq4bo3z+HaOlFWysbzYl/6AzxHed4iQ/7vHkl
e5MQlx7WtWNJVjJRw3fc5SOtYds2Xmc02g+NSmJM9Ve7M3JAp5Lv4LeGvLAu7q5M
UbFhkZ/31uSCwS8cXhdMz91DvNZ5KNAwmS9y4ojUorjcpsMQcs0uHbOHgtmLIJbB
xbjJmUmVfMn+ZsSt/Hx4Y3DGUU01zjnj6prq5RaCKYEJwxhMvXJiYJ4L94rQJGvY
clb2JuH7E7q2H5g+fMJHiQj9KoY/fMhuc0lY0W6Af+M8snCovLwgTR7bpIv98vxA
+FpZS2NINA2nEcF0KpjqQ2zVUBOa9iUx3GLnqXvbGnsi1ayRhTzG9QARAQABiQIf
BBgBCAAJBQJUSSboAhsMAAoJEIKT+4GxgoP1qSUQAJCqBGEp3HRfG3f2B1WELShA
vyT5rn/Nu8OvQ+OnubYlkKl9rBpP0evxEJjfrmK9PRhfPM+Ep7QUARXwMavAbH/g
bSxg6XwPPrimMDrluVoD4o3YE6OBjzpynhxRBHYAW+//VZCzJQoY+0Q6iNcWEfuH
daTsTWwIUUOfXuPimCpXbNP5RLxbnX1gs0MuDuUuBrLudZ2nqR89WVSubWdLNN64
nF6KqANK1HXr5iSRFG7eRPp4hiVDdELo3cJgR6ohFGARctwst39C95URouyCwTRj
fKYwJ50Ha/xeHlMNV8Ddnd+nOvgapxDqCKcBTUC03WRxQSfvu6nMh3KUzUfX9xPM
kCAF0pNT+JE0hdJophU0lSgvFCSHor7bigol31cavlvkswEcI7Kyufvt2W3FAma+
bJaLcqfGCCoIOdf7n4VNCfFArzXsPx2chrPRf7akO4/cumVxqcKrDZf1Gdy3cXEx
Bl7cynwaatNDnspvpJWNxJQ20vJ5ibbfPrZetowAnGV0qhKM2emQIVl4q3+UDUEb
yeHL7FBsg5GXafOTcoZ8F8qhWTjICvG1aXaI4ORO1ljA/fB0wl18ypjhaCtrI6VB
qkxuzU0slqdngdLUr1iA+A8oOIZlXkcFfHTnW36O8hZVj2vK3CU9WVsEa/gJI1p1
p92yZgB3r2+f6/GIe2+7
=jZgG
-----END PGP PUBLIC KEY BLOCK-----`;

const mergeKey1 = '-----BEGIN PGP PUBLIC KEY BLOCK-----\n' +
'\n' +
'mQENBFtDaAIBCACX5Y/YO7CuP6PMBIJWUMXFb50cGgzzowCbhdzpYU589iz1npjR\n' +
'yBmZPmnKK4KfEMz0buY+763/LFwihbfBh5jsh3oV14rqg+P6VNLeCATuGWO/5JKy\n' +
'jRNzjmQZFLcmbStF1W3+vIvJJDibMqvjHLE33z7t17BLU/fVu4F2BuuKVsM5xm/J\n' +
'HIYFzCeWR5O8+0s6Kd1SKZwzy7ySBV0w3Pk0go076RnyKyv8vneogTubA0qSAKJx\n' +
'jm6k94wJSSt3CyH5ogcLd4wjsylA65wOPIy7ROvcg05hdWO83qto4tE8o2mpB+Wc\n' +
'MZ6gkyLZnQEvKBKlh1H2BBrnI2w4iDRVSCOVABEBAAG0JVN1YktleU1lcmdlIFRl\n' +
'c3QgPG5vc3VjaEBleGFtcGxlLm9yZz6JAVQEEwEIAD4WIQSJdpCFeXsnZzf+xlKb\n' +
'N/Be0N878AUCW0NoAgIbAwUJA8JnAAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAK\n' +
'CRCbN/Be0N878MfWB/4wEIXGoYc8sYcFIjeRsIniQN+TaOhKY4kOdbk/MJh5hDcc\n' +
'OwXpahc6C14pzSh7C5bkwRzWrm0hsONR5uhrx09154GU5ie88yIKTYC58ef4TwB+\n' +
'Kq4UvOV0xbkFGmyGhlDWgA9nSCotHzt//9fLqY26m7pZ1JVczDWVHIqwTv4lAF5G\n' +
'fBuDEV9w6fcbvIiqSrTx/lekNQjCE4+JhBahindko4jeP4bj/699Q0f+j2pHJ5xU\n' +
'zHoWAI8RowX7EDzwydnTG0Rrx9QoN2QcUjw6Lsg9//i7fk5PochYa7kGYcHGLvXP\n' +
'8fwk7K1be8ZnRwUx8dqzoQVtYRxdHP19P796PD5guQENBFtDaAIBCAC3FKAMPRU/\n' +
't03vbsVibHkpCI6KVaInTu7+HWksYQ8gp89w2nzQZLvAfIMKJBVdZa+nRoTTjZ6B\n' +
'zwmvtiCjv202/9L8BcBmsNFnKapgi8bD4L8r/9lSMngD1ebSdVuopNQXzDXLYsKl\n' +
'8OLup1AFPQPEwDnn72pHF7fIJBOJkuXnS9syCViLlFeziBGsY/RD0hWE7YgIK+m0\n' +
'0M+57EzDntjsVTI5d3V8EwEUJU1nADtnbkjQoyCXBfqxYe4+SmiWkyFKFVfIQeX/\n' +
'muoq79b9/NVM7G+vTcSzTCPKKKdw1Zefb1i/S/O1HWwA3KJCFYOMPtqLLf2hIF/5\n' +
'3LC1SRVCJ7bHABEBAAGJATwEGAEIACYWIQSJdpCFeXsnZzf+xlKbN/Be0N878AUC\n' +
'W0NoAgIbDAUJA8JnAAAKCRCbN/Be0N878Hf6B/4nun5NklDp/X5EvhHKdTgOMlIC\n' +
'f0RsrqRGvQTOMmoxeQ8w88GkTuGIUSHWPxXPracNfqxETOY+D91dQDKpgIMSPqDk\n' +
'tAEnXhX2S36Eb/68hkkwOF2I5Ngcv39n6BLvREGf8JiUR7O/MRgfcjebfH4Trc/K\n' +
'XorBDo4y3g2wg68ueuEQHfi8HprWec2QjiSgTTaNfG0oS+UKLJB9ZsPhVB59lE4B\n' +
'giI/4DD0FYR9pUfo9SG2sQKWlD5jIWob5S8x2QYZKFXYDEGX7V9/yjReGAfqjhQY\n' +
'EPmHvKuRRWbzEP0ckFPVsyc6E07OzZyfnHOPIGXH/IFO0OF7Zj8Cvh8BaPYW\n' +
'=hJLN\n' +
'-----END PGP PUBLIC KEY BLOCK-----\n';
const mergeKey2 = '-----BEGIN PGP PUBLIC KEY BLOCK-----\n' +
'\n' +
'mQENBFtDaAIBCACX5Y/YO7CuP6PMBIJWUMXFb50cGgzzowCbhdzpYU589iz1npjR\n' +
'yBmZPmnKK4KfEMz0buY+763/LFwihbfBh5jsh3oV14rqg+P6VNLeCATuGWO/5JKy\n' +
'jRNzjmQZFLcmbStF1W3+vIvJJDibMqvjHLE33z7t17BLU/fVu4F2BuuKVsM5xm/J\n' +
'HIYFzCeWR5O8+0s6Kd1SKZwzy7ySBV0w3Pk0go076RnyKyv8vneogTubA0qSAKJx\n' +
'jm6k94wJSSt3CyH5ogcLd4wjsylA65wOPIy7ROvcg05hdWO83qto4tE8o2mpB+Wc\n' +
'MZ6gkyLZnQEvKBKlh1H2BBrnI2w4iDRVSCOVABEBAAG0JVN1YktleU1lcmdlIFRl\n' +
'c3QgPG5vc3VjaEBleGFtcGxlLm9yZz6JAVQEEwEIAD4WIQSJdpCFeXsnZzf+xlKb\n' +
'N/Be0N878AUCW0NoAgIbAwUJA8JnAAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAK\n' +
'CRCbN/Be0N878MfWB/4wEIXGoYc8sYcFIjeRsIniQN+TaOhKY4kOdbk/MJh5hDcc\n' +
'OwXpahc6C14pzSh7C5bkwRzWrm0hsONR5uhrx09154GU5ie88yIKTYC58ef4TwB+\n' +
'Kq4UvOV0xbkFGmyGhlDWgA9nSCotHzt//9fLqY26m7pZ1JVczDWVHIqwTv4lAF5G\n' +
'fBuDEV9w6fcbvIiqSrTx/lekNQjCE4+JhBahindko4jeP4bj/699Q0f+j2pHJ5xU\n' +
'zHoWAI8RowX7EDzwydnTG0Rrx9QoN2QcUjw6Lsg9//i7fk5PochYa7kGYcHGLvXP\n' +
'8fwk7K1be8ZnRwUx8dqzoQVtYRxdHP19P796PD5g0dFT0VEBEAABAQAAAAAAAAAA\n' +
'AAAAAP/Y/+AAEEpGSUYAAQEBASwBLAAA/+EN2kV4aWYAAElJKgAIAAAABQAaAQUA\n' +
'AQAAAEoAAAAbAQUAAQAAAFIAAAAoAQMAAQAAAAIAAAAxAQIADAAAAFoAAAAyAQIA\n' +
'FAAAAGYAAAB6AAAALAEAAAEAAAAsAQAAAQAAAEdJTVAgMi4xMC40ADIwMTg6MDc6\n' +
'MDkgMTU6NTY6NDAACAAAAQQAAQAAAAABAAABAQQAAQAAAAABAAACAQMAAwAAAOAA\n' +
'AAADAQMAAQAAAAYAAAAGAQMAAQAAAAYAAAAVAQMAAQAAAAMAAAABAgQAAQAAAOYA\n' +
'AAACAgQAAQAAAOsMAAAAAAAACAAIAAgA/9j/4AAQSkZJRgABAQAAAQABAAD/2wBD\n' +
'AAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcp\n' +
'LDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIy\n' +
'MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAEAAQAD\n' +
'ASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAA\n' +
'AgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAk\n' +
'M2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlq\n' +
'c3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXG\n' +
'x8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEB\n' +
'AQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSEx\n' +
'BhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5\n' +
'OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaX\n' +
'mJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq\n' +
'8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD3+iiigAooooAKKKKACiiigAooooAKKKKA\n' +
'CiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKA\n' +
'CiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKA\n' +
'CiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKA\n' +
'CiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKK+QPib8Tf8AhY39l/8A\n' +
'Eo/s/wCweb/y8+bv37P9hcY2e/WgDv8A/hpr/qUf/Kl/9qo/4aa/6lH/AMqX/wBq\n' +
'rwCigD6/+GXxN/4WN/an/Eo/s/7B5X/Lz5u/fv8A9hcY2e/WvQK+AK+v/hl8Tf8A\n' +
'hY39qf8AEo/s/wCweV/y8+bv37/9hcY2e/WgD0CiiigAooooAKKKKACiiigAoooo\n' +
'AKKKKACiivkD4m/E3/hY39l/8Sj+z/sHm/8ALz5u/fs/2FxjZ79aAO//AOGmv+pR\n' +
'/wDKl/8AaqP+Gmv+pR/8qX/2qvAKKAPr/wCGXxN/4WN/an/Eo/s/7B5X/Lz5u/fv\n' +
'/wBhcY2e/WvQK+AK+v8A4ZfE3/hY39qf8Sj+z/sHlf8ALz5u/fv/ANhcY2e/WgD0\n' +
'CiiigAooooAKKKKACiiigAr4Ar7/AK+AKACiiigAr3/9mX/maf8At0/9rV4BXv8A\n' +
'+zL/AMzT/wBun/tagD6AooooAKKKKACiiigAooooAKKKKACiiigAr4Ar7/r4AoAK\n' +
'KKKACvf/ANmX/maf+3T/ANrV4BXv/wCzL/zNP/bp/wC1qAPoCiiigAooooAKKKKA\n' +
'CiiigArz/wCJvwy/4WN/Zf8AxN/7P+web/y7ebv37P8AbXGNnv1r0CigD4Aor7/o\n' +
'oA+QPhl8Mv8AhY39qf8AE3/s/wCweV/y7ebv37/9tcY2e/Wvr+iigAooooAKKKKA\n' +
'CiiigAooooAKKKKACiiigArz/wCJvwy/4WN/Zf8AxN/7P+web/y7ebv37P8AbXGN\n' +
'nv1r0CigD4Aor7/ooA+QPhl8Mv8AhY39qf8AE3/s/wCweV/y7ebv37/9tcY2e/Wv\n' +
'r+iigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKA\n' +
'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\n' +
'v+Xbytmzf/ttnO/26V6BQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFA\n' +
'BRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFA\n' +
'BRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFA\n' +
'BRRRQAUUUUAFFFFABRRRQB//2QD/2wBDABsSFBcUERsXFhceHBsgKEIrKCUlKFE6\n' +
'PTBCYFVlZF9VXVtqeJmBanGQc1tdhbWGkJ6jq62rZ4C8ybqmx5moq6T/2wBDARwe\n' +
'HigjKE4rK06kbl1upKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSk\n' +
'pKSkpKSkpKSkpKSkpKT/wgARCABAAEADAREAAhEBAxEB/8QAGQABAQEBAQEAAAAA\n' +
'AAAAAAAAAAQFAwEC/8QAFAEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEAMQAAAB\n' +
'0wAAACY6nQHyTFYMsrKQcTONcAAAAiPSwAGSWk5mGkVHhARm4UEJmnEHc1ygAAAA\n' +
'/8QAHhAAAwACAgMBAAAAAAAAAAAAAQIDAAQQEhETMCD/2gAIAQEAAQUC+NLpMo4d\n' +
'eCQoTYR24vF2pBDOfFV7zlrv7PjexmYW9n5tsN3g5pPan5wEqZ7QwWmcN5jLbHcK\n' +
'pYxn60yuuHwyoOVjRjKQkPj/AP/EABQRAQAAAAAAAAAAAAAAAAAAAGD/2gAIAQMB\n' +
'AT8BAf/EABQRAQAAAAAAAAAAAAAAAAAAAGD/2gAIAQIBAT8BAf/EACMQAAIBAwQB\n' +
'BQAAAAAAAAAAAAERAAIQIRIwMTKBIEFRYXH/2gAIAQEABj8C2UefqMXZ4iyP2+qn\n' +
'LiPNzTASEBtAAZiPb0qg4jPM1j2jHMVY8ztO0004EQDis6cGdDdaT5nydr//xAAi\n' +
'EAEBAAEDBAIDAAAAAAAAAAABEQAhMUEQMGGBUXEgkbH/2gAIAQEAAT8h7OoZ+HDA\n' +
'z6fzq5eDnABo7dTgI9JnOE366qUxcDVS73tGmUXXNWEGumyfjoiBzvc4wmfeMSyi\n' +
'J4wy8HOQCr8MfgfemJRPouLBU3eXKZLxm5arXowtX9OOx9BcRGJEwFYFXIAXkTGI\n' +
'NN3tf//aAAwDAQACAAMAAAAQAAAAAgAAEAEAAAAAEAAggAgkAkgAAAAA/8QAFBEB\n' +
'AAAAAAAAAAAAAAAAAAAAYP/aAAgBAwEBPxAB/8QAFBEBAAAAAAAAAAAAAAAAAAAA\n' +
'YP/aAAgBAgEBPxAB/8QAJBABAAEDAwQCAwAAAAAAAAAAAREAITFBUWEQMIGRIPBx\n' +
'scH/2gAIAQEAAT8Q7JCzpQHylqYMsjlbPPUgJZVWvEAALtZz1NOQkkSANW+KnASm\n' +
'G4COcdTDBIXEiP8AKDEA1EoZiz2pSwLiFzRzaiI5ZAeQbZ+6fACsziEuuTFRgJTT\n' +
'YDPGat0gRi5nxP2KYC2QVCgMCMjymniaUDoTan2xT9pNwewik+Sw2NuD90JedBjl\n' +
'2OaiVfmYmDHFuhhnCj5nh+6zQxVScX2TSJyIRIRoE5EAEq0J3CgB+WnEplyJjBGm\n' +
'e1//2YkBVAQTAQgAPhYhBIl2kIV5eydnN/7GUps38F7Q3zvwBQJbQ2nuAhsDBQkD\n' +
'wmcABQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEJs38F7Q3zvwjvsH/jrxLY5X\n' +
'7qTHTBzsAt8yGRpFB0RBo4CI184t6KA7NpSmjeBiy2J5kz0RjdvEdj4bs5JKQkDk\n' +
'ikUr+3r79w/W04+KDrue1fXCKK9KfWmi/b3qcNBPkpgAhyROtCHHC7OaX6LHnm8w\n' +
'IPO4oMoyqW4wbwPdOyBLde3FkzOx8XPmvgzzBwyC3Wve3CC/PvEnmiT0EjYqAU1j\n' +
'piz7cVLsawElBi7rtA6Ryiz1/xY/LYPprGsLhvG3/wtD+dWVPPSd7xS2sl6C5KJB\n' +
'ZhKI1uIwdTCGO/Th6FKqO/9djRzOgRaPwxe5uR+HTcgWRAUXlzU9AKzWikIBo8Iu\n' +
'eQc3Ss7SlRnwn365AQ0EW0NoAgEIALcUoAw9FT+3Te9uxWJseSkIjopVoidO7v4d\n' +
'aSxhDyCnz3DafNBku8B8gwokFV1lr6dGhNONnoHPCa+2IKO/bTb/0vwFwGaw0Wcp\n' +
'qmCLxsPgvyv/2VIyeAPV5tJ1W6ik1BfMNctiwqXw4u6nUAU9A8TAOefvakcXt8gk\n' +
'E4mS5edL2zIJWIuUV7OIEaxj9EPSFYTtiAgr6bTQz7nsTMOe2OxVMjl3dXwTARQl\n' +
'TWcAO2duSNCjIJcF+rFh7j5KaJaTIUoVV8hB5f+a6irv1v381Uzsb69NxLNMI8oo\n' +
'p3DVl59vWL9L87UdbADcokIVg4w+2ost/aEgX/ncsLVJFUIntscAEQEAAYkBPAQY\n' +
'AQgAJhYhBIl2kIV5eydnN/7GUps38F7Q3zvwBQJbQ2gCAhsMBQkDwmcAAAoJEJs3\n' +
'8F7Q3zvwd/oH/ie6fk2SUOn9fkS+Ecp1OA4yUgJ/RGyupEa9BM4yajF5DzDzwaRO\n' +
'4YhRIdY/Fc+tpw1+rERM5j4P3V1AMqmAgxI+oOS0ASdeFfZLfoRv/ryGSTA4XYjk\n' +
'2By/f2foEu9EQZ/wmJRHs78xGB9yN5t8fhOtz8peisEOjjLeDbCDry564RAd+Lwe\n' +
'mtZ5zZCOJKBNNo18bShL5QoskH1mw+FUHn2UTgGCIj/gMPQVhH2lR+j1IbaxApaU\n' +
'PmMhahvlLzHZBhkoVdgMQZftX3/KNF4YB+qOFBgQ+Ye8q5FFZvMQ/RyQU9WzJzoT\n' +
'Ts7NnJ+cc48gZcf8gU7Q4XtmPwK+HwFo9hY=\n' +
'=REGo\n' +
'-----END PGP PUBLIC KEY BLOCK-----\n';

const priv_key_2000_2008 = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
t/ia1kMpSEiOVLlX5dfHZzhR3WNtBqU=
=C0fJ
-----END PGP PRIVATE KEY BLOCK-----`;


  it('Parsing armored text with two keys', function(done) {
    const pubKeys = openpgp.key.readArmored(twoKeys);
    expect(pubKeys).to.exist;
    expect(pubKeys.err).to.not.exist;
    expect(pubKeys.keys).to.have.length(2);
    expect(pubKeys.keys[0].getKeyId().toHex()).to.equal('4a63613a4d6e4094');
    expect(pubKeys.keys[1].getKeyId().toHex()).to.equal('dbf223e870534df4');
    done();
  });

  it('Parsing V5 public key packet', function() {
    // Manually modified from https://gitlab.com/openpgp-wg/rfc4880bis/blob/00b2092/back.mkd#sample-eddsa-key
    let packetBytes = openpgp.util.hex_to_Uint8Array(`
      98 37 05 53 f3 5f 0b 16  00 00 00 2d  09 2b 06 01 04 01 da 47
      0f 01 01 07 40 3f 09 89  94 bd d9 16 ed 40 53 19
      79 34 e4 a8 7c 80 73 3a  12 80 d6 2f 80 10 99 2e
      43 ee 3b 24 06
    `.replace(/\s+/g, ''));

    let packetlist = new openpgp.packet.List();
    packetlist.read(packetBytes);
    let key = packetlist[0];
    expect(key).to.exist;
  });

  it('Testing key ID and fingerprint for V3 and V4 keys', function(done) {
    const pubKeysV4 = openpgp.key.readArmored(twoKeys);
    expect(pubKeysV4).to.exist;
    expect(pubKeysV4.err).to.not.exist;
    expect(pubKeysV4.keys).to.have.length(2);

    const pubKeyV4 = pubKeysV4.keys[0];
    expect(pubKeyV4).to.exist;

    const pubKeysV3 = openpgp.key.readArmored(pub_v3);

    expect(pubKeysV3).to.exist;
    expect(pubKeysV3.err).to.not.exist;
    expect(pubKeysV3.keys).to.have.length(1);

    const pubKeyV3 = pubKeysV3.keys[0];
    expect(pubKeyV3).to.exist;

    expect(pubKeyV4.getKeyId().toHex()).to.equal('4a63613a4d6e4094');
    expect(pubKeyV4.getFingerprint()).to.equal('f470e50dcb1ad5f1e64e08644a63613a4d6e4094');
    expect(pubKeyV3.getKeyId().toHex()).to.equal('e5b7a014a237ba9d');
    expect(pubKeyV3.getFingerprint()).to.equal('a44fcee620436a443bc4913640ab3e49');
    done();
  });

  it('Create new key ID with fromId()', function() {
    const pubKeyV4 = openpgp.key.readArmored(twoKeys).keys[0];
    const keyId = pubKeyV4.getKeyId();
    const newKeyId = keyId.constructor.fromId(keyId.toHex());
    expect(newKeyId.toHex()).to.equal(keyId.toHex());
  });

  it('Testing key method getSubkeys', function(done) {
    const pubKeys = openpgp.key.readArmored(pub_sig_test);

    expect(pubKeys).to.exist;
    expect(pubKeys.err).to.not.exist;
    expect(pubKeys.keys).to.have.length(1);

    const pubKey = pubKeys.keys[0];
    expect(pubKey).to.exist;

    const packetlist = new openpgp.packet.List();

    packetlist.read(openpgp.armor.decode(pub_sig_test).data);

    const subkeys = pubKey.getSubkeys();
    expect(subkeys).to.exist;
    expect(subkeys).to.have.length(2);
    expect(subkeys[0].getKeyId().equals(packetlist[8].getKeyId())).to.be.true;
    expect(subkeys[1].getKeyId().equals(packetlist[11].getKeyId())).to.be.true;
    done();
  });

  it('Verify status of revoked primary key', function(done) {
    const pubKey = openpgp.key.readArmored(pub_revoked_subkeys).keys[0];
    expect(pubKey.verifyPrimaryKey()).to.eventually.equal(openpgp.enums.keyStatus.revoked).notify(done);
  });

  it('Verify status of revoked subkey', function(done) {
    const pubKeys = openpgp.key.readArmored(pub_sig_test);
    expect(pubKeys).to.exist;
    expect(pubKeys.err).to.not.exist;
    expect(pubKeys.keys).to.have.length(1);

    const pubKey = pubKeys.keys[0];
    expect(pubKey).to.exist;
    expect(pubKey.subKeys).to.exist;
    expect(pubKey.subKeys).to.have.length(2);

    expect(pubKey.subKeys[0].verify(
      pubKey.primaryKey
    )).to.eventually.equal(openpgp.enums.keyStatus.revoked).notify(done);
  });

  it('Evaluate key flags to find valid encryption key packet', async function() {
    const pubKeys = openpgp.key.readArmored(pub_sig_test);
    expect(pubKeys).to.exist;
    expect(pubKeys.err).to.not.exist;
    expect(pubKeys.keys).to.have.length(1);

    const pubKey = pubKeys.keys[0];
    // remove subkeys
    pubKey.subKeys = [];
    // primary key has only key flags for signing
    const encryptionKey = await pubKey.getEncryptionKey();
    expect(encryptionKey).to.not.exist;
  });

  it('Method getExpirationTime V4 Key', async function() {
    const pubKey = openpgp.key.readArmored(twoKeys).keys[1];
    expect(pubKey).to.exist;
    expect(pubKey).to.be.an.instanceof(openpgp.key.Key);
    const expirationTime = await pubKey.getExpirationTime();
    expect(expirationTime.toISOString()).to.be.equal('2018-11-26T10:58:29.000Z');
  });

  it('Method getExpirationTime expired V4 Key', async function() {
    const pubKey = openpgp.key.readArmored(expiredKey).keys[0];
    expect(pubKey).to.exist;
    expect(pubKey).to.be.an.instanceof(openpgp.key.Key);
    const expirationTime = await pubKey.getExpirationTime();
    expect(expirationTime.toISOString()).to.be.equal('1970-01-01T00:22:18.000Z');
  });

  it('Method getExpirationTime V4 SubKey', async function() {
    const pubKey = openpgp.key.readArmored(twoKeys).keys[1];
    expect(pubKey).to.exist;
    expect(pubKey).to.be.an.instanceof(openpgp.key.Key);
    const expirationTime = await pubKey.subKeys[0].getExpirationTime();
    expect(expirationTime.toISOString()).to.be.equal('2018-11-26T10:58:29.000Z');
  });

  it('Method getExpirationTime V4 Key with capabilities', async function() {
    const pubKey = openpgp.key.readArmored(priv_key_2000_2008).keys[0];
    expect(pubKey).to.exist;
    expect(pubKey).to.be.an.instanceof(openpgp.key.Key);
    const expirationTime = await pubKey.getExpirationTime();
    expect(expirationTime).to.equal(Infinity);
    const encryptExpirationTime = await pubKey.getExpirationTime('encrypt_sign');
    expect(encryptExpirationTime.toISOString()).to.equal('2008-02-12T17:12:08.000Z');
  });

  it('update() - throw error if fingerprints not equal', function(done) {
    const keys = openpgp.key.readArmored(twoKeys).keys;
    expect(keys[0].update.bind(
      keys[0], keys[1]
    )()).to.be.rejectedWith('Key update method: fingerprints of keys not equal').notify(done);
  });

  it('update() - merge revocation signatures', function(done) {
    const source = openpgp.key.readArmored(pub_revoked_subkeys).keys[0];
    const dest = openpgp.key.readArmored(pub_revoked_subkeys).keys[0];
    expect(source.revocationSignatures).to.exist;
    dest.revocationSignatures = [];
    dest.update(source).then(() => {
      expect(dest.revocationSignatures[0]).to.exist.and.be.an.instanceof(openpgp.packet.Signature);
      done();
    });
  });

  it('update() - merge user', function() {
    const source = openpgp.key.readArmored(pub_sig_test).keys[0];
    const dest = openpgp.key.readArmored(pub_sig_test).keys[0];
    expect(source.users[1]).to.exist;
    dest.users.pop();
    return dest.update(source).then(() => {
      expect(dest.users[1]).to.exist;
      expect(dest.users[1].userId).to.equal(source.users[1].userId);
    });
  });

  it('update() - merge user - other and certification revocation signatures', function(done) {
    const source = openpgp.key.readArmored(pub_sig_test).keys[0];
    const dest = openpgp.key.readArmored(pub_sig_test).keys[0];
    expect(source.users[1].otherCertifications).to.exist;
    expect(source.users[1].revocationSignatures).to.exist;
    dest.users[1].otherCertifications = [];
    dest.users[1].revocationSignatures.pop();
    dest.update(source).then(() => {
      expect(dest.users[1].otherCertifications).to.exist.and.to.have.length(1);
      expect(dest.users[1].otherCertifications[0].signature).to.equal(source.users[1].otherCertifications[0].signature);
      expect(dest.users[1].revocationSignatures).to.exist.and.to.have.length(2);
      expect(dest.users[1].revocationSignatures[1].signature).to.equal(source.users[1].revocationSignatures[1].signature);
      done();
    });
  });

  it('update() - merge subkey', function(done) {
    const source = openpgp.key.readArmored(pub_sig_test).keys[0];
    const dest = openpgp.key.readArmored(pub_sig_test).keys[0];
    expect(source.subKeys[1]).to.exist;
    dest.subKeys.pop();
    dest.update(source).then(() => {
      expect(dest.subKeys[1]).to.exist;
      expect(
        dest.subKeys[1].getKeyId().toHex()
      ).to.equal(source.subKeys[1].getKeyId().toHex());
      done();
    });
  });

  it('update() - merge subkey - revocation signature', function() {
    const source = openpgp.key.readArmored(pub_sig_test).keys[0];
    const dest = openpgp.key.readArmored(pub_sig_test).keys[0];
    expect(source.subKeys[0].revocationSignatures).to.exist;
    dest.subKeys[0].revocationSignatures = [];
    return dest.update(source).then(() => {
      expect(dest.subKeys[0].revocationSignatures).to.exist;
      expect(dest.subKeys[0].revocationSignatures[0].signature).to.equal(dest.subKeys[0].revocationSignatures[0].signature);
    });
  });

  it('update() - merge private key into public key', function() {
    const source = openpgp.key.readArmored(priv_key_rsa).keys[0];
    const dest = openpgp.key.readArmored(twoKeys).keys[0];
    expect(dest.isPublic()).to.be.true;
    return dest.update(source).then(() => {
      expect(dest.isPrivate()).to.be.true;
      return Promise.all([
        dest.verifyPrimaryKey().then(result => {
          expect(source.verifyPrimaryKey()).to.eventually.equal(result);
        }),
        dest.users[0].verify(dest.primaryKey).then(result => {
          expect(source.users[0].verify(source.primaryKey)).to.eventually.equal(result);
        }),
        dest.subKeys[0].verify(dest.primaryKey).then(result => {
          expect(source.subKeys[0].verify(source.primaryKey)).to.eventually.equal(result);
        })
      ]);
    });
  });

  it('update() - merge private key into public key - no subkeys', function() {
    const source = openpgp.key.readArmored(priv_key_rsa).keys[0];
    const dest = openpgp.key.readArmored(twoKeys).keys[0];
    source.subKeys = [];
    dest.subKeys = [];
    expect(dest.isPublic()).to.be.true;
    return dest.update(source).then(() => {
      expect(dest.isPrivate()).to.be.true;
      return Promise.all([
        dest.verifyPrimaryKey().then(result => {
          expect(source.verifyPrimaryKey()).to.eventually.equal(result);
        }),
        dest.users[0].verify(dest.primaryKey).then(result => {
          expect(source.users[0].verify(source.primaryKey)).to.eventually.equal(result);
        })
      ]);
    });
  });

  it('update() - merge private key into public key - mismatch throws error', function(done) {
    const source = openpgp.key.readArmored(priv_key_rsa).keys[0];
    const dest = openpgp.key.readArmored(twoKeys).keys[0];
    source.subKeys = [];
    expect(dest.subKeys).to.exist;
    expect(dest.isPublic()).to.be.true;
    expect(dest.update.bind(dest, source)())
      .to.be.rejectedWith('Cannot update public key with private key if subkey mismatch').notify(done);
  });

  it('update() - merge subkey binding signatures', async function() {
    const source = openpgp.key.readArmored(pgp_desktop_pub).keys[0];
    const dest = openpgp.key.readArmored(pgp_desktop_priv).keys[0];
    expect(source.subKeys[0].bindingSignatures[0]).to.exist;
    await expect(source.subKeys[0].verify(source.primaryKey))
      .to.eventually.equal(openpgp.enums.keyStatus.valid);
    expect(dest.subKeys[0].bindingSignatures[0]).to.not.exist;
    return dest.update(source).then(async () => {
      expect(dest.subKeys[0].bindingSignatures[0]).to.exist;
      await expect(dest.subKeys[0].verify(source.primaryKey))
        .to.eventually.equal(openpgp.enums.keyStatus.valid);
    });
  });

  it('revoke() - primary key', async function() {
    const privKey = openpgp.key.readArmored(priv_key_arm2).keys[0];
    await privKey.decrypt('hello world');

    await privKey.revoke({
      flag: openpgp.enums.reasonForRevocation.key_retired,
      string: 'Testing key revocation'
    }).then(async revKey => {
      expect(revKey.revocationSignatures).to.exist.and.have.length(1);
      expect(revKey.revocationSignatures[0].signatureType).to.equal(openpgp.enums.signature.key_revocation);
      expect(revKey.revocationSignatures[0].reasonForRevocationFlag).to.equal(openpgp.enums.reasonForRevocation.key_retired);
      expect(revKey.revocationSignatures[0].reasonForRevocationString).to.equal('Testing key revocation');

      expect(await privKey.verifyPrimaryKey()).to.equal(openpgp.enums.keyStatus.valid);
      expect(await revKey.verifyPrimaryKey()).to.equal(openpgp.enums.keyStatus.revoked);
    });
  });

  it('revoke() - subkey', async function() {
    const pubKey = openpgp.key.readArmored(pub_key_arm2).keys[0];
    const privKey = openpgp.key.readArmored(priv_key_arm2).keys[0];
    await privKey.decrypt('hello world');

    const subKey = pubKey.subKeys[0];
    await subKey.revoke(privKey.primaryKey, {
      flag: openpgp.enums.reasonForRevocation.key_superseded
    }).then(async revKey => {
      expect(revKey.revocationSignatures).to.exist.and.have.length(1);
      expect(revKey.revocationSignatures[0].signatureType).to.equal(openpgp.enums.signature.subkey_revocation);
      expect(revKey.revocationSignatures[0].reasonForRevocationFlag).to.equal(openpgp.enums.reasonForRevocation.key_superseded);
      expect(revKey.revocationSignatures[0].reasonForRevocationString).to.equal('');

      expect(await subKey.verify(pubKey.primaryKey)).to.equal(openpgp.enums.keyStatus.valid);
      expect(await revKey.verify(pubKey.primaryKey)).to.equal(openpgp.enums.keyStatus.revoked);
    });
  });

  it('applyRevocationCertificate() should produce the same revoked key as GnuPG', function() {
    const pubKey = openpgp.key.readArmored(pub_key_arm4).keys[0];

    return pubKey.applyRevocationCertificate(revocation_certificate_arm4).then(revKey => {
      expect(revKey.armor()).to.equal(openpgp.key.readArmored(revoked_key_arm4).keys[0].armor());
    });
  });

  it('getRevocationCertificate() should produce the same revocation certificate as GnuPG', function() {
    const revKey = openpgp.key.readArmored(revoked_key_arm4).keys[0];
    const revocationCertificate = revKey.getRevocationCertificate();

    const input = openpgp.armor.decode(revocation_certificate_arm4);
    const packetlist = new openpgp.packet.List();
    packetlist.read(input.data);
    const armored = openpgp.armor.encode(openpgp.enums.armor.public_key, packetlist.write());

    expect(revocationCertificate.replace(/^Comment: .*$\r\n/mg, '')).to.equal(armored.replace(/^Comment: .*$\r\n/mg, ''));
  });

  it('getRevocationCertificate() should have an appropriate comment', function() {
    const revKey = openpgp.key.readArmored(revoked_key_arm4).keys[0];
    const revocationCertificate = revKey.getRevocationCertificate();

    expect(revocationCertificate).to.match(/Comment: This is a revocation certificate/);
    expect(revKey.armor()).not.to.match(/Comment: This is a revocation certificate/);
  });

  it("getPreferredAlgo('symmetric') - one key - AES256", async function() {
    const key1 = openpgp.key.readArmored(twoKeys).keys[0];
    const prefAlgo = await openpgp.key.getPreferredAlgo('symmetric', [key1]);
    expect(prefAlgo).to.equal(openpgp.enums.symmetric.aes256);
  });

  it("getPreferredAlgo('symmetric') - two key - AES128", async function() {
    const keys = openpgp.key.readArmored(twoKeys).keys;
    const key1 = keys[0];
    const key2 = keys[1];
    const primaryUser = await key2.getPrimaryUser();
    primaryUser.selfCertification.preferredSymmetricAlgorithms = [6,7,3];
    const prefAlgo = await openpgp.key.getPreferredAlgo('symmetric', [key1, key2]);
    expect(prefAlgo).to.equal(openpgp.enums.symmetric.aes128);
  });

  it("getPreferredAlgo('symmetric') - two key - one without pref", async function() {
    const keys = openpgp.key.readArmored(twoKeys).keys;
    const key1 = keys[0];
    const key2 = keys[1];
    const primaryUser = await key2.getPrimaryUser();
    primaryUser.selfCertification.preferredSymmetricAlgorithms = null;
    const prefAlgo = await openpgp.key.getPreferredAlgo('symmetric', [key1, key2]);
    expect(prefAlgo).to.equal(openpgp.config.encryption_cipher);
  });

  it("getPreferredAlgo('aead') - one key - OCB", async function() {
    const key1 = openpgp.key.readArmored(twoKeys).keys[0];
    const primaryUser = await key1.getPrimaryUser();
    primaryUser.selfCertification.features = [7]; // Monkey-patch AEAD feature flag
    primaryUser.selfCertification.preferredAeadAlgorithms = [2,1];
    const prefAlgo = await openpgp.key.getPreferredAlgo('aead', [key1]);
    expect(prefAlgo).to.equal(openpgp.enums.aead.ocb);
    const supported = await openpgp.key.isAeadSupported([key1]);
    expect(supported).to.be.true;
  });

  it("getPreferredAlgo('aead') - two key - one without pref", async function() {
    const keys = openpgp.key.readArmored(twoKeys).keys;
    const key1 = keys[0];
    const key2 = keys[1];
    const primaryUser = await key1.getPrimaryUser();
    primaryUser.selfCertification.features = [7]; // Monkey-patch AEAD feature flag
    primaryUser.selfCertification.preferredAeadAlgorithms = [2,1];
    const primaryUser2 = await key2.getPrimaryUser();
    primaryUser2.selfCertification.features = [7]; // Monkey-patch AEAD feature flag
    const prefAlgo = await openpgp.key.getPreferredAlgo('aead', [key1, key2]);
    expect(prefAlgo).to.equal(openpgp.config.aead_mode);
    const supported = await openpgp.key.isAeadSupported([key1, key2]);
    expect(supported).to.be.true;
  });

  it("getPreferredAlgo('aead') - two key - one with no support", async function() {
    const keys = openpgp.key.readArmored(twoKeys).keys;
    const key1 = keys[0];
    const key2 = keys[1];
    const primaryUser = await key1.getPrimaryUser();
    primaryUser.selfCertification.features = [7]; // Monkey-patch AEAD feature flag
    primaryUser.selfCertification.preferredAeadAlgorithms = [2,1];
    const prefAlgo = await openpgp.key.getPreferredAlgo('aead', [key1, key2]);
    expect(prefAlgo).to.equal(openpgp.config.aead_mode);
    const supported = await openpgp.key.isAeadSupported([key1, key2]);
    expect(supported).to.be.false;
  });

  it('Preferences of generated key', function() {
    const testPref = function(key) {
      // key flags
      const keyFlags = openpgp.enums.keyFlags;
      expect(key.users[0].selfCertifications[0].keyFlags[0] & keyFlags.certify_keys).to.equal(keyFlags.certify_keys);
      expect(key.users[0].selfCertifications[0].keyFlags[0] & keyFlags.sign_data).to.equal(keyFlags.sign_data);
      expect(key.subKeys[0].bindingSignatures[0].keyFlags[0] & keyFlags.encrypt_communication).to.equal(keyFlags.encrypt_communication);
      expect(key.subKeys[0].bindingSignatures[0].keyFlags[0] & keyFlags.encrypt_storage).to.equal(keyFlags.encrypt_storage);
      const sym = openpgp.enums.symmetric;
      expect(key.users[0].selfCertifications[0].preferredSymmetricAlgorithms).to.eql([sym.aes256, sym.aes128, sym.aes192, sym.cast5, sym.tripledes]);
      if (openpgp.config.aead_protect && openpgp.config.aead_protect_version === 4) {
        const aead = openpgp.enums.aead;
        expect(key.users[0].selfCertifications[0].preferredAeadAlgorithms).to.eql([aead.eax, aead.ocb]);
      }
      const hash = openpgp.enums.hash;
      expect(key.users[0].selfCertifications[0].preferredHashAlgorithms).to.eql([hash.sha256, hash.sha512, hash.sha1]);
      const compr = openpgp.enums.compression;
      expect(key.users[0].selfCertifications[0].preferredCompressionAlgorithms).to.eql([compr.zlib, compr.zip]);
      expect(key.users[0].selfCertifications[0].features).to.eql(openpgp.config.aead_protect && openpgp.config.aead_protect_version === 4 ? [7] : [1]);
    };
    const opt = {numBits: 512, userIds: 'test <a@b.com>', passphrase: 'hello'};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    return openpgp.generateKey(opt).then(function(key) {
      testPref(key.key);
      testPref(openpgp.key.readArmored(key.publicKeyArmored).keys[0]);
    });
  });

  it('User attribute packet read & write', function() {
    const key = openpgp.key.readArmored(user_attr_key).keys[0];
    const key2 = openpgp.key.readArmored(key.armor()).keys[0];
    expect(key.users[1].userAttribute).eql(key2.users[1].userAttribute);
  });

  it('getPrimaryUser()', async function() {
    const key = openpgp.key.readArmored(pub_sig_test).keys[0];
    const primUser = await key.getPrimaryUser();
    expect(primUser).to.exist;
    expect(primUser.user.userId.userid).to.equal('Signature Test <signature@test.com>');
    expect(primUser.user.userId.name).to.equal('Signature Test');
    expect(primUser.user.userId.email).to.equal('signature@test.com');
    expect(primUser.user.userId.comment).to.equal('');
    expect(primUser.selfCertification).to.be.an.instanceof(openpgp.packet.Signature);
  });

  it('getPrimaryUser() should return null if no UserIDs are bound', async function() {
    const keyWithoutUserID = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEWxpFkRYJKwYBBAHaRw8BAQdAYjjZLkp4qG7KAqJeVQlxQT6uCPq6rylV02nC
c6D/a8YAAP0YtS4UeLzeJGSgjGTlvSd3TWEsjxdGyzwfHCOejXMRbg2+zSFVbmJv
dW5kIFVJRCA8dW5ib3VuZEBleGFtcGxlLm9yZz7HXQRbGkWREgorBgEEAZdVAQUB
AQdAfxbFuoNlm5KfoqaWICETfMljzVTDAtiSM0TYSHzGAz8DAQoJAAD/cuu7bxUE
goBAhIyVH+pmvWpuDJbfu1Vaj5KiQxsKxJgP/MJ+BBgWCgAwApsMBYJbGkWRBYkB
3+IAFqEE30YL4fxJBMTm8ONLPOiTkVxEIS8JkDzok5FcRCEvAABb+gEAnQb/rMLO
Vz/bMCJoAShgybW1r6kRWejybzIjFSLnx/YA/iLZeo5UNdlXRJco+15RbFiNSAbw
VYGdb3eNlV8CfoEC
=FYbP
-----END PGP PRIVATE KEY BLOCK-----`;
    const key = openpgp.key.readArmored(keyWithoutUserID).keys[0];
    const primUser = await key.getPrimaryUser();
    expect(primUser).to.be.null;
  });

  it('Generated key is not unlocked by default', function() {
    const opt = {numBits: 512, userIds: 'test <a@b.com>', passphrase: '123'};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    let key;
    return openpgp.generateKey(opt).then(function(newKey) {
      key = newKey.key;
      return openpgp.message.fromText('hello').encrypt([key]);
    }).then(function(msg) {
      return msg.message.decrypt([key]);
    }).catch(function(err) {
      expect(err.message).to.equal('Private key is not decrypted.');
    });
  });

  it('Generate key - single userid', function() {
    const userId = { name: 'test', email: 'a@b.com', comment: 'test comment' };
    const opt = {numBits: 512, userIds: userId, passphrase: '123'};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    return openpgp.generateKey(opt).then(function(key) {
      key = key.key;
      expect(key.users.length).to.equal(1);
      expect(key.users[0].userId.userid).to.equal('test <a@b.com> (test comment)');
      expect(key.users[0].userId.name).to.equal(userId.name);
      expect(key.users[0].userId.email).to.equal(userId.email);
      expect(key.users[0].userId.comment).to.equal(userId.comment);
    });
  });

  it('Generate key - setting date to the past', function() {
    const past = new Date(0);
    const opt = {
      userIds: { name: 'Test User', email: 'text@example.com' },
      passphrase: 'secret',
      date: past
    };

    return openpgp.generateKey(opt).then(function(newKey) {
      expect(newKey.key).to.exist;
      expect(+newKey.key.getCreationTime()).to.equal(+past);
      expect(+newKey.key.subKeys[0].getCreationTime()).to.equal(+past);
      expect(+newKey.key.subKeys[0].bindingSignatures[0].created).to.equal(+past);
    });
  })

  it('Generate key - multi userid', function() {
    const userId1 = 'test <a@b.com>';
    const userId2 = 'test <b@c.com>';
    const opt = {numBits: 512, userIds: [userId1, userId2], passphrase: '123'};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    return openpgp.generateKey(opt).then(function(key) {
      key = key.key;
      expect(key.users.length).to.equal(2);
      expect(key.users[0].userId.userid).to.equal(userId1);
      expect(key.users[0].selfCertifications[0].isPrimaryUserID).to.be.true;
      expect(key.users[1].userId.userid).to.equal(userId2);
      expect(key.users[1].selfCertifications[0].isPrimaryUserID).to.be.null;
    });
  });

  it('Generate key - two subkeys with default values', function() {
    const userId = 'test <a@b.com>';
    const opt = {curve: 'curve25519', userIds: [userId], passphrase: '123', subkeys:[{},{}]};
    return openpgp.generateKey(opt).then(function(key) {
      key = key.key;
      expect(key.users.length).to.equal(1);
      expect(key.users[0].userId.userid).to.equal(userId);
      expect(key.users[0].selfCertifications[0].isPrimaryUserID).to.be.true;
      expect(key.subKeys).to.have.lengthOf(2);
      expect(key.subKeys[0].getAlgorithmInfo().algorithm).to.equal('ecdh');
      expect(key.subKeys[1].getAlgorithmInfo().algorithm).to.equal('ecdh');
    });
  });

  it('Generate key - one signing subkey', function() {
    const userId = 'test <a@b.com>';
    const opt = {curve: 'curve25519', userIds: [userId], passphrase: '123', subkeys:[{}, {sign: true}]};
    let privateKey;
    return openpgp.generateKey(opt).then(function(key) {
      key = key.key;
      privateKey = key;
      expect(key.users.length).to.equal(1);
      expect(key.users[0].userId.userid).to.equal(userId);
      expect(key.users[0].selfCertifications[0].isPrimaryUserID).to.be.true;
      expect(key.subKeys).to.have.lengthOf(2);
      expect(key.subKeys[0].getAlgorithmInfo().algorithm).to.equal('ecdh');
      expect(key.subKeys[1].getAlgorithmInfo().algorithm).to.equal('eddsa');
      return key.getSigningKey();
    }).then(function(result){
      expect(result).to.equal(privateKey.subKeys[1]);
    });
  });

  it('Generate key - override main key options for subkey', function() {
    const userId = 'test <a@b.com>';
    const opt = {numBits: 2048, userIds: [userId], passphrase: '123', subkeys:[{curve: 'curve25519'}]};
    return openpgp.generateKey(opt).then(function(key) {
      key = key.key;
      expect(key.users.length).to.equal(1);
      expect(key.users[0].userId.userid).to.equal(userId);
      expect(key.users[0].selfCertifications[0].isPrimaryUserID).to.be.true;
      expect(key.getAlgorithmInfo().algorithm).to.equal('rsa_encrypt_sign');
      expect(key.subKeys[0].getAlgorithmInfo().algorithm).to.equal('ecdh');
    });
  });

  it('Encrypt key with new passphrase', async function() {
    const userId = 'test <a@b.com>';
    const opt = {numBits: 512, userIds: userId, passphrase: 'passphrase'};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    const key = (await openpgp.generateKey(opt)).key;
    const armor1 = key.armor();
    const armor2 = key.armor();
    expect(armor1).to.equal(armor2);
    expect(await key.decrypt('passphrase')).to.be.true;
    expect(key.isDecrypted()).to.be.true;
    await key.encrypt('new_passphrase');
    expect(key.isDecrypted()).to.be.false;
    await expect(key.decrypt('passphrase')).to.eventually.be.rejectedWith('Incorrect key passphrase');
    expect(key.isDecrypted()).to.be.false;
    expect(await key.decrypt('new_passphrase')).to.be.true;
    expect(key.isDecrypted()).to.be.true;
    const armor3 = key.armor();
    expect(armor3).to.not.equal(armor1);
  });

  it('Generate key - ensure keyExpirationTime works', function() {
    const expect_delta = 365 * 24 * 60 * 60;
    const userId = 'test <a@b.com>';
    const opt = {numBits: 512, userIds: userId, passphrase: '123', keyExpirationTime: expect_delta};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    return openpgp.generateKey(opt).then(async function(key) {
      key = key.key;

      const expiration = await key.getExpirationTime();
      expect(expiration).to.exist;

      const actual_delta = (new Date(expiration) - new Date()) / 1000;
      expect(Math.abs(actual_delta - expect_delta)).to.be.below(60);

      const subKeyExpiration = await key.subKeys[0].getExpirationTime();
      expect(subKeyExpiration).to.exist;

      const actual_subKeyDelta = (new Date(subKeyExpiration) - new Date()) / 1000;
      expect(Math.abs(actual_subKeyDelta - expect_delta)).to.be.below(60);
    });
  });

  it('Sign and verify key - primary user', async function() {
    let publicKey = openpgp.key.readArmored(pub_sig_test).keys[0];
    const privateKey = openpgp.key.readArmored(priv_key_rsa).keys[0];
    await privateKey.decrypt('hello world');
    publicKey = await publicKey.signPrimaryUser([privateKey]);
    const signatures = await publicKey.verifyPrimaryUser([privateKey]);
    const publicSigningKey = await publicKey.getSigningKey();
    const privateSigningKey = await privateKey.getSigningKey();
    expect(signatures.length).to.equal(2);
    expect(signatures[0].keyid.toHex()).to.equal(publicSigningKey.getKeyId().toHex());
    expect(signatures[0].valid).to.be.null;
    expect(signatures[1].keyid.toHex()).to.equal(privateSigningKey.getKeyId().toHex());
    expect(signatures[1].valid).to.be.true;
  });

  it('Sign key and verify with wrong key - primary user', async function() {
    let publicKey = openpgp.key.readArmored(pub_sig_test).keys[0];
    const privateKey = openpgp.key.readArmored(priv_key_rsa).keys[0];
    const wrongKey = openpgp.key.readArmored(wrong_key).keys[0];
    await privateKey.decrypt('hello world');
    publicKey = await publicKey.signPrimaryUser([privateKey]);
    const signatures = await publicKey.verifyPrimaryUser([wrongKey]);
    const publicSigningKey = await publicKey.getSigningKey();
    const privateSigningKey = await privateKey.getSigningKey();
    expect(signatures.length).to.equal(2);
    expect(signatures[0].keyid.toHex()).to.equal(publicSigningKey.getKeyId().toHex());
    expect(signatures[0].valid).to.be.null;
    expect(signatures[1].keyid.toHex()).to.equal(privateSigningKey.getKeyId().toHex());
    expect(signatures[1].valid).to.be.null;
  });

  it('Sign and verify key - all users', async function() {
    let publicKey = openpgp.key.readArmored(multi_uid_key).keys[0];
    const privateKey = openpgp.key.readArmored(priv_key_rsa).keys[0];
    await privateKey.decrypt('hello world');
    publicKey = await publicKey.signAllUsers([privateKey]);
    const signatures = await publicKey.verifyAllUsers([privateKey]);
    const publicSigningKey = await publicKey.getSigningKey();
    const privateSigningKey = await privateKey.getSigningKey();
    expect(signatures.length).to.equal(4);
    expect(signatures[0].userid).to.equal(publicKey.users[0].userId.userid);
    expect(signatures[0].keyid.toHex()).to.equal(publicSigningKey.getKeyId().toHex());
    expect(signatures[0].valid).to.be.null;
    expect(signatures[1].userid).to.equal(publicKey.users[0].userId.userid);
    expect(signatures[1].keyid.toHex()).to.equal(privateSigningKey.getKeyId().toHex());
    expect(signatures[1].valid).to.be.true;
    expect(signatures[2].userid).to.equal(publicKey.users[1].userId.userid);
    expect(signatures[2].keyid.toHex()).to.equal(publicSigningKey.getKeyId().toHex());
    expect(signatures[2].valid).to.be.null;
    expect(signatures[3].userid).to.equal(publicKey.users[1].userId.userid);
    expect(signatures[3].keyid.toHex()).to.equal(privateSigningKey.getKeyId().toHex());
    expect(signatures[3].valid).to.be.true;
  });

  it('Sign key and verify with wrong key - all users', async function() {
    let publicKey = openpgp.key.readArmored(multi_uid_key).keys[0];
    const privateKey = openpgp.key.readArmored(priv_key_rsa).keys[0];
    const wrongKey = openpgp.key.readArmored(wrong_key).keys[0];
    await privateKey.decrypt('hello world');
    publicKey = await publicKey.signAllUsers([privateKey]);
    const signatures = await publicKey.verifyAllUsers([wrongKey]);
    const publicSigningKey = await publicKey.getSigningKey();
    const privateSigningKey = await privateKey.getSigningKey();
    expect(signatures.length).to.equal(4);
    expect(signatures[0].userid).to.equal(publicKey.users[0].userId.userid);
    expect(signatures[0].keyid.toHex()).to.equal(publicSigningKey.getKeyId().toHex());
    expect(signatures[0].valid).to.be.null;
    expect(signatures[1].userid).to.equal(publicKey.users[0].userId.userid);
    expect(signatures[1].keyid.toHex()).to.equal(privateSigningKey.getKeyId().toHex());
    expect(signatures[1].valid).to.be.null;
    expect(signatures[2].userid).to.equal(publicKey.users[1].userId.userid);
    expect(signatures[2].keyid.toHex()).to.equal(publicSigningKey.getKeyId().toHex());
    expect(signatures[2].valid).to.be.null;
    expect(signatures[3].userid).to.equal(publicKey.users[1].userId.userid);
    expect(signatures[3].keyid.toHex()).to.equal(privateSigningKey.getKeyId().toHex());
    expect(signatures[3].valid).to.be.null;
  });

  it('Encrypt - latest created user', async function() {
    let publicKey = openpgp.key.readArmored(multi_uid_key).keys[0];
    const privateKey = openpgp.key.readArmored(priv_key_rsa).keys[0];
    await privateKey.decrypt('hello world');
    // Set second user to prefer aes128. We should select this user by default, since it was created later.
    publicKey.users[1].selfCertifications[0].preferredSymmetricAlgorithms = [openpgp.enums.symmetric.aes128];
    const encrypted = await openpgp.encrypt({data: 'hello', publicKeys: publicKey, privateKeys: privateKey, armor: false});
    expect(encrypted.message.packets[0].sessionKeyAlgorithm).to.equal('aes128');
  });

  it('Encrypt - primary user', async function() {
    let publicKey = openpgp.key.readArmored(multi_uid_key).keys[0];
    const privateKey = openpgp.key.readArmored(priv_key_rsa).keys[0];
    await privateKey.decrypt('hello world');
    // Set first user to primary. We should select this user by default.
    publicKey.users[0].selfCertifications[0].isPrimaryUserID = true;
    // Set first user to prefer aes128.
    publicKey.users[0].selfCertifications[0].preferredSymmetricAlgorithms = [openpgp.enums.symmetric.aes128];
    const encrypted = await openpgp.encrypt({data: 'hello', publicKeys: publicKey, privateKeys: privateKey, armor: false});
    expect(encrypted.message.packets[0].sessionKeyAlgorithm).to.equal('aes128');
  });

  it('Encrypt - specific user', async function() {
    let publicKey = openpgp.key.readArmored(multi_uid_key).keys[0];
    const privateKey = openpgp.key.readArmored(priv_key_rsa).keys[0];
    await privateKey.decrypt('hello world');
    // Set first user to primary. We won't select this user, this is to test that.
    publicKey.users[0].selfCertifications[0].isPrimaryUserID = true;
    // Set second user to prefer aes128. We will select this user.
    publicKey.users[1].selfCertifications[0].preferredSymmetricAlgorithms = [openpgp.enums.symmetric.aes128];
    const encrypted = await openpgp.encrypt({data: 'hello', publicKeys: publicKey, privateKeys: privateKey, toUserId: {name: 'Test User', email: 'b@c.com'}, armor: false});
    expect(encrypted.message.packets[0].sessionKeyAlgorithm).to.equal('aes128');
    await expect(openpgp.encrypt({data: 'hello', publicKeys: publicKey, privateKeys: privateKey, toUserId: {name: 'Test User', email: 'c@c.com'}, armor: false})).to.be.rejectedWith('Could not find user that matches that user ID');
  });

  it('Sign - specific user', async function() {
    let publicKey = openpgp.key.readArmored(multi_uid_key).keys[0];
    const privateKey = openpgp.key.readArmored(priv_key_rsa).keys[0];
    await privateKey.decrypt('hello world');
    const privateKeyClone = openpgp.key.readArmored(priv_key_rsa).keys[0];
    // Duplicate user
    privateKey.users.push(privateKeyClone.users[0]);
    // Set first user to primary. We won't select this user, this is to test that.
    privateKey.users[0].selfCertifications[0].isPrimaryUserID = true;
    // Change userid of the first user so that we don't select it. This also makes this user invalid.
    privateKey.users[0].userId.parse('Test User <b@c.com>');
    // Set second user to prefer aes128. We will select this user.
    privateKey.users[1].selfCertifications[0].preferredHashAlgorithms = [openpgp.enums.hash.sha512];
    const signed = await openpgp.sign({data: 'hello', privateKeys: privateKey, fromUserId: {name: 'Test McTestington', email: 'test@example.com'}, armor: false});
    expect(signed.message.signature.packets[0].hashAlgorithm).to.equal(openpgp.enums.hash.sha512);
    const encrypted = await openpgp.encrypt({data: 'hello', publicKeys: publicKey, privateKeys: privateKey, fromUserId: {name: 'Test McTestington', email: 'test@example.com'}, detached: true, armor: false});
    expect(encrypted.signature.packets[0].hashAlgorithm).to.equal(openpgp.enums.hash.sha512);
    await expect(openpgp.encrypt({data: 'hello', publicKeys: publicKey, privateKeys: privateKey, fromUserId: {name: 'Not Test McTestington', email: 'test@example.com'}, detached: true, armor: false})).to.be.rejectedWith('Could not find user that matches that user ID');
  });

  it('Reformat key without passphrase', function() {
    const userId1 = 'test1 <a@b.com>';
    const userId2 = 'test2 <b@a.com>';
    const opt = {numBits: 512, userIds: userId1};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    return openpgp.generateKey(opt).then(function(key) {
      key = key.key;
      expect(key.users.length).to.equal(1);
      expect(key.users[0].userId.userid).to.equal(userId1);
      expect(key.isDecrypted()).to.be.true;
      opt.privateKey = key;
      opt.userIds = userId2;
      return openpgp.reformatKey(opt).then(function(newKey) {
        newKey = newKey.key;
        expect(newKey.users.length).to.equal(1);
        expect(newKey.users[0].userId.userid).to.equal(userId2);
        expect(newKey.isDecrypted()).to.be.true;
      });
    });
  });

  it('Reformat key with no subkey with passphrase', function() {
    const userId = 'test1 <a@b.com>';
    const keys = openpgp.key.readArmored(key_without_subkey).keys;
    const opt = {privateKey: keys[0], userIds: [userId], passphrase: "test"};
    return openpgp.reformatKey(opt).then(function(newKey) {
      newKey = newKey.key;
      expect(newKey.users.length).to.equal(1);
      expect(newKey.users[0].userId.userid).to.equal(userId);
      expect(newKey.isDecrypted()).to.be.false;
    });
  });

  it('Reformat key with two subkeys with passphrase', function() {
    const userId1 = 'test <a@b.com>';
    const userId2 = 'test <b@c.com>';
    const now = openpgp.util.normalizeDate(new Date());
    const before = openpgp.util.normalizeDate(new Date(0));
    const opt1 = {curve: 'curve25519', userIds: [userId1], date: now};
    return openpgp.generateKey(opt1).then(function(newKey) {
      newKey = newKey.key;
      expect(newKey.users[0].userId.userid).to.equal(userId1);
      expect(+newKey.getCreationTime()).to.equal(+now);
      expect(+newKey.subKeys[0].getCreationTime()).to.equal(+now);
      expect(+newKey.subKeys[0].bindingSignatures[0].created).to.equal(+now);
      const opt2 = {privateKey: newKey, userIds: [userId2], date: before};
      return openpgp.reformatKey(opt2).then(function(refKey) {
        refKey = refKey.key;
        expect(refKey.users.length).to.equal(1);
        expect(refKey.users[0].userId.userid).to.equal(userId2);
        expect(+refKey.subKeys[0].bindingSignatures[0].created).to.equal(+before);
      });
    });
  });

  it('Reformat key with no subkey without passphrase', function() {
    const userId = 'test1 <a@b.com>';
    const keys = openpgp.key.readArmored(key_without_subkey).keys;
    const opt = {privateKey: keys[0], userIds: [userId]};
    return openpgp.reformatKey(opt).then(function(newKey) {
      newKey = newKey.key;
      expect(newKey.users.length).to.equal(1);
      expect(newKey.users[0].userId.userid).to.equal(userId);
      expect(newKey.isDecrypted()).to.be.true;
      return openpgp.sign({data: 'hello', privateKeys: newKey, armor: true}).then(function(signed) {
        return openpgp.verify(
          {message: openpgp.cleartext.readArmored(signed.data), publicKeys: newKey.toPublic()}
        ).then(async function(verified) {
          expect(verified.signatures[0].valid).to.be.true;
          const newSigningKey = await newKey.getSigningKey();
          expect(verified.signatures[0].keyid.toHex()).to.equal(newSigningKey.getKeyId().toHex());
          expect(verified.signatures[0].signature.packets.length).to.equal(1);
        });
      });
    });
  });

  it('Reformat and encrypt key', function() {
    const userId1 = 'test1 <a@b.com>';
    const userId2 = 'test2 <b@c.com>';
    const userId3 = 'test3 <c@d.com>';
    const opt = {numBits: 512, userIds: userId1};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    return openpgp.generateKey(opt).then(function(key) {
      key = key.key;
      opt.privateKey = key;
      opt.userIds = [userId2, userId3];
      opt.passphrase = '123';
      return openpgp.reformatKey(opt).then(async function(newKey) {
        newKey = newKey.key;
        expect(newKey.users.length).to.equal(2);
        expect(newKey.users[0].userId.userid).to.equal(userId2);
        expect(newKey.isDecrypted()).to.be.false;
        await newKey.decrypt('123');
        expect(newKey.isDecrypted()).to.be.true;
      });
    });
  });

  it('Sign and encrypt with reformatted key', function() {
    const userId1 = 'test1 <a@b.com>';
    const userId2 = 'test2 <b@a.com>';
    const opt = {numBits: 512, userIds: userId1};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    return openpgp.generateKey(opt).then(function(key) {
      key = key.key;
      opt.privateKey = key;
      opt.userIds = userId2;
      return openpgp.reformatKey(opt).then(function(newKey) {
        newKey = newKey.key;
        return openpgp.encrypt({data: 'hello', publicKeys: newKey.toPublic(), privateKeys: newKey, armor: true}).then(function(encrypted) {
          return openpgp.decrypt({message: openpgp.message.readArmored(encrypted.data), privateKeys: newKey, publicKeys: newKey.toPublic()}).then(function(decrypted) {
            expect(decrypted.data).to.equal('hello');
            expect(decrypted.signatures[0].valid).to.be.true;
          });
        });
      });
    });
  });

  it('Reject with user-friendly error when reformatting encrypted key', function() {
    const opt = {numBits: 512, userIds: 'test1 <a@b.com>', passphrase: '1234'};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    return openpgp.generateKey(opt).then(function(original) {
      return openpgp.reformatKey({privateKey: original.key, userIds: 'test2 <b@a.com>', passphrase: '1234'}).then(function() {
        throw new Error('reformatKey should result in error when key not decrypted');
      }).catch(function(error) {
        expect(error.message).to.equal('Error reformatting keypair: Key not decrypted');
      });
    });
  });

  it('Find a valid subkey binding signature among many invalid ones', async function() {
    const key = openpgp.key.readArmored(valid_binding_sig_among_many_expired_sigs_pub).keys[0];
    expect(await key.getEncryptionKey()).to.not.be.null;
  });

  it('Selects the most recent subkey binding signature', async function() {
    const key = openpgp.key.readArmored(multipleBindingSignatures).keys[0];
    expect(key.subKeys[0].getExpirationTime().toISOString()).to.equal('2015-10-18T07:41:30.000Z');
  });

  it('Reject encryption with revoked subkey', function() {
    const key = openpgp.key.readArmored(pub_revoked_subkeys).keys[0];
    return openpgp.encrypt({publicKeys: [key], data: 'random data'}).then(() => {
      throw new Error('encryptSessionKey should not encrypt with revoked public key');
    }).catch(function(error) {
      expect(error.message).to.equal('Error encrypting message: Could not find valid key packet for encryption in key ' + key.getKeyId().toHex());
    });
  });

  it('Reject encryption with key revoked with appended revocation cert', function() {
    const key = openpgp.key.readArmored(pub_revoked_with_cert).keys[0];
    return openpgp.encrypt({publicKeys: [key], data: 'random data'}).then(() => {
      throw new Error('encryptSessionKey should not encrypt with revoked public key');
    }).catch(function(error) {
      expect(error.message).to.equal('Error encrypting message: Could not find valid key packet for encryption in key ' + key.getKeyId().toHex());
    });
  });

  it('Revoke generated key with revocation certificate', function() {
    const opt = {numBits: 512, userIds: 'test1 <a@b.com>', passphrase: '1234'};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    return openpgp.generateKey(opt).then(function(original) {
      return openpgp.revokeKey({key: original.key.toPublic(), revocationCertificate: original.revocationCertificate}).then(function(revKey) {
        revKey = revKey.publicKey;
        expect(revKey.revocationSignatures[0].reasonForRevocationFlag).to.equal(openpgp.enums.reasonForRevocation.no_reason);
        expect(revKey.revocationSignatures[0].reasonForRevocationString).to.equal('');
        return revKey.verifyPrimaryKey().then(function(status) {
          expect(status).to.equal(openpgp.enums.keyStatus.revoked);
        });
      });
    });
  });

  it('Revoke generated key with private key', function() {
    const opt = {numBits: 512, userIds: 'test1 <a@b.com>', passphrase: '1234'};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    return openpgp.generateKey(opt).then(async function(original) {
      await original.key.decrypt('1234');
      return openpgp.revokeKey({key: original.key, reasonForRevocation: {string: 'Testing key revocation'}}).then(function(revKey) {
        revKey = revKey.publicKey;
        expect(revKey.revocationSignatures[0].reasonForRevocationFlag).to.equal(openpgp.enums.reasonForRevocation.no_reason);
        expect(revKey.revocationSignatures[0].reasonForRevocationString).to.equal('Testing key revocation');
        return revKey.verifyPrimaryKey().then(function(status) {
          expect(status).to.equal(openpgp.enums.keyStatus.revoked);
        });
      });
    });
  });

  it('Merge key with another key with non-ID user attributes', function(done) {
    const key = openpgp.key.readArmored(mergeKey1).keys[0];
    const updateKey = openpgp.key.readArmored(mergeKey2).keys[0];
    expect(key).to.exist;
    expect(updateKey).to.exist;
    expect(key.users).to.have.length(1);
    key.update(updateKey).then(() => {
      expect(key.getFingerprint()).to.equal(
        updateKey.getFingerprint());
      expect(key.users).to.have.length(2);
      expect(key.users[1].userId).to.be.null;
      done();
    });
  });

  it('create and add a new rsa subkey to a rsa key', function() {
    const privateKey = openpgp.key.readArmored(priv_key_rsa).keys[0];
    const total = privateKey.subKeys.length;
    return privateKey.decrypt('hello world').then(function(answer){
      return privateKey.generateSubkey();
    }).then(function(answer){
      expect(answer).to.exist;
      expect(privateKey.subKeys.length).to.be.equal(total+1);
      const subkeyN = answer.keyPacket.params[0];
      const pkN = privateKey.primaryKey.params[0];
      expect(subkeyN.byteLength()).to.be.equal(pkN.byteLength());
      expect(answer).to.be.equal(privateKey.subKeys[total]);
      expect(answer.getAlgorithmInfo().algorithm).to.be.equal('rsa_encrypt_sign');
      return answer.verify(privateKey.primaryKey);
    }).then(function(answer){
      expect(answer).to.be.equal(openpgp.enums.keyStatus.valid);
    });
  });

  it('create and add a new ec subkey to a ec key', function() {
    const userId = 'test <a@b.com>';
    const opt = {curve: 'curve25519', userIds: [userId], subkeys:[]};
    let privateKey;
    let total;
    return openpgp.generateKey(opt).then(function(key) {
      privateKey = key.key;
      total = privateKey.subKeys.length;
      return privateKey.generateSubkey({sign: true});
    }).then(function(answer){
      expect(answer).to.exist;
      expect(privateKey.subKeys.length).to.be.equal(total+1);
      expect(answer).to.be.equal(privateKey.subKeys[total]);
      const subkeyOid = answer.keyPacket.params[0];
      const pkOid = privateKey.primaryKey.params[0];
      expect(subkeyOid.getName()).to.be.equal(pkOid.getName());
      expect(answer.getAlgorithmInfo().algorithm).to.be.equal('eddsa');
      return answer.verify(privateKey.primaryKey);
    }).then(function(answer){
      expect(answer).to.be.equal(openpgp.enums.keyStatus.valid);
    });
  });

  it('create and add a new ec subkey to a rsa key', function() {
    const privateKey = openpgp.key.readArmored(priv_key_rsa).keys[0];
    privateKey.subKeys = [];
    const total = privateKey.subKeys.length;
    return privateKey.decrypt('hello world').then(function(answer){
      return privateKey.generateSubkey({curve: 'ed25519'});
    }).then(function(answer){
      expect(answer).to.exist;
      expect(privateKey.subKeys.length).to.be.equal(total+1);
      expect(answer).to.be.equal(privateKey.subKeys[total]);
      expect(answer.keyPacket.params[0].getName()).to.be.equal(openpgp.enums.curve.curve25519);
      expect(answer.getAlgorithmInfo().algorithm).to.be.equal('ecdh');
      return answer.verify(privateKey.primaryKey);
    }).then(function(answer){
      expect(answer).to.be.equal(openpgp.enums.keyStatus.valid);
    });
  });

  it('sign/verify data with the new subkey correctly', function() {
    const userId = 'test <a@b.com>';
    const opt = {curve: 'curve25519', userIds: [userId], subkeys:[]};
    let privateKey;
    let total;
    let newSubkey;
    return openpgp.generateKey(opt).then(function(key) {
      privateKey = key.key;
      total = privateKey.subKeys.length;
      expect(total).to.be.equal(0);
    //   return privateKey.decrypt('123');
    // }).then(function(answer){
      return privateKey.generateSubkey({sign: true});
    }).then(function(answer){
      expect(answer).to.exist;
      expect(privateKey.subKeys.length).to.be.equal(total+1);
      expect(answer).to.be.equal(privateKey.subKeys[total]);
      const subkeyOid = answer.keyPacket.params[0];
      const pkOid = privateKey.primaryKey.params[0];
      expect(subkeyOid.getName()).to.be.equal(pkOid.getName());
      expect(answer.getAlgorithmInfo().algorithm).to.be.equal('eddsa');
      newSubkey = answer;
      return answer.verify(privateKey.primaryKey);
    }).then(function(answer){
      expect(answer).to.be.equal(openpgp.enums.keyStatus.valid);
    //   return privateKey.decrypt('123');
    // }).then(function(){
      return privateKey.getSigningKey();
    }).then(function(answer){
      expect(answer).to.be.equal(newSubkey);
      return openpgp.sign({data: 'the data to signed', privateKeys: privateKey, armor:false})
    }).then(function(answer){
      return answer.message.verify([privateKey.toPublic()]);
    }).then(function(answer){
      expect(answer).to.exist;
      expect(answer.length).to.be.equal(1);
      expect(answer[0].keyid).to.be.equal(newSubkey.getKeyId());
      expect(answer[0].valid).to.be.true;
    });
  });

  it('encrypt/decrypt data with the new subkey correctly', function() {
    const userId = 'test <a@b.com>';
    const vData = 'the data to encrypted!';
    const opt = {curve: 'curve25519', userIds: [userId], subkeys:[]};
    let privateKey;
    let publicKey;
    let total;
    let newSubkey;
    return openpgp.generateKey(opt).then(function(key) {
      privateKey = key.key;
      total = privateKey.subKeys.length;
      expect(total).to.be.equal(0);
    //   return privateKey.decrypt('123');
    // }).then(function(answer){
      return privateKey.generateSubkey();
    }).then(function(answer){
      expect(answer).to.exist;
      expect(privateKey.subKeys.length).to.be.equal(total+1);
      expect(answer).to.be.equal(privateKey.subKeys[total]);
      newSubkey = answer;
      publicKey = privateKey.toPublic();
      return answer.verify(privateKey.primaryKey);
    }).then(function(answer){
      expect(answer).to.be.equal(openpgp.enums.keyStatus.valid);
    //   return privateKey.decrypt('123');
    // }).then(function(){
      return privateKey.getEncryptionKey();
    }).then(function(answer){
      expect(answer).to.be.equal(newSubkey);
      return openpgp.encrypt({data: vData, publicKeys: publicKey, armor:false})
    }).then(function(answer){
      expect(answer.message).to.exist;
      const pkSessionKeys = answer.message.packets.filterByTag(openpgp.enums.packet.publicKeyEncryptedSessionKey);
      expect(pkSessionKeys).to.exist;
      expect(pkSessionKeys.length).to.be.equal(1);
      expect(pkSessionKeys[0].publicKeyId).to.be.equals(publicKey.subKeys[0].keyPacket.getKeyId());
      return answer.message.decrypt([privateKey]);
    }).then(function(answer){
      expect(answer).to.exist;
      expect(answer.getText()).to.be.equal(vData);
    });
  });

}
