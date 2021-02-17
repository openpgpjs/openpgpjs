/* eslint-disable max-lines */
/* globals tryTests: true */

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');
const crypto = require('../../src/crypto');
const random = require('../../src/crypto/random');
const util = require('../../src/util');
const keyIdType = require('../../src/type/keyid');

const spy = require('sinon/lib/sinon/spy');
const input = require('./testInputs.js');
const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;

const pub_key = [
  '-----BEGIN PGP PUBLIC KEY BLOCK-----',
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
  '-----END PGP PUBLIC KEY BLOCK-----'
].join('\n');

const priv_key = [
  '-----BEGIN PGP PRIVATE KEY BLOCK-----',
  'Version: GnuPG v2.0.19 (GNU/Linux)',
  '',
  'lQH+BFJhL04BBADclrUEDDsm0PSZbQ6pml9FpzTyXiyCyDN+rMOsy9J300Oc10kt',
  '/nyBej9vZSRcaW5VpNNj0iA+c1/w2FPf84zNsTzvDmuMaNHFUzky4/vkYuZra//3',
  '+Ri7CF8RawSYQ/4IRbC9zqdBlzniyfQOW7Dp/LYe8eibnDSrmkQem0G0jwARAQAB',
  '/gMDAu7L//czBpE40p1ZqO8K3k7UejemjsQqc7kOqnlDYd1Z6/3NEA/UM30Siipr',
  'KjdIFY5+hp0hcs6EiiNq0PDfm/W2j+7HfrZ5kpeQVxDek4irezYZrl7JS2xezaLv',
  'k0Fv/6fxasnFtjOM6Qbstu67s5Gpl9y06ZxbP3VpT62+Xeibn/swWrfiJjuGEEhM',
  'bgnsMpHtzAz/L8y6KSzViG/05hBaqrvk3/GeEA6nE+o0+0a6r0LYLTemmq6FbaA1',
  'PHo+x7k7oFcBFUUeSzgx78GckuPwqr2mNfeF+IuSRnrlpZl3kcbHASPAOfEkyMXS',
  'sWGE7grCAjbyQyM3OEXTSyqnehvGS/1RdB6kDDxGwgE/QFbwNyEh6K4eaaAThW2j',
  'IEEI0WEnRkPi9fXyxhFsCLSI1XhqTaq7iDNqJTxE+AX2b9ZuZXAxI3Tc/7++vEyL',
  '3p18N/MB2kt1Wb1azmXWL2EKlT1BZ5yDaJuBQ8BhphM3tCRUZXN0IE1jVGVzdGlu',
  'Z3RvbiA8dGVzdEBleGFtcGxlLmNvbT6IuQQTAQIAIwUCUmEvTgIbLwcLCQgHAwIB',
  'BhUIAgkKCwQWAgMBAh4BAheAAAoJEEpjYTpNbkCUMAwD+gIK08qpEZSVas9qW+Ok',
  '32wzNkwxe6PQgZwcyBqMQYZUcKagC8+89pMQQ5sKUGvpIgat42Tf1KLGPcvG4cDA',
  'JZ6w2PYz9YHQqPh9LA+PAnV8m25TcGmKcKgvFUqQ3U53X/Y9sBP8HooRqfwwHcv9',
  'pMgQmojmNbI4VHydRqIBePawnQH+BFJhL04BBADpH8+0EVolpPiOrXTKoBKTiyrB',
  'UyxzodyJ8zmVJ3HMTEU/vidpQwzISwoc/ndDFMXQauq6xqBCD9m2BPQI3UdQzXnb',
  'LsAI52nWCIqOkzM5NAKWoKhyXK9Y4UH4v9LAYQgl/stIISvCgG4mJ8lzzEBWvRdf',
  'Qm2Ghb64/3V5NDdemwARAQAB/gMDAu7L//czBpE40iPcpLzL7GwBbWFhSWgSLy53',
  'Md99Kxw3cApWCok2E8R9/4VS0490xKZIa5y2I/K8thVhqk96Z8Kbt7MRMC1WLHgC',
  'qJvkeQCI6PrFM0PUIPLHAQtDJYKtaLXxYuexcAdKzZj3FHdtLNWCooK6n3vJlL1c',
  'WjZcHJ1PH7USlj1jup4XfxsbziuysRUSyXkjn92GZLm+64vCIiwhqAYoizF2NHHG',
  'hRTN4gQzxrxgkeVchl+ag7DkQUDANIIVI+A63JeLJgWJiH1fbYlwESByHW+zBFNt',
  'qStjfIOhjrfNIc3RvsggbDdWQLcbxmLZj4sB0ydPSgRKoaUdRHJY0S4vp9ouKOtl',
  '2au/P1BP3bhD0fDXl91oeheYth+MSmsJFDg/vZJzCJhFaQ9dp+2EnjN5auNCNbaI',
  'beFJRHFf9cha8p3hh+AK54NRCT++B2MXYf+TPwqX88jYMBv8kk8vYUgo8128r1zQ',
  'EzjviQE9BBgBAgAJBQJSYS9OAhsuAKgJEEpjYTpNbkCUnSAEGQECAAYFAlJhL04A',
  'CgkQ4IT3RGwgLJe6ogQA2aaJEIBIXtgrs+8WSJ4k3DN4rRXcXaUZf667pjdD9nF2',
  '3BzjFH6Z78JIGaxRHJdM7b05aE8YuzM8f3NIlT0F0OLq/TI2muYU9f/U2DQBuf+w',
  'KTB62+PELVgi9MsXC1Qv/u/o1LZtmmxTFFOD35xKsxZZI2OJj2pQpqObW27M8Nlc',
  'BQQAw2YA3fFc38qPK+PY4rZyTRdbvjyyX+1zeqIo8wn7QCQwXs+OGaH2fGoT35AI',
  'SXuqKcWqoEuO7OBSEFThCXBfUYMC01OrqKEswPm/V3zZkLu01q12UMwZach28QwK',
  '/YZly4ioND2tdazj17u2rU2dwtiHPe1iMqGgVMoQirfLc+k=',
  '=lw5e',
  '-----END PGP PRIVATE KEY BLOCK-----'
].join('\n');

const pub_key_de = [
  '-----BEGIN PGP PUBLIC KEY BLOCK-----',
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
  '-----END PGP PUBLIC KEY BLOCK-----'
].join('\n');

const priv_key_de = [
  '-----BEGIN PGP PRIVATE KEY BLOCK-----',
  'Version: GnuPG v2.0.22 (GNU/Linux)',
  '',
  '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',
  'DHTORVqAOdoOcu5Qh7AQg1GdSmfFAsx2',
  '=kyeP',
  '-----END PGP PRIVATE KEY BLOCK-----'
].join('\n');

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

const twoPasswordGPGFail = [
  '-----BEGIN PGP MESSAGE-----',
  'Version: OpenPGP.js v3.0.0',
  'Comment: https://openpgpjs.org',
  '',
  'wy4ECQMIWjj3WEfWxGpgrfb3vXu0TS9L8UNTBvNZFIjltGjMVkLFD+/afgs5',
  'aXt0wy4ECQMIrFo3TFN5xqtgtB+AaAjBcWJrA4bvIPBpJ38PbMWeF0JQgrqg',
  'j3uehxXy0mUB5i7B61g0ho+YplyFGM0s9XayJCnu40tWmr5LqqsRxuwrhJKR',
  'migslOF/l6Y9F0F9xGIZWGhxp3ugQPjVKjj8fOH7ap14mLm60C8q8AOxiSmL',
  'ubsd/hL7FPZatUYAAZVA0a6hmQ==',
  '=cHCV',
  '-----END PGP MESSAGE-----'
].join('\n');

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

const mismatchingKeyParams = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.7.0
Comment: https://openpgpjs.org

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
0NubenKyljKtyHyoU+S+TqUyx7gf5A==
=Lj9k
-----END PGP PRIVATE KEY BLOCK-----
`;

const rsaPrivateKeyPKCS1 = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=dSNv
-----END PGP PRIVATE KEY BLOCK-----
`;

const gnuDummyKeySigningSubkey = `
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js VERSION
Comment: https://openpgpjs.org

xZUEWCC+hwEEALu8GwefswqZLoiKJk1Nd1yKmVWBL1ypV35FN0gCjI1NyyJX
UfQZDdC2h0494OVAM2iqKepqht3tH2DebeFLnc2ivvIFmQJZDnH2/0nFG2gC
rSySWHUjVfbMSpmTaXpit8EX/rjNauGOdbePbezOSsAhW7R9pBdtDjPnq2Zm
vDXXABEBAAH+B2UAR05VAc0JR05VIER1bW15wrgEEwECACIFAlggvocCGwMG
CwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEJ3XHFanUJgCeMYD/2zKefpl
clQoBdDPJKCYJm8IhuWuoF8SnHAsbhD+U42Gbm+2EATTPj0jyGPkZzl7a0th
S2rSjQ4JF0Ktgdr9585haknpGwr31t486KxXOY4AEsiBmRyvTbaQegwKaQ+C
/0JQYo/XKpsaX7PMDBB9SNFSa8NkhxYseLaB7gbM8w+Lx8EYBFggvpwBBADF
YeeJwp6MAVwVwXX/eBRKBIft6LC4E9czu8N2AbOW97WjWNtXi3OuM32OwKXq
vSck8Mx8FLOAuvVq41NEboeknhptw7HzoQMB35q8NxA9lvvPd0+Ef+BvaVB6
NmweHttt45LxYxLMdXdGoIt3wn/HBY81HnMqfV/KnggZ+imJ0wARAQABAAP7
BA56WdHzb53HIzYgWZl04H3BJdB4JU6/FJo0yHpjeWRQ46Q7w2WJzjHS6eBB
G+OhGzjAGYK7AUr8wgjqMq6LQHt2f80N/nWLusZ00a4lcMd7rvoHLWwRj80a
RzviOvvhP7kZY1TrhbS+Sl+BWaNIDOxS2maEkxexztt4GEl2dWUCAMoJvyFm
qPVqVx2Yug29vuJsDcr9XwnjrYI8PtszJI8Fr+5rKgWE3GJumheaXaug60dr
mLMXdvT/0lj3sXquqR0CAPoZ1Mn7GaUKjPVJ7CiJ/UjqSurrGhruA5ikhehQ
vUB+v4uIl7ICcX8zfiP+SMhWY9qdkmOvLSSSMcTkguMfe68B/j/qf2en5OHy
6NJgMIjMrBHvrf34f6pxw5p10J6nxjooZQxV0P+9MoTHWsy0r6Er8IOSSTGc
WyWJ8wmSqiq/dZSoJcLAfQQYAQIACQUCWCC+nAIbAgCoCRCd1xxWp1CYAp0g
BBkBAgAGBQJYIL6cAAoJEOYZSGiVA/C9CT4D/2Vq2dKxHmzn/UD1MWSLXUbN
ISd8tvHjoVg52RafdgHFmg9AbE0DW8ifwaai7FkifD0IXiN04nER3MuVhAn1
gtMu03m1AQyX/X39tHz+otpwBn0g57NhFbHFmzKfr/+N+XsDRj4VXn13hhqM
qQR8i1wgiWBUFJbpP5M1BPdH4Qfkcn8D/j8A3QKYGGETa8bNOdVTRU+sThXr
imOfWu58V1yWCmLE1kK66qkqmgRVUefqacF/ieMqNmsAY+zmR9D4fg2wzu/d
nPjJXp1670Vlzg7oT5XVYnfys7x4GLHsbaOSjXToILq+3GwI9UjNjtpobcfm
mNG2ibD6lftLOtDsVSDY8a6a
=KjxQ
-----END PGP PRIVATE KEY BLOCK-----
`;

const multipleEncryptionAndSigningSubkeys = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=PUAJ
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
        compressSpy = spy(openpgp.CompressedDataPacket.prototype, 'compress');
        decompressSpy = spy(openpgp.CompressedDataPacket.prototype, 'decompress');
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

module.exports = () => describe('OpenPGP.js public api tests', function() {

  describe('generateKey - validate user ids', function() {
    it('should fail for invalid user name', async function() {
      const opt = {
        userIds: [{ name: {}, email: 'text@example.com' }]
      };
      const test = openpgp.generateKey(opt);
      await expect(test).to.eventually.be.rejectedWith(/Invalid user ID format/);
    });

    it('should fail for invalid user email address', async function() {
      const opt = {
        userIds: [{ name: 'Test User', email: 'textexample.com' }]
      };
      const test = openpgp.generateKey(opt);
      await expect(test).to.eventually.be.rejectedWith(/Invalid user ID format/);
    });

    it('should fail for invalid user email address', async function() {
      const opt = {
        userIds: [{ name: 'Test User', email: 'text@examplecom' }]
      };
      const test = openpgp.generateKey(opt);
      await expect(test).to.eventually.be.rejectedWith(/Invalid user ID format/);
    });

    it('should fail for string user ID', async function() {
      const opt = {
        userIds: 'Test User <text@example.com>'
      };
      const test = openpgp.generateKey(opt);
      await expect(test).to.eventually.be.rejectedWith(/Invalid user ID format/);
    });

    it('should work for valid single user ID object', function() {
      const opt = {
        userIds: { name: 'Test User', email: 'text@example.com' }
      };
      return openpgp.generateKey(opt);
    });

    it('should work for array of user ID objects', function() {
      const opt = {
        userIds: [{ name: 'Test User', email: 'text@example.com' }]
      };
      return openpgp.generateKey(opt);
    });

    it('should work for undefined name', function() {
      const opt = {
        userIds: { email: 'text@example.com' }
      };
      return openpgp.generateKey(opt);
    });

    it('should work for an undefined email address', function() {
      const opt = {
        userIds: { name: 'Test User' }
      };
      return openpgp.generateKey(opt);
    });
  });

  describe('generateKey - unit tests', function() {
    it('should have default params set', function() {
      const now = util.normalizeDate(new Date());
      const opt = {
        userIds: { name: 'Test User', email: 'text@example.com' },
        passphrase: 'secret',
        date: now
      };
      return openpgp.generateKey(opt).then(async function(newKey) {
        expect(newKey.key).to.exist;
        expect(newKey.key.users.length).to.equal(1);
        expect(newKey.key.users[0].userId.name).to.equal('Test User');
        expect(newKey.key.users[0].userId.email).to.equal('text@example.com');
        expect(newKey.key.getAlgorithmInfo().rsaBits).to.equal(undefined);
        expect(newKey.key.getAlgorithmInfo().curve).to.equal('ed25519');
        expect(+newKey.key.getCreationTime()).to.equal(+now);
        expect(await newKey.key.getExpirationTime()).to.equal(Infinity);
        expect(newKey.key.subKeys.length).to.equal(1);
        expect(newKey.key.subKeys[0].getAlgorithmInfo().rsaBits).to.equal(undefined);
        expect(newKey.key.subKeys[0].getAlgorithmInfo().curve).to.equal('curve25519');
        expect(+newKey.key.subKeys[0].getCreationTime()).to.equal(+now);
        expect(await newKey.key.subKeys[0].getExpirationTime()).to.equal(Infinity);
        expect(newKey.privateKeyArmored).to.exist;
        expect(newKey.publicKeyArmored).to.exist;
      });
    });
  });

  describe('generateKey - integration tests', function() {
    let useNativeVal;

    beforeEach(function() {
      useNativeVal = openpgp.config.useNative;
    });

    afterEach(function() {
      openpgp.config.useNative = useNativeVal;
    });

    it('should work in JS', function() {
      openpgp.config.useNative = false;
      const opt = {
        userIds: [{ name: 'Test User', email: 'text@example.com' }]
      };

      return openpgp.generateKey(opt).then(function(newKey) {
        expect(newKey.key.getUserIds()[0]).to.equal('Test User <text@example.com>');
        expect(newKey.publicKeyArmored).to.match(/^-----BEGIN PGP PUBLIC/);
        expect(newKey.privateKeyArmored).to.match(/^-----BEGIN PGP PRIVATE/);
      });
    });

    it('should work in with native crypto', function() {
      openpgp.config.useNative = true;
      const opt = {
        userIds: [{ name: 'Test User', email: 'text@example.com' }]
      };

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
    let useNativeVal;
    let aeadProtectVal;
    let aeadModeVal;
    let aeadChunkSizeByteVal;
    let v5KeysVal;
    let privateKeyMismatchingParams;

    beforeEach(async function() {
      publicKey = await openpgp.readKey({ armoredKey: pub_key });
      publicKeyNoAEAD = await openpgp.readKey({ armoredKey: pub_key });
      privateKey = await openpgp.readKey({ armoredKey: priv_key });
      privateKey_2000_2008 = await openpgp.readKey({ armoredKey: priv_key_2000_2008 });
      publicKey_2000_2008 = privateKey_2000_2008.toPublic();
      privateKey_2038_2045 = await openpgp.readKey({ armoredKey: priv_key_2038_2045 });
      publicKey_2038_2045 = privateKey_2038_2045.toPublic();
      privateKey_1337 = await openpgp.readKey({ armoredKey: priv_key_expires_1337 });
      publicKey_1337 = privateKey_1337.toPublic();
      privateKeyMismatchingParams = await openpgp.readKey({ armoredKey: mismatchingKeyParams });

      useNativeVal = openpgp.config.useNative;
      aeadProtectVal = openpgp.config.aeadProtect;
      aeadModeVal = openpgp.config.aeadMode;
      aeadChunkSizeByteVal = openpgp.config.aeadChunkSizeByte;
      v5KeysVal = openpgp.config.v5Keys;
    });

    afterEach(function() {
      openpgp.config.useNative = useNativeVal;
      openpgp.config.aeadProtect = aeadProtectVal;
      openpgp.config.aeadMode = aeadModeVal;
      openpgp.config.aeadChunkSizeByte = aeadChunkSizeByteVal;
      openpgp.config.v5Keys = v5KeysVal;
    });

    it('Configuration', async function() {
      const showCommentVal = openpgp.config.showComment;
      const showVersionVal = openpgp.config.showVersion;
      const commentStringVal = openpgp.config.commentString;

      try {
        const encryptedDefault = await openpgp.encrypt({ publicKeys:publicKey, message:openpgp.Message.fromText(plaintext) });
        expect(encryptedDefault).to.exist;
        expect(encryptedDefault).not.to.match(/^Version:/);
        expect(encryptedDefault).not.to.match(/^Comment:/);

        openpgp.config.showComment = true;
        openpgp.config.commentString = 'different';
        const encryptedWithComment = await openpgp.encrypt({ publicKeys:publicKey, message:openpgp.Message.fromText(plaintext) });
        expect(encryptedWithComment).to.exist;
        expect(encryptedWithComment).not.to.match(/^Version:/);
        expect(encryptedWithComment).to.match(/Comment: different/);
      } finally {
        openpgp.config.showComment = showCommentVal;
        openpgp.config.showVersion = showVersionVal;
        openpgp.config.commentString = commentStringVal;
      }
    });

    it('Decrypting key with wrong passphrase rejected', async function () {
      await expect(privateKey.decrypt('wrong passphrase')).to.eventually.be.rejectedWith('Incorrect key passphrase');
    });

    it('Can decrypt key with correct passphrase', async function () {
      expect(privateKey.isDecrypted()).to.be.false;
      await privateKey.decrypt(passphrase);
      expect(privateKey.isDecrypted()).to.be.true;
    });

    describe('decryptKey', function() {
      it('should work for correct passphrase', async function() {
        const originalKey = await openpgp.readKey({ armoredKey: privateKey.armor() });
        return openpgp.decryptKey({
          privateKey: privateKey,
          passphrase: passphrase
        }).then(function(unlocked){
          expect(unlocked.getKeyId().toHex()).to.equal(privateKey.getKeyId().toHex());
          expect(unlocked.subKeys[0].getKeyId().toHex()).to.equal(privateKey.subKeys[0].getKeyId().toHex());
          expect(unlocked.isDecrypted()).to.be.true;
          expect(unlocked.keyPacket.privateParams).to.not.be.null;
          // original key should be unchanged
          expect(privateKey.isDecrypted()).to.be.false;
          expect(privateKey.keyPacket.privateParams).to.be.null;
          originalKey.subKeys[0].getKeyId(); // fill in keyid
          expect(privateKey).to.deep.equal(originalKey);
        });
      });

      it('should fail for incorrect passphrase', async function() {
        const originalKey = await openpgp.readKey({ armoredKey: privateKey.armor() });
        return openpgp.decryptKey({
          privateKey: privateKey,
          passphrase: 'incorrect'
        }).then(function() {
          throw new Error('Should not decrypt with incorrect passphrase');
        }).catch(function(error){
          expect(error.message).to.match(/Incorrect key passphrase/);
          // original key should be unchanged
          expect(privateKey.isDecrypted()).to.be.false;
          expect(privateKey.keyPacket.privateParams).to.be.null;
          expect(privateKey).to.deep.equal(originalKey);
        });
      });

      it('should fail for corrupted key', async function() {
        const originalKey = await openpgp.readKey({ armoredKey: privateKeyMismatchingParams.armor() });
        return openpgp.decryptKey({
          privateKey: privateKeyMismatchingParams,
          passphrase: 'userpass'
        }).then(function() {
          throw new Error('Should not decrypt corrupted key');
        }).catch(function(error) {
          expect(error.message).to.match(/Key is invalid/);
          expect(privateKeyMismatchingParams.isDecrypted()).to.be.false;
          expect(privateKeyMismatchingParams.keyPacket.privateParams).to.be.null;
          expect(privateKeyMismatchingParams).to.deep.equal(originalKey);
        });
      });
    });

    describe('encryptKey', function() {
      it('should not change original key', async function() {
        const { privateKeyArmored } = await openpgp.generateKey({ userIds: [{ name: 'test', email: 'test@test.com' }] });
        // read both keys from armored data to make sure all fields are exactly the same
        const key = await openpgp.readKey({ armoredKey: privateKeyArmored });
        const originalKey = await openpgp.readKey({ armoredKey: privateKeyArmored });
        return openpgp.encryptKey({
          privateKey: key,
          passphrase: passphrase
        }).then(function(locked){
          expect(locked.getKeyId().toHex()).to.equal(key.getKeyId().toHex());
          expect(locked.subKeys[0].getKeyId().toHex()).to.equal(key.subKeys[0].getKeyId().toHex());
          expect(locked.isDecrypted()).to.be.false;
          expect(locked.keyPacket.privateParams).to.be.null;
          // original key should be unchanged
          expect(key.isDecrypted()).to.be.true;
          expect(key.keyPacket.privateParams).to.not.be.null;
          originalKey.subKeys[0].getKeyId(); // fill in keyid
          expect(key).to.deep.equal(originalKey);
        });
      });

      it('encrypted key can be decrypted', async function() {
        const { key } = await openpgp.generateKey({ userIds: [{ name: 'test', email: 'test@test.com' }] });
        const locked = await openpgp.encryptKey({
          privateKey: key,
          passphrase: passphrase
        });
        expect(locked.isDecrypted()).to.be.false;
        const unlocked = await openpgp.decryptKey({
          privateKey: locked,
          passphrase: passphrase
        });
        expect(unlocked.isDecrypted()).to.be.true;
      });

      it('should support multiple passphrases', async function() {
        const { key } = await openpgp.generateKey({ userIds: [{ name: 'test', email: 'test@test.com' }] });
        const passphrases = ['123', '456'];
        const locked = await openpgp.encryptKey({
          privateKey: key,
          passphrase: passphrases
        });
        expect(locked.isDecrypted()).to.be.false;
        await expect(openpgp.decryptKey({
          privateKey: locked,
          passphrase: passphrases[0]
        })).to.eventually.be.rejectedWith(/Incorrect key passphrase/);
        const unlocked = await openpgp.decryptKey({
          privateKey: locked,
          passphrase: passphrases
        });
        expect(unlocked.isDecrypted()).to.be.true;
      });

      it('should encrypt gnu-dummy key', async function() {
        const key = await openpgp.readKey({ armoredKey: gnuDummyKeySigningSubkey });
        const locked = await openpgp.encryptKey({
          privateKey: key,
          passphrase: passphrase
        });
        expect(key.isDecrypted()).to.be.true;
        expect(locked.isDecrypted()).to.be.false;
        expect(locked.primaryKey.isDummy()).to.be.true;
        const unlocked = await openpgp.decryptKey({
          privateKey: locked,
          passphrase: passphrase
        });
        expect(key.isDecrypted()).to.be.true;
        expect(unlocked.isDecrypted()).to.be.true;
        expect(unlocked.primaryKey.isDummy()).to.be.true;
      });
    });

    it('Calling decrypt with not decrypted key leads to exception', async function() {
      const encOpt = {
        message: openpgp.Message.fromText(plaintext),
        publicKeys: publicKey
      };
      const decOpt = {
        privateKeys: privateKey
      };
      const encrypted = await openpgp.encrypt(encOpt);
      decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
      await expect(openpgp.decrypt(decOpt)).to.be.rejectedWith('Error decrypting message: Private key is not decrypted.');
    });

    tryTests('CFB mode (asm.js)', tests, {
      if: true,
      beforeEach: function() {
        openpgp.config.aeadProtect = false;
      }
    });

    tryTests('GCM mode (V5 keys)', tests, {
      if: true,
      beforeEach: function() {
        openpgp.config.aeadProtect = true;
        openpgp.config.aeadMode = openpgp.enums.aead.experimentalGcm;
        openpgp.config.v5Keys = true;

        // Monkey-patch AEAD feature flag
        publicKey.users[0].selfCertifications[0].features = [7];
        publicKey_2000_2008.users[0].selfCertifications[0].features = [7];
        publicKey_2038_2045.users[0].selfCertifications[0].features = [7];
      }
    });

    tryTests('EAX mode (small chunk size)', tests, {
      if: true,
      beforeEach: function() {
        openpgp.config.aeadProtect = true;
        openpgp.config.aeadChunkSizeByte = 0;

        // Monkey-patch AEAD feature flag
        publicKey.users[0].selfCertifications[0].features = [7];
        publicKey_2000_2008.users[0].selfCertifications[0].features = [7];
        publicKey_2038_2045.users[0].selfCertifications[0].features = [7];
      }
    });

    tryTests('OCB mode', tests, {
      if: !openpgp.config.ci,
      beforeEach: function() {
        openpgp.config.aeadProtect = true;
        openpgp.config.aeadMode = openpgp.enums.aead.ocb;

        // Monkey-patch AEAD feature flag
        publicKey.users[0].selfCertifications[0].features = [7];
        publicKey_2000_2008.users[0].selfCertifications[0].features = [7];
        publicKey_2038_2045.users[0].selfCertifications[0].features = [7];
      }
    });

    function tests() {
      describe('encryptSessionKey, decryptSessionKeys', function() {
        const sk = new Uint8Array([0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01]);

        let decryptedPrivateKey;
        beforeEach(async function() {
          if (!decryptedPrivateKey) {
            await privateKey.decrypt(passphrase);
            decryptedPrivateKey = privateKey;
          }
          privateKey = decryptedPrivateKey;
        });

        it('should encrypt with public key', function() {
          return openpgp.encryptSessionKey({
            data: sk,
            algorithm: 'aes128',
            publicKeys: publicKey,
            armor: false
          }).then(async function(encrypted) {
            const message = await openpgp.readMessage({ binaryMessage: encrypted });
            return openpgp.decryptSessionKeys({
              message,
              privateKeys: privateKey
            });
          }).then(function(decrypted) {
            expect(decrypted[0].data).to.deep.equal(sk);
          });
        });

        it('should encrypt with password', function() {
          return openpgp.encryptSessionKey({
            data: sk,
            algorithm: 'aes128',
            passwords: password1,
            armor: false
          }).then(async function(encrypted) {
            const message = await openpgp.readMessage({ binaryMessage: encrypted });
            return openpgp.decryptSessionKeys({
              message,
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
            publicKeys: publicKey,
            armor: false
          }).then(async function(encrypted) {
            const message = await openpgp.readMessage({ binaryMessage: encrypted });
            const invalidPrivateKey = await openpgp.readKey({ armoredKey: priv_key });
            invalidPrivateKey.subKeys[0].bindingSignatures = [];
            return openpgp.decryptSessionKeys({
              message,
              privateKeys: invalidPrivateKey
            }).then(() => {
              throw new Error('Should not decrypt with invalid key');
            }).catch(error => {
              expect(error.message).to.match(/Error decrypting session keys: Session key decryption failed./);
            });
          });
        });

        it('roundtrip workflow: encrypt, decryptSessionKeys, decrypt with pgp key pair', async function () {
          const encrypted = await openpgp.encrypt({
            message: openpgp.Message.fromText(plaintext),
            publicKeys: publicKey
          });
          const decryptedSessionKeys = await openpgp.decryptSessionKeys({
            message: await openpgp.readMessage({ armoredMessage: encrypted }),
            privateKeys: privateKey
          });
          const decrypted = await openpgp.decrypt({
            message: await openpgp.readMessage({ armoredMessage: encrypted }),
            sessionKeys: decryptedSessionKeys[0]
          });
          expect(decrypted.data).to.equal(plaintext);
        });

        it('roundtrip workflow: encrypt, decryptSessionKeys, decrypt with pgp key pair -- trailing spaces', async function () {
          const plaintext = 'space: \nspace and tab: \t\nno trailing space\n  \ntab:\t\ntab and space:\t ';
          const encrypted = await openpgp.encrypt({
            message: openpgp.Message.fromText(plaintext),
            publicKeys: publicKey
          });
          const decryptedSessionKeys = await openpgp.decryptSessionKeys({
            message: await openpgp.readMessage({ armoredMessage: encrypted }),
            privateKeys: privateKey
          });
          const decrypted = await openpgp.decrypt({
            message: await openpgp.readMessage({ armoredMessage: encrypted }),
            sessionKeys: decryptedSessionKeys[0]
          });
          expect(decrypted.data).to.equal(plaintext);
        });

        it('roundtrip workflow: encrypt, decryptSessionKeys, decrypt with password', async function () {
          const encrypted = await openpgp.encrypt({
            message: openpgp.Message.fromText(plaintext),
            passwords: password1
          });
          const decryptedSessionKeys = await openpgp.decryptSessionKeys({
            message: await openpgp.readMessage({ armoredMessage: encrypted }),
            passwords: password1
          });
          const decrypted = await openpgp.decrypt({
            message: await openpgp.readMessage({ armoredMessage: encrypted }),
            sessionKeys: decryptedSessionKeys[0]
          });
          expect(decrypted.data).to.equal(plaintext);
        });

        it('roundtrip workflow: encrypt with multiple passwords, decryptSessionKeys, decrypt with multiple passwords', async function () {
          const encrypted = await openpgp.encrypt({
            message: openpgp.Message.fromText(plaintext),
            passwords: [password1, password2]
          });
          const decryptedSessionKeys = await openpgp.decryptSessionKeys({
            message: await openpgp.readMessage({ armoredMessage: encrypted }),
            passwords: [password1, password2]
          });
          const decrypted = await openpgp.decrypt({
            message: await openpgp.readMessage({ armoredMessage: encrypted }),
            sessionKeys: decryptedSessionKeys[0]
          });
          expect(decrypted.data).to.equal(plaintext);
        });

        it('roundtrip workflow: encrypt twice with one password, decryptSessionKeys, only one session key', async function () {
          const encrypted = await openpgp.encrypt({
            message: openpgp.Message.fromText(plaintext),
            passwords: [password1, password1]
          });
          const decryptedSessionKeys = await openpgp.decryptSessionKeys({
            message: await openpgp.readMessage({ armoredMessage: encrypted }),
            passwords: password1
          });
          expect(decryptedSessionKeys.length).to.equal(1);
          const decrypted = await openpgp.decrypt({
            message: await openpgp.readMessage({ armoredMessage: encrypted }),
            sessionKeys: decryptedSessionKeys[0]
          });
          expect(decrypted.data).to.equal(plaintext);
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
            await privateKey.decrypt(passphrase);
            decryptedPrivateKey = privateKey;
          }
          privateKey = decryptedPrivateKey;
        });

        it('should encrypt then decrypt', function () {
          const encOpt = {
            message: openpgp.Message.fromText(plaintext),
            publicKeys: publicKey
          };
          const decOpt = {
            privateKeys: privateKey
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            expect(encrypted).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures).to.exist;
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt then decrypt with multiple private keys', async function () {
          const privKeyDE = await openpgp.readKey({ armoredKey: priv_key_de });
          await privKeyDE.decrypt(passphrase);

          const encOpt = {
            message: openpgp.Message.fromText(plaintext),
            publicKeys: publicKey
          };
          const decOpt = {
            privateKeys: [privKeyDE, privateKey]
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            expect(encrypted).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures).to.exist;
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt then decrypt with wildcard', function () {
          const encOpt = {
            message: openpgp.Message.fromText(plaintext),
            publicKeys: publicKey,
            wildcard: true
          };
          const decOpt = {
            privateKeys: privateKey
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            expect(encrypted).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures).to.exist;
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt then decrypt with wildcard with multiple private keys', async function () {
          const privKeyDE = await openpgp.readKey({ armoredKey: priv_key_de });
          await privKeyDE.decrypt(passphrase);

          const encOpt = {
            message: openpgp.Message.fromText(plaintext),
            publicKeys: publicKey,
            wildcard: true
          };
          const decOpt = {
            privateKeys: [privKeyDE, privateKey]
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            expect(encrypted).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures).to.exist;
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt then decrypt using returned session key', async function () {
          const sessionKey = await openpgp.generateSessionKey({
            publicKeys: publicKey
          });
          const encrypted = await openpgp.encrypt({
            message: openpgp.Message.fromText(plaintext),
            sessionKey
          });
          expect(encrypted).to.match(/^-----BEGIN PGP MESSAGE/);
          const decrypted = await openpgp.decrypt({
            message: await openpgp.readMessage({ armoredMessage: encrypted }),
            sessionKeys: sessionKey
          });
          expect(decrypted.data).to.equal(plaintext);
          expect(decrypted.signatures).to.exist;
          expect(decrypted.signatures.length).to.equal(0);
        });

        it('should encrypt using custom session key and decrypt using session key', async function () {
          const sessionKey = {
            data: await crypto.generateSessionKey('aes256'),
            algorithm: 'aes256'
          };
          const encOpt = {
            message: openpgp.Message.fromText(plaintext),
            sessionKey: sessionKey,
            publicKeys: publicKey
          };
          const decOpt = {
            sessionKeys: sessionKey
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            expect(encrypted).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
            expect(!!decOpt.message.packets.findPacket(openpgp.enums.packet.AEADEncryptedData)).to.equal(false);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
          });
        });

        it('should encrypt using custom session key and decrypt using private key', async function () {
          const sessionKey = {
            data: await crypto.generateSessionKey('aes128'),
            algorithm: 'aes128'
          };
          const encOpt = {
            message: openpgp.Message.fromText(plaintext),
            sessionKey: sessionKey,
            publicKeys: publicKey
          };
          const decOpt = {
            privateKeys: privateKey
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            expect(encrypted).to.match(/^-----BEGIN PGP MESSAGE/);
            decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
            expect(!!decOpt.message.packets.findPacket(openpgp.enums.packet.AEADEncryptedData)).to.equal(false);
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
          });
        });

        it('should encrypt/sign and decrypt/verify', function () {
          const encOpt = {
            message: openpgp.Message.fromText(plaintext),
            publicKeys: publicKey,
            privateKeys: privateKey
          };
          const decOpt = {
            privateKeys: privateKey,
            publicKeys: publicKey
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
            expect(!!decOpt.message.packets.findPacket(openpgp.enums.packet.AEADEncryptedData)).to.equal(openpgp.config.aeadProtect);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.true;
            const signingKey = await privateKey.getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should encrypt/sign and decrypt/verify (no AEAD support)', function () {
          const encOpt = {
            message: openpgp.Message.fromText(plaintext),
            publicKeys: publicKeyNoAEAD,
            privateKeys: privateKey
          };
          const decOpt = {
            privateKeys: privateKey,
            publicKeys: publicKeyNoAEAD
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
            expect(!!decOpt.message.packets.findPacket(openpgp.enums.packet.AEADEncryptedData)).to.equal(false);
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.true;
            const signingKey = await privateKey.getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should encrypt/sign and decrypt/verify with generated key', function () {
          const genOpt = {
            userIds: [{ name: 'Test User', email: 'text@example.com' }]
          };

          return openpgp.generateKey(genOpt).then(async function(newKey) {
            const newPublicKey = await openpgp.readKey({ armoredKey: newKey.publicKeyArmored });
            const newPrivateKey = await openpgp.readKey({ armoredKey: newKey.privateKeyArmored });

            const encOpt = {
              message: openpgp.Message.fromText(plaintext),
              publicKeys: newPublicKey,
              privateKeys: newPrivateKey
            };
            const decOpt = {
              privateKeys: newPrivateKey,
              publicKeys: newPublicKey
            };
            return openpgp.encrypt(encOpt).then(async function (encrypted) {
              decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
              expect(!!decOpt.message.packets.findPacket(openpgp.enums.packet.AEADEncryptedData)).to.equal(openpgp.config.aeadProtect);
              return openpgp.decrypt(decOpt);
            }).then(async function (decrypted) {
              expect(decrypted.data).to.equal(plaintext);
              expect(decrypted.signatures[0].valid).to.be.true;
              const signingKey = await newPrivateKey.getSigningKey();
              expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
              expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
            });
          });
        });

        it('should encrypt/sign and decrypt/verify with generated key and detached signatures', async function () {
          const newKey = await openpgp.generateKey({
            userIds: [{ name: 'Test User', email: 'text@example.com' }]
          });
          const newPublicKey = await openpgp.readKey({ armoredKey: newKey.publicKeyArmored });
          const newPrivateKey = await openpgp.readKey({ armoredKey: newKey.privateKeyArmored });

          const encrypted = await openpgp.encrypt({
            message: openpgp.Message.fromText(plaintext),
            publicKeys: newPublicKey
          });
          const signed = await openpgp.sign({
            message: openpgp.Message.fromText(plaintext),
            privateKeys: newPrivateKey,
            detached: true
          });
          const message = await openpgp.readMessage({ armoredMessage: encrypted });
          expect(!!message.packets.findPacket(openpgp.enums.packet.AEADEncryptedData)).to.equal(openpgp.config.aeadProtect);
          const decrypted = await openpgp.decrypt({
            message,
            signature: await openpgp.readSignature({ armoredSignature: signed }),
            privateKeys: newPrivateKey,
            publicKeys: newPublicKey
          });
          expect(decrypted.data).to.equal(plaintext);
          expect(decrypted.signatures[0].valid).to.be.true;
          const signingKey = await newPrivateKey.getSigningKey();
          expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
        });

        it('should encrypt/sign and decrypt/verify with null string input', function () {
          const encOpt = {
            message: openpgp.Message.fromText(''),
            publicKeys: publicKey,
            privateKeys: privateKey
          };
          const decOpt = {
            privateKeys: privateKey,
            publicKeys: publicKey
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal('');
            expect(decrypted.signatures[0].valid).to.be.true;
            const signingKey = await privateKey.getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should encrypt/sign and decrypt/verify with detached signatures', async function () {
          const encrypted = await openpgp.encrypt({
            message: openpgp.Message.fromText(plaintext),
            publicKeys: publicKey
          });
          const signed = await openpgp.sign({
            message: openpgp.Message.fromText(plaintext),
            privateKeys: privateKey,
            detached: true
          });
          const decrypted = await openpgp.decrypt({
            message: await openpgp.readMessage({ armoredMessage: encrypted }),
            signature: await openpgp.readSignature({ armoredSignature: signed }),
            privateKeys: privateKey,
            publicKeys: publicKey
          });
          expect(decrypted.data).to.equal(plaintext);
          expect(decrypted.signatures[0].valid).to.be.true;
          const signingKey = await privateKey.getSigningKey();
          expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
        });

        it('should encrypt and decrypt/verify with detached signature as input for encryption', async function () {
          const plaintext = "  \t┍ͤ޵၂༫዇◧˘˻ᙑ᎚⏴ំந⛑nٓኵΉⅶ⋋ŵ⋲΂ͽᣏ₅ᄶɼ┋⌔û᬴Ƚᔡᧅ≃ṱἆ⃷݂૿ӌ᰹෇ٹჵ⛇໶⛌  \t\n한국어/조선말";

          const privKeyDE = await openpgp.readKey({ armoredKey: priv_key_de });
          await privKeyDE.decrypt(passphrase);

          const pubKeyDE = await openpgp.readKey({ armoredKey: pub_key_de });

          const signOpt = {
            message: openpgp.Message.fromText(plaintext),
            privateKeys: privKeyDE,
            detached: true
          };

          const encOpt = {
            message: openpgp.Message.fromText(plaintext),
            publicKeys: publicKey,
            privateKeys: privateKey
          };

          const decOpt = {
            privateKeys: privateKey,
            publicKeys: [publicKey, pubKeyDE]
          };

          return openpgp.sign(signOpt).then(async function (armoredSignature) {
            encOpt.signature = await openpgp.readSignature({ armoredSignature });
            return openpgp.encrypt(encOpt);
          }).then(async function (armoredMessage) {
            decOpt.message = await openpgp.readMessage({ armoredMessage });
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            let signingKey;
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.true;
            signingKey = await privateKey.getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
            expect(decrypted.signatures[1].valid).to.be.true;
            signingKey = await privKeyDE.getSigningKey();
            expect(decrypted.signatures[1].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[1].signature.packets.length).to.equal(1);
          });
        });

        it('should fail to encrypt and decrypt/verify with detached signature as input for encryption with wrong public key', async function () {
          const signOpt = {
            message: openpgp.Message.fromText(plaintext),
            privateKeys: privateKey,
            detached: true
          };

          const encOpt = {
            message: openpgp.Message.fromText(plaintext),
            publicKeys: publicKey
          };

          const decOpt = {
            privateKeys: privateKey,
            publicKeys: await openpgp.readKey({ armoredKey: wrong_pubkey })
          };

          return openpgp.sign(signOpt).then(async function (armoredSignature) {
            encOpt.signature = await openpgp.readSignature({ armoredSignature });
            return openpgp.encrypt(encOpt);
          }).then(async function (armoredMessage) {
            decOpt.message = await openpgp.readMessage({ armoredMessage });
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should fail to verify decrypted data with wrong public pgp key', async function () {
          const encOpt = {
            message: openpgp.Message.fromText(plaintext),
            publicKeys: publicKey,
            privateKeys: privateKey
          };
          const decOpt = {
            privateKeys: privateKey,
            publicKeys: await openpgp.readKey({ armoredKey: wrong_pubkey })
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should fail to verify decrypted null string with wrong public pgp key', async function () {
          const encOpt = {
            message: openpgp.Message.fromText(''),
            publicKeys: publicKey,
            privateKeys: privateKey
          };
          const decOpt = {
            privateKeys: privateKey,
            publicKeys: await openpgp.readKey({ armoredKey: wrong_pubkey })
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal('');
            expect(decrypted.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should successfully decrypt signed message without public keys to verify', async function () {
          const encOpt = {
            message: openpgp.Message.fromText(plaintext),
            publicKeys: publicKey,
            privateKeys: privateKey
          };
          const decOpt = {
            privateKeys: privateKey
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.null;
            const signingKey = await privateKey.getSigningKey();
            expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
            expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
          });
        });

        it('should fail to verify decrypted data with wrong public pgp key with detached signatures', async function () {
          const encrypted = await openpgp.encrypt({
            message: openpgp.Message.fromText(plaintext),
            publicKeys: publicKey
          });
          const signed = await openpgp.sign({
            message: openpgp.Message.fromText(plaintext),
            privateKeys: privateKey,
            detached: true
          });
          const decrypted = await openpgp.decrypt({
            message: await openpgp.readMessage({ armoredMessage: encrypted }),
            signature: await openpgp.readSignature({ armoredSignature: signed }),
            privateKeys: privateKey,
            publicKeys: await openpgp.readKey({ armoredKey: wrong_pubkey })
          });
          expect(decrypted.data).to.equal(plaintext);
          expect(decrypted.signatures[0].valid).to.be.null;
          const signingKey = await privateKey.getSigningKey();
          expect(decrypted.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
        });

        it('should encrypt and decrypt/verify both signatures when signed with two private keys', async function () {
          const privKeyDE = await openpgp.readKey({ armoredKey: priv_key_de });
          await privKeyDE.decrypt(passphrase);

          const pubKeyDE = await openpgp.readKey({ armoredKey: pub_key_de });

          const encOpt = {
            message: openpgp.Message.fromText(plaintext),
            publicKeys: publicKey,
            privateKeys: [privateKey, privKeyDE]
          };

          const decOpt = {
            privateKeys: privateKey,
            publicKeys: [publicKey, pubKeyDE]
          };

          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
            return openpgp.decrypt(decOpt);
          }).then(async function (decrypted) {
            let signingKey;
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures[0].valid).to.be.true;
            signingKey = await privateKey.getSigningKey();
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
          const key = await openpgp.readKey({ armoredKey: privateKeyArmored });
          const data = await openpgp.encrypt({ message: openpgp.Message.fromBinary(new Uint8Array(500)), publicKeys: [key.toPublic()] });
          let badSumEncrypted = data.replace(/\n=[a-zA-Z0-9/+]{4}/, '\n=aaaa');
          if (badSumEncrypted === data) { // checksum was already =aaaa
            badSumEncrypted = data.replace(/\n=[a-zA-Z0-9/+]{4}/, '\n=bbbb');
          }
          if (badSumEncrypted === data) {
            throw new Error("Was not able to successfully modify checksum");
          }
          const badBodyEncrypted = data.replace(/\n=([a-zA-Z0-9/+]{4})/, 'aaa\n=$1');
          for (let allow_streaming = 1; allow_streaming >= 0; allow_streaming--) {
            openpgp.config.allowUnauthenticatedStream = !!allow_streaming;
            await Promise.all([badSumEncrypted, badBodyEncrypted].map(async (encrypted, i) => {
              await Promise.all([
                encrypted,
                openpgp.stream.toStream(encrypted),
                new openpgp.stream.ReadableStream({
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
                  const message = await openpgp.readMessage({ armoredMessage: encrypted });
                  stepReached = 1;
                  const { data: decrypted } = await openpgp.decrypt({ message: message, privateKeys: [key] });
                  stepReached = 2;
                  await openpgp.stream.readToEnd(decrypted);
                } catch (e) {
                  expect(e.message).to.match(/Ascii armor integrity check on message failed/);
                  expect(stepReached).to.equal(
                    j === 0 ? 0 :
                      (openpgp.config.aeadChunkSizeByte === 0 && (j === 2 || util.detectNode() || util.getHardwareConcurrency() < 8)) || (!openpgp.config.aeadProtect && openpgp.config.allowUnauthenticatedStream) ? 2 :
                        1
                  );
                  return;
                }
                throw new Error(`Expected "Ascii armor integrity check on message failed" error in subtest ${i}.${j}`);
              }));
            }));
          }
        });

        it('should fail to decrypt unarmored message with garbage data appended', async function() {
          const { key } = await openpgp.generateKey({ userIds: {} });
          const message = await openpgp.encrypt({ message: openpgp.Message.fromText('test'), publicKeys: key, privateKeys: key, armor: false });
          const encrypted = util.concat([message, new Uint8Array([11])]);
          await expect(
            openpgp.decrypt({ message: await openpgp.readMessage({ binaryMessage: encrypted }), privateKeys: key, publicKeys: key })
          ).to.be.rejectedWith('Error during parsing. This message / key probably does not conform to a valid OpenPGP format.');
        });
      });

      describe('ELG / DSA encrypt, decrypt, sign, verify', function() {

        it('round trip test', async function () {
          const pubKeyDE = await openpgp.readKey({ armoredKey: pub_key_de });
          const privKeyDE = await openpgp.readKey({ armoredKey: priv_key_de });
          await privKeyDE.decrypt(passphrase);
          pubKeyDE.users[0].selfCertifications[0].features = [7]; // Monkey-patch AEAD feature flag
          return openpgp.encrypt({
            publicKeys: pubKeyDE,
            privateKeys: privKeyDE,
            message: openpgp.Message.fromText(plaintext)
          }).then(async function (encrypted) {
            return openpgp.decrypt({
              privateKeys: privKeyDE,
              publicKeys: pubKeyDE,
              message: await openpgp.readMessage({ armoredMessage: encrypted })
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
        const pgp_msg = [
          '-----BEGIN PGP MESSAGE-----',
          'Version: GnuPG/MacGPG2 v2.0.19 (Darwin)',
          'Comment: GPGTools - https://gpgtools.org',
          '',
          'hIwDBU4Dycfvp2EBA/9tuhQgOrcATcm2PRmIOcs6q947YhlsBTZZdVJDfVjkKlyM',
          'M0yE+lnNplWb041Cpfkkl6IvorKQd2iPbAkOL0IXwmVN41l+PvVgMcuFvvzetehG',
          'Ca0/VEYOaTZRNqyr9FIzcnVy1I/PaWT3iqVAYa+G8TEA5Dh9RLfsx8ZA9UNIaNI+',
          'ASm9aZ3H6FerNhm8RezDY5vRn6xw3o/wH5YEBvV2BEmmFKZ2BlqFQxqChr8UNwd1',
          'Ieebnq0HtBPE8YU/L0U=',
          '=JyIa',
          '-----END PGP MESSAGE-----'
        ].join('\n');

        const priv_key = [
          '-----BEGIN PGP PRIVATE KEY BLOCK-----',
          'Version: GnuPG/MacGPG2 v2.0.19 (Darwin)',
          'Comment: GPGTools - https://gpgtools.org',
          '',
          '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',
          '22q10ausyQXoOxXfDWVwKA==',
          '=IkKW',
          '-----END PGP PRIVATE KEY BLOCK-----'
        ].join('\n');

        it('Decrypt message', async function() {
          const privKey = await openpgp.readKey({ armoredKey: priv_key });
          await privKey.decrypt('1234');
          const message = await openpgp.readMessage({ armoredMessage: pgp_msg });

          return openpgp.decrypt({ privateKeys:privKey, message:message }).then(function(decrypted) {
            expect(decrypted.data).to.equal('hello 3des\n');
            expect(decrypted.signatures.length).to.equal(0);
          });
        });
      });

      describe('AES encrypt, decrypt', function() {

        it('should encrypt and decrypt with one password', function () {
          const encOpt = {
            message: openpgp.Message.fromText(plaintext),
            passwords: password1
          };
          const decOpt = {
            passwords: password1
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt and decrypt with two passwords', function () {
          const encOpt = {
            message: openpgp.Message.fromText(plaintext),
            passwords: [password1, password2]
          };
          const decOpt = {
            passwords: password2
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt and decrypt with password and not ascii armor', function () {
          const encOpt = {
            message: openpgp.Message.fromText(plaintext),
            passwords: password1,
            armor: false
          };
          const decOpt = {
            passwords: password1
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.readMessage({ binaryMessage: encrypted });
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.equal(plaintext);
            expect(decrypted.signatures.length).to.equal(0);
          });
        });

        it('should encrypt and decrypt with binary data', function () {
          const encOpt = {
            message: openpgp.Message.fromBinary(new Uint8Array([0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01])),
            passwords: password1,
            armor: false
          };
          const decOpt = {
            passwords: password1,
            format: 'binary'
          };
          return openpgp.encrypt(encOpt).then(async function (encrypted) {
            decOpt.message = await openpgp.readMessage({ binaryMessage: encrypted });
            return openpgp.decrypt(decOpt);
          }).then(function (decrypted) {
            expect(decrypted.data).to.deep.equal(new Uint8Array([0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]));
            expect(decrypted.signatures.length).to.equal(0);
          });
        });
      });

      describe('Encrypt, decrypt with compression', function() {
        withCompression(function (modifyCompressionEncryptOptions, verifyCompressionDecrypted) {
          it('should encrypt and decrypt with one password', function () {
            const encOpt = modifyCompressionEncryptOptions({
              message: openpgp.Message.fromText(plaintext),
              passwords: password1
            });
            const decOpt = {
              passwords: password1
            };
            return openpgp.encrypt(encOpt).then(async function (encrypted) {
              decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
              return openpgp.decrypt(decOpt);
            }).then(function (decrypted) {
              expect(decrypted.data).to.equal(plaintext);
              expect(decrypted.signatures.length).to.equal(0);
              verifyCompressionDecrypted(decrypted);
            });
          });

          it('Streaming encrypt and decrypt small message roundtrip', async function() {
            const plaintext = [];
            let i = 0;
            const useNativeStream = (() => { try { new global.ReadableStream(); return true; } catch (e) { return false; } })(); // eslint-disable-line no-new
            const ReadableStream = useNativeStream ? global.ReadableStream : openpgp.stream.ReadableStream;
            const data = new ReadableStream({
              async pull(controller) {
                if (i++ < 4) {
                  const randomBytes = await random.getRandomBytes(10);
                  controller.enqueue(randomBytes);
                  plaintext.push(randomBytes.slice());
                } else {
                  controller.close();
                }
              }
            });
            const encrypted = await openpgp.encrypt(modifyCompressionEncryptOptions({
              message: openpgp.Message.fromBinary(data),
              passwords: ['test']
            }));
            expect(openpgp.stream.isStream(encrypted)).to.equal(useNativeStream ? 'web' : 'ponyfill');

            const message = await openpgp.readMessage({ armoredMessage: encrypted });
            const decrypted = await openpgp.decrypt({
              passwords: ['test'],
              message,
              format: 'binary'
            });
            expect(openpgp.stream.isStream(decrypted.data)).to.equal(useNativeStream ? 'web' : 'ponyfill');
            expect(await openpgp.stream.readToEnd(decrypted.data)).to.deep.equal(util.concatUint8Array(plaintext));
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
          await privateKey.decrypt(passphrase);
          decryptedPrivateKey = privateKey;
        }
        privateKey = decryptedPrivateKey;
      });

      it('should sign and verify cleartext message', function () {
        const message = openpgp.CleartextMessage.fromText(plaintext);
        const signOpt = {
          message,
          privateKeys: privateKey
        };
        const verifyOpt = {
          publicKeys: publicKey
        };
        return openpgp.sign(signOpt).then(async function (signed) {
          expect(signed).to.match(/-----BEGIN PGP SIGNED MESSAGE-----/);
          verifyOpt.message = await openpgp.readCleartextMessage({ cleartextMessage: signed });
          return openpgp.verify(verifyOpt);
        }).then(async function (verified) {
          expect(verified.data).to.equal(plaintext.replace(/[ \t]+$/mg, ''));
          expect(verified.signatures[0].valid).to.be.true;
          const signingKey = await privateKey.getSigningKey();
          expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(verified.signatures[0].signature.packets.length).to.equal(1);
        });
      });

      it('should sign and verify cleartext message with multiple private keys', async function () {
        const privKeyDE = await openpgp.readKey({ armoredKey: priv_key_de });
        await privKeyDE.decrypt(passphrase);

        const message = openpgp.CleartextMessage.fromText(plaintext);
        const signOpt = {
          message,
          privateKeys: [privateKey, privKeyDE]
        };
        const verifyOpt = {
          publicKeys: [publicKey, privKeyDE.toPublic()]
        };
        return openpgp.sign(signOpt).then(async function (signed) {
          expect(signed).to.match(/-----BEGIN PGP SIGNED MESSAGE-----/);
          verifyOpt.message = await openpgp.readCleartextMessage({ cleartextMessage: signed });
          return openpgp.verify(verifyOpt);
        }).then(async function (verified) {
          let signingKey;
          expect(verified.data).to.equal(plaintext.replace(/[ \t]+$/mg, ''));
          expect(verified.signatures[0].valid).to.be.true;
          signingKey = await privateKey.getSigningKey();
          expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(verified.signatures[0].signature.packets.length).to.equal(1);
          expect(verified.signatures[1].valid).to.be.true;
          signingKey = await privKeyDE.getSigningKey();
          expect(verified.signatures[1].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(verified.signatures[1].signature.packets.length).to.equal(1);
        });
      });

      it('should sign and verify data with detached signatures', function () {
        const message = openpgp.Message.fromText(plaintext);
        const signOpt = {
          message,
          privateKeys: privateKey,
          detached: true
        };
        const verifyOpt = {
          message,
          publicKeys: publicKey
        };
        return openpgp.sign(signOpt).then(async function (armoredSignature) {
          verifyOpt.signature = await openpgp.readSignature({ armoredSignature });
          return openpgp.verify(verifyOpt);
        }).then(async function (verified) {
          expect(verified.data).to.equal(plaintext);
          expect(verified.signatures[0].valid).to.be.true;
          const signingKey = await privateKey.getSigningKey();
          expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(verified.signatures[0].signature.packets.length).to.equal(1);
        });
      });

      it('should sign and fail to verify cleartext message with wrong public pgp key', async function () {
        const message = openpgp.CleartextMessage.fromText(plaintext);
        const signOpt = {
          message,
          privateKeys: privateKey
        };
        const verifyOpt = {
          publicKeys: await openpgp.readKey({ armoredKey: wrong_pubkey })
        };
        return openpgp.sign(signOpt).then(async function (signed) {
          verifyOpt.message = await openpgp.readCleartextMessage({ cleartextMessage: signed });
          return openpgp.verify(verifyOpt);
        }).then(async function (verified) {
          expect(verified.data).to.equal(plaintext.replace(/[ \t]+$/mg, ''));
          expect(verified.signatures[0].valid).to.be.null;
          const signingKey = await privateKey.getSigningKey();
          expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(verified.signatures[0].signature.packets.length).to.equal(1);
        });
      });

      it('should sign and fail to verify data with wrong public pgp key with detached signature', async function () {
        const message = openpgp.Message.fromText(plaintext);
        const signOpt = {
          message,
          privateKeys: privateKey,
          detached: true
        };
        const verifyOpt = {
          message,
          publicKeys: await openpgp.readKey({ armoredKey: wrong_pubkey })
        };
        return openpgp.sign(signOpt).then(async function (armoredSignature) {
          verifyOpt.signature = await openpgp.readSignature({ armoredSignature });
          return openpgp.verify(verifyOpt);
        }).then(async function (verified) {
          expect(verified.data).to.equal(plaintext);
          expect(verified.signatures[0].valid).to.be.null;
          const signingKey = await privateKey.getSigningKey();
          expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(verified.signatures[0].signature.packets.length).to.equal(1);
        });
      });

      it('should sign and verify data and not armor', function () {
        const message = openpgp.Message.fromText(plaintext);
        const signOpt = {
          message,
          privateKeys: privateKey,
          armor: false
        };
        const verifyOpt = {
          publicKeys: publicKey
        };
        return openpgp.sign(signOpt).then(async function (signed) {
          verifyOpt.message = await openpgp.readMessage({ binaryMessage: signed });
          return openpgp.verify(verifyOpt);
        }).then(async function (verified) {
          expect(verified.data).to.equal(plaintext);
          expect(verified.signatures[0].valid).to.be.true;
          const signingKey = await privateKey.getSigningKey();
          expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(verified.signatures[0].signature.packets.length).to.equal(1);
        });
      });

      it('should sign and verify data and not armor with detached signatures', function () {
        const start = util.normalizeDate();
        const message = openpgp.Message.fromText(plaintext);
        const signOpt = {
          message,
          privateKeys: privateKey,
          detached: true,
          armor: false
        };
        const verifyOpt = {
          message,
          publicKeys: publicKey
        };
        return openpgp.sign(signOpt).then(async function (signed) {
          verifyOpt.signature = await openpgp.readSignature({ binarySignature: signed });
          return openpgp.verify(verifyOpt);
        }).then(async function (verified) {
          expect(verified.data).to.equal(plaintext);
          expect(+verified.signatures[0].signature.packets[0].created).to.be.lte(+util.normalizeDate());
          expect(+verified.signatures[0].signature.packets[0].created).to.be.gte(+start);
          expect(verified.signatures[0].valid).to.be.true;
          const signingKey = await privateKey.getSigningKey();
          expect(verified.signatures[0].keyid.toHex()).to.equal(signingKey.getKeyId().toHex());
          expect(verified.signatures[0].signature.packets.length).to.equal(1);
        });
      });

      it('should sign and verify data with a date in the past', function () {
        const message = openpgp.Message.fromText(plaintext);
        const past = new Date(2000);
        const signOpt = {
          message,
          privateKeys: privateKey_1337,
          detached: true,
          date: past,
          armor: false
        };
        const verifyOpt = {
          message,
          publicKeys: publicKey_1337,
          date: past
        };
        return openpgp.sign(signOpt).then(async function (signed) {
          verifyOpt.signature = await openpgp.readSignature({ binarySignature: signed });
          return openpgp.verify(verifyOpt).then(async function (verified) {
            expect(+verified.signatures[0].signature.packets[0].created).to.equal(+past);
            expect(verified.data).to.equal(plaintext);
            expect(verified.signatures[0].valid).to.be.true;
            expect(await privateKey_1337.getSigningKey(verified.signatures[0].keyid, past))
              .to.be.not.null;
            expect(verified.signatures[0].signature.packets.length).to.equal(1);
            // now check with expiration checking disabled
            verifyOpt.date = null;
            return openpgp.verify(verifyOpt);
          }).then(async function (verified) {
            expect(+verified.signatures[0].signature.packets[0].created).to.equal(+past);
            expect(verified.data).to.equal(plaintext);
            expect(verified.signatures[0].valid).to.be.true;
            expect(await privateKey_1337.getSigningKey(verified.signatures[0].keyid, null))
              .to.be.not.null;
            expect(verified.signatures[0].signature.packets.length).to.equal(1);
          });
        });
      });

      it('should sign and verify binary data with a date in the future', function () {
        const future = new Date(2040, 5, 5, 5, 5, 5, 0);
        const data = new Uint8Array([3, 14, 15, 92, 65, 35, 59]);
        const signOpt = {
          message: openpgp.Message.fromBinary(data),
          privateKeys: privateKey_2038_2045,
          detached: true,
          date: future,
          armor: false
        };
        const verifyOpt = {
          publicKeys: publicKey_2038_2045,
          date: future,
          format: 'binary'
        };
        return openpgp.sign(signOpt).then(async function (signed) {
          verifyOpt.message = openpgp.Message.fromBinary(data);
          verifyOpt.signature = await openpgp.readSignature({ binarySignature: signed });
          return openpgp.verify(verifyOpt);
        }).then(async function (verified) {
          expect(+verified.signatures[0].signature.packets[0].created).to.equal(+future);
          expect([].slice.call(verified.data)).to.deep.equal([].slice.call(data));
          expect(verified.signatures[0].valid).to.be.true;
          expect(await privateKey_2038_2045.getSigningKey(verified.signatures[0].keyid, future))
            .to.be.not.null;
          expect(verified.signatures[0].signature.packets.length).to.equal(1);
        });
      });

      it('should sign and verify binary data without one-pass signature', function () {
        const data = new Uint8Array([3, 14, 15, 92, 65, 35, 59]);
        const signOpt = {
          message: openpgp.Message.fromBinary(data),
          privateKeys: privateKey,
          armor: false
        };
        const verifyOpt = {
          publicKeys: publicKey,
          format: 'binary'
        };
        return openpgp.sign(signOpt).then(async function (signed) {
          const message = await openpgp.readMessage({ binaryMessage: signed });
          message.packets.concat(await openpgp.stream.readToEnd(message.packets.stream, _ => _));
          const packets = new openpgp.PacketList();
          packets.push(message.packets.findPacket(openpgp.enums.packet.signature));
          packets.push(message.packets.findPacket(openpgp.enums.packet.literalData));
          verifyOpt.message = new openpgp.Message(packets);
          return openpgp.verify(verifyOpt);
        }).then(async function (verified) {
          expect([].slice.call(verified.data)).to.deep.equal([].slice.call(data));
          expect(verified.signatures[0].valid).to.be.true;
          expect(await privateKey.getSigningKey(verified.signatures[0].keyid))
            .to.be.not.null;
          expect(verified.signatures[0].signature.packets.length).to.equal(1);
        });
      });

      it('should streaming sign and verify binary data without one-pass signature', function () {
        const data = new Uint8Array([3, 14, 15, 92, 65, 35, 59]);
        const signOpt = {
          message: openpgp.Message.fromBinary(data),
          privateKeys: privateKey,
          armor: false,
          streaming: 'web'
        };
        const verifyOpt = {
          publicKeys: publicKey,
          streaming: 'web',
          format: 'binary'
        };
        const useNativeStream = (() => { try { new global.ReadableStream(); return true; } catch (e) { return false; } })(); // eslint-disable-line no-new
        return openpgp.sign(signOpt).then(async function (signed) {
          expect(openpgp.stream.isStream(signed)).to.equal(useNativeStream ? 'web' : 'ponyfill');
          const message = await openpgp.readMessage({ binaryMessage: signed });
          message.packets.concat(await openpgp.stream.readToEnd(message.packets.stream, _ => _));
          const packets = new openpgp.PacketList();
          packets.push(message.packets.findPacket(openpgp.enums.packet.signature));
          packets.push(message.packets.findPacket(openpgp.enums.packet.literalData));
          verifyOpt.message = new openpgp.Message(packets);
          return openpgp.verify(verifyOpt);
        }).then(async function (verified) {
          expect(openpgp.stream.isStream(verified.data)).to.equal(useNativeStream ? 'web' : 'ponyfill');
          expect([].slice.call(await openpgp.stream.readToEnd(verified.data))).to.deep.equal([].slice.call(data));
          expect(await verified.signatures[0].verified).to.be.true;
          expect(await privateKey.getSigningKey(verified.signatures[0].keyid))
            .to.be.not.null;
          expect((await verified.signatures[0].signature).packets.length).to.equal(1);
        });
      });

      it('should encrypt and decrypt data with a date in the future', function () {
        const future = new Date(2040, 5, 5, 5, 5, 5, 0);
        const encryptOpt = {
          message: openpgp.Message.fromText(plaintext, undefined, future),
          publicKeys: publicKey_2038_2045,
          date: future,
          armor: false
        };

        return openpgp.encrypt(encryptOpt).then(async function (encrypted) {
          const message = await openpgp.readMessage({ binaryMessage: encrypted });
          return message.decrypt([privateKey_2038_2045]);
        }).then(async function (packets) {
          const literals = packets.packets.filterByTag(openpgp.enums.packet.literalData);
          expect(literals.length).to.equal(1);
          expect(+literals[0].date).to.equal(+future);
          expect(await openpgp.stream.readToEnd(packets.getText())).to.equal(plaintext);
        });
      });

      it('should encrypt and decrypt binary data with a date in the past', function () {
        const past = new Date(2005, 5, 5, 5, 5, 5, 0);
        const data = new Uint8Array([3, 14, 15, 92, 65, 35, 59]);
        const encryptOpt = {
          message: openpgp.Message.fromBinary(data, undefined, past),
          publicKeys: publicKey_2000_2008,
          date: past,
          armor: false
        };

        return openpgp.encrypt(encryptOpt).then(async function (encrypted) {
          const message = await openpgp.readMessage({ binaryMessage: encrypted });
          return message.decrypt([privateKey_2000_2008]);
        }).then(async function (packets) {
          const literals = packets.packets.filterByTag(openpgp.enums.packet.literalData);
          expect(literals.length).to.equal(1);
          expect(+literals[0].date).to.equal(+past);
          expect(await openpgp.stream.readToEnd(packets.getLiteralData())).to.deep.equal(data);
        });
      });

      it('should sign, encrypt and decrypt, verify data with a date in the past', function () {
        const past = new Date(2005, 5, 5, 5, 5, 5, 0);
        const encryptOpt = {
          message: openpgp.Message.fromText(plaintext, undefined, past),
          publicKeys: publicKey_2000_2008,
          privateKeys: privateKey_2000_2008,
          date: past,
          armor: false
        };

        return openpgp.encrypt(encryptOpt).then(async function (encrypted) {
          const message = await openpgp.readMessage({ binaryMessage: encrypted });
          return message.decrypt([privateKey_2000_2008]);
        }).then(async function (message) {
          const literals = message.packets.filterByTag(openpgp.enums.packet.literalData);
          expect(literals.length).to.equal(1);
          expect(+literals[0].date).to.equal(+past);
          const signatures = await message.verify([publicKey_2000_2008], past);
          expect(await openpgp.stream.readToEnd(message.getText())).to.equal(plaintext);
          expect(+(await signatures[0].signature).packets[0].created).to.equal(+past);
          expect(await signatures[0].verified).to.be.true;
          expect(await privateKey_2000_2008.getSigningKey(signatures[0].keyid, past))
            .to.be.not.null;
          expect((await signatures[0].signature).packets.length).to.equal(1);
        });
      });

      it('should sign, encrypt and decrypt, verify binary data with a date in the future', function () {
        const future = new Date(2040, 5, 5, 5, 5, 5, 0);
        const data = new Uint8Array([3, 14, 15, 92, 65, 35, 59]);
        const encryptOpt = {
          message: openpgp.Message.fromBinary(data, undefined, future),
          publicKeys: publicKey_2038_2045,
          privateKeys: privateKey_2038_2045,
          date: future,
          armor: false
        };

        return openpgp.encrypt(encryptOpt).then(async function (encrypted) {
          const message = await openpgp.readMessage({ binaryMessage: encrypted });
          return message.decrypt([privateKey_2038_2045]);
        }).then(async function (message) {
          const literals = message.packets.filterByTag(openpgp.enums.packet.literalData);
          expect(literals.length).to.equal(1);
          expect(literals[0].format).to.equal('binary');
          expect(+literals[0].date).to.equal(+future);
          const signatures = await message.verify([publicKey_2038_2045], future);
          expect(await openpgp.stream.readToEnd(message.getLiteralData())).to.deep.equal(data);
          expect(+(await signatures[0].signature).packets[0].created).to.equal(+future);
          expect(await signatures[0].verified).to.be.true;
          expect(await privateKey_2038_2045.getSigningKey(signatures[0].keyid, future))
            .to.be.not.null;
          expect((await signatures[0].signature).packets.length).to.equal(1);
        });
      });

      it('should sign, encrypt and decrypt, verify mime data with a date in the future', function () {
        const future = new Date(2040, 5, 5, 5, 5, 5, 0);
        const data = new Uint8Array([3, 14, 15, 92, 65, 35, 59]);
        const encryptOpt = {
          message: openpgp.Message.fromBinary(data, undefined, future, 'mime'),
          publicKeys: publicKey_2038_2045,
          privateKeys: privateKey_2038_2045,
          date: future,
          armor: false
        };

        return openpgp.encrypt(encryptOpt).then(async function (encrypted) {
          const message = await openpgp.readMessage({ binaryMessage: encrypted });
          return message.decrypt([privateKey_2038_2045]);
        }).then(async function (message) {
          const literals = message.packets.filterByTag(openpgp.enums.packet.literalData);
          expect(literals.length).to.equal(1);
          expect(literals[0].format).to.equal('mime');
          expect(+literals[0].date).to.equal(+future);
          const signatures = await message.verify([publicKey_2038_2045], future);
          expect(await openpgp.stream.readToEnd(message.getLiteralData())).to.deep.equal(data);
          expect(+(await signatures[0].signature).packets[0].created).to.equal(+future);
          expect(await signatures[0].verified).to.be.true;
          expect(await privateKey_2038_2045.getSigningKey(signatures[0].keyid, future))
            .to.be.not.null;
          expect((await signatures[0].signature).packets.length).to.equal(1);
        });
      });

      it('should fail to encrypt with revoked key', function() {
        return openpgp.revokeKey({
          key: privateKey
        }).then(function(revKey) {
          return openpgp.encrypt({
            message: openpgp.Message.fromText(plaintext),
            publicKeys: revKey.publicKey
          }).then(function() {
            throw new Error('Should not encrypt with revoked key');
          }).catch(function(error) {
            expect(error.message).to.match(/Error encrypting message: Primary key is revoked/);
          });
        });
      });

      it('should fail to encrypt with revoked subkey', async function() {
        const pubKeyDE = await openpgp.readKey({ armoredKey: pub_key_de });
        const privKeyDE = await openpgp.readKey({ armoredKey: priv_key_de });
        await privKeyDE.decrypt(passphrase);
        return privKeyDE.subKeys[0].revoke(privKeyDE.primaryKey).then(function(revSubKey) {
          pubKeyDE.subKeys[0] = revSubKey;
          return openpgp.encrypt({
            message: openpgp.Message.fromText(plaintext),
            publicKeys: pubKeyDE
          }).then(function() {
            throw new Error('Should not encrypt with revoked subkey');
          }).catch(function(error) {
            expect(error.message).to.match(/Could not find valid encryption key packet/);
          });
        });
      });

      it('should decrypt with revoked subkey', async function() {
        const pubKeyDE = await openpgp.readKey({ armoredKey: pub_key_de });
        const privKeyDE = await openpgp.readKey({ armoredKey: priv_key_de });
        await privKeyDE.decrypt(passphrase);
        const encrypted = await openpgp.encrypt({
          message: openpgp.Message.fromText(plaintext),
          publicKeys: pubKeyDE
        });
        privKeyDE.subKeys[0] = await privKeyDE.subKeys[0].revoke(privKeyDE.primaryKey);
        const decOpt = {
          message: await openpgp.readMessage({ armoredMessage: encrypted }),
          privateKeys: privKeyDE
        };
        const decrypted = await openpgp.decrypt(decOpt);
        expect(decrypted.data).to.equal(plaintext);
      });

      it('should not decrypt with corrupted subkey', async function() {
        const pubKeyDE = await openpgp.readKey({ armoredKey: pub_key_de });
        const privKeyDE = await openpgp.readKey({ armoredKey: priv_key_de });
        // corrupt the public key params
        privKeyDE.subKeys[0].keyPacket.publicParams.p[0]++;
        // validation will not check the decryption subkey and will succeed
        await privKeyDE.decrypt(passphrase);
        const encrypted = await openpgp.encrypt({
          message: openpgp.Message.fromText(plaintext),
          publicKeys: pubKeyDE
        });
        const decOpt = {
          message: await openpgp.readMessage({ armoredMessage: encrypted }),
          privateKeys: privKeyDE
        };
        // binding signature is invalid
        await expect(openpgp.decrypt(decOpt)).to.be.rejectedWith(/Session key decryption failed/);
      });

      it('RSA decryption with PKCS1 padding of wrong length should fail', async function() {
        const key = await openpgp.readKey({ armoredKey: rsaPrivateKeyPKCS1 });
        // the paddings of these messages are prefixed by 0x02 and 0x000002 instead of 0x0002
        // the code should discriminate between these cases by checking the length of the padded plaintext
        const padding02 = `-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js VERSION
Comment: https://openpgpjs.org

wcBMAxbpoSTRSSl3AQf/fepDhqeam4Ecy8GUFChc47U3hbkdgINobI9TORAf
eGFZVcyTQKVIt7fB8bwQwjxRmU98xCjF7VkLhPQJkzKlkT9cIDBKswU+d3fw
lHAVYo77yUkFkVLXrQTZj/OjsA12V7lfRagO375XB3EpJUHVPvYQFFr3aSlo
FbsCrpZoS6FXxRYVjGpIeMjam3a7qDavQpKhjOQ+Sfm0tk2JZkQwpFom6x7c
9TEn3YSo6+I0ztjiuTBZDyYr8zocHW8imFzZRlcNuuuukesyFzFgHx46eVpO
6PVjmiN50agZvsV9rgPyyH84nb3zYJ63shnrQWubTOVH4daGbe8uHi+ZM3UU
J9I8AcH94nE77JUtCm7s1kOlo0EIshZsAqJwGveDGdAuabfViVwVxG4I24M6
8sqJYJd9FpNjSbYlrLT0R9zy
=+n/4
-----END PGP MESSAGE-----`;
        const padding000002 = `-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js VERSION
Comment: https://openpgpjs.org

wcBMAxbpoSTRSSl3AQf/fepDhqeam4Ecy8GUFChc47U3hbkdgINobI9TORAf
eGFZVcyTQKVIt7fB8bwQwjxRmU98xCjF7VkLhPQJkzKlkT9cIDBKswU+d3fw
lHAVYo77yUkFkVLXrQTZj/OjsA12V7lfRagO375XB3EpJUHVPvYQFFr3aSlo
FbsCrpZoS6FXxRYVjGpIeMjam3a7qDavQpKhjOQ+Sfm0tk2JZkQwpFom6x7c
9TEn3YSo6+I0ztjiuTBZDyYr8zocHW8imFzZRlcNuuuukesyFzFgHx46eVpO
6PVjmiN50agZvsV9rgPyyH84nb3zYJ63shnrQWubTOVH4daGbe8uHi+ZM3UU
J9I8AcH94nE77JUtCm7s1kOlo0EIshZsAqJwGveDGdAuabfViVwVxG4I24M6
8sqJYJd9FpNjSbYlrLT0R9zy
=+n/4
-----END PGP MESSAGE-----`;

        const decOpt02 = {
          message: await openpgp.readMessage({ armoredMessage: padding02 }),
          privateKeys: key
        };
        await expect(openpgp.decrypt(decOpt02)).to.be.rejectedWith(/Decryption error/);

        const decOpt000002 = {
          message: await openpgp.readMessage({ armoredMessage: padding000002 }),
          privateKeys: key
        };
        await expect(openpgp.decrypt(decOpt000002)).to.be.rejectedWith(/Decryption error/);
      });

      it('should decrypt with two passwords message which GPG fails on', async function() {
        const decOpt = {
          message: await openpgp.readMessage({ armoredMessage: twoPasswordGPGFail }),
          passwords: password2
        };
        return openpgp.decrypt(decOpt).then(function(decrypted) {
          expect(decrypted.data).to.equal('short message\nnext line\n한국어/조선말');
          expect(decrypted.signatures.length).to.equal(0);
        });
      });

      it('should decrypt with three passwords', async function() {
        const messageBinary = util.hexToUint8Array('c32e04090308125231fe38b0255f60a7f319fc4959c147c7af33817ceb4cf159a00f2efa17b7921961f6ead025c77588d2430166fe9395cd58e9b69a67a30470e2d31bf0bbbb31c7eca31fb9015dddf70c6957036b093d104cbf0b26e218113e69c4fa89dda97a61d0cba364efa77d5144c5b9b701');
        const message = await openpgp.readMessage({ binaryMessage: messageBinary });
        const passwords = ['Test', 'Pinata', 'a'];
        const decrypted = await openpgp.decrypt({ message, passwords });
        expect(decrypted.data).to.equal('Hello world');
      });

      it('should decrypt broken ECC message from old OpenPGP.js', async function() {
        const key = await openpgp.readKey({ armoredKey: ecdh_dec_key });
        const message = await openpgp.readMessage({ armoredMessage: ecdh_msg_bad });
        await key.decrypt('12345');
        const decrypted = await openpgp.decrypt({ message, privateKeys: [key] });
        expect(decrypted.data).to.equal('\n');
      });

      it('should decrypt broken ECC message from old go crypto', async function() {
        const key = await openpgp.readKey({ armoredKey: ecdh_dec_key_2 });
        const message = await openpgp.readMessage({ armoredMessage: ecdh_msg_bad_2 });
        await key.decrypt('12345');
        const decrypted = await openpgp.decrypt({ message, privateKeys: [key] });
        expect(decrypted.data).to.equal('Tesssst<br><br><br>Sent from ProtonMail mobile<br><br><br>');
      });

      it('should decrypt Blowfish message', async function() {
        const { data } = await openpgp.decrypt({
          passwords: 'test',
          message: await openpgp.readMessage({
            armoredMessage: `-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.9.0
Comment: https://openpgpjs.org

wx4EBAMI7Di70u7hoDfgBUJQ2+1ig6ym3KMjRS9kAovSPAGRQLIPv2DgkINL
3DUgMNqtQCA23xWhq7Ly6o9H1lRfoAo7V5UElVCqGEX7cgyZjI97alY6Je3o
amnR6g==
=rPIK
-----END PGP MESSAGE-----`
          })
        });
        expect(data).to.equal('Hello World!');
      });

      it('should normalize newlines in encrypted text message', async function() {
        const message = openpgp.Message.fromText('"BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\r\nUID:123\r\nDTSTART:20191211T121212Z\r\nDTEND:20191212T121212Z\r\nEND:VEVENT\nEND:VCALENDAR"');
        const encrypted = await openpgp.encrypt({
          passwords: 'test',
          message
        });
        const decrypted = await openpgp.decrypt({
          passwords: 'test',
          message: await openpgp.readMessage({ armoredMessage: encrypted }),
          format: 'binary'
        });
        expect(util.decodeUtf8(decrypted.data)).to.equal('"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:123\r\nDTSTART:20191211T121212Z\r\nDTEND:20191212T121212Z\r\nEND:VEVENT\r\nEND:VCALENDAR"');
      });
    });

    describe('Sign and verify with each curve', function() {
      const curves = ['secp256k1' , 'p256', 'p384', 'p521', 'curve25519', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1'];
      curves.forEach(curve => {
        it(`sign/verify with ${curve}`, async function() {
          const plaintext = 'short message';
          const key = (await openpgp.generateKey({ curve, userIds: { name: 'Alice', email: 'info@alice.com' } })).key;
          const signed = await openpgp.sign({ privateKeys:[key], message: openpgp.CleartextMessage.fromText(plaintext) });
          const verified = await openpgp.verify({ publicKeys:[key], message: await openpgp.readCleartextMessage({ cleartextMessage: signed }) });
          expect(verified.signatures[0].valid).to.be.true;
        });
      });
    });

    describe('Errors', function() {

      it('Error message should contain the original error message', function() {
        return openpgp.encrypt({
          message: openpgp.Message.fromBinary(new Uint8Array([0x01, 0x01, 0x01])),
          passwords: null
        }).then(function() {
          throw new Error('Error expected.');
        }).catch(function(error) {
          expect(error.message).to.match(/No keys, passwords, or session key provided/);
        });
      });

    });

    describe('Specific encryption/signing key testing', async function () {
      const encryptionKeyIds = [
        keyIdType.fromId("87EAE0977B2185EA"),
        keyIdType.fromId("F94F9B34AF93FA14"),
        keyIdType.fromId("08F7D4C7C59545C0")
      ];
      const signingKeyIds = [
        keyIdType.fromId("663277AF60400638"),
        keyIdType.fromId("BBE14491E6EE6366"),
        keyIdType.fromId("3E0F20F1A71D6DFD")
      ];
      const getPrimaryKey = async () => openpgp.readKey({
        armoredKey: multipleEncryptionAndSigningSubkeys
      });

      it('Encrypt message with a specific encryption key id', async function () {
        const primaryKey = await getPrimaryKey();
        let m;
        let p;
        for (let i = 0; i < encryptionKeyIds.length; i++) {
          m = await openpgp.readMessage({
            armoredMessage: await openpgp.encrypt({
              message: openpgp.Message.fromText("Hello World\n"),
              publicKeys: primaryKey,
              encryptionKeyIds: [encryptionKeyIds[i]]
            })
          });
          p = m.packets.filterByTag(openpgp.enums.packet.publicKeyEncryptedSessionKey);
          expect(p.length).equals(1);
          expect(p[0].publicKeyId.equals(encryptionKeyIds[i])).to.be.true;
        }
      });

      it('Sign message with a specific signing key id', async function () {
        const primaryKey = await getPrimaryKey();
        let s;
        let p;
        for (let i = 0; i < signingKeyIds.length; i++) {
          s = await openpgp.readSignature({
            armoredSignature: await openpgp.sign({
              message: openpgp.Message.fromText("Hello World\n"),
              privateKeys: primaryKey,
              signingKeyIds: [signingKeyIds[i]],
              detached: true
            })
          });
          p = s.packets.filterByTag(openpgp.enums.packet.signature);
          expect(p.length).equals(1);
          expect(p[0].issuerKeyId.equals(signingKeyIds[i])).to.be.true;
        }
      });

      it('Encrypt and sign with specific encryption/signing key ids', async function () {
        const primaryKey = await getPrimaryKey();
        const plaintextMessage = openpgp.Message.fromText("Hello World\n");

        const checkEncryptedPackets = (encryptionKeyIds, pKESKList) => {
          pKESKList.forEach(({ publicKeyId }, i) => {
            expect(publicKeyId.equals(encryptionKeyIds[i])).to.be.true;
          });
        };
        const checkSignatures = (signingKeyIds, signatures) => {
          signatures.forEach(({ keyid }, i) => {
            expect(keyid.equals(signingKeyIds[i])).to.be.true;
          });
        };

        const kIds = [encryptionKeyIds[1], encryptionKeyIds[0], encryptionKeyIds[2]];
        const sIds = [signingKeyIds[2], signingKeyIds[1], signingKeyIds[0]];
        const message = await openpgp.readMessage({
          armoredMessage: await openpgp.encrypt({
            message: plaintextMessage,
            privateKeys: [primaryKey, primaryKey, primaryKey],
            publicKeys: [primaryKey, primaryKey, primaryKey],
            encryptionKeyIds: kIds,
            signingKeyIds: sIds
          })
        });
        const pKESKList = message.packets.filterByTag(openpgp.enums.packet.publicKeyEncryptedSessionKey);
        expect(pKESKList.length).equals(3);
        checkEncryptedPackets(kIds, pKESKList);
        const { signatures } = await openpgp.decrypt({
          message,
          privateKeys: [primaryKey, primaryKey, primaryKey]
        });
        expect(signatures.length).equals(3);
        checkSignatures(sIds, signatures);
      });
    });
  });

});
