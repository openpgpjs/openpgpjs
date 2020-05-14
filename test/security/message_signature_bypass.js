const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');

const { key, cleartext, util, SignaturePacket } = openpgp;

const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;

/**
* public key of another user.
*/
const OTHERPUBKEY = `
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js VERSION
Comment: https://openpgpjs.org

xsBNBFuqNY0BCADFUCnl03vimEQRs7mtDIp0g6tItuguhJJu1/QjXwTXUHZg
pZosOPkGOR1EubydjYz4kvAnZ5r9cWA4xQ96rBdvj/kIaP+oJKLB1jXwh4Ft
+8YT4mVU2yWLu7U2p4tSyRoM5VCDEqG64OcbZMwEdDKf8t6JTjYTtEfPfW5R
4hy8NjPYOx0Jw8MG+U0aP4WA1xsMXFP/VWF1IseEcVIWKs/VroJc5Xe80QDN
hRtKTRVJV/wTnkao2MLcq/hgOfhO28NjnxVlX06O/XTWdElA7CCi1Zg1/BZ+
r2XuuE1J2DjERfTokFzkKnMlGK9zXn0LxPnAJAIfu33/SFuAZcVu4UEJABEB
AAHNHVRlc3RpIFRlc3QgPHRlc3RAZXhhbXBsZS5jb20+wsB1BBABCAApBQJb
qjWcBgsJBwgDAgkQVSCLLRis484EFQgKAgMWAgECGQECGwMCHgEAAGNXB/4g
DX082p83RfMmBv8hRN1V9ruPAvlxDWNBHb5dc1Y67yrBXOLMtaSauSZKrbf1
moPDHT2eoLl7cV3BQbXWp+hiMZ4W53ZFJt26Kwwwf1yVRAZME7VRNwqW0aJv
FKgCq7XTgJ61UYNhc31bLH0eVcfCkAExfwqZlwTWRzRSCqr0NL0XZVakJE6F
al1Y+uN7CEr0/vbc6uSuo0hyZwxAw+Iynd5cO9PRXSssAm4IaulSnYUd96r2
l8jsa+p6ooBYPotnLQ9fdd457JMoc8jDHf4m+P9/ZiWpycCB0DgUtNw1wH2T
DHYf+2lfGGoA3osuHeJJfZfJujbKW5L7ZMNJ23tSzsBNBFuqNY0BB/9XKYzS
PdHC/dXoBC9un3YLCcUX6LMNnaQMryVONYKFE1Rt0/si9XtnIDqyBrTr3LRi
D+GIR+b7zCXOGkvmjztblD2P3SweCudPIbVLxePI+SfyjRs9EsMOrEPymN7U
u/CU7jefvNBKvvMHi1m1Ibqg/A+ZheqJ+xBjSQM88dWsY/XB/jh7PGAM0QEu
ezafNwlUUNnXyYRuC3P4h66OIJcDPcfaao3uAuJ/C81E8ttuws3c08kudd/A
szIGpPtxAakimiWVHa0ceKi3exXXjRDrufroPcV3+Gbn4J8NqcUPRhB3L3CD
rCivRme8qGEYh+ADPLy88SytdtCr+6W4hiQVABEBAAHCwF8EGAEIABMFAluq
NZ0JEFUgiy0YrOPOAhsMAABebggAxANqkwS/Ag3NQLUu/wNZMMifZAxpFIWo
CQQrCOU94OSsUKz8Q11yoOvsQN3T4CSL8dG5DbIucnHsx39jVeTniG6P3p9f
NE/lq7RtLnXjVgGYpPNNUbLcOfXaCDhmS4GEunwTsVlsmEqyfLniKLG8to5Q
6f/wGPJRvYB8rgLfVGV3DCvILg/CMzkceM9ia6jDQeHHwnoFVXnlsRAgQefJ
rT5hVim4Wzg/5Lxt9Efry0k1ZhT0kondF1qNMv0wKxIJ+/gDNT2ZP4RIr1Kl
eu6a8CH841yfF0+r5RV9xOky0jxwGgcxT29c8DBoawjXu6TtJ/SP8UrscttA
bVLYdBmWLw==
=nMyV
-----END PGP PUBLIC KEY BLOCK-----`;

/**
* an original unmodified message as a template.
*/
const ORIGINAL = `
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

You owe me € 10
-----BEGIN PGP SIGNATURE-----
Version: OpenPGP.js VERSION
Comment: https://openpgpjs.org

wsBcBAEBCAAQBQJbq0iICRBVIIstGKzjzgAAeV0H/3ZxWuEV+2PNXHR+PdxX
WRxjk6Zu+jjpb/iRS8IynRoe3iDaai3+iiAHM1GsHvOIBVJU6Bjx1ZyyEI0a
dDg/yj3LBqBW9U3AiGpsXPfuyLKYIHfPbrygEleRIQKh7+iwNmn9ScVvzJrl
hUurlZxx1mWbERAchwsrcZpwFCdfjJ/C9sblTxgnsm1YlYZNkf95DFtRnVO5
prUuOjqJ0bA7bxg5GA4FQskRPIQ0ioZ6DyDi2IU3rdVEOs2Pc8S0EsD9K7af
vO5oXKiJsyUN5EXEI8kYRulP1l0kvEWVTlnY2ek1qS637RkBI+DHLcXV5Hcu
fhGyl7nA7UCwgsqf7ZPBhRg=
=nbjQ
-----END PGP SIGNATURE-----`;
async function getOtherPubKey() {
  return await key.readArmored(OTHERPUBKEY);
}

/**
* The "standalone" signature signed by the victim.
*/
const STANDALONE_PKT = util.b64ToUint8Array(`
BAIBCAAQBQJbq3MKCRBVIIstGKzjzgAAWdoIALgj7OuhuuAWr6WEvGfvkx3e
Fn/mg76lh2Hawxq6ryI6+kzUH+YJsG94CfLgGuh5LghZFBnlkdZS11gK87fN
+ifmPdSDj8fsKqSFdX1sHGwzvzBcuPt+qhtHrACCWwiiBgajIOmIczKUlX4D
ASBkthx0o9Qb/r3dT91zmrniIK5I0yqe34/1rsHhOAf8ds2EubupFJJqFOb1
qssMWE+jBrTREoD/EH5q7un2jEGccITcVQSZCqfjHT4EL6dF/bmuggf7wV/E
QLXfFIJS6cZczK86XW1pGaXBKRLvQXYa/eRWHKcGlrujdFKzJYRoT6LVDk8T
jhAfE9q2ElqlaAvZZYw=`);
async function fakeSignature() {
  // read the template and modify the text to
  // invalidate the signature.
  let fake = await cleartext.readArmored(
    ORIGINAL.replace(
      'You owe me',
      'I owe you'));
  // read the standalone signature packet
  const tmp = new SignaturePacket();
  await tmp.read(STANDALONE_PKT);

  // replace the "text" signature with the
  // "standalone" signature
  fake.signature.packets[0] = tmp;
  const faked_armored = await fake.armor();
  // re-read the message to eliminate any
  // behaviour due to cached values.
  fake = await cleartext.readArmored(faked_armored);
  // faked message now verifies correctly
  const res = await openpgp.verify({
    message: fake,
    publicKeys: await getOtherPubKey(),
    streaming: false
  });
  const { signatures } = res;
  expect(signatures).to.have.length(0);
}

module.exports = () => it('Does not accept non-binary/text signatures', fakeSignature);
