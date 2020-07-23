const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');
const chai = require('chai');
const BN = require('bn.js');

chai.use(require('chai-as-promised'));

const expect = chai.expect;
const armoredDSAKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lQNTBF69PO8RCACHP4KLQcYOPGsGV9owTZvxnvHvvrY8W0v8xDUL3y6CLc05srF1
kQp/81iUfP5g57BEiDpJV95kMh+ulBthIOGnuMCkodJjuBICB4K6BtFTV4Fw1Q5S
S7aLC9beCaMvvGHXsK6MbknYl+IVJY7Zmml1qUSrBIQFGp5kqdhIX4o+OrzZ1zYj
ALicqzD7Zx2VRjGNQv7UKv4CkBOC8ncdnq/4/OQeOYFzVbCOf+sJhTgz6yxjHJVC
fLk7w8l2v1zV11VJuc8cQiQ9g8tjbKgLMsbyzy7gl4m9MSCdinG36XZuPibZrSm0
H8gKAdd1FT84a3/qU2rtLLR0y8tCxBj89Xx/AQCv7CDmwoU+/yGpBVVl1mh0ZUkA
/VJUhnJfv5MIOIi3AQf8CS9HrEmYJg/A3z0DcvcwIu/9gqpRLTqH1iT5o4BCg2j+
Cog2ExYkQl1OEPkEQ1lKJSnD8MDwO3BlkJ4cD0VSKxlnwd9dsu9m2+F8T+K1hoA7
PfH89TjD5HrEaGAYIdivLYSwoTNOO+fY8FoVC0RR9pFNOmjiTU5PZZedOxAql5Os
Hp2bYhky0G9trjo8Mt6CGhvgA3dAKyONftLQr9HSM0GKacFV+nRd9TGCPNZidKU8
MDa/SB/08y1bBGX5FK5wwiZ6H5qD8VAUobH3kwKlrg0nL00/EqtYHJqvJ2gkT5/v
h8+z4R4TuYiy4kKF2FLPd5OjdA31IVDoVgCwF0WHLgf/X9AiTr/DPs/5dIYN1+hf
UJwqjzr3dlokRwx3CVDcOVsdkWRwb8cvxubbsIorvUrF02IhYjHJMjIHT/zFt2zA
+VPzO4zabUlawWVepPEwrCtXgvn9aXqjhAYbilG3UZamhfstGUmbmvWVDadALwby
EO8u2pfLhI2lep63V/+KtUOLhfk8jKRSvxvxlYAvMi7sK8kB+lYy17XKN+IMYgf8
gMFV6XGKpdmMSV3jOvat8cI6vnRO0i+g3jANP3PfrFEivat/rVgxo67r4rxezfFn
J29qwB9rgbRgMBGsbDvIlQNV/NWFvHy2uQAEKn5eX4CoLsCZoR2VfK3BwBCxhYDp
/wAA/0GSmI9MlMnLadFNlcX2Bm4i15quZAGF8JxwHbj1dhdUEYq0E1Rlc3QgPHRl
c3RAdGVzdC5pbz6IlAQTEQgAPBYhBAq6lCI5EfrbHP1qZCxnOy/rlEGVBQJevTzv
AhsDBQsJCAcCAyICAQYVCgkICwIEFgIDAQIeBwIXgAAKCRAsZzsv65RBlUPoAP9Q
aTCWpHWZkvZzC8VU64O76fHp31rLWlcZFttuDNLyeAEAhOxkQHk6GR88R+EF5mrn
clr63t9Q4wreqOlO0NR5/9k=
=UW2O
-----END PGP PRIVATE KEY BLOCK-----
`;

const armoredElGamalKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
vqBGKJzmO5q3cECw
=X9kJ
-----END PGP PRIVATE KEY BLOCK-----`;

describe('EdDSA parameter validation', function() {
  let keyParams;
  before(async () => {
    keyParams = await openpgp.crypto.generateParams(openpgp.enums.publicKey.eddsa, null, 'ed25519');
  });

  it('EdDSA params should be valid', async function() {
    const { oid, Q, seed } = openpgp.crypto.publicKey.elliptic.eddsa.parseParams(keyParams);
    const valid = await openpgp.crypto.publicKey.elliptic.eddsa.validateParams(oid, Q, seed);
    expect(valid).to.be.true;
  });

  it('detect invalid edDSA Q', async function() {
    const { oid, Q, seed } = openpgp.crypto.publicKey.elliptic.eddsa.parseParams(keyParams);


    Q[0]++;
    let valid = await openpgp.crypto.publicKey.elliptic.eddsa.validateParams(oid, Q, seed);
    expect(valid).to.be.false;

    const infQ = new Uint8Array(Q.length);
    valid = await openpgp.crypto.publicKey.elliptic.eddsa.validateParams(oid, infQ, seed);
    expect(valid).to.be.false;
  });
});

describe('ECC curve validation', function() {
  it('EdDSA params are not valid for ECDH', async function() {
    const keyParams = await openpgp.crypto.generateParams(
      openpgp.enums.publicKey.eddsa,
      null,
      'ed25519'
    );
    const { oid, Q, seed } = openpgp.crypto.publicKey.elliptic.eddsa.parseParams(keyParams);
    const valid = await openpgp.crypto.publicKey.elliptic.ecdh.validateParams(oid, Q, seed);
    expect(valid).to.be.false;
  });

  it('EdDSA params are not valid for EcDSA', async function() {
    const keyParams = await openpgp.crypto.generateParams(
      openpgp.enums.publicKey.eddsa,
      null,
      'ed25519'
    );
    const { oid, Q, seed } = openpgp.crypto.publicKey.elliptic.eddsa.parseParams(keyParams);
    const valid = await openpgp.crypto.publicKey.elliptic.ecdsa.validateParams(oid, Q, seed);
    expect(valid).to.be.false;
  });

  it('x25519 params are not valid for EcDSA', async function() {
    const keyParams = await openpgp.crypto.generateParams(
      openpgp.enums.publicKey.ecdsa,
      null,
      'curve25519'
    );
    const { oid, Q, d } = openpgp.crypto.publicKey.elliptic.ecdsa.parseParams(keyParams);
    const valid = await openpgp.crypto.publicKey.elliptic.ecdsa.validateParams(oid, Q, d);
    expect(valid).to.be.false;
  });

  it('EcDSA params are not valid for EdDSA', async function() {
    const keyParams = await openpgp.crypto.generateParams(
      openpgp.enums.publicKey.ecdsa, null, 'p256'
    );
    const { oid, Q, d } = openpgp.crypto.publicKey.elliptic.ecdsa.parseParams(keyParams);
    const valid = await openpgp.crypto.publicKey.elliptic.eddsa.validateParams(oid, Q, d);
    expect(valid).to.be.false;
  });

  it('x25519 params are not valid for EdDSA', async function() {
    const keyParams = await openpgp.crypto.generateParams(
      openpgp.enums.publicKey.ecdsa, null, 'curve25519'
    );
    const { oid, Q, d } = openpgp.crypto.publicKey.elliptic.ecdsa.parseParams(keyParams);
    const valid = await openpgp.crypto.publicKey.elliptic.eddsa.validateParams(oid, Q, d);
    expect(valid).to.be.false;
  });
});


const curves = ['curve25519', 'p256', 'p384', 'p521', 'secp256k1', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1'];
curves.forEach(curve => {
  describe(`ECC ${curve} parameter validation`, () => {
    let keyParams;
    before(async () => {
      // we generate also ecdh params as ecdsa ones since we do not need the kdf params
      keyParams = await openpgp.crypto.generateParams(
        openpgp.enums.publicKey.ecdsa, null, curve
      );
    });

    if (curve !== 'curve25519') {
      it(`EcDSA ${curve} params should be valid`, async function() {
        const { oid, Q, d } = openpgp.crypto.publicKey.elliptic.ecdsa.parseParams(keyParams);
        const valid = await openpgp.crypto.publicKey.elliptic.ecdsa.validateParams(oid, Q, d);
        expect(valid).to.be.true;
      });

      it('detect invalid EcDSA Q', async function() {
        const { oid, Q, d } = openpgp.crypto.publicKey.elliptic.ecdsa.parseParams(keyParams);

        Q[16]++;
        let valid = await openpgp.crypto.publicKey.elliptic.ecdsa.validateParams(oid, Q, d);
        expect(valid).to.be.false;

        const infQ = new Uint8Array(Q.length);
        valid = await openpgp.crypto.publicKey.elliptic.ecdsa.validateParams(oid, infQ, d);
        expect(valid).to.be.false;
      });
    }

    it(`ECDH ${curve} params should be valid`, async function() {
      const { oid, Q, d } = openpgp.crypto.publicKey.elliptic.ecdsa.parseParams(keyParams);
      const valid = await openpgp.crypto.publicKey.elliptic.ecdh.validateParams(oid, Q, d);
      expect(valid).to.be.true;
    });

    it('detect invalid ECDH Q', async function() {
      const { oid, Q, d } = openpgp.crypto.publicKey.elliptic.ecdsa.parseParams(keyParams);

      Q[16]++;
      let valid = await openpgp.crypto.publicKey.elliptic.ecdh.validateParams(oid, Q, d);
      expect(valid).to.be.false;

      const infQ = new Uint8Array(Q.length);
      valid = await openpgp.crypto.publicKey.elliptic.ecdh.validateParams(oid, infQ, d);
      expect(valid).to.be.false;
    });
  });
});

describe('RSA parameter validation', function() {
  let keyParams;
  before(async () => {
    keyParams = await openpgp.crypto.generateParams(openpgp.enums.publicKey.rsa_sign, 2048);
  });

  it('generated RSA params are valid', async function() {
    const n = keyParams[0].toUint8Array();
    const e = keyParams[1].toUint8Array();
    const d = keyParams[2].toUint8Array();
    const p = keyParams[3].toUint8Array();
    const q = keyParams[4].toUint8Array();
    const u = keyParams[5].toUint8Array();
    const valid = await openpgp.crypto.publicKey.rsa.validateParams(n, e, d, p, q, u);
    expect(valid).to.be.true;
  });

  it('detect invalid RSA n', async function() {
    const n = keyParams[0].toUint8Array();
    const e = keyParams[1].toUint8Array();
    const d = keyParams[2].toUint8Array();
    const p = keyParams[3].toUint8Array();
    const q = keyParams[4].toUint8Array();
    const u = keyParams[5].toUint8Array();

    n[0]++;
    const valid = await openpgp.crypto.publicKey.rsa.validateParams(n, e, d, p, q, u);
    expect(valid).to.be.false;
  });

  it('detect invalid RSA e', async function() {
    const n = keyParams[0].toUint8Array();
    const e = keyParams[1].toUint8Array();
    const d = keyParams[2].toUint8Array();
    const p = keyParams[3].toUint8Array();
    const q = keyParams[4].toUint8Array();
    const u = keyParams[5].toUint8Array();

    e[0]++;
    const valid = await openpgp.crypto.publicKey.rsa.validateParams(n, e, d, p, q, u);
    expect(valid).to.be.false;
  });
});

describe('DSA parameter validation', function() {
  let dsaKey;
  before(async () => {
    dsaKey = (await openpgp.key.readArmored(armoredDSAKey)).keys[0];
  });

  it('DSA params should be valid', async function() {
    const params = dsaKey.keyPacket.params;
    const p = params[0].toUint8Array();
    const q = params[1].toUint8Array();
    const g = params[2].toUint8Array();
    const y = params[3].toUint8Array();
    const x = params[4].toUint8Array();
    const valid = await openpgp.crypto.publicKey.dsa.validateParams(p, q, g, y, x);
    expect(valid).to.be.true;
  });

  it('detect invalid DSA p', async function() {
    const params = dsaKey.keyPacket.params;
    const p = params[0].toUint8Array();
    const q = params[1].toUint8Array();
    const g = params[2].toUint8Array();
    const y = params[3].toUint8Array();
    const x = params[4].toUint8Array();

    p[0]++;
    const valid = await openpgp.crypto.publicKey.dsa.validateParams(p, q, g, y, x);

    expect(valid).to.be.false;
  });

  it('detect invalid DSA y', async function() {
    const params = dsaKey.keyPacket.params;
    const p = params[0].toUint8Array();
    const q = params[1].toUint8Array();
    const g = params[2].toUint8Array();
    const y = params[3].toUint8Array();
    const x = params[4].toUint8Array();

    y[0]++;
    const valid = await openpgp.crypto.publicKey.dsa.validateParams(p, q, g, y, x);

    expect(valid).to.be.false;
  });

  it('detect invalid DSA g', async function() {
    const params = dsaKey.keyPacket.params;
    const p = params[0].toUint8Array();
    const q = params[1].toUint8Array();
    const g = params[2].toUint8Array();
    const y = params[3].toUint8Array();
    const x = params[4].toUint8Array();

    g[0]++;
    let valid = await openpgp.crypto.publicKey.dsa.validateParams(p, q, g, y, x);
    expect(valid).to.be.false;

    const gOne = new Uint8Array([1]);
    valid = await openpgp.crypto.publicKey.dsa.validateParams(p, q, gOne, y, x);
    expect(valid).to.be.false;
  });
});

describe('ElGamal parameter validation', function() {
  let egKey;
  before(async () => {
    egKey = (await openpgp.key.readArmored(armoredElGamalKey)).keys[0].subKeys[0];
  });

  it('params should be valid', async function() {
    const params = egKey.keyPacket.params;
    const p = params[0].toUint8Array();
    const g = params[1].toUint8Array();
    const y = params[2].toUint8Array();
    const x = params[3].toUint8Array();

    const valid = await openpgp.crypto.publicKey.elgamal.validateParams(p, g, y, x);
    expect(valid).to.be.true;
  });

  it('detect invalid p', async function() {
    const params = egKey.keyPacket.params;
    const p = params[0].toUint8Array();
    const g = params[1].toUint8Array();
    const y = params[2].toUint8Array();
    const x = params[3].toUint8Array();
    p[0]++;
    const valid = await openpgp.crypto.publicKey.elgamal.validateParams(p, g, y, x);

    expect(valid).to.be.false;
  });

  it('detect invalid y', async function() {
    const params = egKey.keyPacket.params;
    const p = params[0].toUint8Array();
    const g = params[1].toUint8Array();
    const y = params[2].toUint8Array();
    const x = params[3].toUint8Array();

    y[0]++;
    const valid = await openpgp.crypto.publicKey.elgamal.validateParams(p, g, y, x);

    expect(valid).to.be.false;
  });

  it('detect invalid g', async function() {
    const params = egKey.keyPacket.params;
    const p = params[0].toUint8Array();
    const g = params[1].toUint8Array();
    const y = params[2].toUint8Array();
    const x = params[3].toUint8Array();

    g[0]++;
    let valid = await openpgp.crypto.publicKey.elgamal.validateParams(p, g, y, x);
    expect(valid).to.be.false;

    const gOne = new Uint8Array([1]);
    valid = await openpgp.crypto.publicKey.elgamal.validateParams(p, gOne, y, x);
    expect(valid).to.be.false;
  });

  it('detect g with small order', async function() {
    const params = egKey.keyPacket.params;
    const p = params[0].toUint8Array();
    const g = params[1].toUint8Array();
    const y = params[2].toUint8Array();
    const x = params[3].toUint8Array();

    const pBN = new BN(p);
    const gModP = new BN(g).toRed(new BN.red(pBN));
    // g**(p-1)/2 has order 2
    const gOrd2 = gModP.redPow(pBN.subn(1).shrn(1));
    const valid = await openpgp.crypto.publicKey.elgamal.validateParams(p, gOrd2.toArrayLike(Uint8Array, 'be'), y, x);
    expect(valid).to.be.false;
  });
});
