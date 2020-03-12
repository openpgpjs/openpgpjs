const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;

const password = 'I am a password';

const tests = {
  zip: {
    input: `-----BEGIN PGP MESSAGE-----

jA0ECQMC5rhAA7l3jOzk0kwBTMc07y+1NME5RCUQ2EOlSofbh1KARLC5B1NMeBlq
jS917VBeCW3R21xG+0ZJ6Z5iWwdQD7XBtg19doWOqExSmXBWWW/6vSaD81ox
=Gw9+
-----END PGP MESSAGE-----`,
    output: 'Hello world! With zip.'
  },
  zlib: {
    input: `-----BEGIN PGP MESSAGE-----

jA0ECQMC8Qfig2+Tygnk0lMB++5JoyZUcpUy5EJqcxBuy93tXw+BSk7OhFhda1Uo
JuQlKv27HlyUaA55tMJsFYPypGBLEXW3k0xi3Cs87RrLqmVGTZSqNhHOVNE28lVe
W40mpQ==
=z0we
-----END PGP MESSAGE-----`,
    output: 'Hello world! With zlib.'
  },
  bzip2: {
    input: `-----BEGIN PGP MESSAGE-----

jA0ECQMC97w+wp7u9/Xk0oABBfapJBuuxGBiHDfNmVgsRzbjLDBWTJ3LD4UtxEku
qu6hwp5JXB0TgI/XQ3tKobSqHv1wSJ9SVxtWZq6WvWulu+j9GtzIVC3mbDA/qRA3
41sUEMdAFC6I7BYLYGEiUAVNpjbvGOmJWptDyawjRgEuZeTzKyTI/UcMc/rLy9Pz
Xg==
=6ek1
-----END PGP MESSAGE-----`,
    output: 'Hello world! With bzip2.'
  }
};

describe('Decrypt and decompress message tests', function () {

  function runTest(key, test) {
    it(`Decrypts message compressed with ${key}`, async function () {
      const message = await openpgp.message.readArmored(test.input);
      const options = {
          passwords: password,
          message
        };
      return openpgp.decrypt(options).then(function (encrypted) {
        expect(encrypted.data).to.equal(test.output + '\n');
      });
    });
  }

  Object.keys(tests).forEach(key => runTest(key, tests[key]));

});
