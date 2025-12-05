import * as stream from '@openpgp/web-stream-tools';
import unbzip2Stream from '@openpgp/unbzip2-stream';
import * as base64 from '../../src/encoding/base64';
import { use as chaiUse, expect } from 'chai';
import chaiAsPromised from 'chai-as-promised'; // eslint-disable-line import/newline-after-import
chaiUse(chaiAsPromised);

import openpgp from '../initOpenpgp.js';

const password = 'I am a password';

function unbzip2(data) {
  return stream.readToEnd(unbzip2Stream(stream.toStream(data)));
}

const tests = {
  zip: {
    input: `-----BEGIN PGP MESSAGE-----

jA0ECQMC5rhAA7l3jOzk0kwBTMc07y+1NME5RCUQ2EOlSofbh1KARLC5B1NMeBlq
jS917VBeCW3R21xG+0ZJ6Z5iWwdQD7XBtg19doWOqExSmXBWWW/6vSaD81ox
=Gw9+
-----END PGP MESSAGE-----`,
    output: 'Hello world! With zip.',
    dos: base64.decode(`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`)
  },
  zlib: {
    input: `-----BEGIN PGP MESSAGE-----

jA0ECQMC8Qfig2+Tygnk0lMB++5JoyZUcpUy5EJqcxBuy93tXw+BSk7OhFhda1Uo
JuQlKv27HlyUaA55tMJsFYPypGBLEXW3k0xi3Cs87RrLqmVGTZSqNhHOVNE28lVe
W40mpQ==
=z0we
-----END PGP MESSAGE-----`,
    output: 'Hello world! With zlib.',
    dos: base64.decode(`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
cKEhZCmvEA==`)
  },
  bzip2: {
    input: `-----BEGIN PGP MESSAGE-----

jA0ECQMC97w+wp7u9/Xk0oABBfapJBuuxGBiHDfNmVgsRzbjLDBWTJ3LD4UtxEku
qu6hwp5JXB0TgI/XQ3tKobSqHv1wSJ9SVxtWZq6WvWulu+j9GtzIVC3mbDA/qRA3
41sUEMdAFC6I7BYLYGEiUAVNpjbvGOmJWptDyawjRgEuZeTzKyTI/UcMc/rLy9Pz
Xg==
=6ek1
-----END PGP MESSAGE-----`,
    output: 'Hello world! With bzip2.',
    dos: base64.decode(`QlpoOTFBWSZTWRsvn9IAAQd/////f37///1re///8Ob7pf//9t7/e/f+/9/y1u0f/3bNwAHc7C3b
djpgjJkA00AAMQAeoAABpoBoADQAADTJoBoAZADI0AA0A9IA0GmgZGhpoOEaGQDTTQAAxANAaAAA
DE09QMgNMgA0yZNGQBoA0A0AAGgAekAAGQACqmEaAAMQ0MgAMQ0Mh6QaZNNAA0AaAAA0AaaANANA
NAAA00AAAAABkKqfpDJNGmINGIBoNAAAAAANNAAAAAAAAAAAAAGgA0AAAA0Gg0bQgngvodzWEAki
pq1tPw9RSCAowCtAJIYpUjBlhApBBbxrcYo3rhEoheIxuAWLDid+PL4QQGa0mcFAbqUJ+AcUQ3Wb
NGkGOL7BVukQxyGZFa47p7uA9KDSSljbWukgBJA4gBQMA+EHRKZcyB/djUhrH9PSMKnQRhV1MWWt
hAdtRubExdt7nwVDvub7BBjZ7XEYKe6V5b06begFkf4k6CAC7Sprc4hd0f7NuVgGNpEAp0QjhZDw
LGDXN0srMMIpZlNyJwo02aVg4wmiUAigAcj5OBkoUoOng+aFhtY5MHSA8tqw/ujyWcEZiqx8QhRl
gmHsHk0Mswb7MgFUKH8d8fZgFR6gKFV57xgzSZJurGbcNtiCbpXdYQNUcFROL0dokhdJdXKA9hGV
XUAlQBDiNGJH8IblsQQ98fI4ffMaHXGCUgx4Ae3r4NJVIPKHAHGEyNYT6QmnHeYMwZ3UY4rmUCAd
VA6cFFRrC9aJkKscrjrWp+4hLz8rGHMS8O7EeEP5Vc/HbN0LJrZMkfMDDzIoPMJQIJPmnGg0eKVU
zGi7kEMGsIkJu3C0VtKG2ABP2SisV+ltUg50gEFXaBIaquqct79S6/NftAUfrkgJ4xkyTDd8LaH7
k5hZ9R5C1ASi5EgqirH9NullFHBa+k2kKqNEiEpaheQOAYog+Vdh9BU6RA1/AhwJWU4BwGVGeGY8
AWNDMF1ivaAs1vvDjSLhOIyB2bRIybHilrNSLmn/9z8jg2OJ9YPxtMFcQTUkkTrVPAsI+Clmt11X
QsTnbbFyWkSU8E+tyw1zzDcRNnR+fXBPg48oiRH9HmnUJgVEeqplTtuoLp+cWINoVEuzCqj/F3JF
OFCQGy+f0g==`)
  }
};

export default () => describe('Decompress message tests', function () {

  function runTest(key, test) {
    it(`Decrypts message compressed with ${key}`, async function () {
      const message = await openpgp.readMessage({
        armoredMessage: test.input
      });
      const options = {
        passwords: password,
        message
      };
      return openpgp.decrypt(options).then(function (decrypted) {
        expect(decrypted.data).to.equal(test.output + '\n');
      });
    });

    it(`Decrypts message compressed with ${key} - streaming`, async function () {
      const message = await openpgp.readMessage({
        armoredMessage: stream.toStream(test.input)
      });
      const options = {
        passwords: password,
        message
      };
      return openpgp.decrypt(options).then(async function (decrypted) {
        expect(stream.isStream(decrypted.data)).to.equal('web');
        expect(await stream.readToEnd(decrypted.data)).to.equal(test.output + '\n');
      });
    });

    it(`Can stop decompressing an overly large ${key} message - low limit`, async function() {
      const messagePromise = openpgp.readMessage({
        binaryMessage: await unbzip2(test.dos),
        config: {
          maxDecompressedMessageSize: 1000
        }
      });

      await expect(messagePromise).to.be.rejectedWith('Maximum decompressed message size exceeded');
    });

    it(`Can stop decompressing an overly large ${key} message - high limit`, async function() {
      const messagePromise = openpgp.readMessage({
        binaryMessage: await unbzip2(test.dos),
        config: {
          maxDecompressedMessageSize: 50_000_000
        }
      });

      await expect(messagePromise).to.be.rejectedWith('Maximum decompressed message size exceeded');
    });

    it(`Can stop decompressing an overly large ${key} message - low limit - streaming`, async function() {
      const messagePromise = openpgp.readMessage({
        binaryMessage: unbzip2Stream(stream.toStream(test.dos)),
        config: {
          maxDecompressedMessageSize: 1000
        }
      });

      await expect(messagePromise).to.be.rejectedWith('Maximum decompressed message size exceeded');
    });

    it(`Can stop decompressing an overly large ${key} message - high limit - streaming`, async function() {
      const message = await openpgp.readMessage({
        binaryMessage: unbzip2Stream(stream.toStream(test.dos)),
        config: {
          maxDecompressedMessageSize: 50_000_000
        }
      });

      const verified = await openpgp.verify({ message, verificationKeys: [] });
      const dataPromise = stream.readToEnd(verified.data);

      await expect(dataPromise).to.be.rejectedWith('Maximum decompressed message size exceeded');
    });
  }

  Object.keys(tests).forEach(key => runTest(key, tests[key]));

});
