// Modified by ProtonTech AG

// Adapted from https://github.com/artjomb/cryptojs-extension/blob/8c61d159/test/eax.js

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;

describe('Symmetric AES-OCB', function() {
  it('Passes all test vectors', async function() {
    const K = '000102030405060708090A0B0C0D0E0F';
    const keyBytes = openpgp.util.hex_to_Uint8Array(K);

    const vectors = [
      // From https://tools.ietf.org/html/rfc7253#appendix-A
      {
        N: 'BBAA99887766554433221100',
        A: '',
        P: '',
        C: '785407BFFFC8AD9EDCC5520AC9111EE6'
      },
      {
        N: 'BBAA99887766554433221101',
        A: '0001020304050607',
        P: '0001020304050607',
        C: '6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009'
      },
      {
        N: 'BBAA99887766554433221102',
        A: '0001020304050607',
        P: '',
        C: '81017F8203F081277152FADE694A0A00'
      },
      {
        N: 'BBAA99887766554433221103',
        A: '',
        P: '0001020304050607',
        C: '45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9'
      },
      {
        N: 'BBAA99887766554433221104',
        A: '000102030405060708090A0B0C0D0E0F',
        P: '000102030405060708090A0B0C0D0E0F',
        C: '571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358'
      },
      {
        N: 'BBAA99887766554433221105',
        A: '000102030405060708090A0B0C0D0E0F',
        P: '',
        C: '8CF761B6902EF764462AD86498CA6B97'
      },
      {
        N: 'BBAA99887766554433221106',
        A: '',
        P: '000102030405060708090A0B0C0D0E0F',
        C: '5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D'
      },
      {
        N: 'BBAA99887766554433221107',
        A: '000102030405060708090A0B0C0D0E0F1011121314151617',
        P: '000102030405060708090A0B0C0D0E0F1011121314151617',
        C: '1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F'
      },
      {
        N: 'BBAA99887766554433221108',
        A: '000102030405060708090A0B0C0D0E0F1011121314151617',
        P: '',
        C: '6DC225A071FC1B9F7C69F93B0F1E10DE'
      },
      {
        N: 'BBAA99887766554433221109',
        A: '',
        P: '000102030405060708090A0B0C0D0E0F1011121314151617',
        C: '221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF'
      },
      {
        N: 'BBAA9988776655443322110A',
        A: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
        P: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
        C: 'BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240'
      },
      {
        N: 'BBAA9988776655443322110B',
        A: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
        P: '',
        C: 'FE80690BEE8A485D11F32965BC9D2A32'
      },
      {
        N: 'BBAA9988776655443322110C',
        A: '',
        P: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
        C: '2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF'
      },
      {
        N: 'BBAA9988776655443322110D',
        A: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627',
        P: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627',
        C: 'D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483A7035490C5769E60'
      },
      {
        N: 'BBAA9988776655443322110E',
        A: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627',
        P: '',
        C: 'C5CD9D1850C141E358649994EE701B68'
      },
      {
        N: 'BBAA9988776655443322110F',
        A: '',
        P: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627',
        C: '4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479'
      }
    ];

    const cipher = 'aes128';

    await Promise.all(vectors.map(async vec => {
      const msgBytes = openpgp.util.hex_to_Uint8Array(vec.P);
      const nonceBytes = openpgp.util.hex_to_Uint8Array(vec.N);
      const headerBytes = openpgp.util.hex_to_Uint8Array(vec.A);
      const ctBytes = openpgp.util.hex_to_Uint8Array(vec.C);

      const ocb = await openpgp.crypto.ocb(cipher, keyBytes);

      // encryption test
      let ct = await ocb.encrypt(msgBytes, nonceBytes, headerBytes);
      expect(openpgp.util.Uint8Array_to_hex(ct)).to.equal(vec.C.toLowerCase());

      // decryption test with verification
      let pt = await ocb.decrypt(ctBytes, nonceBytes, headerBytes);
      expect(openpgp.util.Uint8Array_to_hex(pt)).to.equal(vec.P.toLowerCase());

      // tampering detection test
      ct = await ocb.encrypt(msgBytes, nonceBytes, headerBytes);
      ct[2] ^= 8;
      pt = ocb.decrypt(ct, nonceBytes, headerBytes);
      await expect(pt).to.eventually.be.rejectedWith('Authentication tag mismatch');

      // testing without additional data
      ct = await ocb.encrypt(msgBytes, nonceBytes, new Uint8Array());
      pt = await ocb.decrypt(ct, nonceBytes, new Uint8Array());
      expect(openpgp.util.Uint8Array_to_hex(pt)).to.equal(vec.P.toLowerCase());

      // testing with multiple additional data
      ct = await ocb.encrypt(msgBytes, nonceBytes, openpgp.util.concatUint8Array([headerBytes, headerBytes, headerBytes]));
      pt = await ocb.decrypt(ct, nonceBytes, openpgp.util.concatUint8Array([headerBytes, headerBytes, headerBytes]));
      expect(openpgp.util.Uint8Array_to_hex(pt)).to.equal(vec.P.toLowerCase());
    }));
  });

  it('Different key size test vectors', async function() {
    const taglen = 128;
    const outputs = {
      128: '67E944D23256C5E0B6C61FA22FDF1EA2',
      192: 'F673F2C3E7174AAE7BAE986CA9F29E17',
      256: 'D90EB8E9C977C88B79DD793D7FFA161C'
    };
    const keylens = [128, 192, 256];
    await Promise.all(keylens.map(async keylen => {
      const k = new Uint8Array(keylen / 8);
      k[k.length - 1] = taglen;

      const ocb = await openpgp.crypto.ocb('aes' + keylen, k);

      const c = [];
      let n;
      for (let i = 0; i < 128; i++) {
        const s = new Uint8Array(i);
        n = openpgp.util.concatUint8Array([new Uint8Array(8), openpgp.util.writeNumber(3 * i + 1, 4)]);
        c.push(await ocb.encrypt(s, n, s));
        n = openpgp.util.concatUint8Array([new Uint8Array(8), openpgp.util.writeNumber(3 * i + 2, 4)]);
        c.push(await ocb.encrypt(s, n, new Uint8Array()));
        n = openpgp.util.concatUint8Array([new Uint8Array(8), openpgp.util.writeNumber(3 * i + 3, 4)]);
        c.push(await ocb.encrypt(new Uint8Array(), n, s));
      }
      n = openpgp.util.concatUint8Array([new Uint8Array(8), openpgp.util.writeNumber(385, 4)]);
      const output = await ocb.encrypt(new Uint8Array(), n, openpgp.util.concatUint8Array(c));
      expect(openpgp.util.Uint8Array_to_hex(output)).to.equal(outputs[keylen].toLowerCase());
    }));
  });
});
