import { expect } from 'chai';

import BN from 'bn.js';
import { bigIntToUint8Array, bitLength, byteLength, gcd, getBit, modExp, modInv } from '../../src/crypto/biginteger';
import { getRandomBytes } from '../../src/crypto/random';

async function getRandomBN(min, max) {
  if (max.cmp(min) <= 0) {
    throw new Error('Illegal parameter value: max <= min');
  }

  const modulus = max.sub(min);
  const bytes = modulus.byteLength();
  const r = new BN(getRandomBytes(bytes + 8));
  return r.mod(modulus).add(min);
}


export default () => describe('BigInt', () => {
  it('bitLength is correct', function() {
    const n = BigInt(127);
    const expected = 7;
    expect(bitLength(n)).to.equal(expected);
    expect(bitLength(n + BigInt(1))).to.equal(expected + 1);
  });

  it('byteLength is correct', function() {
    const n = BigInt(65535);
    const expected = 2;
    expect(byteLength(n)).to.equal(expected);
    expect(byteLength(n + BigInt(1))).to.equal(expected + 1);
  });

  it('toUint8Array is correct', function() {
    const nString = '417653931840771530406225971293556769925351769207235721650257629558293828796031115397206059067934284452829611906818956352854418342467914729341523414945427019410284762464062112274326172407819051167058569790660930309496043254270888417520676082271432948852231332576271876251597199882908964994070268531832274431027';
    const n = BigInt(nString);
    const paddedSize = Number(byteLength(n)) + 1;
    // big endian, unpadded
    let expected = new BN(nString).toArrayLike(Uint8Array);
    expect(bigIntToUint8Array(n)).to.deep.equal(expected);
    // big endian, padded
    expected = new BN(nString).toArrayLike(Uint8Array, 'be', paddedSize);
    expect(bigIntToUint8Array(n, 'be', paddedSize)).to.deep.equal(expected);
    // little endian, unpadded
    expected = new BN(nString).toArrayLike(Uint8Array, 'le');
    expect(bigIntToUint8Array(n, 'le')).to.deep.equal(expected);
    //little endian, padded
    expected = new BN(nString).toArrayLike(Uint8Array, 'le', paddedSize);
    expect(bigIntToUint8Array(n, 'le', paddedSize)).to.deep.equal(expected);
  });

  it('modExp is correct (large values)', function() {
    const stringX = '417653931840771530406225971293556769925351769207235721650257629558293828796031115397206059067934284452829611906818956352854418342467914729341523414945427019410284762464062112274326172407819051167058569790660930309496043254270888417520676082271432948852231332576271876251597199882908964994070268531832274431027';
    const stringE = '21139356010872569239159922781526379521587348169074209285187910481667533072168468011617194695181255483288792585413365359733692097084373249198758148704369207793873998901870577262254971784191473102265830193058813215898765238784670469696574407580179153118937858890572095234316482449291777882525949871374961971753';
    const stringN = '129189808515414783602892982235788912674846062846614219472827821758734760420002631653235573915244294540972376140705505703576175711417114803419704967903726436285518767606681184247119430411311152556442947708732584954518890222684529678365388350886907287414896703685680210648760841628375425909680236584021041565183';
    const x = BigInt(stringX);
    const e = BigInt(stringE);
    const n = BigInt(stringN);

    const got = modExp(x, e, n);
    const expected = new BN(stringX).toRed(BN.red(new BN(stringN))).redPow(new BN(stringE));
    // different formats, it's easier to compare strings
    expect(got.toString(), expected.toString());
  });

  it('gcd is correct', async function() {
    const aBN = await getRandomBN(new BN(2), new BN(200));
    const bBN = await getRandomBN(new BN(2), new BN(200));
    if (aBN.isEven()) aBN.iaddn(1);
    const a = BigInt(aBN.toString());
    const b = BigInt(bBN.toString());
    const expected = aBN.gcd(bBN);
    expect(gcd(a, b).toString()).to.equal(expected.toString());
  });

  it('modular inversion is correct', async function() {
    const moduloBN = new BN(229); // this is a prime
    const baseBN = await getRandomBN(new BN(2), moduloBN);
    const a = BigInt(baseBN.toString());
    const n = BigInt(moduloBN.toString());
    const expected = baseBN.invm(moduloBN);
    expect(modInv(a, n).toString()).to.equal(expected.toString());
    // test negative operand
    const expectedNegated = baseBN.neg().invm(moduloBN);
    expect(modInv(-a, n).toString()).to.equal(expectedNegated.toString());
    expect(() => modInv(a * n, n)).to.throw(/Inverse does not exist/);
  });

  it('getBit is correct', async function() {
    const i = 5;
    const nBN = await getRandomBN(new BN(2), new BN(200));
    const n = BigInt(nBN.toString());
    const expected = nBN.testn(5) ? 1 : 0;
    expect(getBit(n, i)).to.equal(expected);
  });
});
