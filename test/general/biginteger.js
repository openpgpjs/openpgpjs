const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');
const random = require('../../src/crypto/random');
const util = require('../../src/util');

const BN = require('bn.js');
const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;
let BigInteger;

async function getRandomBN(min, max) {
  if (max.cmp(min) <= 0) {
    throw new Error('Illegal parameter value: max <= min');
  }

  const modulus = max.sub(min);
  const bytes = modulus.byteLength();
  const r = new BN(await random.getRandomBytes(bytes + 8));
  return r.mod(modulus).add(min);
}

module.exports = () => describe('BigInteger interface', function() {
  before(async () => {
    BigInteger = await util.getBigInteger();
  });

  it('constructor throws on undefined input', function() {
    expect(() => new BigInteger()).to.throw('Invalid BigInteger input');
  });


  it('constructor supports strings', function() {
    const input = '417653931840771530406225971293556769925351769207235721650257629558293828796031115397206059067934284452829611906818956352854418342467914729341523414945427019410284762464062112274326172407819051167058569790660930309496043254270888417520676082271432948852231332576271876251597199882908964994070268531832274431027';
    const got = new BigInteger(input);
    const expected = new BN(input);
    expect(got.toString()).to.equal(expected.toString());
  });

  it('constructor supports Uint8Arrays', function() {
    const expected = new BN('417653931840771530406225971293556769925351769207235721650257629558293828796031115397206059067934284452829611906818956352854418342467914729341523414945427019410284762464062112274326172407819051167058569790660930309496043254270888417520676082271432948852231332576271876251597199882908964994070268531832274431027');
    const input = expected.toArrayLike(Uint8Array);
    const got = new BigInteger(input);
    expect(got.toString()).to.equal(expected.toString());
  });

  it('conditional operators are correct', function() {
    const a = new BigInteger(12);
    const b = new BigInteger(34);

    expect(a.equal(a)).to.be.true;
    expect(a.equal(b)).to.be.false;
    expect(a.gt(a) === a.lt(a)).to.be.true;
    expect(a.gt(b) === a.lt(b)).to.be.false;
    expect(a.gte(a) === a.lte(a)).to.be.true;

    const zero = new BigInteger(0);
    const one = new BigInteger(1);
    expect(zero.isZero()).to.be.true;
    expect(one.isZero()).to.be.false;

    expect(one.isOne()).to.be.true;
    expect(zero.isOne()).to.be.false;

    expect(zero.isEven()).to.be.true;
    expect(one.isEven()).to.be.false;

    expect(zero.isNegative()).to.be.false;
    expect(zero.dec().isNegative()).to.be.true;
  });

  it('bitLength is correct', function() {
    const n = new BigInteger(127);
    let expected = 7;
    expect(n.bitLength() === expected).to.be.true;
    expect(n.inc().bitLength() === (++expected)).to.be.true;
  });

  it('byteLength is correct', function() {
    const n = new BigInteger(65535);
    let expected = 2;
    expect(n.byteLength() === expected).to.be.true;
    expect(n.inc().byteLength() === (++expected)).to.be.true;
  });

  it('toUint8Array is correct', function() {
    const nString = '417653931840771530406225971293556769925351769207235721650257629558293828796031115397206059067934284452829611906818956352854418342467914729341523414945427019410284762464062112274326172407819051167058569790660930309496043254270888417520676082271432948852231332576271876251597199882908964994070268531832274431027';
    const n = new BigInteger(nString);
    const paddedSize = Number(n.byteLength()) + 1;
    // big endian, unpadded
    let expected = new BN(nString).toArrayLike(Uint8Array);
    expect(n.toUint8Array()).to.deep.equal(expected);
    // big endian, padded
    expected = new BN(nString).toArrayLike(Uint8Array, 'be', paddedSize);
    expect(n.toUint8Array('be', paddedSize)).to.deep.equal(expected);
    // little endian, unpadded
    expected = new BN(nString).toArrayLike(Uint8Array, 'le');
    expect(n.toUint8Array('le')).to.deep.equal(expected);
    //little endian, padded
    expected = new BN(nString).toArrayLike(Uint8Array, 'le', paddedSize);
    expect(n.toUint8Array('le', paddedSize)).to.deep.equal(expected);
  });

  it('binary operators are consistent', function() {
    const a = new BigInteger(12);
    const b = new BigInteger(34);
    const ops = ['add', 'sub', 'mul', 'mod', 'leftShift', 'rightShift'];
    ops.forEach(op => {
      const iop = `i${op}`;
      expect(a[op](b).equal(a[iop](b))).to.be.true;
    });
  });

  it('unary operators are consistent', function() {
    const a = new BigInteger(12);
    const one = new BigInteger(1);
    expect(a.sub(one).equal(a.dec())).to.be.true;
    expect(a.add(one).equal(a.inc())).to.be.true;
  });

  it('modExp is correct (large values)', function() {
    const stringX = '417653931840771530406225971293556769925351769207235721650257629558293828796031115397206059067934284452829611906818956352854418342467914729341523414945427019410284762464062112274326172407819051167058569790660930309496043254270888417520676082271432948852231332576271876251597199882908964994070268531832274431027';
    const stringE = '21139356010872569239159922781526379521587348169074209285187910481667533072168468011617194695181255483288792585413365359733692097084373249198758148704369207793873998901870577262254971784191473102265830193058813215898765238784670469696574407580179153118937858890572095234316482449291777882525949871374961971753';
    const stringN = '129189808515414783602892982235788912674846062846614219472827821758734760420002631653235573915244294540972376140705505703576175711417114803419704967903726436285518767606681184247119430411311152556442947708732584954518890222684529678365388350886907287414896703685680210648760841628375425909680236584021041565183';
    const x = new BigInteger(stringX);
    const e = new BigInteger(stringE);
    const n = new BigInteger(stringN);

    const got = x.modExp(e, n);
    const expected = new BN(stringX).toRed(BN.red(new BN(stringN))).redPow(new BN(stringE));
    // different formats, it's easier to compare strings
    expect(got.toString() === expected.toString()).to.be.true;
  });

  it('gcd is correct', async function() {
    const aBN = await getRandomBN(new BN(2), new BN(200));
    const bBN = await getRandomBN(new BN(2), new BN(200));
    if (aBN.isEven()) aBN.iaddn(1);
    const a = new BigInteger(aBN.toString());
    const b = new BigInteger(bBN.toString());
    const expected = aBN.gcd(bBN);
    expect(a.gcd(b).toString()).to.equal(expected.toString());
  });

  it('modular inversion is correct', async function() {
    const moduloBN = new BN(229); // this is a prime
    const baseBN = await getRandomBN(new BN(2), moduloBN);
    const a = new BigInteger(baseBN.toString());
    const n = new BigInteger(moduloBN.toString());
    const expected = baseBN.invm(moduloBN);
    expect(a.modInv(n).toString()).to.equal(expected.toString());
  });

  it('getBit is correct', async function() {
    const i = 5;
    const nBN = await getRandomBN(new BN(2), new BN(200));
    const n = new BigInteger(nBN.toString());
    const expected = nBN.testn(5) ? 1 : 0;
    expect(n.getBit(i) === expected).to.be.true;
  });
});
