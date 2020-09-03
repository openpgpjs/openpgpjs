import BN from 'bn.js';

/**
 * BigInteger implementation of basic operations
 * Wrapper of bn.js library (wwww.github.com/indutny/bn.js)
 */
export default class BigInteger {
  /**
   * Get a BigInteger (input must be big endian for strings and arrays)
   * @param {Number|String|Uint8Array} n value to convert
   * @throws {Error} on undefined input
   */
  constructor(n) {
    if (n === undefined) {
      throw new Error('Invalid BigInteger input');
    }

    this.value = new BN(n);
  }

  clone() {
    const clone = new BigInteger(null);
    this.value.copy(clone.value);
    return clone;
  }

  /**
   * BigInteger increment in place
   */
  iinc() {
    this.value.iadd(one.value);
    return this;
  }

  /**
   * BigInteger increment
   * @returns {BigInteger} this + 1
   */
  inc() {
    return this.clone().iinc();
  }

  /**
   * BigInteger decrement in place
   */
  idec() {
    this.value.isub(one.value);
    return this;
  }

  /**
   * BigInteger decrement
   * @returns {BigInteger} this - 1
   */
  dec() {
    return this.clone().idec();
  }


  /**
   * BigInteger addition in place
   * @param {BigInteger} x value to add
   */
  iadd(x) {
    this.value.iadd(x.value);
    return this;
  }

  /**
   * BigInteger addition
   * @param {BigInteger} x value to add
   * @returns {BigInteger} this + x
   */
  add(x) {
    return this.clone().iadd(x);
  }

  /**
   * BigInteger subtraction in place
   * @param {BigInteger} x value to subtract
   */
  isub(x) {
    this.value.isub(x.value);
    return this;
  }

  /**
   * BigInteger subtraction
   * @param {BigInteger} x value to subtract
   * @returns {BigInteger} this - x
   */
  sub(x) {
    return this.clone().isub(x);
  }

  /**
   * BigInteger multiplication in place
   * @param {BigInteger} x value to multiply
   */
  imul(x) {
    this.value.imul(x.value);
    return this;
  }

  /**
   * BigInteger multiplication
   * @param {BigInteger} x value to multiply
   * @returns {BigInteger} this * x
   */
  mul(x) {
    return this.clone().imul(x);
  }

  /**
   * Compute value modulo m, in place
   * @param {BigInteger} m modulo
   */
  imod(m) {
    this.value = this.value.umod(m.value);
    return this;
  }

  /**
   * Compute value modulo m
   * @param {BigInteger} m modulo
   * @returns {BigInteger} this mod m
   */
  mod(m) {
    return this.clone().imod(m);
  }

  /**
   * Compute modular exponentiation
   * Much faster than this.exp(e).mod(n)
   * @param {BigInteger} e exponent
   * @param {BigInteger} n modulo
   * @returns {BigInteger} this ** e mod n
   */
  modExp(e, n) {
    // We use either Montgomery or normal reduction context
    // Montgomery requires coprime n and R (montogmery multiplier)
    //  bn.js picks R as power of 2, so n must be odd
    const nred = n.isEven() ? BN.red(n.value) : BN.mont(n.value);
    const x = this.clone();
    x.value = x.value.toRed(nred).redPow(e.value).fromRed();
    return x;
  }

  /**
   * Compute the inverse of this value modulo n
   * Note: this and and n must be relatively prime
   * @param {BigInteger} n modulo
   * @return {BigInteger} x such that this*x = 1 mod n
   */
  modInv(n) {
    return new BigInteger(this.value.invm(n.value));
  }

  /**
   * Compute greatest common divisor between this and n
   * @param {BigInteger} n operand
   * @return {BigInteger} gcd
   */
  gcd(n) {
    return new BigInteger(this.value.gcd(n.value));
  }

  /**
   * Shift this to the left by x, in place
   * @param {BigInteger} x shift value
   */
  ileftShift(x) {
    this.value.ishln(x.value.toNumber());
    return this;
  }

  /**
   * Shift this to the left by x
   * @param {BigInteger} x shift value
   * @returns {BigInteger} this << x
   */
  leftShift(x) {
    return this.clone().ileftShift(x);
  }

  /**
   * Shift this to the right by x, in place
   * @param {BigInteger} x shift value
   */
  irightShift(x) {
    this.value.ishrn(x.value.toNumber());
    return this;
  }

  /**
   * Shift this to the right by x
   * @param {BigInteger} x shift value
   * @returns {BigInteger} this >> x
   */
  rightShift(x) {
    return this.clone().irightShift(x);
  }

  /**
   * Whether this value is equal to x
   * @param {BigInteger} x
   * @returns {Boolean}
   */
  equal(x) {
    return this.value.eq(x.value);
  }

  /**
   * Whether this value is less than x
   * @param {BigInteger} x
   * @returns {Boolean}
   */
  lt(x) {
    return this.value.lt(x.value);
  }

  /**
   * Whether this value is less than or equal to x
   * @param {BigInteger} x
   * @returns {Boolean}
   */
  lte(x) {
    return this.value.lte(x.value);
  }

  /**
   * Whether this value is greater than x
   * @param {BigInteger} x
   * @returns {Boolean}
   */
  gt(x) {
    return this.value.gt(x.value);
  }

  /**
   * Whether this value is greater than or equal to x
   * @param {BigInteger} x
   * @returns {Boolean}
   */
  gte(x) {
    return this.value.gte(x.value);
  }

  isZero() {
    return this.value.isZero();
  }

  isOne() {
    return this.equal(one);
  }

  isNegative() {
    return this.value.isNeg();
  }

  isEven() {
    return this.value.isEven();
  }

  abs() {
    const res = this.clone();
    res.value = res.value.abs();
    return res;
  }

  /**
   * Get this value as a string
   * @returns {String} this value
   */
  toString() {
    return this.value.toString();
  }

  /**
   * Get this value as an exact Number (max 53 bits)
   * Fails if this value is too large
   * @return {Number}
   */
  toNumber() {
    return this.value.toNumber();
  }

  /**
   * Get value of i-th bit
   * @param {Number} i bit index
   * @returns {Number} bit value
   */
  getBit(i) {
    return this.value.testn(i) ? 1 : 0;
  }

  /**
   * Compute bit length
   * @returns {Number} bit length
   */
  bitLength() {
    return this.value.bitLength();
  }

  /**
   * Compute byte length
   * @returns {Number} byte length
   */
  byteLength() {
    return this.value.byteLength();
  }

  /**
   * Get Uint8Array representation of this number
   * @param {String} endian endianess of output array (defaults to 'be')
   * @param {Number} length of output array
   * @return {Uint8Array}
   */
  toUint8Array(endian = 'be', length) {
    return this.value.toArrayLike(Uint8Array, endian, length);
  }
}

const one = new BigInteger(1);
