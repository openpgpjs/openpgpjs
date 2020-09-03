/* eslint-disable new-cap */

/**
 * BigInteger implementation of basic operations
 * that wraps the native BigInt library.
 * Operations are not constant time,
 * but we try and limit timing leakage where we can
 */
export default class BigInteger {
  /**
   * Get a BigInteger (input must be big endian for strings and arrays)
   * @param {Number|String|Uint8Array} n value to convert
   * @throws {Error} on null or undefined input
   */
  constructor(n) {
    if (n === undefined) {
      throw new Error('Invalid BigInteger input');
    }

    if (n instanceof Uint8Array) {
      const bytes = n;
      const hex = new Array(bytes.length);
      for (let i = 0; i < bytes.length; i++) {
        const hexByte = bytes[i].toString(16);
        hex[i] = (bytes[i] <= 0xF) ? ('0' + hexByte) : hexByte;
      }
      this.value = BigInt('0x0' + hex.join(''));
    } else {
      this.value = BigInt(n);
    }
  }

  clone() {
    return new BigInteger(this.value);
  }

  /**
   * BigInteger increment in place
   */
  iinc() {
    this.value++;
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
    this.value--;
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
    this.value += x.value;
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
    this.value -= x.value;
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
    this.value *= x.value;
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
    this.value %= m.value;
    if (this.isNegative()) {
      this.iadd(m);
    }
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
   * Compute modular exponentiation using square and multiply
   * @param {BigInteger} e exponent
   * @param {BigInteger} n modulo
   * @returns {BigInteger} this ** e mod n
   */
  modExp(e, n) {
    if (n.isZero()) throw Error("Modulo cannot be zero");
    if (n.isOne()) return new BigInteger(0);
    if (e.isNegative()) throw Error("Unsopported negative exponent");

    let exp = e.value;
    let x = this.value;

    x %= n.value;
    let r = BigInt(1);
    while (exp > BigInt(0)) {
      const lsb = exp & BigInt(1);
      exp >>= BigInt(1); // e / 2
      // Always compute multiplication step, to reduce timing leakage
      const rx = (r * x) % n.value;
      // Update r only if lsb is 1 (odd exponent)
      r = lsb ? rx : r;
      x = (x * x) % n.value; // Square
    }
    return new BigInteger(r);
  }


  /**
   * Compute the inverse of this value modulo n
   * Note: this and and n must be relatively prime
   * @param {BigInteger} n modulo
   * @return {BigInteger} x such that this*x = 1 mod n
   */
  modInv(n) {
    return this._egcd(n).x.add(n).mod(n);
  }

  /**
   * Extended Eucleadian algorithm (http://anh.cs.luc.edu/331/notes/xgcd.pdf)
   * Given a = this and b, compute (x, y) such that ax + by = gdc(a, b)
   * @param {BigInteger} b second operand
   * @returns { gcd, x, y: BigInteger }
   */
  _egcd(b) {
    let x = BigInt(0);
    let y = BigInt(1);
    let xPrev = BigInt(1);
    let yPrev = BigInt(0);

    let a = this.value;
    b = b.value;

    while (b !== BigInt(0)) {
      const q = a / b;
      let tmp = x;
      x = xPrev - q * x;
      xPrev = tmp;

      tmp = y;
      y = yPrev - q * y;
      yPrev = tmp;

      tmp = b;
      b = a % b;
      a = tmp;
    }

    return {
      x: new BigInteger(xPrev),
      y: new BigInteger(yPrev),
      gcd: new BigInteger(a)
    };
  }

  /**
   * Compute greatest common divisor between this and n
   * @param {BigInteger} b operand
   * @return {BigInteger} gcd
   */
  gcd(b) {
    let a = this.value;
    b = b.value;
    while (b !== BigInt(0)) {
      const tmp = b;
      b = a % b;
      a = tmp;
    }
    return new BigInteger(a);
  }

  /**
   * Shift this to the left by x, in place
   * @param {BigInteger} x shift value
   */
  ileftShift(x) {
    this.value <<= x.value;
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
    this.value >>= x.value;
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
    return this.value === x.value;
  }

  /**
   * Whether this value is less than x
   * @param {BigInteger} x
   * @returns {Boolean}
   */
  lt(x) {
    return this.value < x.value;
  }

  /**
   * Whether this value is less than or equal to x
   * @param {BigInteger} x
   * @returns {Boolean}
   */
  lte(x) {
    return this.value <= x.value;
  }

  /**
   * Whether this value is greater than x
   * @param {BigInteger} x
   * @returns {Boolean}
   */
  gt(x) {
    return this.value > x.value;
  }

  /**
   * Whether this value is greater than or equal to x
   * @param {BigInteger} x
   * @returns {Boolean}
   */
  gte(x) {
    return this.value >= x.value;
  }

  isZero() {
    return this.value === BigInt(0);
  }

  isOne() {
    return this.value === BigInt(1);
  }

  isNegative() {
    return this.value < BigInt(0);
  }

  isEven() {
    return !(this.value & BigInt(1));
  }

  abs() {
    const res = this.clone();
    if (this.isNegative()) {
      res.value = -res.value;
    }
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
    const number = Number(this.value);
    if (number > Number.MAX_SAFE_INTEGER) {
      // We throw and error to conform with the bn.js implementation
      throw new Error('Number can only safely store up to 53 bits');
    }
    return number;
  }

  /**
   * Get value of i-th bit
   * @param {Number} i bit index
   * @returns {Number} bit value
   */
  getBit(i) {
    const bit = (this.value >> BigInt(i)) & BigInt(1);
    return (bit === BigInt(0)) ? 0 : 1;
  }

  /**
   * Compute bit length
   * @returns {Number} bit length
   */
  bitLength() {
    const zero = new BigInteger(0);
    const one = new BigInteger(1);
    const negOne = new BigInteger(-1);

    // -1n >> -1n is -1n
    // 1n >> 1n is 0n
    const target = this.isNegative() ? negOne : zero;
    let bitlen = 1;
    const tmp = this.clone();
    while (!tmp.irightShift(one).equal(target)) {
      bitlen++;
    }
    return bitlen;
  }

  /**
   * Compute byte length
   * @returns {Number} byte length
   */
  byteLength() {
    const zero = new BigInteger(0);
    const negOne = new BigInteger(-1);

    const target = this.isNegative() ? negOne : zero;
    const eight = new BigInteger(8);
    let len = 1;
    const tmp = this.clone();
    while (!tmp.irightShift(eight).equal(target)) {
      len++;
    }
    return len;
  }

  /**
   * Get Uint8Array representation of this number
   * @param {String} endian endianess of output array (defaults to 'be')
   * @param {Number} length of output array
   * @return {Uint8Array}
   */
  toUint8Array(endian = 'be', length) {
    // we get and parse the hex string (https://coolaj86.com/articles/convert-js-bigints-to-typedarrays/)
    // this is faster than shift+mod iterations
    let hex = this.value.toString(16);
    if (hex.length % 2 === 1) {
      hex = '0' + hex;
    }

    const rawLength = hex.length / 2;
    const bytes = new Uint8Array(length || rawLength);
    // parse hex
    const offset = length ? (length - rawLength) : 0;
    let i = 0;
    while (i < rawLength) {
      bytes[i + offset] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
      i++;
    }

    if (endian !== 'be') {
      bytes.reverse();
    }

    return bytes;
  }
}
