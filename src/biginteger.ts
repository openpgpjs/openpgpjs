/**
 * @fileoverview
 * BigInteger implementation of basic operations
 * that wraps the native BigInt library.
 * Operations are not constant time,
 * but we try and limit timing leakage where we can
 */
export default class BigInteger {
  private value: bigint;

  /**
   * Get a BigInteger (input must be big endian for strings and arrays)
   * @param {Number|String|Uint8Array} n - Value to convert
   * @throws {Error} on null or undefined input
   */
  constructor(n: Uint8Array | string | number | bigint) {
    if (n === undefined) {
      throw new Error('Invalid BigInteger input');
    }

    if (n instanceof Uint8Array) {
      const bytes = n;
      const hexAlphabet = '0123456789ABCDEF';
      let s = '';
      bytes.forEach(v => {
        s += hexAlphabet[v >> 4] + hexAlphabet[v & 15];
      });
      this.value = BigInt('0x0' + s);
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
   * @returns {BigInteger} this + 1.
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
   * @returns {BigInteger} this - 1.
   */
  dec() {
    return this.clone().idec();
  }

  /**
   * BigInteger addition in place
   * @param {BigInteger} x - Value to add
   */
  iadd(x: BigInteger) {
    this.value += x.value;
    return this;
  }

  /**
   * BigInteger addition
   * @param {BigInteger} x - Value to add
   * @returns {BigInteger} this + x.
   */
  add(x: BigInteger) {
    return this.clone().iadd(x);
  }

  /**
   * BigInteger subtraction in place
   * @param {BigInteger} x - Value to subtract
   */
  isub(x: BigInteger) {
    this.value -= x.value;
    return this;
  }

  /**
   * BigInteger subtraction
   * @param {BigInteger} x - Value to subtract
   * @returns {BigInteger} this - x.
   */
  sub(x: BigInteger) {
    return this.clone().isub(x);
  }

  /**
   * BigInteger multiplication in place
   * @param {BigInteger} x - Value to multiply
   */
  imul(x: BigInteger) {
    this.value *= x.value;
    return this;
  }

  /**
   * BigInteger multiplication
   * @param {BigInteger} x - Value to multiply
   * @returns {BigInteger} this * x.
   */
  mul(x: BigInteger) {
    return this.clone().imul(x);
  }

  /**
   * Compute value modulo m, in place
   * @param {BigInteger} m - Modulo
   */
  imod(m: BigInteger) {
    this.value %= m.value;
    if (this.isNegative()) {
      this.iadd(m);
    }
    return this;
  }

  /**
   * Compute value modulo m
   * @param {BigInteger} m - Modulo
   * @returns {BigInteger} this mod m.
   */
  mod(m: BigInteger) {
    return this.clone().imod(m);
  }

  /**
   * Compute modular exponentiation using square and multiply
   * @param {BigInteger} e - Exponent
   * @param {BigInteger} n - Modulo
   * @returns {BigInteger} this ** e mod n.
   */
  modExp(e: BigInteger, n: BigInteger) {
    if (n.isZero()) throw Error('Modulo cannot be zero');
    if (n.isOne()) return new BigInteger(0);
    if (e.isNegative()) throw Error('Unsopported negative exponent');

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
   * @param {BigInteger} n - Modulo
   * @returns {BigInteger} x such that this*x = 1 mod n
   * @throws {Error} if the inverse does not exist
   */
  modInv(n: BigInteger) {
    const { gcd, x } = this._egcd(n);
    if (!gcd.isOne()) {
      throw new Error('Inverse does not exist');
    }
    return x.add(n).mod(n);
  }

  /**
   * BigInteger division, in place
   * @param {BigInteger} n - Value to divide
   */
  idiv(n: BigInteger) {
    this.value /= n.value;
    return this;
  }

  /**
   * BigInteger division
   * @param {BigInteger} n - Value to divide
   * @returns {BigInteger} this divded by n.
   */
  div(n: BigInteger) {
    return this.clone().idiv(n);
  }

  /**
   * Extended Eucleadian algorithm (http://anh.cs.luc.edu/331/notes/xgcd.pdf)
   * Given a = this and b, compute (x, y) such that ax + by = gdc(a, b).
   * Negative numbers are also supported.
   * @param {BigInteger} b - Second operand
   * @returns {{ gcd, x, y: BigInteger }}
   */
  private _egcd(bInput: BigInteger) {
    let x = BigInt(0);
    let y = BigInt(1);
    let xPrev = BigInt(1);
    let yPrev = BigInt(0);

    // Deal with negative numbers: run algo over absolute values,
    // and "move" the sign to the returned x and/or y.
    // See https://math.stackexchange.com/questions/37806/extended-euclidean-algorithm-with-negative-numbers
    let a = this.abs().value;
    let b = bInput.abs().value;
    const aNegated = this.isNegative();
    const bNegated = bInput.isNegative();

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
      x: new BigInteger(aNegated ? -xPrev : xPrev),
      y: new BigInteger(bNegated ? -yPrev : yPrev),
      gcd: new BigInteger(a)
    };
  }

  /**
   * Compute greatest common divisor between this and n
   * @param {BigInteger} b - Operand
   * @returns {BigInteger} gcd
   */
  gcd(bInput: BigInteger) {
    let a = this.value;
    let b = bInput.value;
    while (b !== BigInt(0)) {
      const tmp = b;
      b = a % b;
      a = tmp;
    }
    return new BigInteger(a);
  }

  /**
   * Shift this to the left by x, in place
   * @param {BigInteger} x - Shift value
   */
  ileftShift(x: BigInteger) {
    this.value <<= x.value;
    return this;
  }

  /**
   * Shift this to the left by x
   * @param {BigInteger} x - Shift value
   * @returns {BigInteger} this << x.
   */
  leftShift(x: BigInteger) {
    return this.clone().ileftShift(x);
  }

  /**
   * Shift this to the right by x, in place
   * @param {BigInteger} x - Shift value
   */
  irightShift(x: BigInteger) {
    this.value >>= x.value;
    return this;
  }

  /**
   * Shift this to the right by x
   * @param {BigInteger} x - Shift value
   * @returns {BigInteger} this >> x.
   */
  rightShift(x: BigInteger) {
    return this.clone().irightShift(x);
  }

  ixor(x: BigInteger) {
    this.value ^= x.value;
    return this;
  }

  xor(x: BigInteger) {
    return this.clone().ixor(x);
  }

  ibitwiseAnd(x: BigInteger) {
    this.value &= x.value;
    return this;
  }

  bitwiseAnd(x: BigInteger) {
    return this.clone().ibitwiseAnd(x);
  }

  ibitwiseOr(x: BigInteger) {
    this.value |= x.value;
    return this;
  }

  /**
   * Whether this value is equal to x
   * @param {BigInteger} x
   * @returns {Boolean}
   */
  equal(x: BigInteger) {
    return this.value === x.value;
  }

  /**
   * Whether this value is less than x
   * @param {BigInteger} x
   * @returns {Boolean}
   */
  lt(x: BigInteger) {
    return this.value < x.value;
  }

  /**
   * Whether this value is less than or equal to x
   * @param {BigInteger} x
   * @returns {Boolean}
   */
  lte(x: BigInteger) {
    return this.value <= x.value;
  }

  /**
   * Whether this value is greater than x
   * @param {BigInteger} x
   * @returns {Boolean}
   */
  gt(x: BigInteger) {
    return this.value > x.value;
  }

  /**
   * Whether this value is greater than or equal to x
   * @param {BigInteger} x
   * @returns {Boolean}
   */
  gte(x: BigInteger) {
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

  negate() {
    const res = this.clone();
    res.value = -res.value;
    return res;
  }

  /**
   * Get this value as a string
   * @returns {String} this value.
   */
  toString() {
    return this.value.toString();
  }

  /**
   * Get this value as an exact Number (max 53 bits)
   * Fails if this value is too large
   * @returns {Number}
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
   * @param {Number} i - Bit index
   * @returns {Number} Bit value.
   */
  getBit(i: number) {
    const bit = (this.value >> BigInt(i)) & BigInt(1);
    return bit === BigInt(0) ? 0 : 1;
  }

  /**
   * Compute bit length
   * @returns {Number} Bit length.
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
   * @returns {Number} Byte length.
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
   * @param {String} endian - Endianess of output array (defaults to 'be')
   * @param {Number} length - Of output array
   * @returns {Uint8Array}
   */
  toUint8Array(endian = 'be', length: number) {
    // we get and parse the hex string (https://coolaj86.com/articles/convert-js-bigints-to-typedarrays/)
    // this is faster than shift+mod iterations
    let hex = this.value.toString(16);
    if (hex.length % 2 === 1) {
      hex = '0' + hex;
    }

    const rawLength = hex.length / 2;
    const bytes = new Uint8Array(length || rawLength);
    // parse hex
    const offset = length ? length - rawLength : 0;
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
