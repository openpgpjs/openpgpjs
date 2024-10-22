// Operations are not constant time, but we try and limit timing leakage where we can

const _0n = BigInt(0);
const _1n = BigInt(1);

export function uint8ArrayToBigInt(bytes: Uint8Array) {
  const hexAlphabet = '0123456789ABCDEF';
  let s = '';
  bytes.forEach(v => {
    s += hexAlphabet[v >> 4] + hexAlphabet[v & 15];
  });
  return BigInt('0x0' + s);
}

export function mod(a: bigint, m: bigint) {
  const reduced = a % m;
  return reduced < _0n ? reduced + m : reduced;
}

/**
 * Compute modular exponentiation using square and multiply
 * @param {BigInt} a - Base
 * @param {BigInt} e - Exponent
 * @param {BigInt} n - Modulo
 * @returns {BigInt} b ** e mod n.
 */
export function modExp(b: bigint, e: bigint, n: bigint) {
  if (n === _0n) throw Error('Modulo cannot be zero');
  if (n === _1n) return BigInt(0);
  if (e < _0n) throw Error('Unsopported negative exponent');

  let exp = e;
  let x = b;

  x %= n;
  let r = BigInt(1);
  while (exp > _0n) {
    const lsb = exp & _1n;
    exp >>= _1n; // e / 2
    // Always compute multiplication step, to reduce timing leakage
    const rx = (r * x) % n;
    // Update r only if lsb is 1 (odd exponent)
    r = lsb ? rx : r;
    x = (x * x) % n; // Square
  }
  return r;
}


function abs(x: bigint) {
  return x >= _0n ? x : -x;
}

/**
 * Extended Eucleadian algorithm (http://anh.cs.luc.edu/331/notes/xgcd.pdf)
 * Given a and b, compute (x, y) such that ax + by = gdc(a, b).
 * Negative numbers are also supported.
 * @param {BigInt} a - First operand
 * @param {BigInt} b - Second operand
 * @returns {{ gcd, x, y: bigint }}
 */
function _egcd(aInput: bigint, bInput: bigint) {
  let x = BigInt(0);
  let y = BigInt(1);
  let xPrev = BigInt(1);
  let yPrev = BigInt(0);

  // Deal with negative numbers: run algo over absolute values,
  // and "move" the sign to the returned x and/or y.
  // See https://math.stackexchange.com/questions/37806/extended-euclidean-algorithm-with-negative-numbers
  let a = abs(aInput);
  let b = abs(bInput);
  const aNegated = aInput < _0n;
  const bNegated = bInput < _0n;

  while (b !== _0n) {
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
    x: aNegated ? -xPrev : xPrev,
    y: bNegated ? -yPrev : yPrev,
    gcd: a
  };
}

/**
 * Compute the inverse of `a` modulo `n`
 * Note: `a` and and `n` must be relatively prime
 * @param {BigInt} a
 * @param {BigInt} n - Modulo
 * @returns {BigInt} x such that a*x = 1 mod n
 * @throws {Error} if the inverse does not exist
 */
export function modInv(a: bigint, n: bigint) {
  const { gcd, x } = _egcd(a, n);
  if (gcd !== _1n) {
    throw new Error('Inverse does not exist');
  }
  return mod(x + n, n);
}

/**
 * Compute greatest common divisor between this and n
 * @param {BigInt} aInput - Operand
 * @param {BigInt} bInput - Operand
 * @returns {BigInt} gcd
 */
export function gcd(aInput: bigint, bInput: bigint) {
  let a = aInput;
  let b = bInput;
  while (b !== _0n) {
    const tmp = b;
    b = a % b;
    a = tmp;
  }
  return a;
}

/**
 * Get this value as an exact Number (max 53 bits)
 * Fails if this value is too large
 * @returns {Number}
 */
export function bigIntToNumber(x: bigint) {
  const number = Number(x);
  if (number > Number.MAX_SAFE_INTEGER) {
    // We throw and error to conform with the bn.js implementation
    throw new Error('Number can only safely store up to 53 bits');
  }
  return number;
}

/**
 * Get value of i-th bit
 * @param {BigInt} x
 * @param {Number} i - Bit index
 * @returns {Number} Bit value.
 */
export function getBit(x:bigint, i: number) {
  const bit = (x >> BigInt(i)) & _1n;
  return bit === _0n ? 0 : 1;
}

/**
 * Compute bit length
 */
export function bitLength(x: bigint) {
  // -1n >> -1n is -1n
  // 1n >> 1n is 0n
  const target = x < _0n ? BigInt(-1) : _0n;
  let bitlen = 1;
  let tmp = x;
  // eslint-disable-next-line no-cond-assign
  while ((tmp >>= _1n) !== target) {
    bitlen++;
  }
  return bitlen;
}

/**
 * Compute byte length
 */
export function byteLength(x: bigint) {
  const target = x < _0n ? BigInt(-1) : _0n;
  const _8n = BigInt(8);
  let len = 1;
  let tmp = x;
  // eslint-disable-next-line no-cond-assign
  while ((tmp >>= _8n) !== target) {
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
export function bigIntToUint8Array(x: bigint, endian = 'be', length: number) {
  // we get and parse the hex string (https://coolaj86.com/articles/convert-js-bigints-to-typedarrays/)
  // this is faster than shift+mod iterations
  let hex = x.toString(16);
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
