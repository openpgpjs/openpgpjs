// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @fileoverview RSA implementation
 * @module crypto/public_key/rsa
 * @access private
 */
import { randomProbablePrime } from './prime';
import { getRandomBigInteger } from '../random';
import util from '../../util';
import { uint8ArrayToB64, b64ToUint8Array } from '../../encoding/base64';
import { emsaEncode, emeEncode, emeDecode } from '../pkcs1';
import enums from '../../enums';
import { bigIntToNumber, bigIntToUint8Array, bitLength, byteLength, mod, modExp, modInv, uint8ArrayToBigInt } from '../biginteger';
import { getHashByteLength } from '../hash';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();
const _1n = BigInt(1);

/** Create signature
 * @param {module:enums.hash} hashAlgo - Hash algorithm
 * @param {Uint8Array} data - Message
 * @param {Uint8Array} n - RSA public modulus
 * @param {Uint8Array} e - RSA public exponent
 * @param {Uint8Array} d - RSA private exponent
 * @param {Uint8Array} p - RSA private prime p
 * @param {Uint8Array} q - RSA private prime q
 * @param {Uint8Array} u - RSA private coefficient
 * @param {Uint8Array} hashed - Hashed message
 * @returns {Promise<Uint8Array>} RSA Signature.
 * @async
 */
export async function sign(hashAlgo, data, n, e, d, p, q, u, hashed) {
  if (getHashByteLength(hashAlgo) >= n.length) {
    // Throw here instead of `emsaEncode` below, to provide a clearer and consistent error
    // e.g. if a 512-bit RSA key is used with a SHA-512 digest.
    // The size limit is actually slightly different but here we only care about throwing
    // on common key sizes.
    throw new Error('Digest size cannot exceed key modulus size');
  }

  if (data && !util.isStream(data)) {
    if (util.getWebCrypto()) {
      try {
        return await webSign(enums.read(enums.webHash, hashAlgo), data, n, e, d, p, q, u);
      } catch (err) {
        util.printDebugError(err);
      }
    } else if (util.getNodeCrypto()) {
      return nodeSign(hashAlgo, data, n, e, d, p, q, u);
    }
  }
  return bnSign(hashAlgo, n, d, hashed);
}

/**
 * Verify signature
 * @param {module:enums.hash} hashAlgo - Hash algorithm
 * @param {Uint8Array} data - Message
 * @param {Uint8Array} s - Signature
 * @param {Uint8Array} n - RSA public modulus
 * @param {Uint8Array} e - RSA public exponent
 * @param {Uint8Array} hashed - Hashed message
 * @returns {Promise<Boolean>}
 * @async
 */
export async function verify(hashAlgo, data, s, n, e, hashed) {
  if (data && !util.isStream(data)) {
    if (util.getWebCrypto()) {
      try {
        return await webVerify(enums.read(enums.webHash, hashAlgo), data, s, n, e);
      } catch (err) {
        util.printDebugError(err);
      }
    } else if (util.getNodeCrypto()) {
      return nodeVerify(hashAlgo, data, s, n, e);
    }
  }
  return bnVerify(hashAlgo, s, n, e, hashed);
}

/**
 * Encrypt message
 * @param {Uint8Array} data - Message
 * @param {Uint8Array} n - RSA public modulus
 * @param {Uint8Array} e - RSA public exponent
 * @returns {Promise<Uint8Array>} RSA Ciphertext.
 * @async
 */
// eslint-disable-next-line @typescript-eslint/require-await
export async function encrypt(data, n, e) {
  if (util.getNodeCrypto()) {
    return nodeEncrypt(data, n, e);
  }
  return bnEncrypt(data, n, e);
}

/**
 * Decrypt RSA message
 * @param {Uint8Array} m - Message
 * @param {Uint8Array} n - RSA public modulus
 * @param {Uint8Array} e - RSA public exponent
 * @param {Uint8Array} d - RSA private exponent
 * @param {Uint8Array} p - RSA private prime p
 * @param {Uint8Array} q - RSA private prime q
 * @param {Uint8Array} u - RSA private coefficient
 * @param {Uint8Array} randomPayload - Data to return on decryption error, instead of throwing
 *                                     (needed for constant-time processing)
 * @returns {Promise<String>} RSA Plaintext.
 * @throws {Error} on decryption error, unless `randomPayload` is given
 * @async
 */
// eslint-disable-next-line @typescript-eslint/require-await
export async function decrypt(data, n, e, d, p, q, u, randomPayload) {
  // Node v18.19.1, 20.11.1 and 21.6.2 have disabled support for PKCS#1 decryption,
  // and we want to avoid checking the error type to decide if the random payload
  // should indeed be returned.
  if (util.getNodeCrypto() && !randomPayload) {
    try {
      return nodeDecrypt(data, n, e, d, p, q, u);
    } catch (err) {
      util.printDebugError(err);
    }
  }
  return bnDecrypt(data, n, e, d, p, q, u, randomPayload);
}

/**
 * Generate a new random private key B bits long with public exponent E.
 *
 * When possible, webCrypto or nodeCrypto is used. Otherwise, primes are generated using
 * 40 rounds of the Miller-Rabin probabilistic random prime generation algorithm.
 * @see module:crypto/public_key/prime
 * @param {Integer} bits - RSA bit length
 * @param {Integer} e - RSA public exponent
 * @returns {Promise<{n, e, d,
 *            p, q ,u: Uint8Array}>} RSA public modulus, RSA public exponent, RSA private exponent,
 *                                  RSA private prime p, RSA private prime q, u = p ** -1 mod q
 * @async
 */
export async function generate(bits, e) {
  e = BigInt(e);

  // Native RSA keygen using Web Crypto
  if (util.getWebCrypto()) {
    const keyGenOpt = {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: bits, // the specified keysize in bits
      publicExponent: bigIntToUint8Array(e), // take three bytes (max 65537) for exponent
      hash: {
        name: 'SHA-1' // not required for actual RSA keys, but for crypto api 'sign' and 'verify'
      }
    };
    const keyPair = await webCrypto.generateKey(keyGenOpt, true, ['sign', 'verify']);

    // export the generated keys as JsonWebKey (JWK)
    // https://tools.ietf.org/html/draft-ietf-jose-json-web-key-33
    const jwk = await webCrypto.exportKey('jwk', keyPair.privateKey);
    // map JWK parameters to corresponding OpenPGP names
    return jwkToPrivate(jwk, e);
  } else if (util.getNodeCrypto()) {
    const opts = {
      modulusLength: bits,
      publicExponent: bigIntToNumber(e),
      publicKeyEncoding: { type: 'pkcs1', format: 'jwk' },
      privateKeyEncoding: { type: 'pkcs1', format: 'jwk' }
    };
    const jwk = await new Promise((resolve, reject) => {
      nodeCrypto.generateKeyPair('rsa', opts, (err, _, jwkPrivateKey) => {
        if (err) {
          reject(err);
        } else {
          resolve(jwkPrivateKey);
        }
      });
    });
    return jwkToPrivate(jwk, e);
  }

  // RSA keygen fallback using 40 iterations of the Miller-Rabin test
  // See https://stackoverflow.com/a/6330138 for justification
  // Also see section C.3 here: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST
  let p;
  let q;
  let n;
  do {
    q = randomProbablePrime(bits - (bits >> 1), e, 40);
    p = randomProbablePrime(bits >> 1, e, 40);
    n = p * q;
  } while (bitLength(n) !== bits);

  const phi = (p - _1n) * (q - _1n);

  if (q < p) {
    [p, q] = [q, p];
  }

  return {
    n: bigIntToUint8Array(n),
    e: bigIntToUint8Array(e),
    d: bigIntToUint8Array(modInv(e, phi)),
    p: bigIntToUint8Array(p),
    q: bigIntToUint8Array(q),
    // dp: d.mod(p.subn(1)),
    // dq: d.mod(q.subn(1)),
    u: bigIntToUint8Array(modInv(p, q))
  };
}

/**
 * Validate RSA parameters
 * @param {Uint8Array} n - RSA public modulus
 * @param {Uint8Array} e - RSA public exponent
 * @param {Uint8Array} d - RSA private exponent
 * @param {Uint8Array} p - RSA private prime p
 * @param {Uint8Array} q - RSA private prime q
 * @param {Uint8Array} u - RSA inverse of p w.r.t. q
 * @returns {Promise<Boolean>} Whether params are valid.
 * @async
 */
// eslint-disable-next-line @typescript-eslint/require-await
export async function validateParams(n, e, d, p, q, u) {
  n = uint8ArrayToBigInt(n);
  p = uint8ArrayToBigInt(p);
  q = uint8ArrayToBigInt(q);

  // expect pq = n
  if ((p * q) !== n) {
    return false;
  }

  const _2n = BigInt(2);
  // expect p*u = 1 mod q
  u = uint8ArrayToBigInt(u);
  if (mod(p * u, q) !== BigInt(1)) {
    return false;
  }

  e = uint8ArrayToBigInt(e);
  d = uint8ArrayToBigInt(d);
  /**
   * In RSA pkcs#1 the exponents (d, e) are inverses modulo lcm(p-1, q-1)
   * We check that [de = 1 mod (p-1)] and [de = 1 mod (q-1)]
   * By CRT on coprime factors of (p-1, q-1) it follows that [de = 1 mod lcm(p-1, q-1)]
   *
   * We blind the multiplication with r, and check that rde = r mod lcm(p-1, q-1)
   */
  const nSizeOver3 = BigInt(Math.floor(bitLength(n) / 3));
  const r = getRandomBigInteger(_2n, _2n << nSizeOver3); // r in [ 2, 2^{|n|/3} ) < p and q
  const rde = r * d * e;

  const areInverses = mod(rde, p - _1n) === r && mod(rde, q - _1n) === r;
  if (!areInverses) {
    return false;
  }

  return true;
}

function bnSign(hashAlgo, n, d, hashed) {
  n = uint8ArrayToBigInt(n);
  const m = uint8ArrayToBigInt(emsaEncode(hashAlgo, hashed, byteLength(n)));
  d = uint8ArrayToBigInt(d);
  return bigIntToUint8Array(modExp(m, d, n), 'be', byteLength(n));
}

async function webSign(hashName, data, n, e, d, p, q, u) {
  /** OpenPGP keys require that p < q, and Safari Web Crypto requires that p > q.
   * We swap them in privateToJWK, so it usually works out, but nevertheless,
   * not all OpenPGP keys are compatible with this requirement.
   * OpenPGP.js used to generate RSA keys the wrong way around (p > q), and still
   * does if the underlying Web Crypto does so (though the tested implementations
   * don't do so).
   */
  const jwk = privateToJWK(n, e, d, p, q, u);
  const algo = {
    name: 'RSASSA-PKCS1-v1_5',
    hash: { name: hashName }
  };
  const key = await webCrypto.importKey('jwk', jwk, algo, false, ['sign']);
  return new Uint8Array(await webCrypto.sign('RSASSA-PKCS1-v1_5', key, data));
}

function nodeSign(hashAlgo, data, n, e, d, p, q, u) {
  const sign = nodeCrypto.createSign(enums.read(enums.hash, hashAlgo));
  sign.write(data);
  sign.end();

  const jwk = privateToJWK(n, e, d, p, q, u);
  return new Uint8Array(sign.sign({ key: jwk, format: 'jwk', type: 'pkcs1' }));
}

function bnVerify(hashAlgo, s, n, e, hashed) {
  n = uint8ArrayToBigInt(n);
  s = uint8ArrayToBigInt(s);
  e = uint8ArrayToBigInt(e);
  if (s >= n) {
    throw new Error('Signature size cannot exceed modulus size');
  }
  const EM1 = bigIntToUint8Array(modExp(s, e, n), 'be', byteLength(n));
  const EM2 = emsaEncode(hashAlgo, hashed, byteLength(n));
  return util.equalsUint8Array(EM1, EM2);
}

async function webVerify(hashName, data, s, n, e) {
  const jwk = publicToJWK(n, e);
  const key = await webCrypto.importKey('jwk', jwk, {
    name: 'RSASSA-PKCS1-v1_5',
    hash: { name:  hashName }
  }, false, ['verify']);
  return webCrypto.verify('RSASSA-PKCS1-v1_5', key, s, data);
}

function nodeVerify(hashAlgo, data, s, n, e) {
  const jwk = publicToJWK(n, e);
  const key = { key: jwk, format: 'jwk', type: 'pkcs1' };

  const verify = nodeCrypto.createVerify(enums.read(enums.hash, hashAlgo));
  verify.write(data);
  verify.end();

  try {
    return verify.verify(key, s);
  } catch {
    return false;
  }
}

function nodeEncrypt(data, n, e) {
  const jwk = publicToJWK(n, e);
  const key = { key: jwk, format: 'jwk', type: 'pkcs1', padding: nodeCrypto.constants.RSA_PKCS1_PADDING };

  return new Uint8Array(nodeCrypto.publicEncrypt(key, data));
}

function bnEncrypt(data, n, e) {
  n = uint8ArrayToBigInt(n);
  data = uint8ArrayToBigInt(emeEncode(data, byteLength(n)));
  e = uint8ArrayToBigInt(e);
  if (data >= n) {
    throw new Error('Message size cannot exceed modulus size');
  }
  return bigIntToUint8Array(modExp(data, e, n), 'be', byteLength(n));
}

function nodeDecrypt(data, n, e, d, p, q, u) {
  const jwk = privateToJWK(n, e, d, p, q, u);
  const key = { key: jwk, format: 'jwk' , type: 'pkcs1', padding: nodeCrypto.constants.RSA_PKCS1_PADDING };

  try {
    return new Uint8Array(nodeCrypto.privateDecrypt(key, data));
  } catch {
    throw new Error('Decryption error');
  }
}

function bnDecrypt(data, n, e, d, p, q, u, randomPayload) {
  data = uint8ArrayToBigInt(data);
  n = uint8ArrayToBigInt(n);
  e = uint8ArrayToBigInt(e);
  d = uint8ArrayToBigInt(d);
  p = uint8ArrayToBigInt(p);
  q = uint8ArrayToBigInt(q);
  u = uint8ArrayToBigInt(u);
  if (data >= n) {
    throw new Error('Data too large.');
  }
  const dq = mod(d, q - _1n); // d mod (q-1)
  const dp = mod(d, p - _1n); // d mod (p-1)

  const unblinder = getRandomBigInteger(BigInt(2), n);
  const blinder = modExp(modInv(unblinder, n), e, n);
  data = mod(data * blinder, n);

  const mp = modExp(data, dp, p); // data**{d mod (q-1)} mod p
  const mq = modExp(data, dq, q); // data**{d mod (p-1)} mod q
  const h = mod(u * (mq - mp), q); // u * (mq-mp) mod q (operands already < q)

  let result = h * p + mp; // result < n due to relations above

  result = mod(result * unblinder, n);

  return emeDecode(bigIntToUint8Array(result, 'be', byteLength(n)), randomPayload);
}

/** Convert Openpgp private key params to jwk key according to
 * @link https://tools.ietf.org/html/rfc7517
 * @param {String} hashAlgo
 * @param {Uint8Array} n
 * @param {Uint8Array} e
 * @param {Uint8Array} d
 * @param {Uint8Array} p
 * @param {Uint8Array} q
 * @param {Uint8Array} u
 */
function privateToJWK(n, e, d, p, q, u) {
  const pNum = uint8ArrayToBigInt(p);
  const qNum = uint8ArrayToBigInt(q);
  const dNum = uint8ArrayToBigInt(d);

  let dq = mod(dNum, qNum - _1n); // d mod (q-1)
  let dp = mod(dNum, pNum - _1n); // d mod (p-1)
  dp = bigIntToUint8Array(dp);
  dq = bigIntToUint8Array(dq);
  return {
    kty: 'RSA',
    n: uint8ArrayToB64(n, true),
    e: uint8ArrayToB64(e, true),
    d: uint8ArrayToB64(d, true),
    // switch p and q
    p: uint8ArrayToB64(q, true),
    q: uint8ArrayToB64(p, true),
    // switch dp and dq
    dp: uint8ArrayToB64(dq, true),
    dq: uint8ArrayToB64(dp, true),
    qi: uint8ArrayToB64(u, true),
    ext: true
  };
}

/** Convert Openpgp key public params to jwk key according to
 * @link https://tools.ietf.org/html/rfc7517
 * @param {String} hashAlgo
 * @param {Uint8Array} n
 * @param {Uint8Array} e
 */
function publicToJWK(n, e) {
  return {
    kty: 'RSA',
    n: uint8ArrayToB64(n, true),
    e: uint8ArrayToB64(e, true),
    ext: true
  };
}

/** Convert JWK private key to OpenPGP private key params */
function jwkToPrivate(jwk, e) {
  return {
    n: b64ToUint8Array(jwk.n),
    e: bigIntToUint8Array(e),
    d: b64ToUint8Array(jwk.d),
    // switch p and q
    p: b64ToUint8Array(jwk.q),
    q: b64ToUint8Array(jwk.p),
    // Since p and q are switched in places, u is the inverse of jwk.q
    u: b64ToUint8Array(jwk.qi)
  };
}
