import { createCurve } from '@noble/curves/_shortw_utils';
import { sha512 } from '@noble/hashes/sha512';
import { Field } from '@noble/curves/abstract/modular';

// brainpoolP512r1: https://datatracker.ietf.org/doc/html/rfc5639#section-3.7

const Fp = Field(BigInt('0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3'));
const CURVE_A = Fp.create(BigInt('0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca'));
const CURVE_B = BigInt('0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723');

// prettier-ignore
export const brainpoolP512r1 = createCurve({
  a: CURVE_A, // Equation params: a, b
  b: CURVE_B,
  Fp,
  // Curve order (q), total count of valid points in the field
  n: BigInt('0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069'),
  // Base (generator) point (x, y)
  Gx: BigInt('0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822'),
  Gy: BigInt('0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892'),
  h: BigInt(1),
  lowS: false,
} as const, sha512);
