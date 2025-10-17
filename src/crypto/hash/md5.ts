// Copied from https://github.com/paulmillr/noble-hashes/blob/main/test/misc/md5.ts

import { HashMD } from '@noble/hashes/_md';
import { rotl, wrapConstructor } from '@noble/hashes/utils';

// Per-round constants
const K = Array.from({ length: 64 }, (_, i) => Math.floor(2 ** 32 * Math.abs(Math.sin(i + 1))));
// Choice: a ? b : c
const Chi = (a: number, b: number, c: number) => (a & b) ^ (~a & c);
// Initial state (same as sha1, but 4 u32 instead of 5)
const IV = /* @__PURE__ */ new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);
// Temporary buffer, not used to store anything between runs
// Named this way for SHA1 compat
const MD5_W = /* @__PURE__ */ new Uint32Array(16);
class MD5 extends HashMD<MD5> {
  private A = IV[0] | 0;
  private B = IV[1] | 0;
  private C = IV[2] | 0;
  private D = IV[3] | 0;
  constructor() {
    super(64, 16, 8, true);
  }
  protected get(): [number, number, number, number] {
    const { A, B, C, D } = this;
    return [A, B, C, D];
  }
  protected set(A: number, B: number, C: number, D: number) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
  }
  protected process(view: DataView, offset: number): void {
    for (let i = 0; i < 16; i++, offset += 4) MD5_W[i] = view.getUint32(offset, true);
    // Compression function main loop, 64 rounds
    let { A, B, C, D } = this;
    for (let i = 0; i < 64; i++) {
      let F, g, s;
      if (i < 16) {
        F = Chi(B, C, D);
        g = i;
        s = [7, 12, 17, 22];
      } else if (i < 32) {
        F = Chi(D, B, C);
        g = (5 * i + 1) % 16;
        s = [5, 9, 14, 20];
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
        s = [4, 11, 16, 23];
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) % 16;
        s = [6, 10, 15, 21];
      }
      F = F + A + K[i] + MD5_W[g];
      A = D;
      D = C;
      C = B;
      B = B + rotl(F, s[i % 4]);
    }
    // Add the compressed chunk to the current hash value
    A = (A + this.A) | 0;
    B = (B + this.B) | 0;
    C = (C + this.C) | 0;
    D = (D + this.D) | 0;
    this.set(A, B, C, D);
  }
  protected roundClean() {
    MD5_W.fill(0);
  }
  destroy() {
    this.set(0, 0, 0, 0);
    this.buffer.fill(0);
  }
}
export const md5 = /* @__PURE__ */ wrapConstructor(() => new MD5());
