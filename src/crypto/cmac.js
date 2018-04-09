/**
 * @requires asmcrypto.js
 */

import { AES_CMAC } from 'asmcrypto.js/src/aes/cmac/cmac';

export default class CMAC extends AES_CMAC {
  constructor(key) {
    super(key);
    this._k = this.k.slice();
  }

  mac(data) {
    if (this.result) {
      this.bufferLength = 0;
      this.k.set(this._k, 0);
      this.cbc.AES_reset(undefined, new Uint8Array(16), false);
    }
    return this.process(data).finish().result;
  }
}
