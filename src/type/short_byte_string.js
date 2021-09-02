import util from '../util';

class ShortByteString {
  constructor(data) {
    if (typeof data === 'undefined') {
      data = new Uint8Array([]);
    }
    if (!util.isUint8Array(data)) {
      throw new Error('data must be in the form of a Uint8Array');
    }
    this.data = data;
    this.length = this.data.byteLength;
  }

  write() {
    return util.concatUint8Array([new Uint8Array([this.length]), this.data]);
  }

  read(input) {
    if (input.length >= 1) {
      const length = input[0];
      if (input.length >= length + 1) {
        this.data = input.subarray(1, 1 + length);
        this.length = length;
        return 1 + length;
      }
    }
    throw new Error('Invalid octet string');
  }
}

export default ShortByteString;
