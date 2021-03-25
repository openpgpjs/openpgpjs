import util from '../util';

class OctetString {
  constructor(data) {
    if (typeof data === 'undefined') {
      data = new Uint8Array([]);
    }
    if (!util.isUint8Array(data)) {
      throw new Error("data must be in the form of a Uint8Array");
    }
    this.data = data;
    this.length = this.data.byteLength;
  }

  write() {
    return util.concatUint8Array([util.writeNumber(this.length, 2), this.data]);
  }

  read(input) {
    if (input.length >= 2) {
      const length = util.readNumber(input.subarray(0,2));
      if (input.length >= length + 2) {
        this.data = input.subarray(2, 2 + length);
        this.length = this.data.length;
        return 2 + length;
      }
    }
    throw new Error("Invalid octet string");
  }
}

export default OctetString;
