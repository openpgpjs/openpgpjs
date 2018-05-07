import util from '../util';

function concat(arrays) {
  const readers = arrays.map(entry => entry.getReader());
  let current = 0;
  return new ReadableStream({
    async pull(controller) {
      const { done, value } = await readers[current].read();
      if (!done) {
        controller.enqueue(value);
      } else if (++current === arrays.length) {
        controller.close();
      } else {
        await this.pull(controller); // ??? Chrome bug?
      }
    }
  });
}

export default { concat };


/*const readerAcquiredMap = new Map();

const _getReader = ReadableStream.prototype.getReader;
ReadableStream.prototype.getReader = function() {
  if (readerAcquiredMap.has(this)) {
    console.error(readerAcquiredMap.get(this));
  } else {
    readerAcquiredMap.set(this, new Error('Reader for this ReadableStream already acquired here.'));
  }
  return _getReader.apply(this, arguments);
};*/


ReadableStream.prototype.transform = function(fn) {
  const reader = this.getReader();
  return new ReadableStream({
    async pull(controller) {
      const { done, value } = await reader.read();
      const result = fn(done, value);
      if (result) controller.enqueue(result);
      if (done) controller.close();
      if (!done && !result) await this.pull(controller); // ??? Chrome bug?
    }
  });
};

ReadableStream.prototype.readToEnd = async function() {
  const reader = this.getReader();
  const result = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    result.push(value);
  }
  return util.concatUint8Array(result);
};


Uint8Array.prototype.getReader = function() {
  let doneReading = false;
  return {
    read: async () => {
      if (doneReading) {
        return { value: undefined, done: true };
      }
      doneReading = true;
      return { value: this, done: false };
    }
  };
};

Uint8Array.prototype.transform = function(fn) {
  const result1 = fn(false, this);
  const result2 = fn(true, undefined);
  if (result1 && result2) return util.concatUint8Array([result1, result2]);
  return result1 || result2;
};

Uint8Array.prototype.tee = function() {
  return [this, this];
};

Uint8Array.prototype.readToEnd = async function() {
  return this;
};
