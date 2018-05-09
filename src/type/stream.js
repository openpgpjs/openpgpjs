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
      try {
        const { done, value } = await reader.read();
        const result = await fn(done, value);
        if (result) controller.enqueue(result);
        else if (!done) await this.pull(controller); // ??? Chrome bug?
        if (done) controller.close();
      } catch(e) {
        controller.error(e);
      }
    }
  });
};

ReadableStream.prototype.readToEnd = async function(join) {
  return this.getReader().readToEnd(join);
};


Uint8Array.prototype.getReader = function() {
  let doneReading = false;
  const reader = Object.create(ReadableStreamDefaultReader.prototype);
  reader._read = async () => {
    if (doneReading) {
      return { value: undefined, done: true };
    }
    doneReading = true;
    return { value: this, done: false };
  };
  return reader;
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

const ReadableStreamDefaultReader = new ReadableStream().getReader().constructor;

ReadableStreamDefaultReader.prototype._read = ReadableStreamDefaultReader.prototype.read;
ReadableStreamDefaultReader.prototype.read = async function() {
  if (this.externalBuffer && this.externalBuffer.length) {
    const value = this.externalBuffer.shift();
    return { done: false, value };
  }
  return this._read();
};

ReadableStreamDefaultReader.prototype.readLine = async function() {
  let buffer = [];
  let returnVal;
  while (!returnVal) {
    const { done, value } = await this.read();
    if (done) {
      if (buffer.length) return util.concatUint8Array(buffer);
      return;
    }
    const lineEndIndex = value.indexOf(10) + 1; // Position after the first "\n"
    if (lineEndIndex) {
      returnVal = util.concatUint8Array(buffer.concat(value.subarray(0, lineEndIndex)));
      buffer = [];
    }
    if (lineEndIndex !== value.length) {
      buffer.push(value.subarray(lineEndIndex));
    }
  }
  this.unshift(...buffer);
  return returnVal;
};

ReadableStreamDefaultReader.prototype.readByte = async function() {
  const { done, value } = await this.read();
  if (done) return;
  const byte = value[0];
  this.unshift(value.subarray(1));
  return byte;
};

ReadableStreamDefaultReader.prototype.readBytes = async function(length) {
  const buffer = [];
  let bufferLength = 0;
  while (true) {
    const { done, value } = await this.read();
    if (done) {
      if (buffer.length) return util.concatUint8Array(buffer);
      return;
    }
    buffer.push(value);
    bufferLength += value.length;
    if (bufferLength >= length) {
      const bufferConcat = util.concatUint8Array(buffer);
      this.unshift(bufferConcat.subarray(length));
      return bufferConcat.subarray(0, length);
    }
  }
};

ReadableStreamDefaultReader.prototype.peekBytes = async function(length) {
  const bytes = await this.readBytes(length);
  this.unshift(bytes);
  return bytes;
};

ReadableStreamDefaultReader.prototype.unshift = function(...values) {
  if (!this.externalBuffer) {
    this.externalBuffer = [];
  }
  this.externalBuffer.unshift(...values.filter(value => value && value.length));
};

ReadableStreamDefaultReader.prototype.substream = function() {
  return new ReadableStream({ pull: pullFrom(this) });
};

function pullFrom(reader) {
  return async controller => {
    const { done, value } = await reader.read();
    if (!done) {
      controller.enqueue(value);
    } else {
      controller.close();
    }
  };
}

ReadableStream.prototype.subarray = function(begin=0, end=Infinity) {
  if (begin >= 0 && end >= 0) {
    const reader = this.getReader();
    let bytesRead = 0;
    return new ReadableStream({
      async pull (controller) {
        const { done, value } = await reader.read();
        if (!done && bytesRead < end) {
          if (bytesRead + value.length >= begin) {
            controller.enqueue(value.subarray(Math.max(begin - bytesRead, 0), end - bytesRead));
          }
          bytesRead += value.length;
          await this.pull(controller); // Only necessary if the above call to enqueue() didn't happen
        } else {
          controller.close();
        }
      }
    });
  }
  return new ReadableStream({
    pull: async controller => {
      // TODO: Don't read entire stream into memory here.
      controller.enqueue((await this.readToEnd()).subarray(begin, end));
      controller.close();
    }
  });
};

ReadableStreamDefaultReader.prototype.readToEnd = async function(join=util.concatUint8Array) {
  const result = [];
  while (true) {
    const { done, value } = await this.read();
    if (done) break;
    result.push(value);
  }
  return join(result);
};
