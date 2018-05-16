import util from './util';

function concat(arrays) {
  const readers = arrays.map(getReader);
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

function getReader(input) {
  return new Reader(input);
}

function transform(input, process = () => undefined, finish = () => undefined) {
  if (util.isStream(input)) {
    const reader = getReader(input);
    return new ReadableStream({
      async pull(controller) {
        try {
          const { done, value } = await reader.read();
          const result = await (!done ? process : finish)(value);
          if (result !== undefined) controller.enqueue(result);
          else if (!done) await this.pull(controller); // ??? Chrome bug?
          if (done) controller.close();
        } catch(e) {
          controller.error(e);
        }
      }
    });
  }
  const result1 = process(input);
  const result2 = finish(undefined);
  if (result1 !== undefined && result2 !== undefined) return util.concat([result1, result2]);
  return result1 !== undefined ? result1 : result2;
}

function tee(input) {
  if (util.isStream(input)) {
    return input.tee();
  }
  return [input, input];
}

function subarray(input, begin=0, end=Infinity) {
  if (util.isStream(input)) {
    if (begin >= 0 && end >= 0) {
      const reader = getReader(input);
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
        controller.enqueue((await readToEnd(input)).subarray(begin, end));
        controller.close();
      }
    });
  }
  return input.subarray(begin, end);
}

async function readToEnd(input, join) {
  if (util.isStream(input)) {
    return getReader(input).readToEnd(join);
  }
  return input;
}


export default { concat, getReader, transform, tee, subarray, readToEnd };


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


function Reader(input) {
  if (util.isStream(input)) {
    const reader = input.getReader();
    this._read = reader.read.bind(reader);
    return;
  }
  let doneReading = false;
  this._read = async () => {
    if (doneReading) {
      return { value: undefined, done: true };
    }
    doneReading = true;
    return { value: input, done: false };
  };
}

Reader.prototype.read = async function() {
  if (this.externalBuffer && this.externalBuffer.length) {
    const value = this.externalBuffer.shift();
    return { done: false, value };
  }
  return this._read();
};

Reader.prototype.readLine = async function() {
  let buffer = [];
  let returnVal;
  while (!returnVal) {
    const { done, value } = await this.read();
    if (done) {
      if (buffer.length) return util.concat(buffer);
      return;
    }
    const lineEndIndex = value.indexOf('\n') + 1;
    if (lineEndIndex) {
      returnVal = util.concat(buffer.concat(value.substr(0, lineEndIndex)));
      buffer = [];
    }
    if (lineEndIndex !== value.length) {
      buffer.push(value.substr(lineEndIndex));
    }
  }
  this.unshift(...buffer);
  return returnVal;
};

Reader.prototype.readByte = async function() {
  const { done, value } = await this.read();
  if (done) return;
  const byte = value[0];
  this.unshift(value.subarray(1));
  return byte;
};

Reader.prototype.readBytes = async function(length) {
  const buffer = [];
  let bufferLength = 0;
  while (true) {
    const { done, value } = await this.read();
    if (done) {
      if (buffer.length) return util.concat(buffer);
      return;
    }
    buffer.push(value);
    bufferLength += value.length;
    if (bufferLength >= length) {
      const bufferConcat = util.concat(buffer);
      this.unshift(bufferConcat.subarray(length));
      return bufferConcat.subarray(0, length);
    }
  }
};

Reader.prototype.peekBytes = async function(length) {
  const bytes = await this.readBytes(length);
  this.unshift(bytes);
  return bytes;
};

Reader.prototype.unshift = function(...values) {
  if (!this.externalBuffer) {
    this.externalBuffer = [];
  }
  this.externalBuffer.unshift(...values.filter(value => value && value.length));
};

Reader.prototype.substream = function() {
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

Reader.prototype.readToEnd = async function(join=util.concat) {
  const result = [];
  while (true) {
    const { done, value } = await this.read();
    if (done) break;
    result.push(value);
  }
  return join(result);
};
