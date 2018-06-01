import util from './util';

if (typeof ReadableStream === 'undefined') {
  Object.assign(typeof window !== 'undefined' ? window : global, require('web-streams-polyfill'));
}

const nodeStream = util.getNodeStream();

function concat(arrays) {
  const readers = arrays.map(getReader);
  let current = 0;
  return new ReadableStream({
    async pull(controller) {
      try {
        const { done, value } = await readers[current].read();
        if (!done) {
          controller.enqueue(value);
        } else if (++current === arrays.length) {
          controller.close();
        } else {
          await this.pull(controller); // ??? Chrome bug?
        }
      } catch(e) {
        controller.error(e);
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
    const teed = input.tee();
    teed[0].externalBuffer = teed[1].externalBuffer = input.externalBuffer;
    return teed;
  }
  return [slice(input), slice(input)];
}

function clone(input) {
  if (util.isStream(input)) {
    const teed = tee(input);
    // Overwrite input.getReader, input.locked, etc to point to teed[0]
    Object.entries(Object.getOwnPropertyDescriptors(ReadableStream.prototype)).forEach(([name, descriptor]) => {
      if (name === 'constructor') return;
      if (descriptor.value) {
        descriptor.value = descriptor.value.bind(teed[0]);
      } else {
        descriptor.get = descriptor.get.bind(teed[0]);
      }
      Object.defineProperty(input, name, descriptor);
    });
    return teed[1];
  }
  return slice(input);
}

function slice(input, begin=0, end=Infinity) {
  if (util.isStream(input)) {
    if (begin >= 0 && end >= 0) {
      const reader = getReader(input);
      let bytesRead = 0;
      return new ReadableStream({
        async pull (controller) {
          const { done, value } = await reader.read();
          if (!done && bytesRead < end) {
            if (bytesRead + value.length >= begin) {
              controller.enqueue(slice(value, Math.max(begin - bytesRead, 0), end - bytesRead));
            }
            bytesRead += value.length;
            await this.pull(controller); // Only necessary if the above call to enqueue() didn't happen
          } else {
            controller.close();
          }
        }
      });
    }
    if (begin < 0 && (end < 0 || end === Infinity)) {
      let lastBytes = [];
      return transform(input, value => {
        if (value.length >= -begin) lastBytes = [value];
        else lastBytes.push(value);
      }, () => slice(util.concat(lastBytes), begin, end));
    }
    if (begin === 0 && end < 0) {
      let lastBytes;
      return transform(input, value => {
        const returnValue = lastBytes ? util.concat([lastBytes, value]) : value;
        if (returnValue.length >= -end) {
          lastBytes = slice(returnValue, end);
          return slice(returnValue, begin, end);
        } else {
          lastBytes = returnValue;
        }
      });
    }
    // TODO: Don't read entire stream into memory here.
    util.print_debug_error(`stream.slice(input, ${begin}, ${end}) not implemented efficiently.`);
    return fromAsync(async () => slice(await readToEnd(input), begin, end));
  }
  if (input.externalBuffer) {
    input = util.concat(input.externalBuffer.concat([input]));
  }
  if (util.isUint8Array(input)) {
    return input.subarray(begin, end);
  }
  return input.slice(begin, end);
}

async function readToEnd(input, join) {
  if (util.isStream(input)) {
    return getReader(input).readToEnd(join);
  }
  return input;
}

async function cancel(input) {
  if (util.isStream(input)) {
    return input.cancel();
  }
}

function fromAsync(fn) {
  return new ReadableStream({
    pull: async controller => {
      try {
        controller.enqueue(await fn());
        controller.close();
      } catch(e) {
        controller.error(e);
      }
    }
  });
}


/**
 * Web / node stream conversion functions
 * From https://github.com/gwicke/node-web-streams
 */

let nodeToWeb;
let webToNode;

if (nodeStream) {

  nodeToWeb = function(nodeStream) {
    return new ReadableStream({
      start(controller) {
        nodeStream.pause();
        nodeStream.on('data', chunk => {
          controller.enqueue(chunk);
          nodeStream.pause();
        });
        nodeStream.on('end', () => controller.close());
        nodeStream.on('error', e => controller.error(e));
      },
      pull() {
        nodeStream.resume();
      },
      cancel() {
        nodeStream.pause();
      }
    });
  };


  class NodeReadable extends nodeStream.Readable {
    constructor(webStream, options) {
      super(options);
      this._webStream = webStream;
      this._reader = getReader(webStream);
      this._reading = false;
    }

    _read(size) {
      if (this._reading) {
        return;
      }
      this._reading = true;
      const doRead = () => {
        this._reader.read()
          .then(res => {
            if (res.done) {
              this.push(null);
              return;
            }
            if (this.push(res.value)) {
              return doRead(size);
            } else {
              this._reading = false;
            }
          });
      };
      doRead();
    }
  }

  webToNode = function(webStream) {
    return new NodeReadable(webStream);
  };

}


export default { concat, getReader, transform, clone, slice, readToEnd, cancel, nodeToWeb, webToNode, fromAsync };


/*const readerAcquiredMap = new Map();

const _getReader = ReadableStream.prototype.getReader;
ReadableStream.prototype.getReader = function() {
  if (readerAcquiredMap.has(this)) {
    console.error(readerAcquiredMap.get(this));
  } else {
    readerAcquiredMap.set(this, new Error('Reader for this ReadableStream already acquired here.'));
  }
  const _this = this;
  const reader = _getReader.apply(this, arguments);
  const _releaseLock = reader.releaseLock;
  reader.releaseLock = function() {
    readerAcquiredMap.delete(_this);
    return _releaseLock.apply(this, arguments);
  };
  return reader;
};

const _tee = ReadableStream.prototype.tee;
ReadableStream.prototype.tee = function() {
  if (readerAcquiredMap.has(this)) {
    console.error(readerAcquiredMap.get(this));
  } else {
    readerAcquiredMap.set(this, new Error('Reader for this ReadableStream already acquired here.'));
  }
  return _tee.apply(this, arguments);
};*/


const doneReadingSet = new WeakSet();
function Reader(input) {
  this.stream = input;
  if (input.externalBuffer) {
    this.externalBuffer = input.externalBuffer.slice();
  }
  if (util.isStream(input)) {
    const reader = input.getReader();
    this._read = reader.read.bind(reader);
    this._releaseLock = reader.releaseLock.bind(reader);
    return;
  }
  let doneReading = false;
  this._read = async () => {
    if (doneReading || doneReadingSet.has(input)) {
      return { value: undefined, done: true };
    }
    doneReading = true;
    return { value: input, done: false };
  };
  this._releaseLock = () => {
    if (doneReading) {
      doneReadingSet.add(input);
    }
  };
}

Reader.prototype.read = async function() {
  if (this.externalBuffer && this.externalBuffer.length) {
    const value = this.externalBuffer.shift();
    return { done: false, value };
  }
  return this._read();
};

Reader.prototype.releaseLock = function() {
  this.stream.externalBuffer = this.externalBuffer;
  this._releaseLock();
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
  this.unshift(slice(value, 1));
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
      this.unshift(slice(bufferConcat, length));
      return slice(bufferConcat, 0, length);
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
