import util from './util';

const nodeStream = util.getNodeStream();

function toStream(input) {
  if (util.isStream(input)) {
    return input;
  }
  return new ReadableStream({
    start(controller) {
      controller.enqueue(input);
      controller.close();
    }
  });
}

function concat(arrays) {
  arrays = arrays.map(toStream);
  const transform = transformWithCancel(async function(reason) {
    await Promise.all(transforms.map(array => cancel(array, reason)));
  });
  let prev = Promise.resolve();
  const transforms = arrays.map((array, i) => transformPair(array, (readable, writable) => {
    prev = prev.then(() => pipe(readable, transform.writable, {
      preventClose: i !== arrays.length - 1
    }));
    return prev;
  }));
  return transform.readable;
}

function getReader(input) {
  return new Reader(input);
}

function getWriter(input) {
  return input.getWriter();
}

async function pipe(input, target, options) {
  if (!util.isStream(input)) {
    input = toStream(input);
  }
  try {
    if (input.externalBuffer) {
      const writer = target.getWriter();
      for (let i = 0; i < input.externalBuffer.length; i++) {
        await writer.ready;
        await writer.write(input.externalBuffer[i]);
      }
      writer.releaseLock();
    }
    return await input.pipeTo(target, options).catch(function() {});
  } catch(e) {
    util.print_debug_error(e);
  }
}

function transformRaw(input, options) {
  const transformStream = new TransformStream(options);
  pipe(input, transformStream.writable);
  return transformStream.readable;
}

function transformWithCancel(cancel) {
  let backpressureChangePromiseResolve = function() {};
  let outputController;
  return {
    readable: new ReadableStream({
      start(controller) {
        outputController = controller;
      },
      pull() {
        backpressureChangePromiseResolve();
      },
      cancel
    }),
    writable: new WritableStream({
      write: async function(chunk) {
        outputController.enqueue(chunk);
        if (outputController.desiredSize <= 0) {
          await new Promise(resolve => {
            backpressureChangePromiseResolve = resolve;
          });
        }
      },
      close: outputController.close.bind(outputController),
      abort: outputController.error.bind(outputController)
    })
  };
}

function transform(input, process = () => undefined, finish = () => undefined) {
  if (util.isStream(input)) {
    return transformRaw(input, {
      async transform(value, controller) {
        try {
          const result = await process(value);
          if (result !== undefined) controller.enqueue(result);
        } catch(e) {
          controller.error(e);
        }
      },
      async flush(controller) {
        try {
          const result = await finish();
          if (result !== undefined) controller.enqueue(result);
        } catch(e) {
          controller.error(e);
        }
      }
    });
  }
  const result1 = process(input);
  const result2 = finish();
  if (result1 !== undefined && result2 !== undefined) return util.concat([result1, result2]);
  return result1 !== undefined ? result1 : result2;
}

function transformPair(input, fn) {
  let incomingTransformController;
  const incoming = new TransformStream({
    start(controller) {
      incomingTransformController = controller;
    }
  });

  const pipeDonePromise = pipe(input, incoming.writable);

  const outgoing = transformWithCancel(async function() {
    incomingTransformController.error(new Error('Readable side was canceled.'));
    await pipeDonePromise;
    await new Promise(setTimeout);
  });
  fn(incoming.readable, outgoing.writable);
  return outgoing.readable;
}

function parse(input, fn) {
  let returnValue;
  const transformed = transformPair(input, (readable, writable) => {
    const reader = getReader(readable);
    reader.remainder = () => {
      reader.releaseLock();
      pipe(readable, writable);
      return transformed;
    };
    returnValue = fn(reader);
  });
  return returnValue;
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
    overwrite(input, teed[0]);
    return teed[1];
  }
  return slice(input);
}

function passiveClone(input) {
  if (util.isStream(input)) {
    return new ReadableStream({
      start(controller) {
        const transformed = transformPair(input, async (readable, writable) => {
          const reader = getReader(readable);
          const writer = getWriter(writable);
          try {
            while (true) {
              await writer.ready;
              const { done, value } = await reader.read();
              if (done) {
                try { controller.close(); } catch(e) {}
                await writer.close();
                return;
              }
              try { controller.enqueue(value); } catch(e) {}
              await writer.write(value);
            }
          } catch(e) {
            controller.error(e);
            await writer.abort(e);
          }
        });
        overwrite(input, transformed);
      }
    });
  }
  return slice(input);
}

function overwrite(input, clone) {
  // Overwrite input.getReader, input.locked, etc to point to clone
  Object.entries(Object.getOwnPropertyDescriptors(ReadableStream.prototype)).forEach(([name, descriptor]) => {
    if (name === 'constructor') {
      return;
    }
    if (descriptor.value) {
      descriptor.value = descriptor.value.bind(clone);
    } else {
      descriptor.get = descriptor.get.bind(clone);
    }
    Object.defineProperty(input, name, descriptor);
  });
}

function slice(input, begin=0, end=Infinity) {
  if (util.isStream(input)) {
    if (begin >= 0 && end >= 0) {
      let bytesRead = 0;
      return transformRaw(input, {
        transform(value, controller) {
          if (bytesRead < end) {
            if (bytesRead + value.length >= begin) {
              controller.enqueue(slice(value, Math.max(begin - bytesRead, 0), end - bytesRead));
            }
            bytesRead += value.length;
          } else {
            controller.terminate();
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

async function cancel(input, reason) {
  if (util.isStream(input)) {
    return input.cancel(reason);
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


export default { toStream, concat, getReader, getWriter, pipe, transformRaw, transform, transformPair, parse, clone, passiveClone, slice, readToEnd, cancel, nodeToWeb, webToNode, fromAsync };


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
      try {
        doneReadingSet.add(input);
      } catch(e) {}
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
  if (this.externalBuffer) {
    this.stream.externalBuffer = this.externalBuffer;
  }
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

Reader.prototype.readToEnd = async function(join=util.concat) {
  const result = [];
  while (true) {
    const { done, value } = await this.read();
    if (done) break;
    result.push(value);
  }
  return join(result);
};
