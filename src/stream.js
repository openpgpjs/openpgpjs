const NodeReadableStream = typeof window === 'undefined' && require('stream').Readable;

const isIE11 = typeof navigator !== 'undefined' && !!navigator.userAgent.match(/Trident\/7\.0.*rv:([0-9.]+).*\).*Gecko$/);

/**
 * Check whether data is a Stream
 * @param {Any} input  data to check
 * @returns {Boolean}
 */
function isStream(input) {
  return ReadableStream.prototype.isPrototypeOf(input);
}

/**
 * Check whether data is a Uint8Array
 * @param {Any} input  data to check
 * @returns {Boolean}
 */
function isUint8Array(input) {
  return Uint8Array.prototype.isPrototypeOf(input);
}

/**
 * Convert data to Stream
 * @param {ReadableStream|Uint8array|String} input  data to convert
 * @returns {ReadableStream} Converted data
 */
function toStream(input) {
  if (isStream(input)) {
    return input;
  }
  return new ReadableStream({
    start(controller) {
      controller.enqueue(input);
      controller.close();
    }
  });
}

/**
 * Concat a list of Uint8Arrays, Strings or Streams
 * The caller should not mix Uint8Arrays with Strings, but may mix Streams with non-Streams.
 * @param {Array<Uint8array|String|ReadableStream>} Array of Uint8Arrays/Strings/Streams to concatenate
 * @returns {Uint8array|String|ReadableStream} Concatenated array
 */
function concat(list) {
  if (list.some(isStream)) {
    return concatStream(list);
  }
  if (typeof list[0] === 'string') {
    return list.join('');
  }
  return concatUint8Array(list);
}

/**
 * Concat Uint8Arrays
 * @param {Array<Uint8array>} Array of Uint8Arrays to concatenate
 * @returns {Uint8array} Concatenated array
 */
function concatUint8Array(arrays) {
  if (arrays.length === 1) return arrays[0];

  let totalLength = 0;
  for (let i = 0; i < arrays.length; i++) {
    if (!isUint8Array(arrays[i])) {
      throw new Error('concatUint8Array: Data must be in the form of a Uint8Array');
    }

    totalLength += arrays[i].length;
  }

  const result = new Uint8Array(totalLength);
  let pos = 0;
  arrays.forEach(function (element) {
    result.set(element, pos);
    pos += element.length;
  });

  return result;
}

/**
 * Concat a list of Streams
 * @param {Array<ReadableStream|Uint8array|String>} list  Array of Uint8Arrays/Strings/Streams to concatenate
 * @returns {ReadableStream} Concatenated list
 */
function concatStream(list) {
  list = list.map(toStream);
  const transform = transformWithCancel(async function(reason) {
    await Promise.all(transforms.map(stream => cancel(stream, reason)));
  });
  let prev = Promise.resolve();
  const transforms = list.map((stream, i) => transformPair(stream, (readable, writable) => {
    prev = prev.then(() => pipe(readable, transform.writable, {
      preventClose: i !== list.length - 1
    }));
    return prev;
  }));
  return transform.readable;
}

/**
 * Get a Reader
 * @param {ReadableStream|Uint8array|String} input
 * @returns {Reader}
 */
function getReader(input) {
  return new Reader(input);
}

/**
 * Get a Writer
 * @param {WritableStream} input
 * @returns {WritableStreamDefaultWriter}
 */
function getWriter(input) {
  return input.getWriter();
}

/**
 * Pipe a readable stream to a writable stream. Don't throw on input stream errors, but forward them to the output stream.
 * @param {ReadableStream|Uint8array|String} input
 * @param {WritableStream} target
 * @param {Object} (optional) options
 * @returns {Promise<undefined>} Promise indicating when piping has finished (input stream closed or errored)
 */
async function pipe(input, target, options) {
  input = toStream(input);
  try {
    if (input[externalBuffer]) {
      const writer = target.getWriter();
      for (let i = 0; i < input[externalBuffer].length; i++) {
        await writer.ready;
        await writer.write(input[externalBuffer][i]);
      }
      writer.releaseLock();
    }
    return await input.pipeTo(target, options);
  } catch(e) {}
}

/**
 * Pipe a readable stream through a transform stream.
 * @param {ReadableStream|Uint8array|String} input
 * @param {Object} (optional) options
 * @returns {ReadableStream} transformed stream
 */
function transformRaw(input, options) {
  const transformStream = new TransformStream(options);
  pipe(input, transformStream.writable);
  return transformStream.readable;
}

/**
 * Create a cancelable TransformStream.
 * @param {Function} cancel
 * @returns {TransformStream}
 */
function transformWithCancel(cancel) {
  let pulled = false;
  let backpressureChangePromiseResolve;
  let outputController;
  return {
    readable: new ReadableStream({
      start(controller) {
        outputController = controller;
      },
      pull() {
        if (backpressureChangePromiseResolve) {
          backpressureChangePromiseResolve();
        } else {
          pulled = true;
        }
      },
      cancel
    }, {highWaterMark: 0}),
    writable: new WritableStream({
      write: async function(chunk) {
        outputController.enqueue(chunk);
        if (!pulled) {
          await new Promise(resolve => {
            backpressureChangePromiseResolve = resolve;
          });
          backpressureChangePromiseResolve = null;
        } else {
          pulled = false;
        }
      },
      close: outputController.close.bind(outputController),
      abort: outputController.error.bind(outputController)
    })
  };
}

/**
 * Transform a stream using helper functions which are called on each chunk, and on stream close, respectively.
 * @param {ReadableStream|Uint8array|String} input
 * @param {Function} process
 * @param {Function} finish
 * @returns {ReadableStream|Uint8array|String}
 */
function transform(input, process = () => undefined, finish = () => undefined) {
  if (isStream(input)) {
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
  if (result1 !== undefined && result2 !== undefined) return concat([result1, result2]);
  return result1 !== undefined ? result1 : result2;
}

/**
 * Transform a stream using a helper function which is passed a readable and a writable stream.
 *   This function also maintains the possibility to cancel the input stream,
 *   and does so on cancelation of the output stream, despite cancelation
 *   normally being impossible when the input stream is being read from.
 * @param {ReadableStream|Uint8array|String} input
 * @param {Function} fn
 * @returns {ReadableStream}
 */
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

/**
 * Parse a stream using a helper function which is passed a Reader.
 *   The reader additionally has a remainder() method which returns a
 *   stream pointing to the remainder of input, and is linked to input
 *   for cancelation.
 * @param {ReadableStream|Uint8array|String} input
 * @param {Function} fn
 * @returns {Any} the return value of fn()
 */
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

/**
 * Tee a Stream for reading it twice. The input stream can no longer be read after tee()ing.
 *   Reading either of the two returned streams will pull from the input stream.
 *   The input stream will only be canceled if both of the returned streams are canceled.
 * @param {ReadableStream|Uint8array|String} input
 * @returns {Array<ReadableStream|Uint8array|String>} array containing two copies of input
 */
function tee(input) {
  if (isStream(input)) {
    const teed = input.tee();
    teed[0][externalBuffer] = teed[1][externalBuffer] = input[externalBuffer];
    return teed;
  }
  return [slice(input), slice(input)];
}

/**
 * Clone a Stream for reading it twice. The input stream can still be read after clone()ing.
 *   Reading from the clone will pull from the input stream.
 *   The input stream will only be canceled if both the clone and the input stream are canceled.
 * @param {ReadableStream|Uint8array|String} input
 * @returns {ReadableStream|Uint8array|String} cloned input
 */
function clone(input) {
  if (isStream(input)) {
    const teed = tee(input);
    overwrite(input, teed[0]);
    return teed[1];
  }
  return slice(input);
}

/**
 * Clone a Stream for reading it twice. Data will arrive at the same rate as the input stream is being read.
 *   Reading from the clone will NOT pull from the input stream. Data only arrives when reading the input stream.
 *   The input stream will NOT be canceled if the clone is canceled, only if the input stream are canceled.
 *   If the input stream is canceled, the clone will be errored.
 * @param {ReadableStream|Uint8array|String} input
 * @returns {ReadableStream|Uint8array|String} cloned input
 */
function passiveClone(input) {
  if (isStream(input)) {
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

/**
 * Modify a stream object to point to a different stream object.
 *   This is used internally by clone() and passiveClone() to provide an abstraction over tee().
 * @param {ReadableStream} input
 * @param {ReadableStream} clone
 */
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

/**
 * Return a stream pointing to a part of the input stream.
 * @param {ReadableStream|Uint8array|String} input
 * @returns {ReadableStream|Uint8array|String} clone
 */
function slice(input, begin=0, end=Infinity) {
  if (isStream(input)) {
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
      }, () => slice(concat(lastBytes), begin, end));
    }
    if (begin === 0 && end < 0) {
      let lastBytes;
      return transform(input, value => {
        const returnValue = lastBytes ? concat([lastBytes, value]) : value;
        if (returnValue.length >= -end) {
          lastBytes = slice(returnValue, end);
          return slice(returnValue, begin, end);
        } else {
          lastBytes = returnValue;
        }
      });
    }
    console.warn(`stream.slice(input, ${begin}, ${end}) not implemented efficiently.`);
    return fromAsync(async () => slice(await readToEnd(input), begin, end));
  }
  if (input[externalBuffer]) {
    input = concat(input[externalBuffer].concat([input]));
  }
  if (isUint8Array(input) && !isIE11) { // IE11 subarray is buggy
    return input.subarray(begin, end);
  }
  return input.slice(begin, end);
}

/**
 * Read a stream to the end and return its contents, concatenated by the concat function (defaults to concat).
 * @param {ReadableStream|Uint8array|String} input
 * @param {Function} concat
 * @returns {Uint8array|String|Any} the return value of concat()
 */
async function readToEnd(input, concat) {
  if (isStream(input)) {
    return getReader(input).readToEnd(concat);
  }
  return input;
}

/**
 * Cancel a stream.
 * @param {ReadableStream|Uint8array|String} input
 * @param {Any} reason
 * @returns {Promise<Any>} indicates when the stream has been canceled
 */
async function cancel(input, reason) {
  if (isStream(input)) {
    return input.cancel(reason);
  }
}

/**
 * Convert an async function to a Stream. When the function returns, its return value is enqueued to the stream.
 * @param {Function} fn
 * @returns {ReadableStream}
 */
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

if (NodeReadableStream) {

  /**
   * Convert a Node Readable Stream to a Web ReadableStream
   * @param {Readable} nodeStream
   * @returns {ReadableStream}
   */
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


  class NodeReadable extends NodeReadableStream {
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

  /**
   * Convert a Web ReadableStream to a Node Readable Stream
   * @param {ReadableStream} webStream
   * @returns {Readable}
   */
  webToNode = function(webStream) {
    return new NodeReadable(webStream);
  };

}


export default { isStream, isUint8Array, toStream, concatUint8Array, concatStream, concat, getReader, getWriter, pipe, transformRaw, transform, transformPair, parse, clone, passiveClone, slice, readToEnd, cancel, nodeToWeb, webToNode, fromAsync };


const doneReadingSet = new WeakSet();
const externalBuffer = Symbol('externalBuffer');
function Reader(input) {
  this.stream = input;
  if (input[externalBuffer]) {
    this[externalBuffer] = input[externalBuffer].slice();
  }
  if (isStream(input)) {
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

/**
 * Read a chunk of data.
 * @returns {Object} Either { done: false, value: Uint8Array | String } or { done: true, value: undefined }
 */
Reader.prototype.read = async function() {
  if (this[externalBuffer] && this[externalBuffer].length) {
    const value = this[externalBuffer].shift();
    return { done: false, value };
  }
  return this._read();
};

/**
 * Allow others to read the stream.
 */
Reader.prototype.releaseLock = function() {
  if (this[externalBuffer]) {
    this.stream[externalBuffer] = this[externalBuffer];
  }
  this._releaseLock();
};

/**
 * Read up to and including the first \n character.
 * @returns {String|Undefined}
 */
Reader.prototype.readLine = async function() {
  let buffer = [];
  let returnVal;
  while (!returnVal) {
    const { done, value } = await this.read();
    if (done) {
      if (buffer.length) return concat(buffer);
      return;
    }
    const lineEndIndex = value.indexOf('\n') + 1;
    if (lineEndIndex) {
      returnVal = concat(buffer.concat(value.substr(0, lineEndIndex)));
      buffer = [];
    }
    if (lineEndIndex !== value.length) {
      buffer.push(value.substr(lineEndIndex));
    }
  }
  this.unshift(...buffer);
  return returnVal;
};

/**
 * Read a single byte/character.
 * @returns {Number|String|Undefined}
 */
Reader.prototype.readByte = async function() {
  const { done, value } = await this.read();
  if (done) return;
  const byte = value[0];
  this.unshift(slice(value, 1));
  return byte;
};

/**
 * Read a specific amount of bytes/characters, unless the stream ends before that amount.
 * @returns {Uint8Array|String|Undefined}
 */
Reader.prototype.readBytes = async function(length) {
  const buffer = [];
  let bufferLength = 0;
  while (true) {
    const { done, value } = await this.read();
    if (done) {
      if (buffer.length) return concat(buffer);
      return;
    }
    buffer.push(value);
    bufferLength += value.length;
    if (bufferLength >= length) {
      const bufferConcat = concat(buffer);
      this.unshift(slice(bufferConcat, length));
      return slice(bufferConcat, 0, length);
    }
  }
};

/**
 * Peek (look ahead) a specific amount of bytes/characters, unless the stream ends before that amount.
 * @returns {Uint8Array|String|Undefined}
 */
Reader.prototype.peekBytes = async function(length) {
  const bytes = await this.readBytes(length);
  this.unshift(bytes);
  return bytes;
};

/**
 * Push data to the front of the stream.
 * @param {Uint8Array|String|Undefined} ...values
 */
Reader.prototype.unshift = function(...values) {
  if (!this[externalBuffer]) {
    this[externalBuffer] = [];
  }
  this[externalBuffer].unshift(...values.filter(value => value && value.length));
};

/**
 * Read the stream to the end and return its contents, concatenated by the join function (defaults to concat).
 * @param {Function} join
 * @returns {Uint8array|String|Any} the return value of join()
 */
Reader.prototype.readToEnd = async function(join=concat) {
  const result = [];
  while (true) {
    const { done, value } = await this.read();
    if (done) break;
    result.push(value);
  }
  return join(result);
};
