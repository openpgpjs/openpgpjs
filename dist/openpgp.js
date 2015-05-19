!function(e){"object"==typeof exports?module.exports=e():"function"==typeof define&&define.amd?define(e):"undefined"!=typeof window?window.openpgp=e():"undefined"!=typeof global?global.openpgp=e():"undefined"!=typeof self&&(self.openpgp=e())}(function(){var define,module,exports;return (function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);throw new Error("Cannot find module '"+o+"'")}var f=n[o]={exports:{}};t[o][0].call(f.exports,function(e){var n=t[o][1][e];return s(n?n:e)},f,f.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){


//
// The shims in this file are not fully implemented shims for the ES5
// features, but do work for the particular usecases there is in
// the other modules.
//

var toString = Object.prototype.toString;
var hasOwnProperty = Object.prototype.hasOwnProperty;

// Array.isArray is supported in IE9
function isArray(xs) {
  return toString.call(xs) === '[object Array]';
}
exports.isArray = typeof Array.isArray === 'function' ? Array.isArray : isArray;

// Array.prototype.indexOf is supported in IE9
exports.indexOf = function indexOf(xs, x) {
  if (xs.indexOf) return xs.indexOf(x);
  for (var i = 0; i < xs.length; i++) {
    if (x === xs[i]) return i;
  }
  return -1;
};

// Array.prototype.filter is supported in IE9
exports.filter = function filter(xs, fn) {
  if (xs.filter) return xs.filter(fn);
  var res = [];
  for (var i = 0; i < xs.length; i++) {
    if (fn(xs[i], i, xs)) res.push(xs[i]);
  }
  return res;
};

// Array.prototype.forEach is supported in IE9
exports.forEach = function forEach(xs, fn, self) {
  if (xs.forEach) return xs.forEach(fn, self);
  for (var i = 0; i < xs.length; i++) {
    fn.call(self, xs[i], i, xs);
  }
};

// Array.prototype.map is supported in IE9
exports.map = function map(xs, fn) {
  if (xs.map) return xs.map(fn);
  var out = new Array(xs.length);
  for (var i = 0; i < xs.length; i++) {
    out[i] = fn(xs[i], i, xs);
  }
  return out;
};

// Array.prototype.reduce is supported in IE9
exports.reduce = function reduce(array, callback, opt_initialValue) {
  if (array.reduce) return array.reduce(callback, opt_initialValue);
  var value, isValueSet = false;

  if (2 < arguments.length) {
    value = opt_initialValue;
    isValueSet = true;
  }
  for (var i = 0, l = array.length; l > i; ++i) {
    if (array.hasOwnProperty(i)) {
      if (isValueSet) {
        value = callback(value, array[i], i, array);
      }
      else {
        value = array[i];
        isValueSet = true;
      }
    }
  }

  return value;
};

// String.prototype.substr - negative index don't work in IE8
if ('ab'.substr(-1) !== 'b') {
  exports.substr = function (str, start, length) {
    // did we get a negative start, calculate how much it is from the beginning of the string
    if (start < 0) start = str.length + start;

    // call the original function
    return str.substr(start, length);
  };
} else {
  exports.substr = function (str, start, length) {
    return str.substr(start, length);
  };
}

// String.prototype.trim is supported in IE9
exports.trim = function (str) {
  if (str.trim) return str.trim();
  return str.replace(/^\s+|\s+$/g, '');
};

// Function.prototype.bind is supported in IE9
exports.bind = function () {
  var args = Array.prototype.slice.call(arguments);
  var fn = args.shift();
  if (fn.bind) return fn.bind.apply(fn, args);
  var self = args.shift();
  return function () {
    fn.apply(self, args.concat([Array.prototype.slice.call(arguments)]));
  };
};

// Object.create is supported in IE9
function create(prototype, properties) {
  var object;
  if (prototype === null) {
    object = { '__proto__' : null };
  }
  else {
    if (typeof prototype !== 'object') {
      throw new TypeError(
        'typeof prototype[' + (typeof prototype) + '] != \'object\''
      );
    }
    var Type = function () {};
    Type.prototype = prototype;
    object = new Type();
    object.__proto__ = prototype;
  }
  if (typeof properties !== 'undefined' && Object.defineProperties) {
    Object.defineProperties(object, properties);
  }
  return object;
}
exports.create = typeof Object.create === 'function' ? Object.create : create;

// Object.keys and Object.getOwnPropertyNames is supported in IE9 however
// they do show a description and number property on Error objects
function notObject(object) {
  return ((typeof object != "object" && typeof object != "function") || object === null);
}

function keysShim(object) {
  if (notObject(object)) {
    throw new TypeError("Object.keys called on a non-object");
  }

  var result = [];
  for (var name in object) {
    if (hasOwnProperty.call(object, name)) {
      result.push(name);
    }
  }
  return result;
}

// getOwnPropertyNames is almost the same as Object.keys one key feature
//  is that it returns hidden properties, since that can't be implemented,
//  this feature gets reduced so it just shows the length property on arrays
function propertyShim(object) {
  if (notObject(object)) {
    throw new TypeError("Object.getOwnPropertyNames called on a non-object");
  }

  var result = keysShim(object);
  if (exports.isArray(object) && exports.indexOf(object, 'length') === -1) {
    result.push('length');
  }
  return result;
}

var keys = typeof Object.keys === 'function' ? Object.keys : keysShim;
var getOwnPropertyNames = typeof Object.getOwnPropertyNames === 'function' ?
  Object.getOwnPropertyNames : propertyShim;

if (new Error().hasOwnProperty('description')) {
  var ERROR_PROPERTY_FILTER = function (obj, array) {
    if (toString.call(obj) === '[object Error]') {
      array = exports.filter(array, function (name) {
        return name !== 'description' && name !== 'number' && name !== 'message';
      });
    }
    return array;
  };

  exports.keys = function (object) {
    return ERROR_PROPERTY_FILTER(object, keys(object));
  };
  exports.getOwnPropertyNames = function (object) {
    return ERROR_PROPERTY_FILTER(object, getOwnPropertyNames(object));
  };
} else {
  exports.keys = keys;
  exports.getOwnPropertyNames = getOwnPropertyNames;
}

// Object.getOwnPropertyDescriptor - supported in IE8 but only on dom elements
function valueObject(value, key) {
  return { value: value[key] };
}

if (typeof Object.getOwnPropertyDescriptor === 'function') {
  try {
    Object.getOwnPropertyDescriptor({'a': 1}, 'a');
    exports.getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  } catch (e) {
    // IE8 dom element issue - use a try catch and default to valueObject
    exports.getOwnPropertyDescriptor = function (value, key) {
      try {
        return Object.getOwnPropertyDescriptor(value, key);
      } catch (e) {
        return valueObject(value, key);
      }
    };
  }
} else {
  exports.getOwnPropertyDescriptor = valueObject;
}

},{}],2:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// a duplex stream is just a stream that is both readable and writable.
// Since JS doesn't have multiple prototypal inheritance, this class
// prototypally inherits from Readable, and then parasitically from
// Writable.

module.exports = Duplex;
var util = require('util');
var shims = require('_shims');
var timers = require('timers');
var Readable = require('_stream_readable');
var Writable = require('_stream_writable');

util.inherits(Duplex, Readable);

shims.forEach(shims.keys(Writable.prototype), function(method) {
  if (!Duplex.prototype[method])
    Duplex.prototype[method] = Writable.prototype[method];
});

function Duplex(options) {
  if (!(this instanceof Duplex))
    return new Duplex(options);

  Readable.call(this, options);
  Writable.call(this, options);

  if (options && options.readable === false)
    this.readable = false;

  if (options && options.writable === false)
    this.writable = false;

  this.allowHalfOpen = true;
  if (options && options.allowHalfOpen === false)
    this.allowHalfOpen = false;

  this.once('end', onend);
}

// the no-half-open enforcer
function onend() {
  // if we allow half-open state, or if the writable side ended,
  // then we're ok.
  if (this.allowHalfOpen || this._writableState.ended)
    return;

  // no more data can be written.
  // But allow more writes to happen in this tick.
  timers.setImmediate(shims.bind(this.end, this));
}

},{"_shims":1,"_stream_readable":4,"_stream_writable":6,"timers":11,"util":12}],3:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// a passthrough stream.
// basically just the most minimal sort of Transform stream.
// Every written chunk gets output as-is.

module.exports = PassThrough;

var Transform = require('_stream_transform');
var util = require('util');
util.inherits(PassThrough, Transform);

function PassThrough(options) {
  if (!(this instanceof PassThrough))
    return new PassThrough(options);

  Transform.call(this, options);
}

PassThrough.prototype._transform = function(chunk, encoding, cb) {
  cb(null, chunk);
};

},{"_stream_transform":5,"util":12}],4:[function(require,module,exports){
var process=require("__browserify_process");// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

module.exports = Readable;
Readable.ReadableState = ReadableState;

var EE = require('events').EventEmitter;
var Stream = require('stream');
var shims = require('_shims');
var Buffer = require('buffer').Buffer;
var timers = require('timers');
var util = require('util');
var StringDecoder;

util.inherits(Readable, Stream);

function ReadableState(options, stream) {
  options = options || {};

  // the point at which it stops calling _read() to fill the buffer
  // Note: 0 is a valid value, means "don't call _read preemptively ever"
  var hwm = options.highWaterMark;
  this.highWaterMark = (hwm || hwm === 0) ? hwm : 16 * 1024;

  // cast to ints.
  this.highWaterMark = ~~this.highWaterMark;

  this.buffer = [];
  this.length = 0;
  this.pipes = null;
  this.pipesCount = 0;
  this.flowing = false;
  this.ended = false;
  this.endEmitted = false;
  this.reading = false;

  // In streams that never have any data, and do push(null) right away,
  // the consumer can miss the 'end' event if they do some I/O before
  // consuming the stream.  So, we don't emit('end') until some reading
  // happens.
  this.calledRead = false;

  // a flag to be able to tell if the onwrite cb is called immediately,
  // or on a later tick.  We set this to true at first, becuase any
  // actions that shouldn't happen until "later" should generally also
  // not happen before the first write call.
  this.sync = true;

  // whenever we return null, then we set a flag to say
  // that we're awaiting a 'readable' event emission.
  this.needReadable = false;
  this.emittedReadable = false;
  this.readableListening = false;


  // object stream flag. Used to make read(n) ignore n and to
  // make all the buffer merging and length checks go away
  this.objectMode = !!options.objectMode;

  // Crypto is kind of old and crusty.  Historically, its default string
  // encoding is 'binary' so we have to make this configurable.
  // Everything else in the universe uses 'utf8', though.
  this.defaultEncoding = options.defaultEncoding || 'utf8';

  // when piping, we only care about 'readable' events that happen
  // after read()ing all the bytes and not getting any pushback.
  this.ranOut = false;

  // the number of writers that are awaiting a drain event in .pipe()s
  this.awaitDrain = 0;

  // if true, a maybeReadMore has been scheduled
  this.readingMore = false;

  this.decoder = null;
  this.encoding = null;
  if (options.encoding) {
    if (!StringDecoder)
      StringDecoder = require('string_decoder').StringDecoder;
    this.decoder = new StringDecoder(options.encoding);
    this.encoding = options.encoding;
  }
}

function Readable(options) {
  if (!(this instanceof Readable))
    return new Readable(options);

  this._readableState = new ReadableState(options, this);

  // legacy
  this.readable = true;

  Stream.call(this);
}

// Manually shove something into the read() buffer.
// This returns true if the highWaterMark has not been hit yet,
// similar to how Writable.write() returns true if you should
// write() some more.
Readable.prototype.push = function(chunk, encoding) {
  var state = this._readableState;

  if (typeof chunk === 'string' && !state.objectMode) {
    encoding = encoding || state.defaultEncoding;
    if (encoding !== state.encoding) {
      chunk = new Buffer(chunk, encoding);
      encoding = '';
    }
  }

  return readableAddChunk(this, state, chunk, encoding, false);
};

// Unshift should *always* be something directly out of read()
Readable.prototype.unshift = function(chunk) {
  var state = this._readableState;
  return readableAddChunk(this, state, chunk, '', true);
};

function readableAddChunk(stream, state, chunk, encoding, addToFront) {
  var er = chunkInvalid(state, chunk);
  if (er) {
    stream.emit('error', er);
  } else if (chunk === null || chunk === undefined) {
    state.reading = false;
    if (!state.ended)
      onEofChunk(stream, state);
  } else if (state.objectMode || chunk && chunk.length > 0) {
    if (state.ended && !addToFront) {
      var e = new Error('stream.push() after EOF');
      stream.emit('error', e);
    } else if (state.endEmitted && addToFront) {
      var e = new Error('stream.unshift() after end event');
      stream.emit('error', e);
    } else {
      if (state.decoder && !addToFront && !encoding)
        chunk = state.decoder.write(chunk);

      // update the buffer info.
      state.length += state.objectMode ? 1 : chunk.length;
      if (addToFront) {
        state.buffer.unshift(chunk);
      } else {
        state.reading = false;
        state.buffer.push(chunk);
      }

      if (state.needReadable)
        emitReadable(stream);

      maybeReadMore(stream, state);
    }
  } else if (!addToFront) {
    state.reading = false;
  }

  return needMoreData(state);
}



// if it's past the high water mark, we can push in some more.
// Also, if we have no data yet, we can stand some
// more bytes.  This is to work around cases where hwm=0,
// such as the repl.  Also, if the push() triggered a
// readable event, and the user called read(largeNumber) such that
// needReadable was set, then we ought to push more, so that another
// 'readable' event will be triggered.
function needMoreData(state) {
  return !state.ended &&
         (state.needReadable ||
          state.length < state.highWaterMark ||
          state.length === 0);
}

// backwards compatibility.
Readable.prototype.setEncoding = function(enc) {
  if (!StringDecoder)
    StringDecoder = require('string_decoder').StringDecoder;
  this._readableState.decoder = new StringDecoder(enc);
  this._readableState.encoding = enc;
};

// Don't raise the hwm > 128MB
var MAX_HWM = 0x800000;
function roundUpToNextPowerOf2(n) {
  if (n >= MAX_HWM) {
    n = MAX_HWM;
  } else {
    // Get the next highest power of 2
    n--;
    for (var p = 1; p < 32; p <<= 1) n |= n >> p;
    n++;
  }
  return n;
}

function howMuchToRead(n, state) {
  if (state.length === 0 && state.ended)
    return 0;

  if (state.objectMode)
    return n === 0 ? 0 : 1;

  if (isNaN(n) || n === null) {
    // only flow one buffer at a time
    if (state.flowing && state.buffer.length)
      return state.buffer[0].length;
    else
      return state.length;
  }

  if (n <= 0)
    return 0;

  // If we're asking for more than the target buffer level,
  // then raise the water mark.  Bump up to the next highest
  // power of 2, to prevent increasing it excessively in tiny
  // amounts.
  if (n > state.highWaterMark)
    state.highWaterMark = roundUpToNextPowerOf2(n);

  // don't have that much.  return null, unless we've ended.
  if (n > state.length) {
    if (!state.ended) {
      state.needReadable = true;
      return 0;
    } else
      return state.length;
  }

  return n;
}

// you can override either this method, or the async _read(n) below.
Readable.prototype.read = function(n) {
  var state = this._readableState;
  state.calledRead = true;
  var nOrig = n;

  if (typeof n !== 'number' || n > 0)
    state.emittedReadable = false;

  // if we're doing read(0) to trigger a readable event, but we
  // already have a bunch of data in the buffer, then just trigger
  // the 'readable' event and move on.
  if (n === 0 &&
      state.needReadable &&
      (state.length >= state.highWaterMark || state.ended)) {
    emitReadable(this);
    return null;
  }

  n = howMuchToRead(n, state);

  // if we've ended, and we're now clear, then finish it up.
  if (n === 0 && state.ended) {
    if (state.length === 0)
      endReadable(this);
    return null;
  }

  // All the actual chunk generation logic needs to be
  // *below* the call to _read.  The reason is that in certain
  // synthetic stream cases, such as passthrough streams, _read
  // may be a completely synchronous operation which may change
  // the state of the read buffer, providing enough data when
  // before there was *not* enough.
  //
  // So, the steps are:
  // 1. Figure out what the state of things will be after we do
  // a read from the buffer.
  //
  // 2. If that resulting state will trigger a _read, then call _read.
  // Note that this may be asynchronous, or synchronous.  Yes, it is
  // deeply ugly to write APIs this way, but that still doesn't mean
  // that the Readable class should behave improperly, as streams are
  // designed to be sync/async agnostic.
  // Take note if the _read call is sync or async (ie, if the read call
  // has returned yet), so that we know whether or not it's safe to emit
  // 'readable' etc.
  //
  // 3. Actually pull the requested chunks out of the buffer and return.

  // if we need a readable event, then we need to do some reading.
  var doRead = state.needReadable;

  // if we currently have less than the highWaterMark, then also read some
  if (state.length - n <= state.highWaterMark)
    doRead = true;

  // however, if we've ended, then there's no point, and if we're already
  // reading, then it's unnecessary.
  if (state.ended || state.reading)
    doRead = false;

  if (doRead) {
    state.reading = true;
    state.sync = true;
    // if the length is currently zero, then we *need* a readable event.
    if (state.length === 0)
      state.needReadable = true;
    // call internal read method
    this._read(state.highWaterMark);
    state.sync = false;
  }

  // If _read called its callback synchronously, then `reading`
  // will be false, and we need to re-evaluate how much data we
  // can return to the user.
  if (doRead && !state.reading)
    n = howMuchToRead(nOrig, state);

  var ret;
  if (n > 0)
    ret = fromList(n, state);
  else
    ret = null;

  if (ret === null) {
    state.needReadable = true;
    n = 0;
  }

  state.length -= n;

  // If we have nothing in the buffer, then we want to know
  // as soon as we *do* get something into the buffer.
  if (state.length === 0 && !state.ended)
    state.needReadable = true;

  // If we happened to read() exactly the remaining amount in the
  // buffer, and the EOF has been seen at this point, then make sure
  // that we emit 'end' on the very next tick.
  if (state.ended && !state.endEmitted && state.length === 0)
    endReadable(this);

  return ret;
};

function chunkInvalid(state, chunk) {
  var er = null;
  if (!Buffer.isBuffer(chunk) &&
      'string' !== typeof chunk &&
      chunk !== null &&
      chunk !== undefined &&
      !state.objectMode &&
      !er) {
    er = new TypeError('Invalid non-string/buffer chunk');
  }
  return er;
}


function onEofChunk(stream, state) {
  if (state.decoder && !state.ended) {
    var chunk = state.decoder.end();
    if (chunk && chunk.length) {
      state.buffer.push(chunk);
      state.length += state.objectMode ? 1 : chunk.length;
    }
  }
  state.ended = true;

  // if we've ended and we have some data left, then emit
  // 'readable' now to make sure it gets picked up.
  if (state.length > 0)
    emitReadable(stream);
  else
    endReadable(stream);
}

// Don't emit readable right away in sync mode, because this can trigger
// another read() call => stack overflow.  This way, it might trigger
// a nextTick recursion warning, but that's not so bad.
function emitReadable(stream) {
  var state = stream._readableState;
  state.needReadable = false;
  if (state.emittedReadable)
    return;

  state.emittedReadable = true;
  if (state.sync)
    timers.setImmediate(function() {
      emitReadable_(stream);
    });
  else
    emitReadable_(stream);
}

function emitReadable_(stream) {
  stream.emit('readable');
}


// at this point, the user has presumably seen the 'readable' event,
// and called read() to consume some data.  that may have triggered
// in turn another _read(n) call, in which case reading = true if
// it's in progress.
// However, if we're not ended, or reading, and the length < hwm,
// then go ahead and try to read some more preemptively.
function maybeReadMore(stream, state) {
  if (!state.readingMore) {
    state.readingMore = true;
    timers.setImmediate(function() {
      maybeReadMore_(stream, state);
    });
  }
}

function maybeReadMore_(stream, state) {
  var len = state.length;
  while (!state.reading && !state.flowing && !state.ended &&
         state.length < state.highWaterMark) {
    stream.read(0);
    if (len === state.length)
      // didn't get any data, stop spinning.
      break;
    else
      len = state.length;
  }
  state.readingMore = false;
}

// abstract method.  to be overridden in specific implementation classes.
// call cb(er, data) where data is <= n in length.
// for virtual (non-string, non-buffer) streams, "length" is somewhat
// arbitrary, and perhaps not very meaningful.
Readable.prototype._read = function(n) {
  this.emit('error', new Error('not implemented'));
};

Readable.prototype.pipe = function(dest, pipeOpts) {
  var src = this;
  var state = this._readableState;

  switch (state.pipesCount) {
    case 0:
      state.pipes = dest;
      break;
    case 1:
      state.pipes = [state.pipes, dest];
      break;
    default:
      state.pipes.push(dest);
      break;
  }
  state.pipesCount += 1;

  var doEnd = (!pipeOpts || pipeOpts.end !== false) &&
              dest !== process.stdout &&
              dest !== process.stderr;

  var endFn = doEnd ? onend : cleanup;
  if (state.endEmitted)
    timers.setImmediate(endFn);
  else
    src.once('end', endFn);

  dest.on('unpipe', onunpipe);
  function onunpipe(readable) {
    if (readable !== src) return;
    cleanup();
  }

  function onend() {
    dest.end();
  }

  // when the dest drains, it reduces the awaitDrain counter
  // on the source.  This would be more elegant with a .once()
  // handler in flow(), but adding and removing repeatedly is
  // too slow.
  var ondrain = pipeOnDrain(src);
  dest.on('drain', ondrain);

  function cleanup() {
    // cleanup event handlers once the pipe is broken
    dest.removeListener('close', onclose);
    dest.removeListener('finish', onfinish);
    dest.removeListener('drain', ondrain);
    dest.removeListener('error', onerror);
    dest.removeListener('unpipe', onunpipe);
    src.removeListener('end', onend);
    src.removeListener('end', cleanup);

    // if the reader is waiting for a drain event from this
    // specific writer, then it would cause it to never start
    // flowing again.
    // So, if this is awaiting a drain, then we just call it now.
    // If we don't know, then assume that we are waiting for one.
    if (!dest._writableState || dest._writableState.needDrain)
      ondrain();
  }

  // if the dest has an error, then stop piping into it.
  // however, don't suppress the throwing behavior for this.
  // check for listeners before emit removes one-time listeners.
  var errListeners = EE.listenerCount(dest, 'error');
  function onerror(er) {
    unpipe();
    if (errListeners === 0 && EE.listenerCount(dest, 'error') === 0)
      dest.emit('error', er);
  }
  dest.once('error', onerror);

  // Both close and finish should trigger unpipe, but only once.
  function onclose() {
    dest.removeListener('finish', onfinish);
    unpipe();
  }
  dest.once('close', onclose);
  function onfinish() {
    dest.removeListener('close', onclose);
    unpipe();
  }
  dest.once('finish', onfinish);

  function unpipe() {
    src.unpipe(dest);
  }

  // tell the dest that it's being piped to
  dest.emit('pipe', src);

  // start the flow if it hasn't been started already.
  if (!state.flowing) {
    // the handler that waits for readable events after all
    // the data gets sucked out in flow.
    // This would be easier to follow with a .once() handler
    // in flow(), but that is too slow.
    this.on('readable', pipeOnReadable);

    state.flowing = true;
    timers.setImmediate(function() {
      flow(src);
    });
  }

  return dest;
};

function pipeOnDrain(src) {
  return function() {
    var dest = this;
    var state = src._readableState;
    state.awaitDrain--;
    if (state.awaitDrain === 0)
      flow(src);
  };
}

function flow(src) {
  var state = src._readableState;
  var chunk;
  state.awaitDrain = 0;

  function write(dest, i, list) {
    var written = dest.write(chunk);
    if (false === written) {
      state.awaitDrain++;
    }
  }

  while (state.pipesCount && null !== (chunk = src.read())) {

    if (state.pipesCount === 1)
      write(state.pipes, 0, null);
    else
      shims.forEach(state.pipes, write);

    src.emit('data', chunk);

    // if anyone needs a drain, then we have to wait for that.
    if (state.awaitDrain > 0)
      return;
  }

  // if every destination was unpiped, either before entering this
  // function, or in the while loop, then stop flowing.
  //
  // NB: This is a pretty rare edge case.
  if (state.pipesCount === 0) {
    state.flowing = false;

    // if there were data event listeners added, then switch to old mode.
    if (EE.listenerCount(src, 'data') > 0)
      emitDataEvents(src);
    return;
  }

  // at this point, no one needed a drain, so we just ran out of data
  // on the next readable event, start it over again.
  state.ranOut = true;
}

function pipeOnReadable() {
  if (this._readableState.ranOut) {
    this._readableState.ranOut = false;
    flow(this);
  }
}


Readable.prototype.unpipe = function(dest) {
  var state = this._readableState;

  // if we're not piping anywhere, then do nothing.
  if (state.pipesCount === 0)
    return this;

  // just one destination.  most common case.
  if (state.pipesCount === 1) {
    // passed in one, but it's not the right one.
    if (dest && dest !== state.pipes)
      return this;

    if (!dest)
      dest = state.pipes;

    // got a match.
    state.pipes = null;
    state.pipesCount = 0;
    this.removeListener('readable', pipeOnReadable);
    state.flowing = false;
    if (dest)
      dest.emit('unpipe', this);
    return this;
  }

  // slow case. multiple pipe destinations.

  if (!dest) {
    // remove all.
    var dests = state.pipes;
    var len = state.pipesCount;
    state.pipes = null;
    state.pipesCount = 0;
    this.removeListener('readable', pipeOnReadable);
    state.flowing = false;

    for (var i = 0; i < len; i++)
      dests[i].emit('unpipe', this);
    return this;
  }

  // try to find the right one.
  var i = shims.indexOf(state.pipes, dest);
  if (i === -1)
    return this;

  state.pipes.splice(i, 1);
  state.pipesCount -= 1;
  if (state.pipesCount === 1)
    state.pipes = state.pipes[0];

  dest.emit('unpipe', this);

  return this;
};

// set up data events if they are asked for
// Ensure readable listeners eventually get something
Readable.prototype.on = function(ev, fn) {
  var res = Stream.prototype.on.call(this, ev, fn);

  if (ev === 'data' && !this._readableState.flowing)
    emitDataEvents(this);

  if (ev === 'readable' && this.readable) {
    var state = this._readableState;
    if (!state.readableListening) {
      state.readableListening = true;
      state.emittedReadable = false;
      state.needReadable = true;
      if (!state.reading) {
        this.read(0);
      } else if (state.length) {
        emitReadable(this, state);
      }
    }
  }

  return res;
};
Readable.prototype.addListener = Readable.prototype.on;

// pause() and resume() are remnants of the legacy readable stream API
// If the user uses them, then switch into old mode.
Readable.prototype.resume = function() {
  emitDataEvents(this);
  this.read(0);
  this.emit('resume');
};

Readable.prototype.pause = function() {
  emitDataEvents(this, true);
  this.emit('pause');
};

function emitDataEvents(stream, startPaused) {
  var state = stream._readableState;

  if (state.flowing) {
    // https://github.com/isaacs/readable-stream/issues/16
    throw new Error('Cannot switch to old mode now.');
  }

  var paused = startPaused || false;
  var readable = false;

  // convert to an old-style stream.
  stream.readable = true;
  stream.pipe = Stream.prototype.pipe;
  stream.on = stream.addListener = Stream.prototype.on;

  stream.on('readable', function() {
    readable = true;

    var c;
    while (!paused && (null !== (c = stream.read())))
      stream.emit('data', c);

    if (c === null) {
      readable = false;
      stream._readableState.needReadable = true;
    }
  });

  stream.pause = function() {
    paused = true;
    this.emit('pause');
  };

  stream.resume = function() {
    paused = false;
    if (readable)
      timers.setImmediate(function() {
        stream.emit('readable');
      });
    else
      this.read(0);
    this.emit('resume');
  };

  // now make it start, just in case it hadn't already.
  stream.emit('readable');
}

// wrap an old-style stream as the async data source.
// This is *not* part of the readable stream interface.
// It is an ugly unfortunate mess of history.
Readable.prototype.wrap = function(stream) {
  var state = this._readableState;
  var paused = false;

  var self = this;
  stream.on('end', function() {
    if (state.decoder && !state.ended) {
      var chunk = state.decoder.end();
      if (chunk && chunk.length)
        self.push(chunk);
    }

    self.push(null);
  });

  stream.on('data', function(chunk) {
    if (state.decoder)
      chunk = state.decoder.write(chunk);
    if (!chunk || !state.objectMode && !chunk.length)
      return;

    var ret = self.push(chunk);
    if (!ret) {
      paused = true;
      stream.pause();
    }
  });

  // proxy all the other methods.
  // important when wrapping filters and duplexes.
  for (var i in stream) {
    if (typeof stream[i] === 'function' &&
        typeof this[i] === 'undefined') {
      this[i] = function(method) { return function() {
        return stream[method].apply(stream, arguments);
      }}(i);
    }
  }

  // proxy certain important events.
  var events = ['error', 'close', 'destroy', 'pause', 'resume'];
  shims.forEach(events, function(ev) {
    stream.on(ev, shims.bind(self.emit, self, ev));
  });

  // when we try to consume some more bytes, simply unpause the
  // underlying stream.
  self._read = function(n) {
    if (paused) {
      paused = false;
      stream.resume();
    }
  };

  return self;
};



// exposed for testing purposes only.
Readable._fromList = fromList;

// Pluck off n bytes from an array of buffers.
// Length is the combined lengths of all the buffers in the list.
function fromList(n, state) {
  var list = state.buffer;
  var length = state.length;
  var stringMode = !!state.decoder;
  var objectMode = !!state.objectMode;
  var ret;

  // nothing in the list, definitely empty.
  if (list.length === 0)
    return null;

  if (length === 0)
    ret = null;
  else if (objectMode)
    ret = list.shift();
  else if (!n || n >= length) {
    // read it all, truncate the array.
    if (stringMode)
      ret = list.join('');
    else
      ret = Buffer.concat(list, length);
    list.length = 0;
  } else {
    // read just some of it.
    if (n < list[0].length) {
      // just take a part of the first list item.
      // slice is the same for buffers and strings.
      var buf = list[0];
      ret = buf.slice(0, n);
      list[0] = buf.slice(n);
    } else if (n === list[0].length) {
      // first list is a perfect match
      ret = list.shift();
    } else {
      // complex case.
      // we have enough to cover it, but it spans past the first buffer.
      if (stringMode)
        ret = '';
      else
        ret = new Buffer(n);

      var c = 0;
      for (var i = 0, l = list.length; i < l && c < n; i++) {
        var buf = list[0];
        var cpy = Math.min(n - c, buf.length);

        if (stringMode)
          ret += buf.slice(0, cpy);
        else
          buf.copy(ret, c, 0, cpy);

        if (cpy < buf.length)
          list[0] = buf.slice(cpy);
        else
          list.shift();

        c += cpy;
      }
    }
  }

  return ret;
}

function endReadable(stream) {
  var state = stream._readableState;

  // If we get here before consuming all the bytes, then that is a
  // bug in node.  Should never happen.
  if (state.length > 0)
    throw new Error('endReadable called on non-empty stream');

  if (!state.endEmitted && state.calledRead) {
    state.ended = true;
    timers.setImmediate(function() {
      // Check that we didn't get one last unshift.
      if (!state.endEmitted && state.length === 0) {
        state.endEmitted = true;
        stream.readable = false;
        stream.emit('end');
      }
    });
  }
}

},{"__browserify_process":17,"_shims":1,"buffer":14,"events":8,"stream":9,"string_decoder":10,"timers":11,"util":12}],5:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// a transform stream is a readable/writable stream where you do
// something with the data.  Sometimes it's called a "filter",
// but that's not a great name for it, since that implies a thing where
// some bits pass through, and others are simply ignored.  (That would
// be a valid example of a transform, of course.)
//
// While the output is causally related to the input, it's not a
// necessarily symmetric or synchronous transformation.  For example,
// a zlib stream might take multiple plain-text writes(), and then
// emit a single compressed chunk some time in the future.
//
// Here's how this works:
//
// The Transform stream has all the aspects of the readable and writable
// stream classes.  When you write(chunk), that calls _write(chunk,cb)
// internally, and returns false if there's a lot of pending writes
// buffered up.  When you call read(), that calls _read(n) until
// there's enough pending readable data buffered up.
//
// In a transform stream, the written data is placed in a buffer.  When
// _read(n) is called, it transforms the queued up data, calling the
// buffered _write cb's as it consumes chunks.  If consuming a single
// written chunk would result in multiple output chunks, then the first
// outputted bit calls the readcb, and subsequent chunks just go into
// the read buffer, and will cause it to emit 'readable' if necessary.
//
// This way, back-pressure is actually determined by the reading side,
// since _read has to be called to start processing a new chunk.  However,
// a pathological inflate type of transform can cause excessive buffering
// here.  For example, imagine a stream where every byte of input is
// interpreted as an integer from 0-255, and then results in that many
// bytes of output.  Writing the 4 bytes {ff,ff,ff,ff} would result in
// 1kb of data being output.  In this case, you could write a very small
// amount of input, and end up with a very large amount of output.  In
// such a pathological inflating mechanism, there'd be no way to tell
// the system to stop doing the transform.  A single 4MB write could
// cause the system to run out of memory.
//
// However, even in such a pathological case, only a single written chunk
// would be consumed, and then the rest would wait (un-transformed) until
// the results of the previous transformed chunk were consumed.

module.exports = Transform;

var Duplex = require('_stream_duplex');
var util = require('util');
util.inherits(Transform, Duplex);


function TransformState(options, stream) {
  this.afterTransform = function(er, data) {
    return afterTransform(stream, er, data);
  };

  this.needTransform = false;
  this.transforming = false;
  this.writecb = null;
  this.writechunk = null;
}

function afterTransform(stream, er, data) {
  var ts = stream._transformState;
  ts.transforming = false;

  var cb = ts.writecb;

  if (!cb)
    return stream.emit('error', new Error('no writecb in Transform class'));

  ts.writechunk = null;
  ts.writecb = null;

  if (data !== null && data !== undefined)
    stream.push(data);

  if (cb)
    cb(er);

  var rs = stream._readableState;
  rs.reading = false;
  if (rs.needReadable || rs.length < rs.highWaterMark) {
    stream._read(rs.highWaterMark);
  }
}


function Transform(options) {
  if (!(this instanceof Transform))
    return new Transform(options);

  Duplex.call(this, options);

  var ts = this._transformState = new TransformState(options, this);

  // when the writable side finishes, then flush out anything remaining.
  var stream = this;

  // start out asking for a readable event once data is transformed.
  this._readableState.needReadable = true;

  // we have implemented the _read method, and done the other things
  // that Readable wants before the first _read call, so unset the
  // sync guard flag.
  this._readableState.sync = false;

  this.once('finish', function() {
    if ('function' === typeof this._flush)
      this._flush(function(er) {
        done(stream, er);
      });
    else
      done(stream);
  });
}

Transform.prototype.push = function(chunk, encoding) {
  this._transformState.needTransform = false;
  return Duplex.prototype.push.call(this, chunk, encoding);
};

// This is the part where you do stuff!
// override this function in implementation classes.
// 'chunk' is an input chunk.
//
// Call `push(newChunk)` to pass along transformed output
// to the readable side.  You may call 'push' zero or more times.
//
// Call `cb(err)` when you are done with this chunk.  If you pass
// an error, then that'll put the hurt on the whole operation.  If you
// never call cb(), then you'll never get another chunk.
Transform.prototype._transform = function(chunk, encoding, cb) {
  throw new Error('not implemented');
};

Transform.prototype._write = function(chunk, encoding, cb) {
  var ts = this._transformState;
  ts.writecb = cb;
  ts.writechunk = chunk;
  ts.writeencoding = encoding;
  if (!ts.transforming) {
    var rs = this._readableState;
    if (ts.needTransform ||
        rs.needReadable ||
        rs.length < rs.highWaterMark)
      this._read(rs.highWaterMark);
  }
};

// Doesn't matter what the args are here.
// _transform does all the work.
// That we got here means that the readable side wants more data.
Transform.prototype._read = function(n) {
  var ts = this._transformState;

  if (ts.writechunk && ts.writecb && !ts.transforming) {
    ts.transforming = true;
    this._transform(ts.writechunk, ts.writeencoding, ts.afterTransform);
  } else {
    // mark that we need a transform, so that any data that comes in
    // will get processed, now that we've asked for it.
    ts.needTransform = true;
  }
};


function done(stream, er) {
  if (er)
    return stream.emit('error', er);

  // if there's nothing in the write buffer, then that means
  // that nothing more will ever be provided
  var ws = stream._writableState;
  var rs = stream._readableState;
  var ts = stream._transformState;

  if (ws.length)
    throw new Error('calling transform done when ws.length != 0');

  if (ts.transforming)
    throw new Error('calling transform done when still transforming');

  return stream.push(null);
}

},{"_stream_duplex":2,"util":12}],6:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// A bit simpler than readable streams.
// Implement an async ._write(chunk, cb), and it'll handle all
// the drain event emission and buffering.

module.exports = Writable;
Writable.WritableState = WritableState;

var util = require('util');
var Stream = require('stream');
var timers = require('timers');
var Buffer = require('buffer').Buffer;

util.inherits(Writable, Stream);

function WriteReq(chunk, encoding, cb) {
  this.chunk = chunk;
  this.encoding = encoding;
  this.callback = cb;
}

function WritableState(options, stream) {
  options = options || {};

  // the point at which write() starts returning false
  // Note: 0 is a valid value, means that we always return false if
  // the entire buffer is not flushed immediately on write()
  var hwm = options.highWaterMark;
  this.highWaterMark = (hwm || hwm === 0) ? hwm : 16 * 1024;

  // object stream flag to indicate whether or not this stream
  // contains buffers or objects.
  this.objectMode = !!options.objectMode;

  // cast to ints.
  this.highWaterMark = ~~this.highWaterMark;

  this.needDrain = false;
  // at the start of calling end()
  this.ending = false;
  // when end() has been called, and returned
  this.ended = false;
  // when 'finish' is emitted
  this.finished = false;

  // should we decode strings into buffers before passing to _write?
  // this is here so that some node-core streams can optimize string
  // handling at a lower level.
  var noDecode = options.decodeStrings === false;
  this.decodeStrings = !noDecode;

  // Crypto is kind of old and crusty.  Historically, its default string
  // encoding is 'binary' so we have to make this configurable.
  // Everything else in the universe uses 'utf8', though.
  this.defaultEncoding = options.defaultEncoding || 'utf8';

  // not an actual buffer we keep track of, but a measurement
  // of how much we're waiting to get pushed to some underlying
  // socket or file.
  this.length = 0;

  // a flag to see when we're in the middle of a write.
  this.writing = false;

  // a flag to be able to tell if the onwrite cb is called immediately,
  // or on a later tick.  We set this to true at first, becuase any
  // actions that shouldn't happen until "later" should generally also
  // not happen before the first write call.
  this.sync = true;

  // a flag to know if we're processing previously buffered items, which
  // may call the _write() callback in the same tick, so that we don't
  // end up in an overlapped onwrite situation.
  this.bufferProcessing = false;

  // the callback that's passed to _write(chunk,cb)
  this.onwrite = function(er) {
    onwrite(stream, er);
  };

  // the callback that the user supplies to write(chunk,encoding,cb)
  this.writecb = null;

  // the amount that is being written when _write is called.
  this.writelen = 0;

  this.buffer = [];
}

function Writable(options) {
  // Writable ctor is applied to Duplexes, though they're not
  // instanceof Writable, they're instanceof Readable.
  if (!(this instanceof Writable) && !(this instanceof Stream.Duplex))
    return new Writable(options);

  this._writableState = new WritableState(options, this);

  // legacy.
  this.writable = true;

  Stream.call(this);
}

// Otherwise people can pipe Writable streams, which is just wrong.
Writable.prototype.pipe = function() {
  this.emit('error', new Error('Cannot pipe. Not readable.'));
};


function writeAfterEnd(stream, state, cb) {
  var er = new Error('write after end');
  // TODO: defer error events consistently everywhere, not just the cb
  stream.emit('error', er);
  timers.setImmediate(function() {
    cb(er);
  });
}

// If we get something that is not a buffer, string, null, or undefined,
// and we're not in objectMode, then that's an error.
// Otherwise stream chunks are all considered to be of length=1, and the
// watermarks determine how many objects to keep in the buffer, rather than
// how many bytes or characters.
function validChunk(stream, state, chunk, cb) {
  var valid = true;
  if (!Buffer.isBuffer(chunk) &&
      'string' !== typeof chunk &&
      chunk !== null &&
      chunk !== undefined &&
      !state.objectMode) {
    var er = new TypeError('Invalid non-string/buffer chunk');
    stream.emit('error', er);
    timers.setImmediate(function() {
      cb(er);
    });
    valid = false;
  }
  return valid;
}

Writable.prototype.write = function(chunk, encoding, cb) {
  var state = this._writableState;
  var ret = false;

  if (typeof encoding === 'function') {
    cb = encoding;
    encoding = null;
  }

  if (Buffer.isBuffer(chunk))
    encoding = 'buffer';
  else if (!encoding)
    encoding = state.defaultEncoding;

  if (typeof cb !== 'function')
    cb = function() {};

  if (state.ended)
    writeAfterEnd(this, state, cb);
  else if (validChunk(this, state, chunk, cb))
    ret = writeOrBuffer(this, state, chunk, encoding, cb);

  return ret;
};

function decodeChunk(state, chunk, encoding) {
  if (!state.objectMode &&
      state.decodeStrings !== false &&
      typeof chunk === 'string') {
    chunk = new Buffer(chunk, encoding);
  }
  return chunk;
}

// if we're already writing something, then just put this
// in the queue, and wait our turn.  Otherwise, call _write
// If we return false, then we need a drain event, so set that flag.
function writeOrBuffer(stream, state, chunk, encoding, cb) {
  chunk = decodeChunk(state, chunk, encoding);
  var len = state.objectMode ? 1 : chunk.length;

  state.length += len;

  var ret = state.length < state.highWaterMark;
  state.needDrain = !ret;

  if (state.writing)
    state.buffer.push(new WriteReq(chunk, encoding, cb));
  else
    doWrite(stream, state, len, chunk, encoding, cb);

  return ret;
}

function doWrite(stream, state, len, chunk, encoding, cb) {
  state.writelen = len;
  state.writecb = cb;
  state.writing = true;
  state.sync = true;
  stream._write(chunk, encoding, state.onwrite);
  state.sync = false;
}

function onwriteError(stream, state, sync, er, cb) {
  if (sync)
    timers.setImmediate(function() {
      cb(er);
    });
  else
    cb(er);

  stream.emit('error', er);
}

function onwriteStateUpdate(state) {
  state.writing = false;
  state.writecb = null;
  state.length -= state.writelen;
  state.writelen = 0;
}

function onwrite(stream, er) {
  var state = stream._writableState;
  var sync = state.sync;
  var cb = state.writecb;

  onwriteStateUpdate(state);

  if (er)
    onwriteError(stream, state, sync, er, cb);
  else {
    // Check if we're actually ready to finish, but don't emit yet
    var finished = needFinish(stream, state);

    if (!finished && !state.bufferProcessing && state.buffer.length)
      clearBuffer(stream, state);

    if (sync) {
      timers.setImmediate(function() {
        afterWrite(stream, state, finished, cb);
      });
    } else {
      afterWrite(stream, state, finished, cb);
    }
  }
}

function afterWrite(stream, state, finished, cb) {
  if (!finished)
    onwriteDrain(stream, state);
  cb();
  if (finished)
    finishMaybe(stream, state);
}

// Must force callback to be called on nextTick, so that we don't
// emit 'drain' before the write() consumer gets the 'false' return
// value, and has a chance to attach a 'drain' listener.
function onwriteDrain(stream, state) {
  if (state.length === 0 && state.needDrain) {
    state.needDrain = false;
    stream.emit('drain');
  }
}


// if there's something in the buffer waiting, then process it
function clearBuffer(stream, state) {
  state.bufferProcessing = true;

  for (var c = 0; c < state.buffer.length; c++) {
    var entry = state.buffer[c];
    var chunk = entry.chunk;
    var encoding = entry.encoding;
    var cb = entry.callback;
    var len = state.objectMode ? 1 : chunk.length;

    doWrite(stream, state, len, chunk, encoding, cb);

    // if we didn't call the onwrite immediately, then
    // it means that we need to wait until it does.
    // also, that means that the chunk and cb are currently
    // being processed, so move the buffer counter past them.
    if (state.writing) {
      c++;
      break;
    }
  }

  state.bufferProcessing = false;
  if (c < state.buffer.length)
    state.buffer = state.buffer.slice(c);
  else
    state.buffer.length = 0;
}

Writable.prototype._write = function(chunk, encoding, cb) {
  cb(new Error('not implemented'));
};

Writable.prototype.end = function(chunk, encoding, cb) {
  var state = this._writableState;

  if (typeof chunk === 'function') {
    cb = chunk;
    chunk = null;
    encoding = null;
  } else if (typeof encoding === 'function') {
    cb = encoding;
    encoding = null;
  }

  if (typeof chunk !== 'undefined' && chunk !== null)
    this.write(chunk, encoding);

  // ignore unnecessary end() calls.
  if (!state.ending && !state.finished)
    endWritable(this, state, cb);
};


function needFinish(stream, state) {
  return (state.ending &&
          state.length === 0 &&
          !state.finished &&
          !state.writing);
}

function finishMaybe(stream, state) {
  var need = needFinish(stream, state);
  if (need) {
    state.finished = true;
    stream.emit('finish');
  }
  return need;
}

function endWritable(stream, state, cb) {
  state.ending = true;
  finishMaybe(stream, state);
  if (cb) {
    if (state.finished)
      timers.setImmediate(cb);
    else
      stream.once('finish', cb);
  }
  state.ended = true;
}

},{"buffer":14,"stream":9,"timers":11,"util":12}],7:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// UTILITY
var util = require('util');
var shims = require('_shims');
var pSlice = Array.prototype.slice;

// 1. The assert module provides functions that throw
// AssertionError's when particular conditions are not met. The
// assert module must conform to the following interface.

var assert = module.exports = ok;

// 2. The AssertionError is defined in assert.
// new assert.AssertionError({ message: message,
//                             actual: actual,
//                             expected: expected })

assert.AssertionError = function AssertionError(options) {
  this.name = 'AssertionError';
  this.actual = options.actual;
  this.expected = options.expected;
  this.operator = options.operator;
  this.message = options.message || getMessage(this);
};

// assert.AssertionError instanceof Error
util.inherits(assert.AssertionError, Error);

function replacer(key, value) {
  if (util.isUndefined(value)) {
    return '' + value;
  }
  if (util.isNumber(value) && (isNaN(value) || !isFinite(value))) {
    return value.toString();
  }
  if (util.isFunction(value) || util.isRegExp(value)) {
    return value.toString();
  }
  return value;
}

function truncate(s, n) {
  if (util.isString(s)) {
    return s.length < n ? s : s.slice(0, n);
  } else {
    return s;
  }
}

function getMessage(self) {
  return truncate(JSON.stringify(self.actual, replacer), 128) + ' ' +
         self.operator + ' ' +
         truncate(JSON.stringify(self.expected, replacer), 128);
}

// At present only the three keys mentioned above are used and
// understood by the spec. Implementations or sub modules can pass
// other keys to the AssertionError's constructor - they will be
// ignored.

// 3. All of the following functions must throw an AssertionError
// when a corresponding condition is not met, with a message that
// may be undefined if not provided.  All assertion methods provide
// both the actual and expected values to the assertion error for
// display purposes.

function fail(actual, expected, message, operator, stackStartFunction) {
  throw new assert.AssertionError({
    message: message,
    actual: actual,
    expected: expected,
    operator: operator,
    stackStartFunction: stackStartFunction
  });
}

// EXTENSION! allows for well behaved errors defined elsewhere.
assert.fail = fail;

// 4. Pure assertion tests whether a value is truthy, as determined
// by !!guard.
// assert.ok(guard, message_opt);
// This statement is equivalent to assert.equal(true, !!guard,
// message_opt);. To test strictly for the value true, use
// assert.strictEqual(true, guard, message_opt);.

function ok(value, message) {
  if (!value) fail(value, true, message, '==', assert.ok);
}
assert.ok = ok;

// 5. The equality assertion tests shallow, coercive equality with
// ==.
// assert.equal(actual, expected, message_opt);

assert.equal = function equal(actual, expected, message) {
  if (actual != expected) fail(actual, expected, message, '==', assert.equal);
};

// 6. The non-equality assertion tests for whether two objects are not equal
// with != assert.notEqual(actual, expected, message_opt);

assert.notEqual = function notEqual(actual, expected, message) {
  if (actual == expected) {
    fail(actual, expected, message, '!=', assert.notEqual);
  }
};

// 7. The equivalence assertion tests a deep equality relation.
// assert.deepEqual(actual, expected, message_opt);

assert.deepEqual = function deepEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected)) {
    fail(actual, expected, message, 'deepEqual', assert.deepEqual);
  }
};

function _deepEqual(actual, expected) {
  // 7.1. All identical values are equivalent, as determined by ===.
  if (actual === expected) {
    return true;

  } else if (util.isBuffer(actual) && util.isBuffer(expected)) {
    if (actual.length != expected.length) return false;

    for (var i = 0; i < actual.length; i++) {
      if (actual[i] !== expected[i]) return false;
    }

    return true;

  // 7.2. If the expected value is a Date object, the actual value is
  // equivalent if it is also a Date object that refers to the same time.
  } else if (util.isDate(actual) && util.isDate(expected)) {
    return actual.getTime() === expected.getTime();

  // 7.3 If the expected value is a RegExp object, the actual value is
  // equivalent if it is also a RegExp object with the same source and
  // properties (`global`, `multiline`, `lastIndex`, `ignoreCase`).
  } else if (util.isRegExp(actual) && util.isRegExp(expected)) {
    return actual.source === expected.source &&
           actual.global === expected.global &&
           actual.multiline === expected.multiline &&
           actual.lastIndex === expected.lastIndex &&
           actual.ignoreCase === expected.ignoreCase;

  // 7.4. Other pairs that do not both pass typeof value == 'object',
  // equivalence is determined by ==.
  } else if (!util.isObject(actual) && !util.isObject(expected)) {
    return actual == expected;

  // 7.5 For all other Object pairs, including Array objects, equivalence is
  // determined by having the same number of owned properties (as verified
  // with Object.prototype.hasOwnProperty.call), the same set of keys
  // (although not necessarily the same order), equivalent values for every
  // corresponding key, and an identical 'prototype' property. Note: this
  // accounts for both named and indexed properties on Arrays.
  } else {
    return objEquiv(actual, expected);
  }
}

function isArguments(object) {
  return Object.prototype.toString.call(object) == '[object Arguments]';
}

function objEquiv(a, b) {
  if (util.isNullOrUndefined(a) || util.isNullOrUndefined(b))
    return false;
  // an identical 'prototype' property.
  if (a.prototype !== b.prototype) return false;
  //~~~I've managed to break Object.keys through screwy arguments passing.
  //   Converting to array solves the problem.
  if (isArguments(a)) {
    if (!isArguments(b)) {
      return false;
    }
    a = pSlice.call(a);
    b = pSlice.call(b);
    return _deepEqual(a, b);
  }
  try {
    var ka = shims.keys(a),
        kb = shims.keys(b),
        key, i;
  } catch (e) {//happens when one is a string literal and the other isn't
    return false;
  }
  // having the same number of owned properties (keys incorporates
  // hasOwnProperty)
  if (ka.length != kb.length)
    return false;
  //the same set of keys (although not necessarily the same order),
  ka.sort();
  kb.sort();
  //~~~cheap key test
  for (i = ka.length - 1; i >= 0; i--) {
    if (ka[i] != kb[i])
      return false;
  }
  //equivalent values for every corresponding key, and
  //~~~possibly expensive deep test
  for (i = ka.length - 1; i >= 0; i--) {
    key = ka[i];
    if (!_deepEqual(a[key], b[key])) return false;
  }
  return true;
}

// 8. The non-equivalence assertion tests for any deep inequality.
// assert.notDeepEqual(actual, expected, message_opt);

assert.notDeepEqual = function notDeepEqual(actual, expected, message) {
  if (_deepEqual(actual, expected)) {
    fail(actual, expected, message, 'notDeepEqual', assert.notDeepEqual);
  }
};

// 9. The strict equality assertion tests strict equality, as determined by ===.
// assert.strictEqual(actual, expected, message_opt);

assert.strictEqual = function strictEqual(actual, expected, message) {
  if (actual !== expected) {
    fail(actual, expected, message, '===', assert.strictEqual);
  }
};

// 10. The strict non-equality assertion tests for strict inequality, as
// determined by !==.  assert.notStrictEqual(actual, expected, message_opt);

assert.notStrictEqual = function notStrictEqual(actual, expected, message) {
  if (actual === expected) {
    fail(actual, expected, message, '!==', assert.notStrictEqual);
  }
};

function expectedException(actual, expected) {
  if (!actual || !expected) {
    return false;
  }

  if (Object.prototype.toString.call(expected) == '[object RegExp]') {
    return expected.test(actual);
  } else if (actual instanceof expected) {
    return true;
  } else if (expected.call({}, actual) === true) {
    return true;
  }

  return false;
}

function _throws(shouldThrow, block, expected, message) {
  var actual;

  if (util.isString(expected)) {
    message = expected;
    expected = null;
  }

  try {
    block();
  } catch (e) {
    actual = e;
  }

  message = (expected && expected.name ? ' (' + expected.name + ').' : '.') +
            (message ? ' ' + message : '.');

  if (shouldThrow && !actual) {
    fail(actual, expected, 'Missing expected exception' + message);
  }

  if (!shouldThrow && expectedException(actual, expected)) {
    fail(actual, expected, 'Got unwanted exception' + message);
  }

  if ((shouldThrow && actual && expected &&
      !expectedException(actual, expected)) || (!shouldThrow && actual)) {
    throw actual;
  }
}

// 11. Expected to throw an error:
// assert.throws(block, Error_opt, message_opt);

assert.throws = function(block, /*optional*/error, /*optional*/message) {
  _throws.apply(this, [true].concat(pSlice.call(arguments)));
};

// EXTENSION! This is annoying to write outside this module.
assert.doesNotThrow = function(block, /*optional*/message) {
  _throws.apply(this, [false].concat(pSlice.call(arguments)));
};

assert.ifError = function(err) { if (err) {throw err;}};
},{"_shims":1,"util":12}],8:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var util = require('util');

function EventEmitter() {
  this._events = this._events || {};
  this._maxListeners = this._maxListeners || undefined;
}
module.exports = EventEmitter;

// Backwards-compat with node 0.10.x
EventEmitter.EventEmitter = EventEmitter;

EventEmitter.prototype._events = undefined;
EventEmitter.prototype._maxListeners = undefined;

// By default EventEmitters will print a warning if more than 10 listeners are
// added to it. This is a useful default which helps finding memory leaks.
EventEmitter.defaultMaxListeners = 10;

// Obviously not all Emitters should be limited to 10. This function allows
// that to be increased. Set to zero for unlimited.
EventEmitter.prototype.setMaxListeners = function(n) {
  if (!util.isNumber(n) || n < 0)
    throw TypeError('n must be a positive number');
  this._maxListeners = n;
  return this;
};

EventEmitter.prototype.emit = function(type) {
  var er, handler, len, args, i, listeners;

  if (!this._events)
    this._events = {};

  // If there is no 'error' event listener then throw.
  if (type === 'error') {
    if (!this._events.error ||
        (util.isObject(this._events.error) && !this._events.error.length)) {
      er = arguments[1];
      if (er instanceof Error) {
        throw er; // Unhandled 'error' event
      } else {
        throw TypeError('Uncaught, unspecified "error" event.');
      }
      return false;
    }
  }

  handler = this._events[type];

  if (util.isUndefined(handler))
    return false;

  if (util.isFunction(handler)) {
    switch (arguments.length) {
      // fast cases
      case 1:
        handler.call(this);
        break;
      case 2:
        handler.call(this, arguments[1]);
        break;
      case 3:
        handler.call(this, arguments[1], arguments[2]);
        break;
      // slower
      default:
        len = arguments.length;
        args = new Array(len - 1);
        for (i = 1; i < len; i++)
          args[i - 1] = arguments[i];
        handler.apply(this, args);
    }
  } else if (util.isObject(handler)) {
    len = arguments.length;
    args = new Array(len - 1);
    for (i = 1; i < len; i++)
      args[i - 1] = arguments[i];

    listeners = handler.slice();
    len = listeners.length;
    for (i = 0; i < len; i++)
      listeners[i].apply(this, args);
  }

  return true;
};

EventEmitter.prototype.addListener = function(type, listener) {
  var m;

  if (!util.isFunction(listener))
    throw TypeError('listener must be a function');

  if (!this._events)
    this._events = {};

  // To avoid recursion in the case that type === "newListener"! Before
  // adding it to the listeners, first emit "newListener".
  if (this._events.newListener)
    this.emit('newListener', type,
              util.isFunction(listener.listener) ?
              listener.listener : listener);

  if (!this._events[type])
    // Optimize the case of one listener. Don't need the extra array object.
    this._events[type] = listener;
  else if (util.isObject(this._events[type]))
    // If we've already got an array, just append.
    this._events[type].push(listener);
  else
    // Adding the second element, need to change to array.
    this._events[type] = [this._events[type], listener];

  // Check for listener leak
  if (util.isObject(this._events[type]) && !this._events[type].warned) {
    var m;
    if (!util.isUndefined(this._maxListeners)) {
      m = this._maxListeners;
    } else {
      m = EventEmitter.defaultMaxListeners;
    }

    if (m && m > 0 && this._events[type].length > m) {
      this._events[type].warned = true;
      console.error('(node) warning: possible EventEmitter memory ' +
                    'leak detected. %d listeners added. ' +
                    'Use emitter.setMaxListeners() to increase limit.',
                    this._events[type].length);
      console.trace();
    }
  }

  return this;
};

EventEmitter.prototype.on = EventEmitter.prototype.addListener;

EventEmitter.prototype.once = function(type, listener) {
  if (!util.isFunction(listener))
    throw TypeError('listener must be a function');

  function g() {
    this.removeListener(type, g);
    listener.apply(this, arguments);
  }

  g.listener = listener;
  this.on(type, g);

  return this;
};

// emits a 'removeListener' event iff the listener was removed
EventEmitter.prototype.removeListener = function(type, listener) {
  var list, position, length, i;

  if (!util.isFunction(listener))
    throw TypeError('listener must be a function');

  if (!this._events || !this._events[type])
    return this;

  list = this._events[type];
  length = list.length;
  position = -1;

  if (list === listener ||
      (util.isFunction(list.listener) && list.listener === listener)) {
    delete this._events[type];
    if (this._events.removeListener)
      this.emit('removeListener', type, listener);

  } else if (util.isObject(list)) {
    for (i = length; i-- > 0;) {
      if (list[i] === listener ||
          (list[i].listener && list[i].listener === listener)) {
        position = i;
        break;
      }
    }

    if (position < 0)
      return this;

    if (list.length === 1) {
      list.length = 0;
      delete this._events[type];
    } else {
      list.splice(position, 1);
    }

    if (this._events.removeListener)
      this.emit('removeListener', type, listener);
  }

  return this;
};

EventEmitter.prototype.removeAllListeners = function(type) {
  var key, listeners;

  if (!this._events)
    return this;

  // not listening for removeListener, no need to emit
  if (!this._events.removeListener) {
    if (arguments.length === 0)
      this._events = {};
    else if (this._events[type])
      delete this._events[type];
    return this;
  }

  // emit removeListener for all listeners on all events
  if (arguments.length === 0) {
    for (key in this._events) {
      if (key === 'removeListener') continue;
      this.removeAllListeners(key);
    }
    this.removeAllListeners('removeListener');
    this._events = {};
    return this;
  }

  listeners = this._events[type];

  if (util.isFunction(listeners)) {
    this.removeListener(type, listeners);
  } else {
    // LIFO order
    while (listeners.length)
      this.removeListener(type, listeners[listeners.length - 1]);
  }
  delete this._events[type];

  return this;
};

EventEmitter.prototype.listeners = function(type) {
  var ret;
  if (!this._events || !this._events[type])
    ret = [];
  else if (util.isFunction(this._events[type]))
    ret = [this._events[type]];
  else
    ret = this._events[type].slice();
  return ret;
};

EventEmitter.listenerCount = function(emitter, type) {
  var ret;
  if (!emitter._events || !emitter._events[type])
    ret = 0;
  else if (util.isFunction(emitter._events[type]))
    ret = 1;
  else
    ret = emitter._events[type].length;
  return ret;
};
},{"util":12}],9:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

module.exports = Stream;

var EE = require('events').EventEmitter;
var util = require('util');

util.inherits(Stream, EE);
Stream.Readable = require('_stream_readable');
Stream.Writable = require('_stream_writable');
Stream.Duplex = require('_stream_duplex');
Stream.Transform = require('_stream_transform');
Stream.PassThrough = require('_stream_passthrough');

// Backwards-compat with node 0.4.x
Stream.Stream = Stream;



// old-style streams.  Note that the pipe method (the only relevant
// part of this class) is overridden in the Readable class.

function Stream() {
  EE.call(this);
}

Stream.prototype.pipe = function(dest, options) {
  var source = this;

  function ondata(chunk) {
    if (dest.writable) {
      if (false === dest.write(chunk) && source.pause) {
        source.pause();
      }
    }
  }

  source.on('data', ondata);

  function ondrain() {
    if (source.readable && source.resume) {
      source.resume();
    }
  }

  dest.on('drain', ondrain);

  // If the 'end' option is not supplied, dest.end() will be called when
  // source gets the 'end' or 'close' events.  Only dest.end() once.
  if (!dest._isStdio && (!options || options.end !== false)) {
    source.on('end', onend);
    source.on('close', onclose);
  }

  var didOnEnd = false;
  function onend() {
    if (didOnEnd) return;
    didOnEnd = true;

    dest.end();
  }


  function onclose() {
    if (didOnEnd) return;
    didOnEnd = true;

    if (typeof dest.destroy === 'function') dest.destroy();
  }

  // don't leave dangling pipes when there are errors.
  function onerror(er) {
    cleanup();
    if (EE.listenerCount(this, 'error') === 0) {
      throw er; // Unhandled stream error in pipe.
    }
  }

  source.on('error', onerror);
  dest.on('error', onerror);

  // remove all the event listeners that were added.
  function cleanup() {
    source.removeListener('data', ondata);
    dest.removeListener('drain', ondrain);

    source.removeListener('end', onend);
    source.removeListener('close', onclose);

    source.removeListener('error', onerror);
    dest.removeListener('error', onerror);

    source.removeListener('end', cleanup);
    source.removeListener('close', cleanup);

    dest.removeListener('close', cleanup);
  }

  source.on('end', cleanup);
  source.on('close', cleanup);

  dest.on('close', cleanup);

  dest.emit('pipe', source);

  // Allow for unix-like usage: A.pipe(B).pipe(C)
  return dest;
};

},{"_stream_duplex":2,"_stream_passthrough":3,"_stream_readable":4,"_stream_transform":5,"_stream_writable":6,"events":8,"util":12}],10:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var Buffer = require('buffer').Buffer;

function assertEncoding(encoding) {
  if (encoding && !Buffer.isEncoding(encoding)) {
    throw new Error('Unknown encoding: ' + encoding);
  }
}

var StringDecoder = exports.StringDecoder = function(encoding) {
  this.encoding = (encoding || 'utf8').toLowerCase().replace(/[-_]/, '');
  assertEncoding(encoding);
  switch (this.encoding) {
    case 'utf8':
      // CESU-8 represents each of Surrogate Pair by 3-bytes
      this.surrogateSize = 3;
      break;
    case 'ucs2':
    case 'utf16le':
      // UTF-16 represents each of Surrogate Pair by 2-bytes
      this.surrogateSize = 2;
      this.detectIncompleteChar = utf16DetectIncompleteChar;
      break;
    case 'base64':
      // Base-64 stores 3 bytes in 4 chars, and pads the remainder.
      this.surrogateSize = 3;
      this.detectIncompleteChar = base64DetectIncompleteChar;
      break;
    default:
      this.write = passThroughWrite;
      return;
  }

  this.charBuffer = new Buffer(6);
  this.charReceived = 0;
  this.charLength = 0;
};


StringDecoder.prototype.write = function(buffer) {
  var charStr = '';
  var offset = 0;

  // if our last write ended with an incomplete multibyte character
  while (this.charLength) {
    // determine how many remaining bytes this buffer has to offer for this char
    var i = (buffer.length >= this.charLength - this.charReceived) ?
                this.charLength - this.charReceived :
                buffer.length;

    // add the new bytes to the char buffer
    buffer.copy(this.charBuffer, this.charReceived, offset, i);
    this.charReceived += (i - offset);
    offset = i;

    if (this.charReceived < this.charLength) {
      // still not enough chars in this buffer? wait for more ...
      return '';
    }

    // get the character that was split
    charStr = this.charBuffer.slice(0, this.charLength).toString(this.encoding);

    // lead surrogate (D800-DBFF) is also the incomplete character
    var charCode = charStr.charCodeAt(charStr.length - 1);
    if (charCode >= 0xD800 && charCode <= 0xDBFF) {
      this.charLength += this.surrogateSize;
      charStr = '';
      continue;
    }
    this.charReceived = this.charLength = 0;

    // if there are no more bytes in this buffer, just emit our char
    if (i == buffer.length) return charStr;

    // otherwise cut off the characters end from the beginning of this buffer
    buffer = buffer.slice(i, buffer.length);
    break;
  }

  var lenIncomplete = this.detectIncompleteChar(buffer);

  var end = buffer.length;
  if (this.charLength) {
    // buffer the incomplete character bytes we got
    buffer.copy(this.charBuffer, 0, buffer.length - lenIncomplete, end);
    this.charReceived = lenIncomplete;
    end -= lenIncomplete;
  }

  charStr += buffer.toString(this.encoding, 0, end);

  var end = charStr.length - 1;
  var charCode = charStr.charCodeAt(end);
  // lead surrogate (D800-DBFF) is also the incomplete character
  if (charCode >= 0xD800 && charCode <= 0xDBFF) {
    var size = this.surrogateSize;
    this.charLength += size;
    this.charReceived += size;
    this.charBuffer.copy(this.charBuffer, size, 0, size);
    this.charBuffer.write(charStr.charAt(charStr.length - 1), this.encoding);
    return charStr.substring(0, end);
  }

  // or just emit the charStr
  return charStr;
};

StringDecoder.prototype.detectIncompleteChar = function(buffer) {
  // determine how many bytes we have to check at the end of this buffer
  var i = (buffer.length >= 3) ? 3 : buffer.length;

  // Figure out if one of the last i bytes of our buffer announces an
  // incomplete char.
  for (; i > 0; i--) {
    var c = buffer[buffer.length - i];

    // See http://en.wikipedia.org/wiki/UTF-8#Description

    // 110XXXXX
    if (i == 1 && c >> 5 == 0x06) {
      this.charLength = 2;
      break;
    }

    // 1110XXXX
    if (i <= 2 && c >> 4 == 0x0E) {
      this.charLength = 3;
      break;
    }

    // 11110XXX
    if (i <= 3 && c >> 3 == 0x1E) {
      this.charLength = 4;
      break;
    }
  }

  return i;
};

StringDecoder.prototype.end = function(buffer) {
  var res = '';
  if (buffer && buffer.length)
    res = this.write(buffer);

  if (this.charReceived) {
    var cr = this.charReceived;
    var buf = this.charBuffer;
    var enc = this.encoding;
    res += buf.slice(0, cr).toString(enc);
  }

  return res;
};

function passThroughWrite(buffer) {
  return buffer.toString(this.encoding);
}

function utf16DetectIncompleteChar(buffer) {
  var incomplete = this.charReceived = buffer.length % 2;
  this.charLength = incomplete ? 2 : 0;
  return incomplete;
}

function base64DetectIncompleteChar(buffer) {
  var incomplete = this.charReceived = buffer.length % 3;
  this.charLength = incomplete ? 3 : 0;
  return incomplete;
}

},{"buffer":14}],11:[function(require,module,exports){
try {
    // Old IE browsers that do not curry arguments
    if (!setTimeout.call) {
        var slicer = Array.prototype.slice;
        exports.setTimeout = function(fn) {
            var args = slicer.call(arguments, 1);
            return setTimeout(function() {
                return fn.apply(this, args);
            })
        };

        exports.setInterval = function(fn) {
            var args = slicer.call(arguments, 1);
            return setInterval(function() {
                return fn.apply(this, args);
            });
        };
    } else {
        exports.setTimeout = setTimeout;
        exports.setInterval = setInterval;
    }
    exports.clearTimeout = clearTimeout;
    exports.clearInterval = clearInterval;

    if (window.setImmediate) {
      exports.setImmediate = window.setImmediate;
      exports.clearImmediate = window.clearImmediate;
    }

    // Chrome and PhantomJS seems to depend on `this` pseudo variable being a
    // `window` and throws invalid invocation exception otherwise. If this code
    // runs in such JS runtime next line will throw and `catch` clause will
    // exported timers functions bound to a window.
    exports.setTimeout(function() {});
} catch (_) {
    function bind(f, context) {
        return function () { return f.apply(context, arguments) };
    }

    if (typeof window !== 'undefined') {
      exports.setTimeout = bind(setTimeout, window);
      exports.setInterval = bind(setInterval, window);
      exports.clearTimeout = bind(clearTimeout, window);
      exports.clearInterval = bind(clearInterval, window);
      if (window.setImmediate) {
        exports.setImmediate = bind(window.setImmediate, window);
        exports.clearImmediate = bind(window.clearImmediate, window);
      }
    } else {
      if (typeof setTimeout !== 'undefined') {
        exports.setTimeout = setTimeout;
      }
      if (typeof setInterval !== 'undefined') {
        exports.setInterval = setInterval;
      }
      if (typeof clearTimeout !== 'undefined') {
        exports.clearTimeout = clearTimeout;
      }
      if (typeof clearInterval === 'function') {
        exports.clearInterval = clearInterval;
      }
    }
}

exports.unref = function unref() {};
exports.ref = function ref() {};

if (!exports.setImmediate) {
  var currentKey = 0, queue = {}, active = false;

  exports.setImmediate = (function () {
      function drain() {
        active = false;
        for (var key in queue) {
          if (queue.hasOwnProperty(currentKey, key)) {
            var fn = queue[key];
            delete queue[key];
            fn();
          }
        }
      }

      if (typeof window !== 'undefined' &&
          window.postMessage && window.addEventListener) {
        window.addEventListener('message', function (ev) {
          if (ev.source === window && ev.data === 'browserify-tick') {
            ev.stopPropagation();
            drain();
          }
        }, true);

        return function setImmediate(fn) {
          var id = ++currentKey;
          queue[id] = fn;
          if (!active) {
            active = true;
            window.postMessage('browserify-tick', '*');
          }
          return id;
        };
      } else {
        return function setImmediate(fn) {
          var id = ++currentKey;
          queue[id] = fn;
          if (!active) {
            active = true;
            setTimeout(drain, 0);
          }
          return id;
        };
      }
  })();

  exports.clearImmediate = function clearImmediate(id) {
    delete queue[id];
  };
}

},{}],12:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var shims = require('_shims');

var formatRegExp = /%[sdj%]/g;
exports.format = function(f) {
  if (!isString(f)) {
    var objects = [];
    for (var i = 0; i < arguments.length; i++) {
      objects.push(inspect(arguments[i]));
    }
    return objects.join(' ');
  }

  var i = 1;
  var args = arguments;
  var len = args.length;
  var str = String(f).replace(formatRegExp, function(x) {
    if (x === '%%') return '%';
    if (i >= len) return x;
    switch (x) {
      case '%s': return String(args[i++]);
      case '%d': return Number(args[i++]);
      case '%j':
        try {
          return JSON.stringify(args[i++]);
        } catch (_) {
          return '[Circular]';
        }
      default:
        return x;
    }
  });
  for (var x = args[i]; i < len; x = args[++i]) {
    if (isNull(x) || !isObject(x)) {
      str += ' ' + x;
    } else {
      str += ' ' + inspect(x);
    }
  }
  return str;
};

/**
 * Echos the value of a value. Trys to print the value out
 * in the best way possible given the different types.
 *
 * @param {Object} obj The object to print out.
 * @param {Object} opts Optional options object that alters the output.
 */
/* legacy: obj, showHidden, depth, colors*/
function inspect(obj, opts) {
  // default options
  var ctx = {
    seen: [],
    stylize: stylizeNoColor
  };
  // legacy...
  if (arguments.length >= 3) ctx.depth = arguments[2];
  if (arguments.length >= 4) ctx.colors = arguments[3];
  if (isBoolean(opts)) {
    // legacy...
    ctx.showHidden = opts;
  } else if (opts) {
    // got an "options" object
    exports._extend(ctx, opts);
  }
  // set default options
  if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
  if (isUndefined(ctx.depth)) ctx.depth = 2;
  if (isUndefined(ctx.colors)) ctx.colors = false;
  if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
  if (ctx.colors) ctx.stylize = stylizeWithColor;
  return formatValue(ctx, obj, ctx.depth);
}
exports.inspect = inspect;


// http://en.wikipedia.org/wiki/ANSI_escape_code#graphics
inspect.colors = {
  'bold' : [1, 22],
  'italic' : [3, 23],
  'underline' : [4, 24],
  'inverse' : [7, 27],
  'white' : [37, 39],
  'grey' : [90, 39],
  'black' : [30, 39],
  'blue' : [34, 39],
  'cyan' : [36, 39],
  'green' : [32, 39],
  'magenta' : [35, 39],
  'red' : [31, 39],
  'yellow' : [33, 39]
};

// Don't use 'blue' not visible on cmd.exe
inspect.styles = {
  'special': 'cyan',
  'number': 'yellow',
  'boolean': 'yellow',
  'undefined': 'grey',
  'null': 'bold',
  'string': 'green',
  'date': 'magenta',
  // "name": intentionally not styling
  'regexp': 'red'
};


function stylizeWithColor(str, styleType) {
  var style = inspect.styles[styleType];

  if (style) {
    return '\u001b[' + inspect.colors[style][0] + 'm' + str +
           '\u001b[' + inspect.colors[style][1] + 'm';
  } else {
    return str;
  }
}


function stylizeNoColor(str, styleType) {
  return str;
}


function arrayToHash(array) {
  var hash = {};

  shims.forEach(array, function(val, idx) {
    hash[val] = true;
  });

  return hash;
}


function formatValue(ctx, value, recurseTimes) {
  // Provide a hook for user-specified inspect functions.
  // Check that value is an object with an inspect function on it
  if (ctx.customInspect &&
      value &&
      isFunction(value.inspect) &&
      // Filter out the util module, it's inspect function is special
      value.inspect !== exports.inspect &&
      // Also filter out any prototype objects using the circular check.
      !(value.constructor && value.constructor.prototype === value)) {
    var ret = value.inspect(recurseTimes);
    if (!isString(ret)) {
      ret = formatValue(ctx, ret, recurseTimes);
    }
    return ret;
  }

  // Primitive types cannot have properties
  var primitive = formatPrimitive(ctx, value);
  if (primitive) {
    return primitive;
  }

  // Look up the keys of the object.
  var keys = shims.keys(value);
  var visibleKeys = arrayToHash(keys);

  if (ctx.showHidden) {
    keys = shims.getOwnPropertyNames(value);
  }

  // Some type of object without properties can be shortcutted.
  if (keys.length === 0) {
    if (isFunction(value)) {
      var name = value.name ? ': ' + value.name : '';
      return ctx.stylize('[Function' + name + ']', 'special');
    }
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    }
    if (isDate(value)) {
      return ctx.stylize(Date.prototype.toString.call(value), 'date');
    }
    if (isError(value)) {
      return formatError(value);
    }
  }

  var base = '', array = false, braces = ['{', '}'];

  // Make Array say that they are Array
  if (isArray(value)) {
    array = true;
    braces = ['[', ']'];
  }

  // Make functions say that they are functions
  if (isFunction(value)) {
    var n = value.name ? ': ' + value.name : '';
    base = ' [Function' + n + ']';
  }

  // Make RegExps say that they are RegExps
  if (isRegExp(value)) {
    base = ' ' + RegExp.prototype.toString.call(value);
  }

  // Make dates with properties first say the date
  if (isDate(value)) {
    base = ' ' + Date.prototype.toUTCString.call(value);
  }

  // Make error with message first say the error
  if (isError(value)) {
    base = ' ' + formatError(value);
  }

  if (keys.length === 0 && (!array || value.length == 0)) {
    return braces[0] + base + braces[1];
  }

  if (recurseTimes < 0) {
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    } else {
      return ctx.stylize('[Object]', 'special');
    }
  }

  ctx.seen.push(value);

  var output;
  if (array) {
    output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
  } else {
    output = keys.map(function(key) {
      return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
    });
  }

  ctx.seen.pop();

  return reduceToSingleString(output, base, braces);
}


function formatPrimitive(ctx, value) {
  if (isUndefined(value))
    return ctx.stylize('undefined', 'undefined');
  if (isString(value)) {
    var simple = '\'' + JSON.stringify(value).replace(/^"|"$/g, '')
                                             .replace(/'/g, "\\'")
                                             .replace(/\\"/g, '"') + '\'';
    return ctx.stylize(simple, 'string');
  }
  if (isNumber(value))
    return ctx.stylize('' + value, 'number');
  if (isBoolean(value))
    return ctx.stylize('' + value, 'boolean');
  // For some reason typeof null is "object", so special case here.
  if (isNull(value))
    return ctx.stylize('null', 'null');
}


function formatError(value) {
  return '[' + Error.prototype.toString.call(value) + ']';
}


function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
  var output = [];
  for (var i = 0, l = value.length; i < l; ++i) {
    if (hasOwnProperty(value, String(i))) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          String(i), true));
    } else {
      output.push('');
    }
  }

  shims.forEach(keys, function(key) {
    if (!key.match(/^\d+$/)) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          key, true));
    }
  });
  return output;
}


function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
  var name, str, desc;
  desc = shims.getOwnPropertyDescriptor(value, key) || { value: value[key] };
  if (desc.get) {
    if (desc.set) {
      str = ctx.stylize('[Getter/Setter]', 'special');
    } else {
      str = ctx.stylize('[Getter]', 'special');
    }
  } else {
    if (desc.set) {
      str = ctx.stylize('[Setter]', 'special');
    }
  }

  if (!hasOwnProperty(visibleKeys, key)) {
    name = '[' + key + ']';
  }
  if (!str) {
    if (shims.indexOf(ctx.seen, desc.value) < 0) {
      if (isNull(recurseTimes)) {
        str = formatValue(ctx, desc.value, null);
      } else {
        str = formatValue(ctx, desc.value, recurseTimes - 1);
      }
      if (str.indexOf('\n') > -1) {
        if (array) {
          str = str.split('\n').map(function(line) {
            return '  ' + line;
          }).join('\n').substr(2);
        } else {
          str = '\n' + str.split('\n').map(function(line) {
            return '   ' + line;
          }).join('\n');
        }
      }
    } else {
      str = ctx.stylize('[Circular]', 'special');
    }
  }
  if (isUndefined(name)) {
    if (array && key.match(/^\d+$/)) {
      return str;
    }
    name = JSON.stringify('' + key);
    if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
      name = name.substr(1, name.length - 2);
      name = ctx.stylize(name, 'name');
    } else {
      name = name.replace(/'/g, "\\'")
                 .replace(/\\"/g, '"')
                 .replace(/(^"|"$)/g, "'");
      name = ctx.stylize(name, 'string');
    }
  }

  return name + ': ' + str;
}


function reduceToSingleString(output, base, braces) {
  var numLinesEst = 0;
  var length = shims.reduce(output, function(prev, cur) {
    numLinesEst++;
    if (cur.indexOf('\n') >= 0) numLinesEst++;
    return prev + cur.replace(/\u001b\[\d\d?m/g, '').length + 1;
  }, 0);

  if (length > 60) {
    return braces[0] +
           (base === '' ? '' : base + '\n ') +
           ' ' +
           output.join(',\n  ') +
           ' ' +
           braces[1];
  }

  return braces[0] + base + ' ' + output.join(', ') + ' ' + braces[1];
}


// NOTE: These type checking functions intentionally don't use `instanceof`
// because it is fragile and can be easily faked with `Object.create()`.
function isArray(ar) {
  return shims.isArray(ar);
}
exports.isArray = isArray;

function isBoolean(arg) {
  return typeof arg === 'boolean';
}
exports.isBoolean = isBoolean;

function isNull(arg) {
  return arg === null;
}
exports.isNull = isNull;

function isNullOrUndefined(arg) {
  return arg == null;
}
exports.isNullOrUndefined = isNullOrUndefined;

function isNumber(arg) {
  return typeof arg === 'number';
}
exports.isNumber = isNumber;

function isString(arg) {
  return typeof arg === 'string';
}
exports.isString = isString;

function isSymbol(arg) {
  return typeof arg === 'symbol';
}
exports.isSymbol = isSymbol;

function isUndefined(arg) {
  return arg === void 0;
}
exports.isUndefined = isUndefined;

function isRegExp(re) {
  return isObject(re) && objectToString(re) === '[object RegExp]';
}
exports.isRegExp = isRegExp;

function isObject(arg) {
  return typeof arg === 'object' && arg;
}
exports.isObject = isObject;

function isDate(d) {
  return isObject(d) && objectToString(d) === '[object Date]';
}
exports.isDate = isDate;

function isError(e) {
  return isObject(e) && objectToString(e) === '[object Error]';
}
exports.isError = isError;

function isFunction(arg) {
  return typeof arg === 'function';
}
exports.isFunction = isFunction;

function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}
exports.isPrimitive = isPrimitive;

function isBuffer(arg) {
  return arg && typeof arg === 'object'
    && typeof arg.copy === 'function'
    && typeof arg.fill === 'function'
    && typeof arg.binarySlice === 'function'
  ;
}
exports.isBuffer = isBuffer;

function objectToString(o) {
  return Object.prototype.toString.call(o);
}


function pad(n) {
  return n < 10 ? '0' + n.toString(10) : n.toString(10);
}


var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
              'Oct', 'Nov', 'Dec'];

// 26 Feb 16:19:34
function timestamp() {
  var d = new Date();
  var time = [pad(d.getHours()),
              pad(d.getMinutes()),
              pad(d.getSeconds())].join(':');
  return [d.getDate(), months[d.getMonth()], time].join(' ');
}


// log is just a thin wrapper to console.log that prepends a timestamp
exports.log = function() {
  console.log('%s - %s', timestamp(), exports.format.apply(exports, arguments));
};


/**
 * Inherit the prototype methods from one constructor into another.
 *
 * The Function.prototype.inherits from lang.js rewritten as a standalone
 * function (not on Function.prototype). NOTE: If this file is to be loaded
 * during bootstrapping this function needs to be rewritten using some native
 * functions as prototype setup using normal JavaScript does not work as
 * expected during bootstrapping (see mirror.js in r114903).
 *
 * @param {function} ctor Constructor function which needs to inherit the
 *     prototype.
 * @param {function} superCtor Constructor function to inherit prototype from.
 */
exports.inherits = function(ctor, superCtor) {
  ctor.super_ = superCtor;
  ctor.prototype = shims.create(superCtor.prototype, {
    constructor: {
      value: ctor,
      enumerable: false,
      writable: true,
      configurable: true
    }
  });
};

exports._extend = function(origin, add) {
  // Don't do anything if add isn't an object
  if (!add || !isObject(add)) return origin;

  var keys = shims.keys(add);
  var i = keys.length;
  while (i--) {
    origin[keys[i]] = add[keys[i]];
  }
  return origin;
};

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

},{"_shims":1}],13:[function(require,module,exports){
exports.readIEEE754 = function(buffer, offset, isBE, mLen, nBytes) {
  var e, m,
      eLen = nBytes * 8 - mLen - 1,
      eMax = (1 << eLen) - 1,
      eBias = eMax >> 1,
      nBits = -7,
      i = isBE ? 0 : (nBytes - 1),
      d = isBE ? 1 : -1,
      s = buffer[offset + i];

  i += d;

  e = s & ((1 << (-nBits)) - 1);
  s >>= (-nBits);
  nBits += eLen;
  for (; nBits > 0; e = e * 256 + buffer[offset + i], i += d, nBits -= 8);

  m = e & ((1 << (-nBits)) - 1);
  e >>= (-nBits);
  nBits += mLen;
  for (; nBits > 0; m = m * 256 + buffer[offset + i], i += d, nBits -= 8);

  if (e === 0) {
    e = 1 - eBias;
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity);
  } else {
    m = m + Math.pow(2, mLen);
    e = e - eBias;
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen);
};

exports.writeIEEE754 = function(buffer, value, offset, isBE, mLen, nBytes) {
  var e, m, c,
      eLen = nBytes * 8 - mLen - 1,
      eMax = (1 << eLen) - 1,
      eBias = eMax >> 1,
      rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0),
      i = isBE ? (nBytes - 1) : 0,
      d = isBE ? -1 : 1,
      s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0;

  value = Math.abs(value);

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0;
    e = eMax;
  } else {
    e = Math.floor(Math.log(value) / Math.LN2);
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--;
      c *= 2;
    }
    if (e + eBias >= 1) {
      value += rt / c;
    } else {
      value += rt * Math.pow(2, 1 - eBias);
    }
    if (value * c >= 2) {
      e++;
      c /= 2;
    }

    if (e + eBias >= eMax) {
      m = 0;
      e = eMax;
    } else if (e + eBias >= 1) {
      m = (value * c - 1) * Math.pow(2, mLen);
      e = e + eBias;
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen);
      e = 0;
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8);

  e = (e << mLen) | m;
  eLen += mLen;
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8);

  buffer[offset + i - d] |= s * 128;
};

},{}],14:[function(require,module,exports){
var assert;
exports.Buffer = Buffer;
exports.SlowBuffer = Buffer;
Buffer.poolSize = 8192;
exports.INSPECT_MAX_BYTES = 50;

function stringtrim(str) {
  if (str.trim) return str.trim();
  return str.replace(/^\s+|\s+$/g, '');
}

function Buffer(subject, encoding, offset) {
  if(!assert) assert= require('assert');
  if (!(this instanceof Buffer)) {
    return new Buffer(subject, encoding, offset);
  }
  this.parent = this;
  this.offset = 0;

  // Work-around: node's base64 implementation
  // allows for non-padded strings while base64-js
  // does not..
  if (encoding == "base64" && typeof subject == "string") {
    subject = stringtrim(subject);
    while (subject.length % 4 != 0) {
      subject = subject + "="; 
    }
  }

  var type;

  // Are we slicing?
  if (typeof offset === 'number') {
    this.length = coerce(encoding);
    // slicing works, with limitations (no parent tracking/update)
    // check https://github.com/toots/buffer-browserify/issues/19
    for (var i = 0; i < this.length; i++) {
        this[i] = subject.get(i+offset);
    }
  } else {
    // Find the length
    switch (type = typeof subject) {
      case 'number':
        this.length = coerce(subject);
        break;

      case 'string':
        this.length = Buffer.byteLength(subject, encoding);
        break;

      case 'object': // Assume object is an array
        this.length = coerce(subject.length);
        break;

      default:
        throw new TypeError('First argument needs to be a number, ' +
                            'array or string.');
    }

    // Treat array-ish objects as a byte array.
    if (isArrayIsh(subject)) {
      for (var i = 0; i < this.length; i++) {
        if (subject instanceof Buffer) {
          this[i] = subject.readUInt8(i);
        }
        else {
          // Round-up subject[i] to a UInt8.
          // e.g.: ((-432 % 256) + 256) % 256 = (-176 + 256) % 256
          //                                  = 80
          this[i] = ((subject[i] % 256) + 256) % 256;
        }
      }
    } else if (type == 'string') {
      // We are a string
      this.length = this.write(subject, 0, encoding);
    } else if (type === 'number') {
      for (var i = 0; i < this.length; i++) {
        this[i] = 0;
      }
    }
  }
}

Buffer.prototype.get = function get(i) {
  if (i < 0 || i >= this.length) throw new Error('oob');
  return this[i];
};

Buffer.prototype.set = function set(i, v) {
  if (i < 0 || i >= this.length) throw new Error('oob');
  return this[i] = v;
};

Buffer.byteLength = function (str, encoding) {
  switch (encoding || "utf8") {
    case 'hex':
      return str.length / 2;

    case 'utf8':
    case 'utf-8':
      return utf8ToBytes(str).length;

    case 'ascii':
    case 'binary':
      return str.length;

    case 'base64':
      return base64ToBytes(str).length;

    default:
      throw new Error('Unknown encoding');
  }
};

Buffer.prototype.utf8Write = function (string, offset, length) {
  var bytes, pos;
  return Buffer._charsWritten =  blitBuffer(utf8ToBytes(string), this, offset, length);
};

Buffer.prototype.asciiWrite = function (string, offset, length) {
  var bytes, pos;
  return Buffer._charsWritten =  blitBuffer(asciiToBytes(string), this, offset, length);
};

Buffer.prototype.binaryWrite = Buffer.prototype.asciiWrite;

Buffer.prototype.base64Write = function (string, offset, length) {
  var bytes, pos;
  return Buffer._charsWritten = blitBuffer(base64ToBytes(string), this, offset, length);
};

Buffer.prototype.base64Slice = function (start, end) {
  var bytes = Array.prototype.slice.apply(this, arguments)
  return require("base64-js").fromByteArray(bytes);
};

Buffer.prototype.utf8Slice = function () {
  var bytes = Array.prototype.slice.apply(this, arguments);
  var res = "";
  var tmp = "";
  var i = 0;
  while (i < bytes.length) {
    if (bytes[i] <= 0x7F) {
      res += decodeUtf8Char(tmp) + String.fromCharCode(bytes[i]);
      tmp = "";
    } else
      tmp += "%" + bytes[i].toString(16);

    i++;
  }

  return res + decodeUtf8Char(tmp);
}

Buffer.prototype.asciiSlice = function () {
  var bytes = Array.prototype.slice.apply(this, arguments);
  var ret = "";
  for (var i = 0; i < bytes.length; i++)
    ret += String.fromCharCode(bytes[i]);
  return ret;
}

Buffer.prototype.binarySlice = Buffer.prototype.asciiSlice;

Buffer.prototype.inspect = function() {
  var out = [],
      len = this.length;
  for (var i = 0; i < len; i++) {
    out[i] = toHex(this[i]);
    if (i == exports.INSPECT_MAX_BYTES) {
      out[i + 1] = '...';
      break;
    }
  }
  return '<Buffer ' + out.join(' ') + '>';
};


Buffer.prototype.hexSlice = function(start, end) {
  var len = this.length;

  if (!start || start < 0) start = 0;
  if (!end || end < 0 || end > len) end = len;

  var out = '';
  for (var i = start; i < end; i++) {
    out += toHex(this[i]);
  }
  return out;
};


Buffer.prototype.toString = function(encoding, start, end) {
  encoding = String(encoding || 'utf8').toLowerCase();
  start = +start || 0;
  if (typeof end == 'undefined') end = this.length;

  // Fastpath empty strings
  if (+end == start) {
    return '';
  }

  switch (encoding) {
    case 'hex':
      return this.hexSlice(start, end);

    case 'utf8':
    case 'utf-8':
      return this.utf8Slice(start, end);

    case 'ascii':
      return this.asciiSlice(start, end);

    case 'binary':
      return this.binarySlice(start, end);

    case 'base64':
      return this.base64Slice(start, end);

    case 'ucs2':
    case 'ucs-2':
      return this.ucs2Slice(start, end);

    default:
      throw new Error('Unknown encoding');
  }
};


Buffer.prototype.hexWrite = function(string, offset, length) {
  offset = +offset || 0;
  var remaining = this.length - offset;
  if (!length) {
    length = remaining;
  } else {
    length = +length;
    if (length > remaining) {
      length = remaining;
    }
  }

  // must be an even number of digits
  var strLen = string.length;
  if (strLen % 2) {
    throw new Error('Invalid hex string');
  }
  if (length > strLen / 2) {
    length = strLen / 2;
  }
  for (var i = 0; i < length; i++) {
    var b = parseInt(string.substr(i * 2, 2), 16);
    if (isNaN(b)) throw new Error('Invalid hex string');
    this[offset + i] = b;
  }
  Buffer._charsWritten = i * 2;
  return i;
};


Buffer.prototype.write = function(string, offset, length, encoding) {
  // Support both (string, offset, length, encoding)
  // and the legacy (string, encoding, offset, length)
  if (isFinite(offset)) {
    if (!isFinite(length)) {
      encoding = length;
      length = undefined;
    }
  } else {  // legacy
    var swap = encoding;
    encoding = offset;
    offset = length;
    length = swap;
  }

  offset = +offset || 0;
  var remaining = this.length - offset;
  if (!length) {
    length = remaining;
  } else {
    length = +length;
    if (length > remaining) {
      length = remaining;
    }
  }
  encoding = String(encoding || 'utf8').toLowerCase();

  switch (encoding) {
    case 'hex':
      return this.hexWrite(string, offset, length);

    case 'utf8':
    case 'utf-8':
      return this.utf8Write(string, offset, length);

    case 'ascii':
      return this.asciiWrite(string, offset, length);

    case 'binary':
      return this.binaryWrite(string, offset, length);

    case 'base64':
      return this.base64Write(string, offset, length);

    case 'ucs2':
    case 'ucs-2':
      return this.ucs2Write(string, offset, length);

    default:
      throw new Error('Unknown encoding');
  }
};

// slice(start, end)
function clamp(index, len, defaultValue) {
  if (typeof index !== 'number') return defaultValue;
  index = ~~index;  // Coerce to integer.
  if (index >= len) return len;
  if (index >= 0) return index;
  index += len;
  if (index >= 0) return index;
  return 0;
}

Buffer.prototype.slice = function(start, end) {
  var len = this.length;
  start = clamp(start, len, 0);
  end = clamp(end, len, len);
  return new Buffer(this, end - start, +start);
};

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function(target, target_start, start, end) {
  var source = this;
  start || (start = 0);
  if (end === undefined || isNaN(end)) {
    end = this.length;
  }
  target_start || (target_start = 0);

  if (end < start) throw new Error('sourceEnd < sourceStart');

  // Copy 0 bytes; we're done
  if (end === start) return 0;
  if (target.length == 0 || source.length == 0) return 0;

  if (target_start < 0 || target_start >= target.length) {
    throw new Error('targetStart out of bounds');
  }

  if (start < 0 || start >= source.length) {
    throw new Error('sourceStart out of bounds');
  }

  if (end < 0 || end > source.length) {
    throw new Error('sourceEnd out of bounds');
  }

  // Are we oob?
  if (end > this.length) {
    end = this.length;
  }

  if (target.length - target_start < end - start) {
    end = target.length - target_start + start;
  }

  var temp = [];
  for (var i=start; i<end; i++) {
    assert.ok(typeof this[i] !== 'undefined', "copying undefined buffer bytes!");
    temp.push(this[i]);
  }

  for (var i=target_start; i<target_start+temp.length; i++) {
    target[i] = temp[i-target_start];
  }
};

// fill(value, start=0, end=buffer.length)
Buffer.prototype.fill = function fill(value, start, end) {
  value || (value = 0);
  start || (start = 0);
  end || (end = this.length);

  if (typeof value === 'string') {
    value = value.charCodeAt(0);
  }
  if (!(typeof value === 'number') || isNaN(value)) {
    throw new Error('value is not a number');
  }

  if (end < start) throw new Error('end < start');

  // Fill 0 bytes; we're done
  if (end === start) return 0;
  if (this.length == 0) return 0;

  if (start < 0 || start >= this.length) {
    throw new Error('start out of bounds');
  }

  if (end < 0 || end > this.length) {
    throw new Error('end out of bounds');
  }

  for (var i = start; i < end; i++) {
    this[i] = value;
  }
}

// Static methods
Buffer.isBuffer = function isBuffer(b) {
  return b instanceof Buffer;
};

Buffer.concat = function (list, totalLength) {
  if (!isArray(list)) {
    throw new Error("Usage: Buffer.concat(list, [totalLength])\n \
      list should be an Array.");
  }

  if (list.length === 0) {
    return new Buffer(0);
  } else if (list.length === 1) {
    return list[0];
  }

  if (typeof totalLength !== 'number') {
    totalLength = 0;
    for (var i = 0; i < list.length; i++) {
      var buf = list[i];
      totalLength += buf.length;
    }
  }

  var buffer = new Buffer(totalLength);
  var pos = 0;
  for (var i = 0; i < list.length; i++) {
    var buf = list[i];
    buf.copy(buffer, pos);
    pos += buf.length;
  }
  return buffer;
};

Buffer.isEncoding = function(encoding) {
  switch ((encoding + '').toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
    case 'raw':
      return true;

    default:
      return false;
  }
};

// helpers

function coerce(length) {
  // Coerce length to a number (possibly NaN), round up
  // in case it's fractional (e.g. 123.456) then do a
  // double negate to coerce a NaN to 0. Easy, right?
  length = ~~Math.ceil(+length);
  return length < 0 ? 0 : length;
}

function isArray(subject) {
  return (Array.isArray ||
    function(subject){
      return {}.toString.apply(subject) == '[object Array]'
    })
    (subject)
}

function isArrayIsh(subject) {
  return isArray(subject) || Buffer.isBuffer(subject) ||
         subject && typeof subject === 'object' &&
         typeof subject.length === 'number';
}

function toHex(n) {
  if (n < 16) return '0' + n.toString(16);
  return n.toString(16);
}

function utf8ToBytes(str) {
  var byteArray = [];
  for (var i = 0; i < str.length; i++)
    if (str.charCodeAt(i) <= 0x7F)
      byteArray.push(str.charCodeAt(i));
    else {
      var h = encodeURIComponent(str.charAt(i)).substr(1).split('%');
      for (var j = 0; j < h.length; j++)
        byteArray.push(parseInt(h[j], 16));
    }

  return byteArray;
}

function asciiToBytes(str) {
  var byteArray = []
  for (var i = 0; i < str.length; i++ )
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push( str.charCodeAt(i) & 0xFF );

  return byteArray;
}

function base64ToBytes(str) {
  return require("base64-js").toByteArray(str);
}

function blitBuffer(src, dst, offset, length) {
  var pos, i = 0;
  while (i < length) {
    if ((i+offset >= dst.length) || (i >= src.length))
      break;

    dst[i + offset] = src[i];
    i++;
  }
  return i;
}

function decodeUtf8Char(str) {
  try {
    return decodeURIComponent(str);
  } catch (err) {
    return String.fromCharCode(0xFFFD); // UTF 8 invalid char
  }
}

// read/write bit-twiddling

Buffer.prototype.readUInt8 = function(offset, noAssert) {
  var buffer = this;

  if (!noAssert) {
    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset < buffer.length,
        'Trying to read beyond buffer length');
  }

  if (offset >= buffer.length) return;

  return buffer[offset];
};

function readUInt16(buffer, offset, isBigEndian, noAssert) {
  var val = 0;


  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 1 < buffer.length,
        'Trying to read beyond buffer length');
  }

  if (offset >= buffer.length) return 0;

  if (isBigEndian) {
    val = buffer[offset] << 8;
    if (offset + 1 < buffer.length) {
      val |= buffer[offset + 1];
    }
  } else {
    val = buffer[offset];
    if (offset + 1 < buffer.length) {
      val |= buffer[offset + 1] << 8;
    }
  }

  return val;
}

Buffer.prototype.readUInt16LE = function(offset, noAssert) {
  return readUInt16(this, offset, false, noAssert);
};

Buffer.prototype.readUInt16BE = function(offset, noAssert) {
  return readUInt16(this, offset, true, noAssert);
};

function readUInt32(buffer, offset, isBigEndian, noAssert) {
  var val = 0;

  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 3 < buffer.length,
        'Trying to read beyond buffer length');
  }

  if (offset >= buffer.length) return 0;

  if (isBigEndian) {
    if (offset + 1 < buffer.length)
      val = buffer[offset + 1] << 16;
    if (offset + 2 < buffer.length)
      val |= buffer[offset + 2] << 8;
    if (offset + 3 < buffer.length)
      val |= buffer[offset + 3];
    val = val + (buffer[offset] << 24 >>> 0);
  } else {
    if (offset + 2 < buffer.length)
      val = buffer[offset + 2] << 16;
    if (offset + 1 < buffer.length)
      val |= buffer[offset + 1] << 8;
    val |= buffer[offset];
    if (offset + 3 < buffer.length)
      val = val + (buffer[offset + 3] << 24 >>> 0);
  }

  return val;
}

Buffer.prototype.readUInt32LE = function(offset, noAssert) {
  return readUInt32(this, offset, false, noAssert);
};

Buffer.prototype.readUInt32BE = function(offset, noAssert) {
  return readUInt32(this, offset, true, noAssert);
};


/*
 * Signed integer types, yay team! A reminder on how two's complement actually
 * works. The first bit is the signed bit, i.e. tells us whether or not the
 * number should be positive or negative. If the two's complement value is
 * positive, then we're done, as it's equivalent to the unsigned representation.
 *
 * Now if the number is positive, you're pretty much done, you can just leverage
 * the unsigned translations and return those. Unfortunately, negative numbers
 * aren't quite that straightforward.
 *
 * At first glance, one might be inclined to use the traditional formula to
 * translate binary numbers between the positive and negative values in two's
 * complement. (Though it doesn't quite work for the most negative value)
 * Mainly:
 *  - invert all the bits
 *  - add one to the result
 *
 * Of course, this doesn't quite work in Javascript. Take for example the value
 * of -128. This could be represented in 16 bits (big-endian) as 0xff80. But of
 * course, Javascript will do the following:
 *
 * > ~0xff80
 * -65409
 *
 * Whoh there, Javascript, that's not quite right. But wait, according to
 * Javascript that's perfectly correct. When Javascript ends up seeing the
 * constant 0xff80, it has no notion that it is actually a signed number. It
 * assumes that we've input the unsigned value 0xff80. Thus, when it does the
 * binary negation, it casts it into a signed value, (positive 0xff80). Then
 * when you perform binary negation on that, it turns it into a negative number.
 *
 * Instead, we're going to have to use the following general formula, that works
 * in a rather Javascript friendly way. I'm glad we don't support this kind of
 * weird numbering scheme in the kernel.
 *
 * (BIT-MAX - (unsigned)val + 1) * -1
 *
 * The astute observer, may think that this doesn't make sense for 8-bit numbers
 * (really it isn't necessary for them). However, when you get 16-bit numbers,
 * you do. Let's go back to our prior example and see how this will look:
 *
 * (0xffff - 0xff80 + 1) * -1
 * (0x007f + 1) * -1
 * (0x0080) * -1
 */
Buffer.prototype.readInt8 = function(offset, noAssert) {
  var buffer = this;
  var neg;

  if (!noAssert) {
    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset < buffer.length,
        'Trying to read beyond buffer length');
  }

  if (offset >= buffer.length) return;

  neg = buffer[offset] & 0x80;
  if (!neg) {
    return (buffer[offset]);
  }

  return ((0xff - buffer[offset] + 1) * -1);
};

function readInt16(buffer, offset, isBigEndian, noAssert) {
  var neg, val;

  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 1 < buffer.length,
        'Trying to read beyond buffer length');
  }

  val = readUInt16(buffer, offset, isBigEndian, noAssert);
  neg = val & 0x8000;
  if (!neg) {
    return val;
  }

  return (0xffff - val + 1) * -1;
}

Buffer.prototype.readInt16LE = function(offset, noAssert) {
  return readInt16(this, offset, false, noAssert);
};

Buffer.prototype.readInt16BE = function(offset, noAssert) {
  return readInt16(this, offset, true, noAssert);
};

function readInt32(buffer, offset, isBigEndian, noAssert) {
  var neg, val;

  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 3 < buffer.length,
        'Trying to read beyond buffer length');
  }

  val = readUInt32(buffer, offset, isBigEndian, noAssert);
  neg = val & 0x80000000;
  if (!neg) {
    return (val);
  }

  return (0xffffffff - val + 1) * -1;
}

Buffer.prototype.readInt32LE = function(offset, noAssert) {
  return readInt32(this, offset, false, noAssert);
};

Buffer.prototype.readInt32BE = function(offset, noAssert) {
  return readInt32(this, offset, true, noAssert);
};

function readFloat(buffer, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset + 3 < buffer.length,
        'Trying to read beyond buffer length');
  }

  return require('./buffer_ieee754').readIEEE754(buffer, offset, isBigEndian,
      23, 4);
}

Buffer.prototype.readFloatLE = function(offset, noAssert) {
  return readFloat(this, offset, false, noAssert);
};

Buffer.prototype.readFloatBE = function(offset, noAssert) {
  return readFloat(this, offset, true, noAssert);
};

function readDouble(buffer, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset + 7 < buffer.length,
        'Trying to read beyond buffer length');
  }

  return require('./buffer_ieee754').readIEEE754(buffer, offset, isBigEndian,
      52, 8);
}

Buffer.prototype.readDoubleLE = function(offset, noAssert) {
  return readDouble(this, offset, false, noAssert);
};

Buffer.prototype.readDoubleBE = function(offset, noAssert) {
  return readDouble(this, offset, true, noAssert);
};


/*
 * We have to make sure that the value is a valid integer. This means that it is
 * non-negative. It has no fractional component and that it does not exceed the
 * maximum allowed value.
 *
 *      value           The number to check for validity
 *
 *      max             The maximum value
 */
function verifuint(value, max) {
  assert.ok(typeof (value) == 'number',
      'cannot write a non-number as a number');

  assert.ok(value >= 0,
      'specified a negative value for writing an unsigned value');

  assert.ok(value <= max, 'value is larger than maximum value for type');

  assert.ok(Math.floor(value) === value, 'value has a fractional component');
}

Buffer.prototype.writeUInt8 = function(value, offset, noAssert) {
  var buffer = this;

  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset < buffer.length,
        'trying to write beyond buffer length');

    verifuint(value, 0xff);
  }

  if (offset < buffer.length) {
    buffer[offset] = value;
  }
};

function writeUInt16(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 1 < buffer.length,
        'trying to write beyond buffer length');

    verifuint(value, 0xffff);
  }

  for (var i = 0; i < Math.min(buffer.length - offset, 2); i++) {
    buffer[offset + i] =
        (value & (0xff << (8 * (isBigEndian ? 1 - i : i)))) >>>
            (isBigEndian ? 1 - i : i) * 8;
  }

}

Buffer.prototype.writeUInt16LE = function(value, offset, noAssert) {
  writeUInt16(this, value, offset, false, noAssert);
};

Buffer.prototype.writeUInt16BE = function(value, offset, noAssert) {
  writeUInt16(this, value, offset, true, noAssert);
};

function writeUInt32(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 3 < buffer.length,
        'trying to write beyond buffer length');

    verifuint(value, 0xffffffff);
  }

  for (var i = 0; i < Math.min(buffer.length - offset, 4); i++) {
    buffer[offset + i] =
        (value >>> (isBigEndian ? 3 - i : i) * 8) & 0xff;
  }
}

Buffer.prototype.writeUInt32LE = function(value, offset, noAssert) {
  writeUInt32(this, value, offset, false, noAssert);
};

Buffer.prototype.writeUInt32BE = function(value, offset, noAssert) {
  writeUInt32(this, value, offset, true, noAssert);
};


/*
 * We now move onto our friends in the signed number category. Unlike unsigned
 * numbers, we're going to have to worry a bit more about how we put values into
 * arrays. Since we are only worrying about signed 32-bit values, we're in
 * slightly better shape. Unfortunately, we really can't do our favorite binary
 * & in this system. It really seems to do the wrong thing. For example:
 *
 * > -32 & 0xff
 * 224
 *
 * What's happening above is really: 0xe0 & 0xff = 0xe0. However, the results of
 * this aren't treated as a signed number. Ultimately a bad thing.
 *
 * What we're going to want to do is basically create the unsigned equivalent of
 * our representation and pass that off to the wuint* functions. To do that
 * we're going to do the following:
 *
 *  - if the value is positive
 *      we can pass it directly off to the equivalent wuint
 *  - if the value is negative
 *      we do the following computation:
 *         mb + val + 1, where
 *         mb   is the maximum unsigned value in that byte size
 *         val  is the Javascript negative integer
 *
 *
 * As a concrete value, take -128. In signed 16 bits this would be 0xff80. If
 * you do out the computations:
 *
 * 0xffff - 128 + 1
 * 0xffff - 127
 * 0xff80
 *
 * You can then encode this value as the signed version. This is really rather
 * hacky, but it should work and get the job done which is our goal here.
 */

/*
 * A series of checks to make sure we actually have a signed 32-bit number
 */
function verifsint(value, max, min) {
  assert.ok(typeof (value) == 'number',
      'cannot write a non-number as a number');

  assert.ok(value <= max, 'value larger than maximum allowed value');

  assert.ok(value >= min, 'value smaller than minimum allowed value');

  assert.ok(Math.floor(value) === value, 'value has a fractional component');
}

function verifIEEE754(value, max, min) {
  assert.ok(typeof (value) == 'number',
      'cannot write a non-number as a number');

  assert.ok(value <= max, 'value larger than maximum allowed value');

  assert.ok(value >= min, 'value smaller than minimum allowed value');
}

Buffer.prototype.writeInt8 = function(value, offset, noAssert) {
  var buffer = this;

  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset < buffer.length,
        'Trying to write beyond buffer length');

    verifsint(value, 0x7f, -0x80);
  }

  if (value >= 0) {
    buffer.writeUInt8(value, offset, noAssert);
  } else {
    buffer.writeUInt8(0xff + value + 1, offset, noAssert);
  }
};

function writeInt16(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 1 < buffer.length,
        'Trying to write beyond buffer length');

    verifsint(value, 0x7fff, -0x8000);
  }

  if (value >= 0) {
    writeUInt16(buffer, value, offset, isBigEndian, noAssert);
  } else {
    writeUInt16(buffer, 0xffff + value + 1, offset, isBigEndian, noAssert);
  }
}

Buffer.prototype.writeInt16LE = function(value, offset, noAssert) {
  writeInt16(this, value, offset, false, noAssert);
};

Buffer.prototype.writeInt16BE = function(value, offset, noAssert) {
  writeInt16(this, value, offset, true, noAssert);
};

function writeInt32(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 3 < buffer.length,
        'Trying to write beyond buffer length');

    verifsint(value, 0x7fffffff, -0x80000000);
  }

  if (value >= 0) {
    writeUInt32(buffer, value, offset, isBigEndian, noAssert);
  } else {
    writeUInt32(buffer, 0xffffffff + value + 1, offset, isBigEndian, noAssert);
  }
}

Buffer.prototype.writeInt32LE = function(value, offset, noAssert) {
  writeInt32(this, value, offset, false, noAssert);
};

Buffer.prototype.writeInt32BE = function(value, offset, noAssert) {
  writeInt32(this, value, offset, true, noAssert);
};

function writeFloat(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 3 < buffer.length,
        'Trying to write beyond buffer length');

    verifIEEE754(value, 3.4028234663852886e+38, -3.4028234663852886e+38);
  }

  require('./buffer_ieee754').writeIEEE754(buffer, value, offset, isBigEndian,
      23, 4);
}

Buffer.prototype.writeFloatLE = function(value, offset, noAssert) {
  writeFloat(this, value, offset, false, noAssert);
};

Buffer.prototype.writeFloatBE = function(value, offset, noAssert) {
  writeFloat(this, value, offset, true, noAssert);
};

function writeDouble(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 7 < buffer.length,
        'Trying to write beyond buffer length');

    verifIEEE754(value, 1.7976931348623157E+308, -1.7976931348623157E+308);
  }

  require('./buffer_ieee754').writeIEEE754(buffer, value, offset, isBigEndian,
      52, 8);
}

Buffer.prototype.writeDoubleLE = function(value, offset, noAssert) {
  writeDouble(this, value, offset, false, noAssert);
};

Buffer.prototype.writeDoubleBE = function(value, offset, noAssert) {
  writeDouble(this, value, offset, true, noAssert);
};

},{"./buffer_ieee754":13,"assert":7,"base64-js":15}],15:[function(require,module,exports){
var lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

;(function (exports) {
	'use strict';

  var Arr = (typeof Uint8Array !== 'undefined')
    ? Uint8Array
    : Array

	var PLUS   = '+'.charCodeAt(0)
	var SLASH  = '/'.charCodeAt(0)
	var NUMBER = '0'.charCodeAt(0)
	var LOWER  = 'a'.charCodeAt(0)
	var UPPER  = 'A'.charCodeAt(0)
	var PLUS_URL_SAFE = '-'.charCodeAt(0)
	var SLASH_URL_SAFE = '_'.charCodeAt(0)

	function decode (elt) {
		var code = elt.charCodeAt(0)
		if (code === PLUS ||
		    code === PLUS_URL_SAFE)
			return 62 // '+'
		if (code === SLASH ||
		    code === SLASH_URL_SAFE)
			return 63 // '/'
		if (code < NUMBER)
			return -1 //no match
		if (code < NUMBER + 10)
			return code - NUMBER + 26 + 26
		if (code < UPPER + 26)
			return code - UPPER
		if (code < LOWER + 26)
			return code - LOWER + 26
	}

	function b64ToByteArray (b64) {
		var i, j, l, tmp, placeHolders, arr

		if (b64.length % 4 > 0) {
			throw new Error('Invalid string. Length must be a multiple of 4')
		}

		// the number of equal signs (place holders)
		// if there are two placeholders, than the two characters before it
		// represent one byte
		// if there is only one, then the three characters before it represent 2 bytes
		// this is just a cheap hack to not do indexOf twice
		var len = b64.length
		placeHolders = '=' === b64.charAt(len - 2) ? 2 : '=' === b64.charAt(len - 1) ? 1 : 0

		// base64 is 4/3 + up to two characters of the original data
		arr = new Arr(b64.length * 3 / 4 - placeHolders)

		// if there are placeholders, only get up to the last complete 4 chars
		l = placeHolders > 0 ? b64.length - 4 : b64.length

		var L = 0

		function push (v) {
			arr[L++] = v
		}

		for (i = 0, j = 0; i < l; i += 4, j += 3) {
			tmp = (decode(b64.charAt(i)) << 18) | (decode(b64.charAt(i + 1)) << 12) | (decode(b64.charAt(i + 2)) << 6) | decode(b64.charAt(i + 3))
			push((tmp & 0xFF0000) >> 16)
			push((tmp & 0xFF00) >> 8)
			push(tmp & 0xFF)
		}

		if (placeHolders === 2) {
			tmp = (decode(b64.charAt(i)) << 2) | (decode(b64.charAt(i + 1)) >> 4)
			push(tmp & 0xFF)
		} else if (placeHolders === 1) {
			tmp = (decode(b64.charAt(i)) << 10) | (decode(b64.charAt(i + 1)) << 4) | (decode(b64.charAt(i + 2)) >> 2)
			push((tmp >> 8) & 0xFF)
			push(tmp & 0xFF)
		}

		return arr
	}

	function uint8ToBase64 (uint8) {
		var i,
			extraBytes = uint8.length % 3, // if we have 1 byte left, pad 2 bytes
			output = "",
			temp, length

		function encode (num) {
			return lookup.charAt(num)
		}

		function tripletToBase64 (num) {
			return encode(num >> 18 & 0x3F) + encode(num >> 12 & 0x3F) + encode(num >> 6 & 0x3F) + encode(num & 0x3F)
		}

		// go through the array every three bytes, we'll deal with trailing stuff later
		for (i = 0, length = uint8.length - extraBytes; i < length; i += 3) {
			temp = (uint8[i] << 16) + (uint8[i + 1] << 8) + (uint8[i + 2])
			output += tripletToBase64(temp)
		}

		// pad the end with zeros, but make sure to not forget the extra bytes
		switch (extraBytes) {
			case 1:
				temp = uint8[uint8.length - 1]
				output += encode(temp >> 2)
				output += encode((temp << 4) & 0x3F)
				output += '=='
				break
			case 2:
				temp = (uint8[uint8.length - 2] << 8) + (uint8[uint8.length - 1])
				output += encode(temp >> 10)
				output += encode((temp >> 4) & 0x3F)
				output += encode((temp << 2) & 0x3F)
				output += '='
				break
		}

		return output
	}

	exports.toByteArray = b64ToByteArray
	exports.fromByteArray = uint8ToBase64
}(typeof exports === 'undefined' ? (this.base64js = {}) : exports))

},{}],16:[function(require,module,exports){
require=(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);throw new Error("Cannot find module '"+o+"'")}var f=n[o]={exports:{}};t[o][0].call(f.exports,function(e){var n=t[o][1][e];return s(n?n:e)},f,f.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
exports.readIEEE754 = function(buffer, offset, isBE, mLen, nBytes) {
  var e, m,
      eLen = nBytes * 8 - mLen - 1,
      eMax = (1 << eLen) - 1,
      eBias = eMax >> 1,
      nBits = -7,
      i = isBE ? 0 : (nBytes - 1),
      d = isBE ? 1 : -1,
      s = buffer[offset + i];

  i += d;

  e = s & ((1 << (-nBits)) - 1);
  s >>= (-nBits);
  nBits += eLen;
  for (; nBits > 0; e = e * 256 + buffer[offset + i], i += d, nBits -= 8);

  m = e & ((1 << (-nBits)) - 1);
  e >>= (-nBits);
  nBits += mLen;
  for (; nBits > 0; m = m * 256 + buffer[offset + i], i += d, nBits -= 8);

  if (e === 0) {
    e = 1 - eBias;
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity);
  } else {
    m = m + Math.pow(2, mLen);
    e = e - eBias;
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen);
};

exports.writeIEEE754 = function(buffer, value, offset, isBE, mLen, nBytes) {
  var e, m, c,
      eLen = nBytes * 8 - mLen - 1,
      eMax = (1 << eLen) - 1,
      eBias = eMax >> 1,
      rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0),
      i = isBE ? (nBytes - 1) : 0,
      d = isBE ? -1 : 1,
      s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0;

  value = Math.abs(value);

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0;
    e = eMax;
  } else {
    e = Math.floor(Math.log(value) / Math.LN2);
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--;
      c *= 2;
    }
    if (e + eBias >= 1) {
      value += rt / c;
    } else {
      value += rt * Math.pow(2, 1 - eBias);
    }
    if (value * c >= 2) {
      e++;
      c /= 2;
    }

    if (e + eBias >= eMax) {
      m = 0;
      e = eMax;
    } else if (e + eBias >= 1) {
      m = (value * c - 1) * Math.pow(2, mLen);
      e = e + eBias;
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen);
      e = 0;
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8);

  e = (e << mLen) | m;
  eLen += mLen;
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8);

  buffer[offset + i - d] |= s * 128;
};

},{}],"q9TxCC":[function(require,module,exports){
var assert;
exports.Buffer = Buffer;
exports.SlowBuffer = Buffer;
Buffer.poolSize = 8192;
exports.INSPECT_MAX_BYTES = 50;

function stringtrim(str) {
  if (str.trim) return str.trim();
  return str.replace(/^\s+|\s+$/g, '');
}

function Buffer(subject, encoding, offset) {
  if(!assert) assert= require('assert');
  if (!(this instanceof Buffer)) {
    return new Buffer(subject, encoding, offset);
  }
  this.parent = this;
  this.offset = 0;

  // Work-around: node's base64 implementation
  // allows for non-padded strings while base64-js
  // does not..
  if (encoding == "base64" && typeof subject == "string") {
    subject = stringtrim(subject);
    while (subject.length % 4 != 0) {
      subject = subject + "="; 
    }
  }

  var type;

  // Are we slicing?
  if (typeof offset === 'number') {
    this.length = coerce(encoding);
    // slicing works, with limitations (no parent tracking/update)
    // check https://github.com/toots/buffer-browserify/issues/19
    for (var i = 0; i < this.length; i++) {
        this[i] = subject.get(i+offset);
    }
  } else {
    // Find the length
    switch (type = typeof subject) {
      case 'number':
        this.length = coerce(subject);
        break;

      case 'string':
        this.length = Buffer.byteLength(subject, encoding);
        break;

      case 'object': // Assume object is an array
        this.length = coerce(subject.length);
        break;

      default:
        throw new Error('First argument needs to be a number, ' +
                        'array or string.');
    }

    // Treat array-ish objects as a byte array.
    if (isArrayIsh(subject)) {
      for (var i = 0; i < this.length; i++) {
        if (subject instanceof Buffer) {
          this[i] = subject.readUInt8(i);
        }
        else {
          this[i] = subject[i];
        }
      }
    } else if (type == 'string') {
      // We are a string
      this.length = this.write(subject, 0, encoding);
    } else if (type === 'number') {
      for (var i = 0; i < this.length; i++) {
        this[i] = 0;
      }
    }
  }
}

Buffer.prototype.get = function get(i) {
  if (i < 0 || i >= this.length) throw new Error('oob');
  return this[i];
};

Buffer.prototype.set = function set(i, v) {
  if (i < 0 || i >= this.length) throw new Error('oob');
  return this[i] = v;
};

Buffer.byteLength = function (str, encoding) {
  switch (encoding || "utf8") {
    case 'hex':
      return str.length / 2;

    case 'utf8':
    case 'utf-8':
      return utf8ToBytes(str).length;

    case 'ascii':
    case 'binary':
      return str.length;

    case 'base64':
      return base64ToBytes(str).length;

    default:
      throw new Error('Unknown encoding');
  }
};

Buffer.prototype.utf8Write = function (string, offset, length) {
  var bytes, pos;
  return Buffer._charsWritten =  blitBuffer(utf8ToBytes(string), this, offset, length);
};

Buffer.prototype.asciiWrite = function (string, offset, length) {
  var bytes, pos;
  return Buffer._charsWritten =  blitBuffer(asciiToBytes(string), this, offset, length);
};

Buffer.prototype.binaryWrite = Buffer.prototype.asciiWrite;

Buffer.prototype.base64Write = function (string, offset, length) {
  var bytes, pos;
  return Buffer._charsWritten = blitBuffer(base64ToBytes(string), this, offset, length);
};

Buffer.prototype.base64Slice = function (start, end) {
  var bytes = Array.prototype.slice.apply(this, arguments)
  return require("base64-js").fromByteArray(bytes);
};

Buffer.prototype.utf8Slice = function () {
  var bytes = Array.prototype.slice.apply(this, arguments);
  var res = "";
  var tmp = "";
  var i = 0;
  while (i < bytes.length) {
    if (bytes[i] <= 0x7F) {
      res += decodeUtf8Char(tmp) + String.fromCharCode(bytes[i]);
      tmp = "";
    } else
      tmp += "%" + bytes[i].toString(16);

    i++;
  }

  return res + decodeUtf8Char(tmp);
}

Buffer.prototype.asciiSlice = function () {
  var bytes = Array.prototype.slice.apply(this, arguments);
  var ret = "";
  for (var i = 0; i < bytes.length; i++)
    ret += String.fromCharCode(bytes[i]);
  return ret;
}

Buffer.prototype.binarySlice = Buffer.prototype.asciiSlice;

Buffer.prototype.inspect = function() {
  var out = [],
      len = this.length;
  for (var i = 0; i < len; i++) {
    out[i] = toHex(this[i]);
    if (i == exports.INSPECT_MAX_BYTES) {
      out[i + 1] = '...';
      break;
    }
  }
  return '<Buffer ' + out.join(' ') + '>';
};


Buffer.prototype.hexSlice = function(start, end) {
  var len = this.length;

  if (!start || start < 0) start = 0;
  if (!end || end < 0 || end > len) end = len;

  var out = '';
  for (var i = start; i < end; i++) {
    out += toHex(this[i]);
  }
  return out;
};


Buffer.prototype.toString = function(encoding, start, end) {
  encoding = String(encoding || 'utf8').toLowerCase();
  start = +start || 0;
  if (typeof end == 'undefined') end = this.length;

  // Fastpath empty strings
  if (+end == start) {
    return '';
  }

  switch (encoding) {
    case 'hex':
      return this.hexSlice(start, end);

    case 'utf8':
    case 'utf-8':
      return this.utf8Slice(start, end);

    case 'ascii':
      return this.asciiSlice(start, end);

    case 'binary':
      return this.binarySlice(start, end);

    case 'base64':
      return this.base64Slice(start, end);

    case 'ucs2':
    case 'ucs-2':
      return this.ucs2Slice(start, end);

    default:
      throw new Error('Unknown encoding');
  }
};


Buffer.prototype.hexWrite = function(string, offset, length) {
  offset = +offset || 0;
  var remaining = this.length - offset;
  if (!length) {
    length = remaining;
  } else {
    length = +length;
    if (length > remaining) {
      length = remaining;
    }
  }

  // must be an even number of digits
  var strLen = string.length;
  if (strLen % 2) {
    throw new Error('Invalid hex string');
  }
  if (length > strLen / 2) {
    length = strLen / 2;
  }
  for (var i = 0; i < length; i++) {
    var byte = parseInt(string.substr(i * 2, 2), 16);
    if (isNaN(byte)) throw new Error('Invalid hex string');
    this[offset + i] = byte;
  }
  Buffer._charsWritten = i * 2;
  return i;
};


Buffer.prototype.write = function(string, offset, length, encoding) {
  // Support both (string, offset, length, encoding)
  // and the legacy (string, encoding, offset, length)
  if (isFinite(offset)) {
    if (!isFinite(length)) {
      encoding = length;
      length = undefined;
    }
  } else {  // legacy
    var swap = encoding;
    encoding = offset;
    offset = length;
    length = swap;
  }

  offset = +offset || 0;
  var remaining = this.length - offset;
  if (!length) {
    length = remaining;
  } else {
    length = +length;
    if (length > remaining) {
      length = remaining;
    }
  }
  encoding = String(encoding || 'utf8').toLowerCase();

  switch (encoding) {
    case 'hex':
      return this.hexWrite(string, offset, length);

    case 'utf8':
    case 'utf-8':
      return this.utf8Write(string, offset, length);

    case 'ascii':
      return this.asciiWrite(string, offset, length);

    case 'binary':
      return this.binaryWrite(string, offset, length);

    case 'base64':
      return this.base64Write(string, offset, length);

    case 'ucs2':
    case 'ucs-2':
      return this.ucs2Write(string, offset, length);

    default:
      throw new Error('Unknown encoding');
  }
};

// slice(start, end)
function clamp(index, len, defaultValue) {
  if (typeof index !== 'number') return defaultValue;
  index = ~~index;  // Coerce to integer.
  if (index >= len) return len;
  if (index >= 0) return index;
  index += len;
  if (index >= 0) return index;
  return 0;
}

Buffer.prototype.slice = function(start, end) {
  var len = this.length;
  start = clamp(start, len, 0);
  end = clamp(end, len, len);
  return new Buffer(this, end - start, +start);
};

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function(target, target_start, start, end) {
  var source = this;
  start || (start = 0);
  if (end === undefined || isNaN(end)) {
    end = this.length;
  }
  target_start || (target_start = 0);

  if (end < start) throw new Error('sourceEnd < sourceStart');

  // Copy 0 bytes; we're done
  if (end === start) return 0;
  if (target.length == 0 || source.length == 0) return 0;

  if (target_start < 0 || target_start >= target.length) {
    throw new Error('targetStart out of bounds');
  }

  if (start < 0 || start >= source.length) {
    throw new Error('sourceStart out of bounds');
  }

  if (end < 0 || end > source.length) {
    throw new Error('sourceEnd out of bounds');
  }

  // Are we oob?
  if (end > this.length) {
    end = this.length;
  }

  if (target.length - target_start < end - start) {
    end = target.length - target_start + start;
  }

  var temp = [];
  for (var i=start; i<end; i++) {
    assert.ok(typeof this[i] !== 'undefined', "copying undefined buffer bytes!");
    temp.push(this[i]);
  }

  for (var i=target_start; i<target_start+temp.length; i++) {
    target[i] = temp[i-target_start];
  }
};

// fill(value, start=0, end=buffer.length)
Buffer.prototype.fill = function fill(value, start, end) {
  value || (value = 0);
  start || (start = 0);
  end || (end = this.length);

  if (typeof value === 'string') {
    value = value.charCodeAt(0);
  }
  if (!(typeof value === 'number') || isNaN(value)) {
    throw new Error('value is not a number');
  }

  if (end < start) throw new Error('end < start');

  // Fill 0 bytes; we're done
  if (end === start) return 0;
  if (this.length == 0) return 0;

  if (start < 0 || start >= this.length) {
    throw new Error('start out of bounds');
  }

  if (end < 0 || end > this.length) {
    throw new Error('end out of bounds');
  }

  for (var i = start; i < end; i++) {
    this[i] = value;
  }
}

// Static methods
Buffer.isBuffer = function isBuffer(b) {
  return b instanceof Buffer || b instanceof Buffer;
};

Buffer.concat = function (list, totalLength) {
  if (!isArray(list)) {
    throw new Error("Usage: Buffer.concat(list, [totalLength])\n \
      list should be an Array.");
  }

  if (list.length === 0) {
    return new Buffer(0);
  } else if (list.length === 1) {
    return list[0];
  }

  if (typeof totalLength !== 'number') {
    totalLength = 0;
    for (var i = 0; i < list.length; i++) {
      var buf = list[i];
      totalLength += buf.length;
    }
  }

  var buffer = new Buffer(totalLength);
  var pos = 0;
  for (var i = 0; i < list.length; i++) {
    var buf = list[i];
    buf.copy(buffer, pos);
    pos += buf.length;
  }
  return buffer;
};

Buffer.isEncoding = function(encoding) {
  switch ((encoding + '').toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
    case 'raw':
      return true;

    default:
      return false;
  }
};

// helpers

function coerce(length) {
  // Coerce length to a number (possibly NaN), round up
  // in case it's fractional (e.g. 123.456) then do a
  // double negate to coerce a NaN to 0. Easy, right?
  length = ~~Math.ceil(+length);
  return length < 0 ? 0 : length;
}

function isArray(subject) {
  return (Array.isArray ||
    function(subject){
      return {}.toString.apply(subject) == '[object Array]'
    })
    (subject)
}

function isArrayIsh(subject) {
  return isArray(subject) || Buffer.isBuffer(subject) ||
         subject && typeof subject === 'object' &&
         typeof subject.length === 'number';
}

function toHex(n) {
  if (n < 16) return '0' + n.toString(16);
  return n.toString(16);
}

function utf8ToBytes(str) {
  var byteArray = [];
  for (var i = 0; i < str.length; i++)
    if (str.charCodeAt(i) <= 0x7F)
      byteArray.push(str.charCodeAt(i));
    else {
      var h = encodeURIComponent(str.charAt(i)).substr(1).split('%');
      for (var j = 0; j < h.length; j++)
        byteArray.push(parseInt(h[j], 16));
    }

  return byteArray;
}

function asciiToBytes(str) {
  var byteArray = []
  for (var i = 0; i < str.length; i++ )
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push( str.charCodeAt(i) & 0xFF );

  return byteArray;
}

function base64ToBytes(str) {
  return require("base64-js").toByteArray(str);
}

function blitBuffer(src, dst, offset, length) {
  var pos, i = 0;
  while (i < length) {
    if ((i+offset >= dst.length) || (i >= src.length))
      break;

    dst[i + offset] = src[i];
    i++;
  }
  return i;
}

function decodeUtf8Char(str) {
  try {
    return decodeURIComponent(str);
  } catch (err) {
    return String.fromCharCode(0xFFFD); // UTF 8 invalid char
  }
}

// read/write bit-twiddling

Buffer.prototype.readUInt8 = function(offset, noAssert) {
  var buffer = this;

  if (!noAssert) {
    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset < buffer.length,
        'Trying to read beyond buffer length');
  }

  if (offset >= buffer.length) return;

  return buffer[offset];
};

function readUInt16(buffer, offset, isBigEndian, noAssert) {
  var val = 0;


  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 1 < buffer.length,
        'Trying to read beyond buffer length');
  }

  if (offset >= buffer.length) return 0;

  if (isBigEndian) {
    val = buffer[offset] << 8;
    if (offset + 1 < buffer.length) {
      val |= buffer[offset + 1];
    }
  } else {
    val = buffer[offset];
    if (offset + 1 < buffer.length) {
      val |= buffer[offset + 1] << 8;
    }
  }

  return val;
}

Buffer.prototype.readUInt16LE = function(offset, noAssert) {
  return readUInt16(this, offset, false, noAssert);
};

Buffer.prototype.readUInt16BE = function(offset, noAssert) {
  return readUInt16(this, offset, true, noAssert);
};

function readUInt32(buffer, offset, isBigEndian, noAssert) {
  var val = 0;

  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 3 < buffer.length,
        'Trying to read beyond buffer length');
  }

  if (offset >= buffer.length) return 0;

  if (isBigEndian) {
    if (offset + 1 < buffer.length)
      val = buffer[offset + 1] << 16;
    if (offset + 2 < buffer.length)
      val |= buffer[offset + 2] << 8;
    if (offset + 3 < buffer.length)
      val |= buffer[offset + 3];
    val = val + (buffer[offset] << 24 >>> 0);
  } else {
    if (offset + 2 < buffer.length)
      val = buffer[offset + 2] << 16;
    if (offset + 1 < buffer.length)
      val |= buffer[offset + 1] << 8;
    val |= buffer[offset];
    if (offset + 3 < buffer.length)
      val = val + (buffer[offset + 3] << 24 >>> 0);
  }

  return val;
}

Buffer.prototype.readUInt32LE = function(offset, noAssert) {
  return readUInt32(this, offset, false, noAssert);
};

Buffer.prototype.readUInt32BE = function(offset, noAssert) {
  return readUInt32(this, offset, true, noAssert);
};


/*
 * Signed integer types, yay team! A reminder on how two's complement actually
 * works. The first bit is the signed bit, i.e. tells us whether or not the
 * number should be positive or negative. If the two's complement value is
 * positive, then we're done, as it's equivalent to the unsigned representation.
 *
 * Now if the number is positive, you're pretty much done, you can just leverage
 * the unsigned translations and return those. Unfortunately, negative numbers
 * aren't quite that straightforward.
 *
 * At first glance, one might be inclined to use the traditional formula to
 * translate binary numbers between the positive and negative values in two's
 * complement. (Though it doesn't quite work for the most negative value)
 * Mainly:
 *  - invert all the bits
 *  - add one to the result
 *
 * Of course, this doesn't quite work in Javascript. Take for example the value
 * of -128. This could be represented in 16 bits (big-endian) as 0xff80. But of
 * course, Javascript will do the following:
 *
 * > ~0xff80
 * -65409
 *
 * Whoh there, Javascript, that's not quite right. But wait, according to
 * Javascript that's perfectly correct. When Javascript ends up seeing the
 * constant 0xff80, it has no notion that it is actually a signed number. It
 * assumes that we've input the unsigned value 0xff80. Thus, when it does the
 * binary negation, it casts it into a signed value, (positive 0xff80). Then
 * when you perform binary negation on that, it turns it into a negative number.
 *
 * Instead, we're going to have to use the following general formula, that works
 * in a rather Javascript friendly way. I'm glad we don't support this kind of
 * weird numbering scheme in the kernel.
 *
 * (BIT-MAX - (unsigned)val + 1) * -1
 *
 * The astute observer, may think that this doesn't make sense for 8-bit numbers
 * (really it isn't necessary for them). However, when you get 16-bit numbers,
 * you do. Let's go back to our prior example and see how this will look:
 *
 * (0xffff - 0xff80 + 1) * -1
 * (0x007f + 1) * -1
 * (0x0080) * -1
 */
Buffer.prototype.readInt8 = function(offset, noAssert) {
  var buffer = this;
  var neg;

  if (!noAssert) {
    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset < buffer.length,
        'Trying to read beyond buffer length');
  }

  if (offset >= buffer.length) return;

  neg = buffer[offset] & 0x80;
  if (!neg) {
    return (buffer[offset]);
  }

  return ((0xff - buffer[offset] + 1) * -1);
};

function readInt16(buffer, offset, isBigEndian, noAssert) {
  var neg, val;

  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 1 < buffer.length,
        'Trying to read beyond buffer length');
  }

  val = readUInt16(buffer, offset, isBigEndian, noAssert);
  neg = val & 0x8000;
  if (!neg) {
    return val;
  }

  return (0xffff - val + 1) * -1;
}

Buffer.prototype.readInt16LE = function(offset, noAssert) {
  return readInt16(this, offset, false, noAssert);
};

Buffer.prototype.readInt16BE = function(offset, noAssert) {
  return readInt16(this, offset, true, noAssert);
};

function readInt32(buffer, offset, isBigEndian, noAssert) {
  var neg, val;

  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 3 < buffer.length,
        'Trying to read beyond buffer length');
  }

  val = readUInt32(buffer, offset, isBigEndian, noAssert);
  neg = val & 0x80000000;
  if (!neg) {
    return (val);
  }

  return (0xffffffff - val + 1) * -1;
}

Buffer.prototype.readInt32LE = function(offset, noAssert) {
  return readInt32(this, offset, false, noAssert);
};

Buffer.prototype.readInt32BE = function(offset, noAssert) {
  return readInt32(this, offset, true, noAssert);
};

function readFloat(buffer, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset + 3 < buffer.length,
        'Trying to read beyond buffer length');
  }

  return require('./buffer_ieee754').readIEEE754(buffer, offset, isBigEndian,
      23, 4);
}

Buffer.prototype.readFloatLE = function(offset, noAssert) {
  return readFloat(this, offset, false, noAssert);
};

Buffer.prototype.readFloatBE = function(offset, noAssert) {
  return readFloat(this, offset, true, noAssert);
};

function readDouble(buffer, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset + 7 < buffer.length,
        'Trying to read beyond buffer length');
  }

  return require('./buffer_ieee754').readIEEE754(buffer, offset, isBigEndian,
      52, 8);
}

Buffer.prototype.readDoubleLE = function(offset, noAssert) {
  return readDouble(this, offset, false, noAssert);
};

Buffer.prototype.readDoubleBE = function(offset, noAssert) {
  return readDouble(this, offset, true, noAssert);
};


/*
 * We have to make sure that the value is a valid integer. This means that it is
 * non-negative. It has no fractional component and that it does not exceed the
 * maximum allowed value.
 *
 *      value           The number to check for validity
 *
 *      max             The maximum value
 */
function verifuint(value, max) {
  assert.ok(typeof (value) == 'number',
      'cannot write a non-number as a number');

  assert.ok(value >= 0,
      'specified a negative value for writing an unsigned value');

  assert.ok(value <= max, 'value is larger than maximum value for type');

  assert.ok(Math.floor(value) === value, 'value has a fractional component');
}

Buffer.prototype.writeUInt8 = function(value, offset, noAssert) {
  var buffer = this;

  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset < buffer.length,
        'trying to write beyond buffer length');

    verifuint(value, 0xff);
  }

  if (offset < buffer.length) {
    buffer[offset] = value;
  }
};

function writeUInt16(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 1 < buffer.length,
        'trying to write beyond buffer length');

    verifuint(value, 0xffff);
  }

  for (var i = 0; i < Math.min(buffer.length - offset, 2); i++) {
    buffer[offset + i] =
        (value & (0xff << (8 * (isBigEndian ? 1 - i : i)))) >>>
            (isBigEndian ? 1 - i : i) * 8;
  }

}

Buffer.prototype.writeUInt16LE = function(value, offset, noAssert) {
  writeUInt16(this, value, offset, false, noAssert);
};

Buffer.prototype.writeUInt16BE = function(value, offset, noAssert) {
  writeUInt16(this, value, offset, true, noAssert);
};

function writeUInt32(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 3 < buffer.length,
        'trying to write beyond buffer length');

    verifuint(value, 0xffffffff);
  }

  for (var i = 0; i < Math.min(buffer.length - offset, 4); i++) {
    buffer[offset + i] =
        (value >>> (isBigEndian ? 3 - i : i) * 8) & 0xff;
  }
}

Buffer.prototype.writeUInt32LE = function(value, offset, noAssert) {
  writeUInt32(this, value, offset, false, noAssert);
};

Buffer.prototype.writeUInt32BE = function(value, offset, noAssert) {
  writeUInt32(this, value, offset, true, noAssert);
};


/*
 * We now move onto our friends in the signed number category. Unlike unsigned
 * numbers, we're going to have to worry a bit more about how we put values into
 * arrays. Since we are only worrying about signed 32-bit values, we're in
 * slightly better shape. Unfortunately, we really can't do our favorite binary
 * & in this system. It really seems to do the wrong thing. For example:
 *
 * > -32 & 0xff
 * 224
 *
 * What's happening above is really: 0xe0 & 0xff = 0xe0. However, the results of
 * this aren't treated as a signed number. Ultimately a bad thing.
 *
 * What we're going to want to do is basically create the unsigned equivalent of
 * our representation and pass that off to the wuint* functions. To do that
 * we're going to do the following:
 *
 *  - if the value is positive
 *      we can pass it directly off to the equivalent wuint
 *  - if the value is negative
 *      we do the following computation:
 *         mb + val + 1, where
 *         mb   is the maximum unsigned value in that byte size
 *         val  is the Javascript negative integer
 *
 *
 * As a concrete value, take -128. In signed 16 bits this would be 0xff80. If
 * you do out the computations:
 *
 * 0xffff - 128 + 1
 * 0xffff - 127
 * 0xff80
 *
 * You can then encode this value as the signed version. This is really rather
 * hacky, but it should work and get the job done which is our goal here.
 */

/*
 * A series of checks to make sure we actually have a signed 32-bit number
 */
function verifsint(value, max, min) {
  assert.ok(typeof (value) == 'number',
      'cannot write a non-number as a number');

  assert.ok(value <= max, 'value larger than maximum allowed value');

  assert.ok(value >= min, 'value smaller than minimum allowed value');

  assert.ok(Math.floor(value) === value, 'value has a fractional component');
}

function verifIEEE754(value, max, min) {
  assert.ok(typeof (value) == 'number',
      'cannot write a non-number as a number');

  assert.ok(value <= max, 'value larger than maximum allowed value');

  assert.ok(value >= min, 'value smaller than minimum allowed value');
}

Buffer.prototype.writeInt8 = function(value, offset, noAssert) {
  var buffer = this;

  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset < buffer.length,
        'Trying to write beyond buffer length');

    verifsint(value, 0x7f, -0x80);
  }

  if (value >= 0) {
    buffer.writeUInt8(value, offset, noAssert);
  } else {
    buffer.writeUInt8(0xff + value + 1, offset, noAssert);
  }
};

function writeInt16(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 1 < buffer.length,
        'Trying to write beyond buffer length');

    verifsint(value, 0x7fff, -0x8000);
  }

  if (value >= 0) {
    writeUInt16(buffer, value, offset, isBigEndian, noAssert);
  } else {
    writeUInt16(buffer, 0xffff + value + 1, offset, isBigEndian, noAssert);
  }
}

Buffer.prototype.writeInt16LE = function(value, offset, noAssert) {
  writeInt16(this, value, offset, false, noAssert);
};

Buffer.prototype.writeInt16BE = function(value, offset, noAssert) {
  writeInt16(this, value, offset, true, noAssert);
};

function writeInt32(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 3 < buffer.length,
        'Trying to write beyond buffer length');

    verifsint(value, 0x7fffffff, -0x80000000);
  }

  if (value >= 0) {
    writeUInt32(buffer, value, offset, isBigEndian, noAssert);
  } else {
    writeUInt32(buffer, 0xffffffff + value + 1, offset, isBigEndian, noAssert);
  }
}

Buffer.prototype.writeInt32LE = function(value, offset, noAssert) {
  writeInt32(this, value, offset, false, noAssert);
};

Buffer.prototype.writeInt32BE = function(value, offset, noAssert) {
  writeInt32(this, value, offset, true, noAssert);
};

function writeFloat(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 3 < buffer.length,
        'Trying to write beyond buffer length');

    verifIEEE754(value, 3.4028234663852886e+38, -3.4028234663852886e+38);
  }

  require('./buffer_ieee754').writeIEEE754(buffer, value, offset, isBigEndian,
      23, 4);
}

Buffer.prototype.writeFloatLE = function(value, offset, noAssert) {
  writeFloat(this, value, offset, false, noAssert);
};

Buffer.prototype.writeFloatBE = function(value, offset, noAssert) {
  writeFloat(this, value, offset, true, noAssert);
};

function writeDouble(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 7 < buffer.length,
        'Trying to write beyond buffer length');

    verifIEEE754(value, 1.7976931348623157E+308, -1.7976931348623157E+308);
  }

  require('./buffer_ieee754').writeIEEE754(buffer, value, offset, isBigEndian,
      52, 8);
}

Buffer.prototype.writeDoubleLE = function(value, offset, noAssert) {
  writeDouble(this, value, offset, false, noAssert);
};

Buffer.prototype.writeDoubleBE = function(value, offset, noAssert) {
  writeDouble(this, value, offset, true, noAssert);
};

},{"./buffer_ieee754":1,"assert":6,"base64-js":4}],"buffer-browserify":[function(require,module,exports){
module.exports=require('q9TxCC');
},{}],4:[function(require,module,exports){
(function (exports) {
	'use strict';

	var lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

	function b64ToByteArray(b64) {
		var i, j, l, tmp, placeHolders, arr;
	
		if (b64.length % 4 > 0) {
			throw 'Invalid string. Length must be a multiple of 4';
		}

		// the number of equal signs (place holders)
		// if there are two placeholders, than the two characters before it
		// represent one byte
		// if there is only one, then the three characters before it represent 2 bytes
		// this is just a cheap hack to not do indexOf twice
		placeHolders = b64.indexOf('=');
		placeHolders = placeHolders > 0 ? b64.length - placeHolders : 0;

		// base64 is 4/3 + up to two characters of the original data
		arr = [];//new Uint8Array(b64.length * 3 / 4 - placeHolders);

		// if there are placeholders, only get up to the last complete 4 chars
		l = placeHolders > 0 ? b64.length - 4 : b64.length;

		for (i = 0, j = 0; i < l; i += 4, j += 3) {
			tmp = (lookup.indexOf(b64[i]) << 18) | (lookup.indexOf(b64[i + 1]) << 12) | (lookup.indexOf(b64[i + 2]) << 6) | lookup.indexOf(b64[i + 3]);
			arr.push((tmp & 0xFF0000) >> 16);
			arr.push((tmp & 0xFF00) >> 8);
			arr.push(tmp & 0xFF);
		}

		if (placeHolders === 2) {
			tmp = (lookup.indexOf(b64[i]) << 2) | (lookup.indexOf(b64[i + 1]) >> 4);
			arr.push(tmp & 0xFF);
		} else if (placeHolders === 1) {
			tmp = (lookup.indexOf(b64[i]) << 10) | (lookup.indexOf(b64[i + 1]) << 4) | (lookup.indexOf(b64[i + 2]) >> 2);
			arr.push((tmp >> 8) & 0xFF);
			arr.push(tmp & 0xFF);
		}

		return arr;
	}

	function uint8ToBase64(uint8) {
		var i,
			extraBytes = uint8.length % 3, // if we have 1 byte left, pad 2 bytes
			output = "",
			temp, length;

		function tripletToBase64 (num) {
			return lookup[num >> 18 & 0x3F] + lookup[num >> 12 & 0x3F] + lookup[num >> 6 & 0x3F] + lookup[num & 0x3F];
		};

		// go through the array every three bytes, we'll deal with trailing stuff later
		for (i = 0, length = uint8.length - extraBytes; i < length; i += 3) {
			temp = (uint8[i] << 16) + (uint8[i + 1] << 8) + (uint8[i + 2]);
			output += tripletToBase64(temp);
		}

		// pad the end with zeros, but make sure to not forget the extra bytes
		switch (extraBytes) {
			case 1:
				temp = uint8[uint8.length - 1];
				output += lookup[temp >> 2];
				output += lookup[(temp << 4) & 0x3F];
				output += '==';
				break;
			case 2:
				temp = (uint8[uint8.length - 2] << 8) + (uint8[uint8.length - 1]);
				output += lookup[temp >> 10];
				output += lookup[(temp >> 4) & 0x3F];
				output += lookup[(temp << 2) & 0x3F];
				output += '=';
				break;
		}

		return output;
	}

	module.exports.toByteArray = b64ToByteArray;
	module.exports.fromByteArray = uint8ToBase64;
}());

},{}],5:[function(require,module,exports){


//
// The shims in this file are not fully implemented shims for the ES5
// features, but do work for the particular usecases there is in
// the other modules.
//

var toString = Object.prototype.toString;
var hasOwnProperty = Object.prototype.hasOwnProperty;

// Array.isArray is supported in IE9
function isArray(xs) {
  return toString.call(xs) === '[object Array]';
}
exports.isArray = typeof Array.isArray === 'function' ? Array.isArray : isArray;

// Array.prototype.indexOf is supported in IE9
exports.indexOf = function indexOf(xs, x) {
  if (xs.indexOf) return xs.indexOf(x);
  for (var i = 0; i < xs.length; i++) {
    if (x === xs[i]) return i;
  }
  return -1;
};

// Array.prototype.filter is supported in IE9
exports.filter = function filter(xs, fn) {
  if (xs.filter) return xs.filter(fn);
  var res = [];
  for (var i = 0; i < xs.length; i++) {
    if (fn(xs[i], i, xs)) res.push(xs[i]);
  }
  return res;
};

// Array.prototype.forEach is supported in IE9
exports.forEach = function forEach(xs, fn, self) {
  if (xs.forEach) return xs.forEach(fn, self);
  for (var i = 0; i < xs.length; i++) {
    fn.call(self, xs[i], i, xs);
  }
};

// Array.prototype.map is supported in IE9
exports.map = function map(xs, fn) {
  if (xs.map) return xs.map(fn);
  var out = new Array(xs.length);
  for (var i = 0; i < xs.length; i++) {
    out[i] = fn(xs[i], i, xs);
  }
  return out;
};

// Array.prototype.reduce is supported in IE9
exports.reduce = function reduce(array, callback, opt_initialValue) {
  if (array.reduce) return array.reduce(callback, opt_initialValue);
  var value, isValueSet = false;

  if (2 < arguments.length) {
    value = opt_initialValue;
    isValueSet = true;
  }
  for (var i = 0, l = array.length; l > i; ++i) {
    if (array.hasOwnProperty(i)) {
      if (isValueSet) {
        value = callback(value, array[i], i, array);
      }
      else {
        value = array[i];
        isValueSet = true;
      }
    }
  }

  return value;
};

// String.prototype.substr - negative index don't work in IE8
if ('ab'.substr(-1) !== 'b') {
  exports.substr = function (str, start, length) {
    // did we get a negative start, calculate how much it is from the beginning of the string
    if (start < 0) start = str.length + start;

    // call the original function
    return str.substr(start, length);
  };
} else {
  exports.substr = function (str, start, length) {
    return str.substr(start, length);
  };
}

// String.prototype.trim is supported in IE9
exports.trim = function (str) {
  if (str.trim) return str.trim();
  return str.replace(/^\s+|\s+$/g, '');
};

// Function.prototype.bind is supported in IE9
exports.bind = function () {
  var args = Array.prototype.slice.call(arguments);
  var fn = args.shift();
  if (fn.bind) return fn.bind.apply(fn, args);
  var self = args.shift();
  return function () {
    fn.apply(self, args.concat([Array.prototype.slice.call(arguments)]));
  };
};

// Object.create is supported in IE9
function create(prototype, properties) {
  var object;
  if (prototype === null) {
    object = { '__proto__' : null };
  }
  else {
    if (typeof prototype !== 'object') {
      throw new TypeError(
        'typeof prototype[' + (typeof prototype) + '] != \'object\''
      );
    }
    var Type = function () {};
    Type.prototype = prototype;
    object = new Type();
    object.__proto__ = prototype;
  }
  if (typeof properties !== 'undefined' && Object.defineProperties) {
    Object.defineProperties(object, properties);
  }
  return object;
}
exports.create = typeof Object.create === 'function' ? Object.create : create;

// Object.keys and Object.getOwnPropertyNames is supported in IE9 however
// they do show a description and number property on Error objects
function notObject(object) {
  return ((typeof object != "object" && typeof object != "function") || object === null);
}

function keysShim(object) {
  if (notObject(object)) {
    throw new TypeError("Object.keys called on a non-object");
  }

  var result = [];
  for (var name in object) {
    if (hasOwnProperty.call(object, name)) {
      result.push(name);
    }
  }
  return result;
}

// getOwnPropertyNames is almost the same as Object.keys one key feature
//  is that it returns hidden properties, since that can't be implemented,
//  this feature gets reduced so it just shows the length property on arrays
function propertyShim(object) {
  if (notObject(object)) {
    throw new TypeError("Object.getOwnPropertyNames called on a non-object");
  }

  var result = keysShim(object);
  if (exports.isArray(object) && exports.indexOf(object, 'length') === -1) {
    result.push('length');
  }
  return result;
}

var keys = typeof Object.keys === 'function' ? Object.keys : keysShim;
var getOwnPropertyNames = typeof Object.getOwnPropertyNames === 'function' ?
  Object.getOwnPropertyNames : propertyShim;

if (new Error().hasOwnProperty('description')) {
  var ERROR_PROPERTY_FILTER = function (obj, array) {
    if (toString.call(obj) === '[object Error]') {
      array = exports.filter(array, function (name) {
        return name !== 'description' && name !== 'number' && name !== 'message';
      });
    }
    return array;
  };

  exports.keys = function (object) {
    return ERROR_PROPERTY_FILTER(object, keys(object));
  };
  exports.getOwnPropertyNames = function (object) {
    return ERROR_PROPERTY_FILTER(object, getOwnPropertyNames(object));
  };
} else {
  exports.keys = keys;
  exports.getOwnPropertyNames = getOwnPropertyNames;
}

// Object.getOwnPropertyDescriptor - supported in IE8 but only on dom elements
function valueObject(value, key) {
  return { value: value[key] };
}

if (typeof Object.getOwnPropertyDescriptor === 'function') {
  try {
    Object.getOwnPropertyDescriptor({'a': 1}, 'a');
    exports.getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  } catch (e) {
    // IE8 dom element issue - use a try catch and default to valueObject
    exports.getOwnPropertyDescriptor = function (value, key) {
      try {
        return Object.getOwnPropertyDescriptor(value, key);
      } catch (e) {
        return valueObject(value, key);
      }
    };
  }
} else {
  exports.getOwnPropertyDescriptor = valueObject;
}

},{}],6:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// UTILITY
var util = require('util');
var shims = require('_shims');
var pSlice = Array.prototype.slice;

// 1. The assert module provides functions that throw
// AssertionError's when particular conditions are not met. The
// assert module must conform to the following interface.

var assert = module.exports = ok;

// 2. The AssertionError is defined in assert.
// new assert.AssertionError({ message: message,
//                             actual: actual,
//                             expected: expected })

assert.AssertionError = function AssertionError(options) {
  this.name = 'AssertionError';
  this.actual = options.actual;
  this.expected = options.expected;
  this.operator = options.operator;
  this.message = options.message || getMessage(this);
};

// assert.AssertionError instanceof Error
util.inherits(assert.AssertionError, Error);

function replacer(key, value) {
  if (util.isUndefined(value)) {
    return '' + value;
  }
  if (util.isNumber(value) && (isNaN(value) || !isFinite(value))) {
    return value.toString();
  }
  if (util.isFunction(value) || util.isRegExp(value)) {
    return value.toString();
  }
  return value;
}

function truncate(s, n) {
  if (util.isString(s)) {
    return s.length < n ? s : s.slice(0, n);
  } else {
    return s;
  }
}

function getMessage(self) {
  return truncate(JSON.stringify(self.actual, replacer), 128) + ' ' +
         self.operator + ' ' +
         truncate(JSON.stringify(self.expected, replacer), 128);
}

// At present only the three keys mentioned above are used and
// understood by the spec. Implementations or sub modules can pass
// other keys to the AssertionError's constructor - they will be
// ignored.

// 3. All of the following functions must throw an AssertionError
// when a corresponding condition is not met, with a message that
// may be undefined if not provided.  All assertion methods provide
// both the actual and expected values to the assertion error for
// display purposes.

function fail(actual, expected, message, operator, stackStartFunction) {
  throw new assert.AssertionError({
    message: message,
    actual: actual,
    expected: expected,
    operator: operator,
    stackStartFunction: stackStartFunction
  });
}

// EXTENSION! allows for well behaved errors defined elsewhere.
assert.fail = fail;

// 4. Pure assertion tests whether a value is truthy, as determined
// by !!guard.
// assert.ok(guard, message_opt);
// This statement is equivalent to assert.equal(true, !!guard,
// message_opt);. To test strictly for the value true, use
// assert.strictEqual(true, guard, message_opt);.

function ok(value, message) {
  if (!value) fail(value, true, message, '==', assert.ok);
}
assert.ok = ok;

// 5. The equality assertion tests shallow, coercive equality with
// ==.
// assert.equal(actual, expected, message_opt);

assert.equal = function equal(actual, expected, message) {
  if (actual != expected) fail(actual, expected, message, '==', assert.equal);
};

// 6. The non-equality assertion tests for whether two objects are not equal
// with != assert.notEqual(actual, expected, message_opt);

assert.notEqual = function notEqual(actual, expected, message) {
  if (actual == expected) {
    fail(actual, expected, message, '!=', assert.notEqual);
  }
};

// 7. The equivalence assertion tests a deep equality relation.
// assert.deepEqual(actual, expected, message_opt);

assert.deepEqual = function deepEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected)) {
    fail(actual, expected, message, 'deepEqual', assert.deepEqual);
  }
};

function _deepEqual(actual, expected) {
  // 7.1. All identical values are equivalent, as determined by ===.
  if (actual === expected) {
    return true;

  } else if (util.isBuffer(actual) && util.isBuffer(expected)) {
    if (actual.length != expected.length) return false;

    for (var i = 0; i < actual.length; i++) {
      if (actual[i] !== expected[i]) return false;
    }

    return true;

  // 7.2. If the expected value is a Date object, the actual value is
  // equivalent if it is also a Date object that refers to the same time.
  } else if (util.isDate(actual) && util.isDate(expected)) {
    return actual.getTime() === expected.getTime();

  // 7.3 If the expected value is a RegExp object, the actual value is
  // equivalent if it is also a RegExp object with the same source and
  // properties (`global`, `multiline`, `lastIndex`, `ignoreCase`).
  } else if (util.isRegExp(actual) && util.isRegExp(expected)) {
    return actual.source === expected.source &&
           actual.global === expected.global &&
           actual.multiline === expected.multiline &&
           actual.lastIndex === expected.lastIndex &&
           actual.ignoreCase === expected.ignoreCase;

  // 7.4. Other pairs that do not both pass typeof value == 'object',
  // equivalence is determined by ==.
  } else if (!util.isObject(actual) && !util.isObject(expected)) {
    return actual == expected;

  // 7.5 For all other Object pairs, including Array objects, equivalence is
  // determined by having the same number of owned properties (as verified
  // with Object.prototype.hasOwnProperty.call), the same set of keys
  // (although not necessarily the same order), equivalent values for every
  // corresponding key, and an identical 'prototype' property. Note: this
  // accounts for both named and indexed properties on Arrays.
  } else {
    return objEquiv(actual, expected);
  }
}

function isArguments(object) {
  return Object.prototype.toString.call(object) == '[object Arguments]';
}

function objEquiv(a, b) {
  if (util.isNullOrUndefined(a) || util.isNullOrUndefined(b))
    return false;
  // an identical 'prototype' property.
  if (a.prototype !== b.prototype) return false;
  //~~~I've managed to break Object.keys through screwy arguments passing.
  //   Converting to array solves the problem.
  if (isArguments(a)) {
    if (!isArguments(b)) {
      return false;
    }
    a = pSlice.call(a);
    b = pSlice.call(b);
    return _deepEqual(a, b);
  }
  try {
    var ka = shims.keys(a),
        kb = shims.keys(b),
        key, i;
  } catch (e) {//happens when one is a string literal and the other isn't
    return false;
  }
  // having the same number of owned properties (keys incorporates
  // hasOwnProperty)
  if (ka.length != kb.length)
    return false;
  //the same set of keys (although not necessarily the same order),
  ka.sort();
  kb.sort();
  //~~~cheap key test
  for (i = ka.length - 1; i >= 0; i--) {
    if (ka[i] != kb[i])
      return false;
  }
  //equivalent values for every corresponding key, and
  //~~~possibly expensive deep test
  for (i = ka.length - 1; i >= 0; i--) {
    key = ka[i];
    if (!_deepEqual(a[key], b[key])) return false;
  }
  return true;
}

// 8. The non-equivalence assertion tests for any deep inequality.
// assert.notDeepEqual(actual, expected, message_opt);

assert.notDeepEqual = function notDeepEqual(actual, expected, message) {
  if (_deepEqual(actual, expected)) {
    fail(actual, expected, message, 'notDeepEqual', assert.notDeepEqual);
  }
};

// 9. The strict equality assertion tests strict equality, as determined by ===.
// assert.strictEqual(actual, expected, message_opt);

assert.strictEqual = function strictEqual(actual, expected, message) {
  if (actual !== expected) {
    fail(actual, expected, message, '===', assert.strictEqual);
  }
};

// 10. The strict non-equality assertion tests for strict inequality, as
// determined by !==.  assert.notStrictEqual(actual, expected, message_opt);

assert.notStrictEqual = function notStrictEqual(actual, expected, message) {
  if (actual === expected) {
    fail(actual, expected, message, '!==', assert.notStrictEqual);
  }
};

function expectedException(actual, expected) {
  if (!actual || !expected) {
    return false;
  }

  if (Object.prototype.toString.call(expected) == '[object RegExp]') {
    return expected.test(actual);
  } else if (actual instanceof expected) {
    return true;
  } else if (expected.call({}, actual) === true) {
    return true;
  }

  return false;
}

function _throws(shouldThrow, block, expected, message) {
  var actual;

  if (util.isString(expected)) {
    message = expected;
    expected = null;
  }

  try {
    block();
  } catch (e) {
    actual = e;
  }

  message = (expected && expected.name ? ' (' + expected.name + ').' : '.') +
            (message ? ' ' + message : '.');

  if (shouldThrow && !actual) {
    fail(actual, expected, 'Missing expected exception' + message);
  }

  if (!shouldThrow && expectedException(actual, expected)) {
    fail(actual, expected, 'Got unwanted exception' + message);
  }

  if ((shouldThrow && actual && expected &&
      !expectedException(actual, expected)) || (!shouldThrow && actual)) {
    throw actual;
  }
}

// 11. Expected to throw an error:
// assert.throws(block, Error_opt, message_opt);

assert.throws = function(block, /*optional*/error, /*optional*/message) {
  _throws.apply(this, [true].concat(pSlice.call(arguments)));
};

// EXTENSION! This is annoying to write outside this module.
assert.doesNotThrow = function(block, /*optional*/message) {
  _throws.apply(this, [false].concat(pSlice.call(arguments)));
};

assert.ifError = function(err) { if (err) {throw err;}};
},{"_shims":5,"util":7}],7:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var shims = require('_shims');

var formatRegExp = /%[sdj%]/g;
exports.format = function(f) {
  if (!isString(f)) {
    var objects = [];
    for (var i = 0; i < arguments.length; i++) {
      objects.push(inspect(arguments[i]));
    }
    return objects.join(' ');
  }

  var i = 1;
  var args = arguments;
  var len = args.length;
  var str = String(f).replace(formatRegExp, function(x) {
    if (x === '%%') return '%';
    if (i >= len) return x;
    switch (x) {
      case '%s': return String(args[i++]);
      case '%d': return Number(args[i++]);
      case '%j':
        try {
          return JSON.stringify(args[i++]);
        } catch (_) {
          return '[Circular]';
        }
      default:
        return x;
    }
  });
  for (var x = args[i]; i < len; x = args[++i]) {
    if (isNull(x) || !isObject(x)) {
      str += ' ' + x;
    } else {
      str += ' ' + inspect(x);
    }
  }
  return str;
};

/**
 * Echos the value of a value. Trys to print the value out
 * in the best way possible given the different types.
 *
 * @param {Object} obj The object to print out.
 * @param {Object} opts Optional options object that alters the output.
 */
/* legacy: obj, showHidden, depth, colors*/
function inspect(obj, opts) {
  // default options
  var ctx = {
    seen: [],
    stylize: stylizeNoColor
  };
  // legacy...
  if (arguments.length >= 3) ctx.depth = arguments[2];
  if (arguments.length >= 4) ctx.colors = arguments[3];
  if (isBoolean(opts)) {
    // legacy...
    ctx.showHidden = opts;
  } else if (opts) {
    // got an "options" object
    exports._extend(ctx, opts);
  }
  // set default options
  if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
  if (isUndefined(ctx.depth)) ctx.depth = 2;
  if (isUndefined(ctx.colors)) ctx.colors = false;
  if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
  if (ctx.colors) ctx.stylize = stylizeWithColor;
  return formatValue(ctx, obj, ctx.depth);
}
exports.inspect = inspect;


// http://en.wikipedia.org/wiki/ANSI_escape_code#graphics
inspect.colors = {
  'bold' : [1, 22],
  'italic' : [3, 23],
  'underline' : [4, 24],
  'inverse' : [7, 27],
  'white' : [37, 39],
  'grey' : [90, 39],
  'black' : [30, 39],
  'blue' : [34, 39],
  'cyan' : [36, 39],
  'green' : [32, 39],
  'magenta' : [35, 39],
  'red' : [31, 39],
  'yellow' : [33, 39]
};

// Don't use 'blue' not visible on cmd.exe
inspect.styles = {
  'special': 'cyan',
  'number': 'yellow',
  'boolean': 'yellow',
  'undefined': 'grey',
  'null': 'bold',
  'string': 'green',
  'date': 'magenta',
  // "name": intentionally not styling
  'regexp': 'red'
};


function stylizeWithColor(str, styleType) {
  var style = inspect.styles[styleType];

  if (style) {
    return '\u001b[' + inspect.colors[style][0] + 'm' + str +
           '\u001b[' + inspect.colors[style][1] + 'm';
  } else {
    return str;
  }
}


function stylizeNoColor(str, styleType) {
  return str;
}


function arrayToHash(array) {
  var hash = {};

  shims.forEach(array, function(val, idx) {
    hash[val] = true;
  });

  return hash;
}


function formatValue(ctx, value, recurseTimes) {
  // Provide a hook for user-specified inspect functions.
  // Check that value is an object with an inspect function on it
  if (ctx.customInspect &&
      value &&
      isFunction(value.inspect) &&
      // Filter out the util module, it's inspect function is special
      value.inspect !== exports.inspect &&
      // Also filter out any prototype objects using the circular check.
      !(value.constructor && value.constructor.prototype === value)) {
    var ret = value.inspect(recurseTimes);
    if (!isString(ret)) {
      ret = formatValue(ctx, ret, recurseTimes);
    }
    return ret;
  }

  // Primitive types cannot have properties
  var primitive = formatPrimitive(ctx, value);
  if (primitive) {
    return primitive;
  }

  // Look up the keys of the object.
  var keys = shims.keys(value);
  var visibleKeys = arrayToHash(keys);

  if (ctx.showHidden) {
    keys = shims.getOwnPropertyNames(value);
  }

  // Some type of object without properties can be shortcutted.
  if (keys.length === 0) {
    if (isFunction(value)) {
      var name = value.name ? ': ' + value.name : '';
      return ctx.stylize('[Function' + name + ']', 'special');
    }
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    }
    if (isDate(value)) {
      return ctx.stylize(Date.prototype.toString.call(value), 'date');
    }
    if (isError(value)) {
      return formatError(value);
    }
  }

  var base = '', array = false, braces = ['{', '}'];

  // Make Array say that they are Array
  if (isArray(value)) {
    array = true;
    braces = ['[', ']'];
  }

  // Make functions say that they are functions
  if (isFunction(value)) {
    var n = value.name ? ': ' + value.name : '';
    base = ' [Function' + n + ']';
  }

  // Make RegExps say that they are RegExps
  if (isRegExp(value)) {
    base = ' ' + RegExp.prototype.toString.call(value);
  }

  // Make dates with properties first say the date
  if (isDate(value)) {
    base = ' ' + Date.prototype.toUTCString.call(value);
  }

  // Make error with message first say the error
  if (isError(value)) {
    base = ' ' + formatError(value);
  }

  if (keys.length === 0 && (!array || value.length == 0)) {
    return braces[0] + base + braces[1];
  }

  if (recurseTimes < 0) {
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    } else {
      return ctx.stylize('[Object]', 'special');
    }
  }

  ctx.seen.push(value);

  var output;
  if (array) {
    output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
  } else {
    output = keys.map(function(key) {
      return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
    });
  }

  ctx.seen.pop();

  return reduceToSingleString(output, base, braces);
}


function formatPrimitive(ctx, value) {
  if (isUndefined(value))
    return ctx.stylize('undefined', 'undefined');
  if (isString(value)) {
    var simple = '\'' + JSON.stringify(value).replace(/^"|"$/g, '')
                                             .replace(/'/g, "\\'")
                                             .replace(/\\"/g, '"') + '\'';
    return ctx.stylize(simple, 'string');
  }
  if (isNumber(value))
    return ctx.stylize('' + value, 'number');
  if (isBoolean(value))
    return ctx.stylize('' + value, 'boolean');
  // For some reason typeof null is "object", so special case here.
  if (isNull(value))
    return ctx.stylize('null', 'null');
}


function formatError(value) {
  return '[' + Error.prototype.toString.call(value) + ']';
}


function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
  var output = [];
  for (var i = 0, l = value.length; i < l; ++i) {
    if (hasOwnProperty(value, String(i))) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          String(i), true));
    } else {
      output.push('');
    }
  }

  shims.forEach(keys, function(key) {
    if (!key.match(/^\d+$/)) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          key, true));
    }
  });
  return output;
}


function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
  var name, str, desc;
  desc = shims.getOwnPropertyDescriptor(value, key) || { value: value[key] };
  if (desc.get) {
    if (desc.set) {
      str = ctx.stylize('[Getter/Setter]', 'special');
    } else {
      str = ctx.stylize('[Getter]', 'special');
    }
  } else {
    if (desc.set) {
      str = ctx.stylize('[Setter]', 'special');
    }
  }

  if (!hasOwnProperty(visibleKeys, key)) {
    name = '[' + key + ']';
  }
  if (!str) {
    if (shims.indexOf(ctx.seen, desc.value) < 0) {
      if (isNull(recurseTimes)) {
        str = formatValue(ctx, desc.value, null);
      } else {
        str = formatValue(ctx, desc.value, recurseTimes - 1);
      }
      if (str.indexOf('\n') > -1) {
        if (array) {
          str = str.split('\n').map(function(line) {
            return '  ' + line;
          }).join('\n').substr(2);
        } else {
          str = '\n' + str.split('\n').map(function(line) {
            return '   ' + line;
          }).join('\n');
        }
      }
    } else {
      str = ctx.stylize('[Circular]', 'special');
    }
  }
  if (isUndefined(name)) {
    if (array && key.match(/^\d+$/)) {
      return str;
    }
    name = JSON.stringify('' + key);
    if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
      name = name.substr(1, name.length - 2);
      name = ctx.stylize(name, 'name');
    } else {
      name = name.replace(/'/g, "\\'")
                 .replace(/\\"/g, '"')
                 .replace(/(^"|"$)/g, "'");
      name = ctx.stylize(name, 'string');
    }
  }

  return name + ': ' + str;
}


function reduceToSingleString(output, base, braces) {
  var numLinesEst = 0;
  var length = shims.reduce(output, function(prev, cur) {
    numLinesEst++;
    if (cur.indexOf('\n') >= 0) numLinesEst++;
    return prev + cur.replace(/\u001b\[\d\d?m/g, '').length + 1;
  }, 0);

  if (length > 60) {
    return braces[0] +
           (base === '' ? '' : base + '\n ') +
           ' ' +
           output.join(',\n  ') +
           ' ' +
           braces[1];
  }

  return braces[0] + base + ' ' + output.join(', ') + ' ' + braces[1];
}


// NOTE: These type checking functions intentionally don't use `instanceof`
// because it is fragile and can be easily faked with `Object.create()`.
function isArray(ar) {
  return shims.isArray(ar);
}
exports.isArray = isArray;

function isBoolean(arg) {
  return typeof arg === 'boolean';
}
exports.isBoolean = isBoolean;

function isNull(arg) {
  return arg === null;
}
exports.isNull = isNull;

function isNullOrUndefined(arg) {
  return arg == null;
}
exports.isNullOrUndefined = isNullOrUndefined;

function isNumber(arg) {
  return typeof arg === 'number';
}
exports.isNumber = isNumber;

function isString(arg) {
  return typeof arg === 'string';
}
exports.isString = isString;

function isSymbol(arg) {
  return typeof arg === 'symbol';
}
exports.isSymbol = isSymbol;

function isUndefined(arg) {
  return arg === void 0;
}
exports.isUndefined = isUndefined;

function isRegExp(re) {
  return isObject(re) && objectToString(re) === '[object RegExp]';
}
exports.isRegExp = isRegExp;

function isObject(arg) {
  return typeof arg === 'object' && arg;
}
exports.isObject = isObject;

function isDate(d) {
  return isObject(d) && objectToString(d) === '[object Date]';
}
exports.isDate = isDate;

function isError(e) {
  return isObject(e) && objectToString(e) === '[object Error]';
}
exports.isError = isError;

function isFunction(arg) {
  return typeof arg === 'function';
}
exports.isFunction = isFunction;

function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}
exports.isPrimitive = isPrimitive;

function isBuffer(arg) {
  return arg instanceof Buffer;
}
exports.isBuffer = isBuffer;

function objectToString(o) {
  return Object.prototype.toString.call(o);
}


function pad(n) {
  return n < 10 ? '0' + n.toString(10) : n.toString(10);
}


var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
              'Oct', 'Nov', 'Dec'];

// 26 Feb 16:19:34
function timestamp() {
  var d = new Date();
  var time = [pad(d.getHours()),
              pad(d.getMinutes()),
              pad(d.getSeconds())].join(':');
  return [d.getDate(), months[d.getMonth()], time].join(' ');
}


// log is just a thin wrapper to console.log that prepends a timestamp
exports.log = function() {
  console.log('%s - %s', timestamp(), exports.format.apply(exports, arguments));
};


/**
 * Inherit the prototype methods from one constructor into another.
 *
 * The Function.prototype.inherits from lang.js rewritten as a standalone
 * function (not on Function.prototype). NOTE: If this file is to be loaded
 * during bootstrapping this function needs to be rewritten using some native
 * functions as prototype setup using normal JavaScript does not work as
 * expected during bootstrapping (see mirror.js in r114903).
 *
 * @param {function} ctor Constructor function which needs to inherit the
 *     prototype.
 * @param {function} superCtor Constructor function to inherit prototype from.
 */
exports.inherits = function(ctor, superCtor) {
  ctor.super_ = superCtor;
  ctor.prototype = shims.create(superCtor.prototype, {
    constructor: {
      value: ctor,
      enumerable: false,
      writable: true,
      configurable: true
    }
  });
};

exports._extend = function(origin, add) {
  // Don't do anything if add isn't an object
  if (!add || !isObject(add)) return origin;

  var keys = shims.keys(add);
  var i = keys.length;
  while (i--) {
    origin[keys[i]] = add[keys[i]];
  }
  return origin;
};

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

},{"_shims":5}]},{},[])
;;module.exports=require("buffer-browserify")

},{}],17:[function(require,module,exports){
// shim for using process in browser

var process = module.exports = {};

process.nextTick = (function () {
    var canSetImmediate = typeof window !== 'undefined'
    && window.setImmediate;
    var canPost = typeof window !== 'undefined'
    && window.postMessage && window.addEventListener
    ;

    if (canSetImmediate) {
        return function (f) { return window.setImmediate(f) };
    }

    if (canPost) {
        var queue = [];
        window.addEventListener('message', function (ev) {
            var source = ev.source;
            if ((source === window || source === null) && ev.data === 'process-tick') {
                ev.stopPropagation();
                if (queue.length > 0) {
                    var fn = queue.shift();
                    fn();
                }
            }
        }, true);

        return function nextTick(fn) {
            queue.push(fn);
            window.postMessage('process-tick', '*');
        };
    }

    return function nextTick(fn) {
        setTimeout(fn, 0);
    };
})();

process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];

process.binding = function (name) {
    throw new Error('process.binding is not supported');
}

// TODO(shtylman)
process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};

},{}],18:[function(require,module,exports){
"use strict";
var Promise = require("./promise/promise").Promise;
var polyfill = require("./promise/polyfill").polyfill;
exports.Promise = Promise;
exports.polyfill = polyfill;
},{"./promise/polyfill":22,"./promise/promise":23}],19:[function(require,module,exports){
"use strict";
/* global toString */

var isArray = require("./utils").isArray;
var isFunction = require("./utils").isFunction;

/**
  Returns a promise that is fulfilled when all the given promises have been
  fulfilled, or rejected if any of them become rejected. The return promise
  is fulfilled with an array that gives all the values in the order they were
  passed in the `promises` array argument.

  Example:

  ```javascript
  var promise1 = RSVP.resolve(1);
  var promise2 = RSVP.resolve(2);
  var promise3 = RSVP.resolve(3);
  var promises = [ promise1, promise2, promise3 ];

  RSVP.all(promises).then(function(array){
    // The array here would be [ 1, 2, 3 ];
  });
  ```

  If any of the `promises` given to `RSVP.all` are rejected, the first promise
  that is rejected will be given as an argument to the returned promises's
  rejection handler. For example:

  Example:

  ```javascript
  var promise1 = RSVP.resolve(1);
  var promise2 = RSVP.reject(new Error("2"));
  var promise3 = RSVP.reject(new Error("3"));
  var promises = [ promise1, promise2, promise3 ];

  RSVP.all(promises).then(function(array){
    // Code here never runs because there are rejected promises!
  }, function(error) {
    // error.message === "2"
  });
  ```

  @method all
  @for RSVP
  @param {Array} promises
  @param {String} label
  @return {Promise} promise that is fulfilled when all `promises` have been
  fulfilled, or rejected if any of them become rejected.
*/
function all(promises) {
  /*jshint validthis:true */
  var Promise = this;

  if (!isArray(promises)) {
    throw new TypeError('You must pass an array to all.');
  }

  return new Promise(function(resolve, reject) {
    var results = [], remaining = promises.length,
    promise;

    if (remaining === 0) {
      resolve([]);
    }

    function resolver(index) {
      return function(value) {
        resolveAll(index, value);
      };
    }

    function resolveAll(index, value) {
      results[index] = value;
      if (--remaining === 0) {
        resolve(results);
      }
    }

    for (var i = 0; i < promises.length; i++) {
      promise = promises[i];

      if (promise && isFunction(promise.then)) {
        promise.then(resolver(i), reject);
      } else {
        resolveAll(i, promise);
      }
    }
  });
}

exports.all = all;
},{"./utils":27}],20:[function(require,module,exports){
var process=require("__browserify_process"),global=typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {};"use strict";
var browserGlobal = (typeof window !== 'undefined') ? window : {};
var BrowserMutationObserver = browserGlobal.MutationObserver || browserGlobal.WebKitMutationObserver;
var local = (typeof global !== 'undefined') ? global : (this === undefined? window:this);

// node
function useNextTick() {
  return function() {
    process.nextTick(flush);
  };
}

function useMutationObserver() {
  var iterations = 0;
  var observer = new BrowserMutationObserver(flush);
  var node = document.createTextNode('');
  observer.observe(node, { characterData: true });

  return function() {
    node.data = (iterations = ++iterations % 2);
  };
}

function useSetTimeout() {
  return function() {
    local.setTimeout(flush, 1);
  };
}

var queue = [];
function flush() {
  for (var i = 0; i < queue.length; i++) {
    var tuple = queue[i];
    var callback = tuple[0], arg = tuple[1];
    callback(arg);
  }
  queue = [];
}

var scheduleFlush;

// Decide what async method to use to triggering processing of queued callbacks:
if (typeof process !== 'undefined' && {}.toString.call(process) === '[object process]') {
  scheduleFlush = useNextTick();
} else if (BrowserMutationObserver) {
  scheduleFlush = useMutationObserver();
} else {
  scheduleFlush = useSetTimeout();
}

function asap(callback, arg) {
  var length = queue.push([callback, arg]);
  if (length === 1) {
    // If length is 1, that means that we need to schedule an async flush.
    // If additional callbacks are queued before the queue is flushed, they
    // will be processed by this flush that we are scheduling.
    scheduleFlush();
  }
}

exports.asap = asap;
},{"__browserify_process":17}],21:[function(require,module,exports){
"use strict";
var config = {
  instrument: false
};

function configure(name, value) {
  if (arguments.length === 2) {
    config[name] = value;
  } else {
    return config[name];
  }
}

exports.config = config;
exports.configure = configure;
},{}],22:[function(require,module,exports){
var global=typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {};"use strict";
/*global self*/
var RSVPPromise = require("./promise").Promise;
var isFunction = require("./utils").isFunction;

function polyfill() {
  var local;

  if (typeof global !== 'undefined') {
    local = global;
  } else if (typeof window !== 'undefined' && window.document) {
    local = window;
  } else {
    local = self;
  }

  var es6PromiseSupport = 
    "Promise" in local &&
    // Some of these methods are missing from
    // Firefox/Chrome experimental implementations
    "resolve" in local.Promise &&
    "reject" in local.Promise &&
    "all" in local.Promise &&
    "race" in local.Promise &&
    // Older version of the spec had a resolver object
    // as the arg rather than a function
    (function() {
      var resolve;
      new local.Promise(function(r) { resolve = r; });
      return isFunction(resolve);
    }());

  if (!es6PromiseSupport) {
    local.Promise = RSVPPromise;
  }
}

exports.polyfill = polyfill;
},{"./promise":23,"./utils":27}],23:[function(require,module,exports){
"use strict";
var config = require("./config").config;
var configure = require("./config").configure;
var objectOrFunction = require("./utils").objectOrFunction;
var isFunction = require("./utils").isFunction;
var now = require("./utils").now;
var all = require("./all").all;
var race = require("./race").race;
var staticResolve = require("./resolve").resolve;
var staticReject = require("./reject").reject;
var asap = require("./asap").asap;

var counter = 0;

config.async = asap; // default async is asap;

function Promise(resolver) {
  if (!isFunction(resolver)) {
    throw new TypeError('You must pass a resolver function as the first argument to the promise constructor');
  }

  if (!(this instanceof Promise)) {
    throw new TypeError("Failed to construct 'Promise': Please use the 'new' operator, this object constructor cannot be called as a function.");
  }

  this._subscribers = [];

  invokeResolver(resolver, this);
}

function invokeResolver(resolver, promise) {
  function resolvePromise(value) {
    resolve(promise, value);
  }

  function rejectPromise(reason) {
    reject(promise, reason);
  }

  try {
    resolver(resolvePromise, rejectPromise);
  } catch(e) {
    rejectPromise(e);
  }
}

function invokeCallback(settled, promise, callback, detail) {
  var hasCallback = isFunction(callback),
      value, error, succeeded, failed;

  if (hasCallback) {
    try {
      value = callback(detail);
      succeeded = true;
    } catch(e) {
      failed = true;
      error = e;
    }
  } else {
    value = detail;
    succeeded = true;
  }

  if (handleThenable(promise, value)) {
    return;
  } else if (hasCallback && succeeded) {
    resolve(promise, value);
  } else if (failed) {
    reject(promise, error);
  } else if (settled === FULFILLED) {
    resolve(promise, value);
  } else if (settled === REJECTED) {
    reject(promise, value);
  }
}

var PENDING   = void 0;
var SEALED    = 0;
var FULFILLED = 1;
var REJECTED  = 2;

function subscribe(parent, child, onFulfillment, onRejection) {
  var subscribers = parent._subscribers;
  var length = subscribers.length;

  subscribers[length] = child;
  subscribers[length + FULFILLED] = onFulfillment;
  subscribers[length + REJECTED]  = onRejection;
}

function publish(promise, settled) {
  var child, callback, subscribers = promise._subscribers, detail = promise._detail;

  for (var i = 0; i < subscribers.length; i += 3) {
    child = subscribers[i];
    callback = subscribers[i + settled];

    invokeCallback(settled, child, callback, detail);
  }

  promise._subscribers = null;
}

Promise.prototype = {
  constructor: Promise,

  _state: undefined,
  _detail: undefined,
  _subscribers: undefined,

  then: function(onFulfillment, onRejection) {
    var promise = this;

    var thenPromise = new this.constructor(function() {});

    if (this._state) {
      var callbacks = arguments;
      config.async(function invokePromiseCallback() {
        invokeCallback(promise._state, thenPromise, callbacks[promise._state - 1], promise._detail);
      });
    } else {
      subscribe(this, thenPromise, onFulfillment, onRejection);
    }

    return thenPromise;
  },

  'catch': function(onRejection) {
    return this.then(null, onRejection);
  }
};

Promise.all = all;
Promise.race = race;
Promise.resolve = staticResolve;
Promise.reject = staticReject;

function handleThenable(promise, value) {
  var then = null,
  resolved;

  try {
    if (promise === value) {
      throw new TypeError("A promises callback cannot return that same promise.");
    }

    if (objectOrFunction(value)) {
      then = value.then;

      if (isFunction(then)) {
        then.call(value, function(val) {
          if (resolved) { return true; }
          resolved = true;

          if (value !== val) {
            resolve(promise, val);
          } else {
            fulfill(promise, val);
          }
        }, function(val) {
          if (resolved) { return true; }
          resolved = true;

          reject(promise, val);
        });

        return true;
      }
    }
  } catch (error) {
    if (resolved) { return true; }
    reject(promise, error);
    return true;
  }

  return false;
}

function resolve(promise, value) {
  if (promise === value) {
    fulfill(promise, value);
  } else if (!handleThenable(promise, value)) {
    fulfill(promise, value);
  }
}

function fulfill(promise, value) {
  if (promise._state !== PENDING) { return; }
  promise._state = SEALED;
  promise._detail = value;

  config.async(publishFulfillment, promise);
}

function reject(promise, reason) {
  if (promise._state !== PENDING) { return; }
  promise._state = SEALED;
  promise._detail = reason;

  config.async(publishRejection, promise);
}

function publishFulfillment(promise) {
  publish(promise, promise._state = FULFILLED);
}

function publishRejection(promise) {
  publish(promise, promise._state = REJECTED);
}

exports.Promise = Promise;
},{"./all":19,"./asap":20,"./config":21,"./race":24,"./reject":25,"./resolve":26,"./utils":27}],24:[function(require,module,exports){
"use strict";
/* global toString */
var isArray = require("./utils").isArray;

/**
  `RSVP.race` allows you to watch a series of promises and act as soon as the
  first promise given to the `promises` argument fulfills or rejects.

  Example:

  ```javascript
  var promise1 = new RSVP.Promise(function(resolve, reject){
    setTimeout(function(){
      resolve("promise 1");
    }, 200);
  });

  var promise2 = new RSVP.Promise(function(resolve, reject){
    setTimeout(function(){
      resolve("promise 2");
    }, 100);
  });

  RSVP.race([promise1, promise2]).then(function(result){
    // result === "promise 2" because it was resolved before promise1
    // was resolved.
  });
  ```

  `RSVP.race` is deterministic in that only the state of the first completed
  promise matters. For example, even if other promises given to the `promises`
  array argument are resolved, but the first completed promise has become
  rejected before the other promises became fulfilled, the returned promise
  will become rejected:

  ```javascript
  var promise1 = new RSVP.Promise(function(resolve, reject){
    setTimeout(function(){
      resolve("promise 1");
    }, 200);
  });

  var promise2 = new RSVP.Promise(function(resolve, reject){
    setTimeout(function(){
      reject(new Error("promise 2"));
    }, 100);
  });

  RSVP.race([promise1, promise2]).then(function(result){
    // Code here never runs because there are rejected promises!
  }, function(reason){
    // reason.message === "promise2" because promise 2 became rejected before
    // promise 1 became fulfilled
  });
  ```

  @method race
  @for RSVP
  @param {Array} promises array of promises to observe
  @param {String} label optional string for describing the promise returned.
  Useful for tooling.
  @return {Promise} a promise that becomes fulfilled with the value the first
  completed promises is resolved with if the first completed promise was
  fulfilled, or rejected with the reason that the first completed promise
  was rejected with.
*/
function race(promises) {
  /*jshint validthis:true */
  var Promise = this;

  if (!isArray(promises)) {
    throw new TypeError('You must pass an array to race.');
  }
  return new Promise(function(resolve, reject) {
    var results = [], promise;

    for (var i = 0; i < promises.length; i++) {
      promise = promises[i];

      if (promise && typeof promise.then === 'function') {
        promise.then(resolve, reject);
      } else {
        resolve(promise);
      }
    }
  });
}

exports.race = race;
},{"./utils":27}],25:[function(require,module,exports){
"use strict";
/**
  `RSVP.reject` returns a promise that will become rejected with the passed
  `reason`. `RSVP.reject` is essentially shorthand for the following:

  ```javascript
  var promise = new RSVP.Promise(function(resolve, reject){
    reject(new Error('WHOOPS'));
  });

  promise.then(function(value){
    // Code here doesn't run because the promise is rejected!
  }, function(reason){
    // reason.message === 'WHOOPS'
  });
  ```

  Instead of writing the above, your code now simply becomes the following:

  ```javascript
  var promise = RSVP.reject(new Error('WHOOPS'));

  promise.then(function(value){
    // Code here doesn't run because the promise is rejected!
  }, function(reason){
    // reason.message === 'WHOOPS'
  });
  ```

  @method reject
  @for RSVP
  @param {Any} reason value that the returned promise will be rejected with.
  @param {String} label optional string for identifying the returned promise.
  Useful for tooling.
  @return {Promise} a promise that will become rejected with the given
  `reason`.
*/
function reject(reason) {
  /*jshint validthis:true */
  var Promise = this;

  return new Promise(function (resolve, reject) {
    reject(reason);
  });
}

exports.reject = reject;
},{}],26:[function(require,module,exports){
"use strict";
function resolve(value) {
  /*jshint validthis:true */
  if (value && typeof value === 'object' && value.constructor === this) {
    return value;
  }

  var Promise = this;

  return new Promise(function(resolve) {
    resolve(value);
  });
}

exports.resolve = resolve;
},{}],27:[function(require,module,exports){
"use strict";
function objectOrFunction(x) {
  return isFunction(x) || (typeof x === "object" && x !== null);
}

function isFunction(x) {
  return typeof x === "function";
}

function isArray(x) {
  return Object.prototype.toString.call(x) === "[object Array]";
}

// Date.now is not available in browsers < IE9
// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/now#Compatibility
var now = Date.now || function() { return new Date().getTime(); };


exports.objectOrFunction = objectOrFunction;
exports.isFunction = isFunction;
exports.isArray = isArray;
exports.now = now;
},{}],28:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires config
 * @requires encoding/armor
 * @requires enums
 * @requires packet
 * @module cleartext
 */

'use strict';

var config = require('./config'),
  packet = require('./packet'),
  enums = require('./enums.js'),
  armor = require('./encoding/armor.js');

/**
 * @class
 * @classdesc Class that represents an OpenPGP cleartext signed message.
 * See {@link http://tools.ietf.org/html/rfc4880#section-7}
 * @param  {String}     text       The cleartext of the signed message
 * @param  {module:packet/packetlist} packetlist The packetlist with signature packets or undefined
 *                                 if message not yet signed
 */

function CleartextMessage(text, packetlist) {
  if (!(this instanceof CleartextMessage)) {
    return new CleartextMessage(text, packetlist);
  }
  // normalize EOL to canonical form <CR><LF>
  this.text = text.replace(/\r/g, '').replace(/[\t ]+\n/g, "\n").replace(/\n/g,"\r\n");
  this.packets = packetlist || new packet.List();
}

/**
 * Returns the key IDs of the keys that signed the cleartext message
 * @return {Array<module:type/keyid>} array of keyid objects
 */
CleartextMessage.prototype.getSigningKeyIds = function() {
  var keyIds = [];
  var signatureList = this.packets.filterByTag(enums.packet.signature);
  signatureList.forEach(function(packet) {
    keyIds.push(packet.issuerKeyId);
  });
  return keyIds;
};

/**
 * Sign the cleartext message
 * @param  {Array<module:key~Key>} privateKeys private keys with decrypted secret key data for signing
 */
CleartextMessage.prototype.sign = function(privateKeys) {
  var packetlist = new packet.List();
  var literalDataPacket = new packet.Literal();
  literalDataPacket.setText(this.text);
  for (var i = 0; i < privateKeys.length; i++) {
    if (privateKeys[i].isPublic()) {
      throw new Error('Need private key for signing');
    }
    var signaturePacket = new packet.Signature();
    signaturePacket.signatureType = enums.signature.text;
    signaturePacket.hashAlgorithm = config.prefer_hash_algorithm;
    var signingKeyPacket = privateKeys[i].getSigningKeyPacket();
    signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
    if (!signingKeyPacket.isDecrypted) throw new Error('Private key is not decrypted.');
    signaturePacket.sign(signingKeyPacket, literalDataPacket);
    packetlist.push(signaturePacket);
  }
  this.packets = packetlist;
};

/**
 * Verify signatures of cleartext signed message
 * @param {Array<module:key~Key>} keys array of keys to verify signatures
 * @return {Array<{keyid: module:type/keyid, valid: Boolean}>} list of signer's keyid and validity of signature
 */
CleartextMessage.prototype.verify = function(keys) {
  var result = [];
  var signatureList = this.packets.filterByTag(enums.packet.signature);
  var literalDataPacket = new packet.Literal();
  // we assume that cleartext signature is generated based on UTF8 cleartext
  literalDataPacket.setText(this.text);
  for (var i = 0; i < signatureList.length; i++) {
    var keyPacket = null;
    for (var j = 0; j < keys.length; j++) {
      keyPacket = keys[j].getSigningKeyPacket(signatureList[i].issuerKeyId);
      if (keyPacket) {
        break;
      }
    }

    var verifiedSig = {};
    if (keyPacket) {
      verifiedSig.keyid = signatureList[i].issuerKeyId;
      verifiedSig.valid = signatureList[i].verify(keyPacket, literalDataPacket);
    } else {
      verifiedSig.keyid = signatureList[i].issuerKeyId;
      verifiedSig.valid = null;
    }
    result.push(verifiedSig);
  }
  return result;
};

/**
 * Get cleartext
 * @return {String} cleartext of message
 */
CleartextMessage.prototype.getText = function() {
  // normalize end of line to \n
  return this.text.replace(/\r\n/g,"\n");
};

/**
 * Returns ASCII armored text of cleartext signed message
 * @return {String} ASCII armor
 */
CleartextMessage.prototype.armor = function() {
  var body = {
    hash: enums.read(enums.hash, config.prefer_hash_algorithm).toUpperCase(),
    text: this.text,
    data: this.packets.write()
  };
  return armor.encode(enums.armor.signed, body);
};


/**
 * reads an OpenPGP cleartext signed message and returns a CleartextMessage object
 * @param {String} armoredText text to be parsed
 * @return {module:cleartext~CleartextMessage} new cleartext message object
 * @static
 */
function readArmored(armoredText) {
  var input = armor.decode(armoredText);
  if (input.type !== enums.armor.signed) {
    throw new Error('No cleartext signed message.');
  }
  var packetlist = new packet.List();
  packetlist.read(input.data);
  verifyHeaders(input.headers, packetlist);
  var newMessage = new CleartextMessage(input.text, packetlist);
  return newMessage;
}

/**
 * Compare hash algorithm specified in the armor header with signatures
 * @private
 * @param  {Array<String>} headers    Armor headers
 * @param  {module:packet/packetlist} packetlist The packetlist with signature packets
 */
function verifyHeaders(headers, packetlist) {
  var checkHashAlgos = function(hashAlgos) {
    for (var i = 0; i < packetlist.length; i++) {
      if (packetlist[i].tag === enums.packet.signature &&
          !hashAlgos.some(function(algo) {
            return packetlist[i].hashAlgorithm === algo;
          })) {
        return false;
      }
    }
    return true;
  }
  var oneHeader = null;
  var hashAlgos = [];
  for (var i = 0; i < headers.length; i++) {
    oneHeader = headers[i].match(/Hash: (.+)/); // get header value
    if (oneHeader) {
      oneHeader = oneHeader[1].replace(/\s/g, '');  // remove whitespace
      oneHeader = oneHeader.split(',');
      oneHeader = oneHeader.map(function(hash) {
        hash = hash.toLowerCase();
        try {
          return enums.write(enums.hash, hash);
        } catch (e) {
          throw new Error('Unknown hash algorithm in armor header: ' + hash);
        }
      });
      hashAlgos = hashAlgos.concat(oneHeader);
    } else {
      throw new Error('Only "Hash" header allowed in cleartext signed message');
    }
  }
  if (!hashAlgos.length && !checkHashAlgos([enums.hash.md5])) {
    throw new Error('If no "Hash" header in cleartext signed message, then only MD5 signatures allowed');
  } else if (!checkHashAlgos(hashAlgos)) {
    throw new Error('Hash algorithm mismatch in armor header and signature');
  }
}

exports.CleartextMessage = CleartextMessage;
exports.readArmored = readArmored;

},{"./config":33,"./encoding/armor.js":58,"./enums.js":60,"./packet":70}],29:[function(require,module,exports){
/** @license zlib.js 2012 - imaya [ https://github.com/imaya/zlib.js ] The MIT License */(function() {'use strict';var n=void 0,u=!0,aa=this;function ba(e,d){var c=e.split("."),f=aa;!(c[0]in f)&&f.execScript&&f.execScript("var "+c[0]);for(var a;c.length&&(a=c.shift());)!c.length&&d!==n?f[a]=d:f=f[a]?f[a]:f[a]={}};var C="undefined"!==typeof Uint8Array&&"undefined"!==typeof Uint16Array&&"undefined"!==typeof Uint32Array&&"undefined"!==typeof DataView;function K(e,d){this.index="number"===typeof d?d:0;this.d=0;this.buffer=e instanceof(C?Uint8Array:Array)?e:new (C?Uint8Array:Array)(32768);if(2*this.buffer.length<=this.index)throw Error("invalid index");this.buffer.length<=this.index&&ca(this)}function ca(e){var d=e.buffer,c,f=d.length,a=new (C?Uint8Array:Array)(f<<1);if(C)a.set(d);else for(c=0;c<f;++c)a[c]=d[c];return e.buffer=a}
K.prototype.a=function(e,d,c){var f=this.buffer,a=this.index,b=this.d,k=f[a],m;c&&1<d&&(e=8<d?(L[e&255]<<24|L[e>>>8&255]<<16|L[e>>>16&255]<<8|L[e>>>24&255])>>32-d:L[e]>>8-d);if(8>d+b)k=k<<d|e,b+=d;else for(m=0;m<d;++m)k=k<<1|e>>d-m-1&1,8===++b&&(b=0,f[a++]=L[k],k=0,a===f.length&&(f=ca(this)));f[a]=k;this.buffer=f;this.d=b;this.index=a};K.prototype.finish=function(){var e=this.buffer,d=this.index,c;0<this.d&&(e[d]<<=8-this.d,e[d]=L[e[d]],d++);C?c=e.subarray(0,d):(e.length=d,c=e);return c};
var ga=new (C?Uint8Array:Array)(256),M;for(M=0;256>M;++M){for(var R=M,S=R,ha=7,R=R>>>1;R;R>>>=1)S<<=1,S|=R&1,--ha;ga[M]=(S<<ha&255)>>>0}var L=ga;function ja(e){this.buffer=new (C?Uint16Array:Array)(2*e);this.length=0}ja.prototype.getParent=function(e){return 2*((e-2)/4|0)};ja.prototype.push=function(e,d){var c,f,a=this.buffer,b;c=this.length;a[this.length++]=d;for(a[this.length++]=e;0<c;)if(f=this.getParent(c),a[c]>a[f])b=a[c],a[c]=a[f],a[f]=b,b=a[c+1],a[c+1]=a[f+1],a[f+1]=b,c=f;else break;return this.length};
ja.prototype.pop=function(){var e,d,c=this.buffer,f,a,b;d=c[0];e=c[1];this.length-=2;c[0]=c[this.length];c[1]=c[this.length+1];for(b=0;;){a=2*b+2;if(a>=this.length)break;a+2<this.length&&c[a+2]>c[a]&&(a+=2);if(c[a]>c[b])f=c[b],c[b]=c[a],c[a]=f,f=c[b+1],c[b+1]=c[a+1],c[a+1]=f;else break;b=a}return{index:e,value:d,length:this.length}};function ka(e,d){this.e=ma;this.f=0;this.input=C&&e instanceof Array?new Uint8Array(e):e;this.c=0;d&&(d.lazy&&(this.f=d.lazy),"number"===typeof d.compressionType&&(this.e=d.compressionType),d.outputBuffer&&(this.b=C&&d.outputBuffer instanceof Array?new Uint8Array(d.outputBuffer):d.outputBuffer),"number"===typeof d.outputIndex&&(this.c=d.outputIndex));this.b||(this.b=new (C?Uint8Array:Array)(32768))}var ma=2,T=[],U;
for(U=0;288>U;U++)switch(u){case 143>=U:T.push([U+48,8]);break;case 255>=U:T.push([U-144+400,9]);break;case 279>=U:T.push([U-256+0,7]);break;case 287>=U:T.push([U-280+192,8]);break;default:throw"invalid literal: "+U;}
ka.prototype.h=function(){var e,d,c,f,a=this.input;switch(this.e){case 0:c=0;for(f=a.length;c<f;){d=C?a.subarray(c,c+65535):a.slice(c,c+65535);c+=d.length;var b=d,k=c===f,m=n,g=n,p=n,v=n,x=n,l=this.b,h=this.c;if(C){for(l=new Uint8Array(this.b.buffer);l.length<=h+b.length+5;)l=new Uint8Array(l.length<<1);l.set(this.b)}m=k?1:0;l[h++]=m|0;g=b.length;p=~g+65536&65535;l[h++]=g&255;l[h++]=g>>>8&255;l[h++]=p&255;l[h++]=p>>>8&255;if(C)l.set(b,h),h+=b.length,l=l.subarray(0,h);else{v=0;for(x=b.length;v<x;++v)l[h++]=
b[v];l.length=h}this.c=h;this.b=l}break;case 1:var q=new K(C?new Uint8Array(this.b.buffer):this.b,this.c);q.a(1,1,u);q.a(1,2,u);var t=na(this,a),w,da,z;w=0;for(da=t.length;w<da;w++)if(z=t[w],K.prototype.a.apply(q,T[z]),256<z)q.a(t[++w],t[++w],u),q.a(t[++w],5),q.a(t[++w],t[++w],u);else if(256===z)break;this.b=q.finish();this.c=this.b.length;break;case ma:var B=new K(C?new Uint8Array(this.b.buffer):this.b,this.c),ra,J,N,O,P,Ia=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15],W,sa,X,ta,ea,ia=Array(19),
ua,Q,fa,y,va;ra=ma;B.a(1,1,u);B.a(ra,2,u);J=na(this,a);W=oa(this.j,15);sa=pa(W);X=oa(this.i,7);ta=pa(X);for(N=286;257<N&&0===W[N-1];N--);for(O=30;1<O&&0===X[O-1];O--);var wa=N,xa=O,F=new (C?Uint32Array:Array)(wa+xa),r,G,s,Y,E=new (C?Uint32Array:Array)(316),D,A,H=new (C?Uint8Array:Array)(19);for(r=G=0;r<wa;r++)F[G++]=W[r];for(r=0;r<xa;r++)F[G++]=X[r];if(!C){r=0;for(Y=H.length;r<Y;++r)H[r]=0}r=D=0;for(Y=F.length;r<Y;r+=G){for(G=1;r+G<Y&&F[r+G]===F[r];++G);s=G;if(0===F[r])if(3>s)for(;0<s--;)E[D++]=0,
H[0]++;else for(;0<s;)A=138>s?s:138,A>s-3&&A<s&&(A=s-3),10>=A?(E[D++]=17,E[D++]=A-3,H[17]++):(E[D++]=18,E[D++]=A-11,H[18]++),s-=A;else if(E[D++]=F[r],H[F[r]]++,s--,3>s)for(;0<s--;)E[D++]=F[r],H[F[r]]++;else for(;0<s;)A=6>s?s:6,A>s-3&&A<s&&(A=s-3),E[D++]=16,E[D++]=A-3,H[16]++,s-=A}e=C?E.subarray(0,D):E.slice(0,D);ea=oa(H,7);for(y=0;19>y;y++)ia[y]=ea[Ia[y]];for(P=19;4<P&&0===ia[P-1];P--);ua=pa(ea);B.a(N-257,5,u);B.a(O-1,5,u);B.a(P-4,4,u);for(y=0;y<P;y++)B.a(ia[y],3,u);y=0;for(va=e.length;y<va;y++)if(Q=
e[y],B.a(ua[Q],ea[Q],u),16<=Q){y++;switch(Q){case 16:fa=2;break;case 17:fa=3;break;case 18:fa=7;break;default:throw"invalid code: "+Q;}B.a(e[y],fa,u)}var ya=[sa,W],za=[ta,X],I,Aa,Z,la,Ba,Ca,Da,Ea;Ba=ya[0];Ca=ya[1];Da=za[0];Ea=za[1];I=0;for(Aa=J.length;I<Aa;++I)if(Z=J[I],B.a(Ba[Z],Ca[Z],u),256<Z)B.a(J[++I],J[++I],u),la=J[++I],B.a(Da[la],Ea[la],u),B.a(J[++I],J[++I],u);else if(256===Z)break;this.b=B.finish();this.c=this.b.length;break;default:throw"invalid compression type";}return this.b};
function qa(e,d){this.length=e;this.g=d}
var Fa=function(){function e(a){switch(u){case 3===a:return[257,a-3,0];case 4===a:return[258,a-4,0];case 5===a:return[259,a-5,0];case 6===a:return[260,a-6,0];case 7===a:return[261,a-7,0];case 8===a:return[262,a-8,0];case 9===a:return[263,a-9,0];case 10===a:return[264,a-10,0];case 12>=a:return[265,a-11,1];case 14>=a:return[266,a-13,1];case 16>=a:return[267,a-15,1];case 18>=a:return[268,a-17,1];case 22>=a:return[269,a-19,2];case 26>=a:return[270,a-23,2];case 30>=a:return[271,a-27,2];case 34>=a:return[272,
a-31,2];case 42>=a:return[273,a-35,3];case 50>=a:return[274,a-43,3];case 58>=a:return[275,a-51,3];case 66>=a:return[276,a-59,3];case 82>=a:return[277,a-67,4];case 98>=a:return[278,a-83,4];case 114>=a:return[279,a-99,4];case 130>=a:return[280,a-115,4];case 162>=a:return[281,a-131,5];case 194>=a:return[282,a-163,5];case 226>=a:return[283,a-195,5];case 257>=a:return[284,a-227,5];case 258===a:return[285,a-258,0];default:throw"invalid length: "+a;}}var d=[],c,f;for(c=3;258>=c;c++)f=e(c),d[c]=f[2]<<24|
f[1]<<16|f[0];return d}(),Ga=C?new Uint32Array(Fa):Fa;
function na(e,d){function c(a,c){var b=a.g,d=[],f=0,e;e=Ga[a.length];d[f++]=e&65535;d[f++]=e>>16&255;d[f++]=e>>24;var g;switch(u){case 1===b:g=[0,b-1,0];break;case 2===b:g=[1,b-2,0];break;case 3===b:g=[2,b-3,0];break;case 4===b:g=[3,b-4,0];break;case 6>=b:g=[4,b-5,1];break;case 8>=b:g=[5,b-7,1];break;case 12>=b:g=[6,b-9,2];break;case 16>=b:g=[7,b-13,2];break;case 24>=b:g=[8,b-17,3];break;case 32>=b:g=[9,b-25,3];break;case 48>=b:g=[10,b-33,4];break;case 64>=b:g=[11,b-49,4];break;case 96>=b:g=[12,b-
65,5];break;case 128>=b:g=[13,b-97,5];break;case 192>=b:g=[14,b-129,6];break;case 256>=b:g=[15,b-193,6];break;case 384>=b:g=[16,b-257,7];break;case 512>=b:g=[17,b-385,7];break;case 768>=b:g=[18,b-513,8];break;case 1024>=b:g=[19,b-769,8];break;case 1536>=b:g=[20,b-1025,9];break;case 2048>=b:g=[21,b-1537,9];break;case 3072>=b:g=[22,b-2049,10];break;case 4096>=b:g=[23,b-3073,10];break;case 6144>=b:g=[24,b-4097,11];break;case 8192>=b:g=[25,b-6145,11];break;case 12288>=b:g=[26,b-8193,12];break;case 16384>=
b:g=[27,b-12289,12];break;case 24576>=b:g=[28,b-16385,13];break;case 32768>=b:g=[29,b-24577,13];break;default:throw"invalid distance";}e=g;d[f++]=e[0];d[f++]=e[1];d[f++]=e[2];var k,m;k=0;for(m=d.length;k<m;++k)l[h++]=d[k];t[d[0]]++;w[d[3]]++;q=a.length+c-1;x=null}var f,a,b,k,m,g={},p,v,x,l=C?new Uint16Array(2*d.length):[],h=0,q=0,t=new (C?Uint32Array:Array)(286),w=new (C?Uint32Array:Array)(30),da=e.f,z;if(!C){for(b=0;285>=b;)t[b++]=0;for(b=0;29>=b;)w[b++]=0}t[256]=1;f=0;for(a=d.length;f<a;++f){b=
m=0;for(k=3;b<k&&f+b!==a;++b)m=m<<8|d[f+b];g[m]===n&&(g[m]=[]);p=g[m];if(!(0<q--)){for(;0<p.length&&32768<f-p[0];)p.shift();if(f+3>=a){x&&c(x,-1);b=0;for(k=a-f;b<k;++b)z=d[f+b],l[h++]=z,++t[z];break}0<p.length?(v=Ha(d,f,p),x?x.length<v.length?(z=d[f-1],l[h++]=z,++t[z],c(v,0)):c(x,-1):v.length<da?x=v:c(v,0)):x?c(x,-1):(z=d[f],l[h++]=z,++t[z])}p.push(f)}l[h++]=256;t[256]++;e.j=t;e.i=w;return C?l.subarray(0,h):l}
function Ha(e,d,c){var f,a,b=0,k,m,g,p,v=e.length;m=0;p=c.length;a:for(;m<p;m++){f=c[p-m-1];k=3;if(3<b){for(g=b;3<g;g--)if(e[f+g-1]!==e[d+g-1])continue a;k=b}for(;258>k&&d+k<v&&e[f+k]===e[d+k];)++k;k>b&&(a=f,b=k);if(258===k)break}return new qa(b,d-a)}
function oa(e,d){var c=e.length,f=new ja(572),a=new (C?Uint8Array:Array)(c),b,k,m,g,p;if(!C)for(g=0;g<c;g++)a[g]=0;for(g=0;g<c;++g)0<e[g]&&f.push(g,e[g]);b=Array(f.length/2);k=new (C?Uint32Array:Array)(f.length/2);if(1===b.length)return a[f.pop().index]=1,a;g=0;for(p=f.length/2;g<p;++g)b[g]=f.pop(),k[g]=b[g].value;m=Ja(k,k.length,d);g=0;for(p=b.length;g<p;++g)a[b[g].index]=m[g];return a}
function Ja(e,d,c){function f(a){var b=g[a][p[a]];b===d?(f(a+1),f(a+1)):--k[b];++p[a]}var a=new (C?Uint16Array:Array)(c),b=new (C?Uint8Array:Array)(c),k=new (C?Uint8Array:Array)(d),m=Array(c),g=Array(c),p=Array(c),v=(1<<c)-d,x=1<<c-1,l,h,q,t,w;a[c-1]=d;for(h=0;h<c;++h)v<x?b[h]=0:(b[h]=1,v-=x),v<<=1,a[c-2-h]=(a[c-1-h]/2|0)+d;a[0]=b[0];m[0]=Array(a[0]);g[0]=Array(a[0]);for(h=1;h<c;++h)a[h]>2*a[h-1]+b[h]&&(a[h]=2*a[h-1]+b[h]),m[h]=Array(a[h]),g[h]=Array(a[h]);for(l=0;l<d;++l)k[l]=c;for(q=0;q<a[c-1];++q)m[c-
1][q]=e[q],g[c-1][q]=q;for(l=0;l<c;++l)p[l]=0;1===b[c-1]&&(--k[0],++p[c-1]);for(h=c-2;0<=h;--h){t=l=0;w=p[h+1];for(q=0;q<a[h];q++)t=m[h+1][w]+m[h+1][w+1],t>e[l]?(m[h][q]=t,g[h][q]=d,w+=2):(m[h][q]=e[l],g[h][q]=l,++l);p[h]=0;1===b[h]&&f(h)}return k}
function pa(e){var d=new (C?Uint16Array:Array)(e.length),c=[],f=[],a=0,b,k,m,g;b=0;for(k=e.length;b<k;b++)c[e[b]]=(c[e[b]]|0)+1;b=1;for(k=16;b<=k;b++)f[b]=a,a+=c[b]|0,a<<=1;b=0;for(k=e.length;b<k;b++){a=f[e[b]];f[e[b]]+=1;m=d[b]=0;for(g=e[b];m<g;m++)d[b]=d[b]<<1|a&1,a>>>=1}return d};ba("Zlib.RawDeflate",ka);ba("Zlib.RawDeflate.prototype.compress",ka.prototype.h);var Ka={NONE:0,FIXED:1,DYNAMIC:ma},V,La,$,Ma;if(Object.keys)V=Object.keys(Ka);else for(La in V=[],$=0,Ka)V[$++]=La;$=0;for(Ma=V.length;$<Ma;++$)La=V[$],ba("Zlib.RawDeflate.CompressionType."+La,Ka[La]);}).call(this); //@ sourceMappingURL=rawdeflate.min.js.map

},{}],30:[function(require,module,exports){
/** @license zlib.js 2012 - imaya [ https://github.com/imaya/zlib.js ] The MIT License */(function() {'use strict';var l=this;function p(b,e){var a=b.split("."),c=l;!(a[0]in c)&&c.execScript&&c.execScript("var "+a[0]);for(var d;a.length&&(d=a.shift());)!a.length&&void 0!==e?c[d]=e:c=c[d]?c[d]:c[d]={}};var q="undefined"!==typeof Uint8Array&&"undefined"!==typeof Uint16Array&&"undefined"!==typeof Uint32Array&&"undefined"!==typeof DataView;function t(b){var e=b.length,a=0,c=Number.POSITIVE_INFINITY,d,f,g,h,k,m,r,n,s,J;for(n=0;n<e;++n)b[n]>a&&(a=b[n]),b[n]<c&&(c=b[n]);d=1<<a;f=new (q?Uint32Array:Array)(d);g=1;h=0;for(k=2;g<=a;){for(n=0;n<e;++n)if(b[n]===g){m=0;r=h;for(s=0;s<g;++s)m=m<<1|r&1,r>>=1;J=g<<16|n;for(s=m;s<d;s+=k)f[s]=J;++h}++g;h<<=1;k<<=1}return[f,a,c]};function u(b,e){this.g=[];this.h=32768;this.c=this.f=this.d=this.k=0;this.input=q?new Uint8Array(b):b;this.l=!1;this.i=v;this.q=!1;if(e||!(e={}))e.index&&(this.d=e.index),e.bufferSize&&(this.h=e.bufferSize),e.bufferType&&(this.i=e.bufferType),e.resize&&(this.q=e.resize);switch(this.i){case w:this.a=32768;this.b=new (q?Uint8Array:Array)(32768+this.h+258);break;case v:this.a=0;this.b=new (q?Uint8Array:Array)(this.h);this.e=this.v;this.m=this.s;this.j=this.t;break;default:throw Error("invalid inflate mode");
}}var w=0,v=1;
u.prototype.u=function(){for(;!this.l;){var b=x(this,3);b&1&&(this.l=!0);b>>>=1;switch(b){case 0:var e=this.input,a=this.d,c=this.b,d=this.a,f=e.length,g=void 0,h=void 0,k=c.length,m=void 0;this.c=this.f=0;if(a+1>=f)throw Error("invalid uncompressed block header: LEN");g=e[a++]|e[a++]<<8;if(a+1>=f)throw Error("invalid uncompressed block header: NLEN");h=e[a++]|e[a++]<<8;if(g===~h)throw Error("invalid uncompressed block header: length verify");if(a+g>e.length)throw Error("input buffer is broken");switch(this.i){case w:for(;d+
g>c.length;){m=k-d;g-=m;if(q)c.set(e.subarray(a,a+m),d),d+=m,a+=m;else for(;m--;)c[d++]=e[a++];this.a=d;c=this.e();d=this.a}break;case v:for(;d+g>c.length;)c=this.e({o:2});break;default:throw Error("invalid inflate mode");}if(q)c.set(e.subarray(a,a+g),d),d+=g,a+=g;else for(;g--;)c[d++]=e[a++];this.d=a;this.a=d;this.b=c;break;case 1:this.j(y,z);break;case 2:A(this);break;default:throw Error("unknown BTYPE: "+b);}}return this.m()};
var B=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15],C=q?new Uint16Array(B):B,D=[3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258,258,258],E=q?new Uint16Array(D):D,F=[0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0,0,0],G=q?new Uint8Array(F):F,H=[1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577],I=q?new Uint16Array(H):H,K=[0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,
13],L=q?new Uint8Array(K):K,M=new (q?Uint8Array:Array)(288),N,O;N=0;for(O=M.length;N<O;++N)M[N]=143>=N?8:255>=N?9:279>=N?7:8;var y=t(M),P=new (q?Uint8Array:Array)(30),Q,R;Q=0;for(R=P.length;Q<R;++Q)P[Q]=5;var z=t(P);function x(b,e){for(var a=b.f,c=b.c,d=b.input,f=b.d,g=d.length,h;c<e;){if(f>=g)throw Error("input buffer is broken");a|=d[f++]<<c;c+=8}h=a&(1<<e)-1;b.f=a>>>e;b.c=c-e;b.d=f;return h}
function S(b,e){for(var a=b.f,c=b.c,d=b.input,f=b.d,g=d.length,h=e[0],k=e[1],m,r;c<k&&!(f>=g);)a|=d[f++]<<c,c+=8;m=h[a&(1<<k)-1];r=m>>>16;b.f=a>>r;b.c=c-r;b.d=f;return m&65535}
function A(b){function e(a,b,c){var e,d=this.p,f,g;for(g=0;g<a;)switch(e=S(this,b),e){case 16:for(f=3+x(this,2);f--;)c[g++]=d;break;case 17:for(f=3+x(this,3);f--;)c[g++]=0;d=0;break;case 18:for(f=11+x(this,7);f--;)c[g++]=0;d=0;break;default:d=c[g++]=e}this.p=d;return c}var a=x(b,5)+257,c=x(b,5)+1,d=x(b,4)+4,f=new (q?Uint8Array:Array)(C.length),g,h,k,m;for(m=0;m<d;++m)f[C[m]]=x(b,3);if(!q){m=d;for(d=f.length;m<d;++m)f[C[m]]=0}g=t(f);h=new (q?Uint8Array:Array)(a);k=new (q?Uint8Array:Array)(c);b.p=0;
b.j(t(e.call(b,a,g,h)),t(e.call(b,c,g,k)))}u.prototype.j=function(b,e){var a=this.b,c=this.a;this.n=b;for(var d=a.length-258,f,g,h,k;256!==(f=S(this,b));)if(256>f)c>=d&&(this.a=c,a=this.e(),c=this.a),a[c++]=f;else{g=f-257;k=E[g];0<G[g]&&(k+=x(this,G[g]));f=S(this,e);h=I[f];0<L[f]&&(h+=x(this,L[f]));c>=d&&(this.a=c,a=this.e(),c=this.a);for(;k--;)a[c]=a[c++-h]}for(;8<=this.c;)this.c-=8,this.d--;this.a=c};
u.prototype.t=function(b,e){var a=this.b,c=this.a;this.n=b;for(var d=a.length,f,g,h,k;256!==(f=S(this,b));)if(256>f)c>=d&&(a=this.e(),d=a.length),a[c++]=f;else{g=f-257;k=E[g];0<G[g]&&(k+=x(this,G[g]));f=S(this,e);h=I[f];0<L[f]&&(h+=x(this,L[f]));c+k>d&&(a=this.e(),d=a.length);for(;k--;)a[c]=a[c++-h]}for(;8<=this.c;)this.c-=8,this.d--;this.a=c};
u.prototype.e=function(){var b=new (q?Uint8Array:Array)(this.a-32768),e=this.a-32768,a,c,d=this.b;if(q)b.set(d.subarray(32768,b.length));else{a=0;for(c=b.length;a<c;++a)b[a]=d[a+32768]}this.g.push(b);this.k+=b.length;if(q)d.set(d.subarray(e,e+32768));else for(a=0;32768>a;++a)d[a]=d[e+a];this.a=32768;return d};
u.prototype.v=function(b){var e,a=this.input.length/this.d+1|0,c,d,f,g=this.input,h=this.b;b&&("number"===typeof b.o&&(a=b.o),"number"===typeof b.r&&(a+=b.r));2>a?(c=(g.length-this.d)/this.n[2],f=258*(c/2)|0,d=f<h.length?h.length+f:h.length<<1):d=h.length*a;q?(e=new Uint8Array(d),e.set(h)):e=h;return this.b=e};
u.prototype.m=function(){var b=0,e=this.b,a=this.g,c,d=new (q?Uint8Array:Array)(this.k+(this.a-32768)),f,g,h,k;if(0===a.length)return q?this.b.subarray(32768,this.a):this.b.slice(32768,this.a);f=0;for(g=a.length;f<g;++f){c=a[f];h=0;for(k=c.length;h<k;++h)d[b++]=c[h]}f=32768;for(g=this.a;f<g;++f)d[b++]=e[f];this.g=[];return this.buffer=d};
u.prototype.s=function(){var b,e=this.a;q?this.q?(b=new Uint8Array(e),b.set(this.b.subarray(0,e))):b=this.b.subarray(0,e):(this.b.length>e&&(this.b.length=e),b=this.b);return this.buffer=b};p("Zlib.RawInflate",u);p("Zlib.RawInflate.prototype.decompress",u.prototype.u);var T={ADAPTIVE:v,BLOCK:w},U,V,W,X;if(Object.keys)U=Object.keys(T);else for(V in U=[],W=0,T)U[W++]=V;W=0;for(X=U.length;W<X;++W)V=U[W],p("Zlib.RawInflate.BufferType."+V,T[V]);}).call(this); //@ sourceMappingURL=rawinflate.min.js.map

},{}],31:[function(require,module,exports){
/** @license zlib.js 2012 - imaya [ https://github.com/imaya/zlib.js ] The MIT License */(function() {'use strict';function l(d){throw d;}var v=void 0,x=!0,aa=this;function D(d,a){var c=d.split("."),e=aa;!(c[0]in e)&&e.execScript&&e.execScript("var "+c[0]);for(var b;c.length&&(b=c.shift());)!c.length&&a!==v?e[b]=a:e=e[b]?e[b]:e[b]={}};var F="undefined"!==typeof Uint8Array&&"undefined"!==typeof Uint16Array&&"undefined"!==typeof Uint32Array&&"undefined"!==typeof DataView;function H(d,a){this.index="number"===typeof a?a:0;this.i=0;this.buffer=d instanceof(F?Uint8Array:Array)?d:new (F?Uint8Array:Array)(32768);2*this.buffer.length<=this.index&&l(Error("invalid index"));this.buffer.length<=this.index&&this.f()}H.prototype.f=function(){var d=this.buffer,a,c=d.length,e=new (F?Uint8Array:Array)(c<<1);if(F)e.set(d);else for(a=0;a<c;++a)e[a]=d[a];return this.buffer=e};
H.prototype.d=function(d,a,c){var e=this.buffer,b=this.index,f=this.i,g=e[b],h;c&&1<a&&(d=8<a?(N[d&255]<<24|N[d>>>8&255]<<16|N[d>>>16&255]<<8|N[d>>>24&255])>>32-a:N[d]>>8-a);if(8>a+f)g=g<<a|d,f+=a;else for(h=0;h<a;++h)g=g<<1|d>>a-h-1&1,8===++f&&(f=0,e[b++]=N[g],g=0,b===e.length&&(e=this.f()));e[b]=g;this.buffer=e;this.i=f;this.index=b};H.prototype.finish=function(){var d=this.buffer,a=this.index,c;0<this.i&&(d[a]<<=8-this.i,d[a]=N[d[a]],a++);F?c=d.subarray(0,a):(d.length=a,c=d);return c};
var fa=new (F?Uint8Array:Array)(256),O;for(O=0;256>O;++O){for(var P=O,Q=P,ga=7,P=P>>>1;P;P>>>=1)Q<<=1,Q|=P&1,--ga;fa[O]=(Q<<ga&255)>>>0}var N=fa;function ha(d){this.buffer=new (F?Uint16Array:Array)(2*d);this.length=0}ha.prototype.getParent=function(d){return 2*((d-2)/4|0)};ha.prototype.push=function(d,a){var c,e,b=this.buffer,f;c=this.length;b[this.length++]=a;for(b[this.length++]=d;0<c;)if(e=this.getParent(c),b[c]>b[e])f=b[c],b[c]=b[e],b[e]=f,f=b[c+1],b[c+1]=b[e+1],b[e+1]=f,c=e;else break;return this.length};
ha.prototype.pop=function(){var d,a,c=this.buffer,e,b,f;a=c[0];d=c[1];this.length-=2;c[0]=c[this.length];c[1]=c[this.length+1];for(f=0;;){b=2*f+2;if(b>=this.length)break;b+2<this.length&&c[b+2]>c[b]&&(b+=2);if(c[b]>c[f])e=c[f],c[f]=c[b],c[b]=e,e=c[f+1],c[f+1]=c[b+1],c[b+1]=e;else break;f=b}return{index:d,value:a,length:this.length}};function R(d){var a=d.length,c=0,e=Number.POSITIVE_INFINITY,b,f,g,h,k,n,q,r,p,m;for(r=0;r<a;++r)d[r]>c&&(c=d[r]),d[r]<e&&(e=d[r]);b=1<<c;f=new (F?Uint32Array:Array)(b);g=1;h=0;for(k=2;g<=c;){for(r=0;r<a;++r)if(d[r]===g){n=0;q=h;for(p=0;p<g;++p)n=n<<1|q&1,q>>=1;m=g<<16|r;for(p=n;p<b;p+=k)f[p]=m;++h}++g;h<<=1;k<<=1}return[f,c,e]};function ia(d,a){this.h=ma;this.w=0;this.input=F&&d instanceof Array?new Uint8Array(d):d;this.b=0;a&&(a.lazy&&(this.w=a.lazy),"number"===typeof a.compressionType&&(this.h=a.compressionType),a.outputBuffer&&(this.a=F&&a.outputBuffer instanceof Array?new Uint8Array(a.outputBuffer):a.outputBuffer),"number"===typeof a.outputIndex&&(this.b=a.outputIndex));this.a||(this.a=new (F?Uint8Array:Array)(32768))}var ma=2,na={NONE:0,r:1,k:ma,O:3},oa=[],S;
for(S=0;288>S;S++)switch(x){case 143>=S:oa.push([S+48,8]);break;case 255>=S:oa.push([S-144+400,9]);break;case 279>=S:oa.push([S-256+0,7]);break;case 287>=S:oa.push([S-280+192,8]);break;default:l("invalid literal: "+S)}
ia.prototype.j=function(){var d,a,c,e,b=this.input;switch(this.h){case 0:c=0;for(e=b.length;c<e;){a=F?b.subarray(c,c+65535):b.slice(c,c+65535);c+=a.length;var f=a,g=c===e,h=v,k=v,n=v,q=v,r=v,p=this.a,m=this.b;if(F){for(p=new Uint8Array(this.a.buffer);p.length<=m+f.length+5;)p=new Uint8Array(p.length<<1);p.set(this.a)}h=g?1:0;p[m++]=h|0;k=f.length;n=~k+65536&65535;p[m++]=k&255;p[m++]=k>>>8&255;p[m++]=n&255;p[m++]=n>>>8&255;if(F)p.set(f,m),m+=f.length,p=p.subarray(0,m);else{q=0;for(r=f.length;q<r;++q)p[m++]=
f[q];p.length=m}this.b=m;this.a=p}break;case 1:var s=new H(F?new Uint8Array(this.a.buffer):this.a,this.b);s.d(1,1,x);s.d(1,2,x);var w=pa(this,b),y,ja,A;y=0;for(ja=w.length;y<ja;y++)if(A=w[y],H.prototype.d.apply(s,oa[A]),256<A)s.d(w[++y],w[++y],x),s.d(w[++y],5),s.d(w[++y],w[++y],x);else if(256===A)break;this.a=s.finish();this.b=this.a.length;break;case ma:var C=new H(F?new Uint8Array(this.a.buffer):this.a,this.b),Ea,M,U,V,W,gb=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15],ba,Fa,ca,Ga,ka,ra=Array(19),
Ha,X,la,z,Ia;Ea=ma;C.d(1,1,x);C.d(Ea,2,x);M=pa(this,b);ba=qa(this.M,15);Fa=sa(ba);ca=qa(this.L,7);Ga=sa(ca);for(U=286;257<U&&0===ba[U-1];U--);for(V=30;1<V&&0===ca[V-1];V--);var Ja=U,Ka=V,I=new (F?Uint32Array:Array)(Ja+Ka),t,J,u,da,G=new (F?Uint32Array:Array)(316),E,B,K=new (F?Uint8Array:Array)(19);for(t=J=0;t<Ja;t++)I[J++]=ba[t];for(t=0;t<Ka;t++)I[J++]=ca[t];if(!F){t=0;for(da=K.length;t<da;++t)K[t]=0}t=E=0;for(da=I.length;t<da;t+=J){for(J=1;t+J<da&&I[t+J]===I[t];++J);u=J;if(0===I[t])if(3>u)for(;0<
u--;)G[E++]=0,K[0]++;else for(;0<u;)B=138>u?u:138,B>u-3&&B<u&&(B=u-3),10>=B?(G[E++]=17,G[E++]=B-3,K[17]++):(G[E++]=18,G[E++]=B-11,K[18]++),u-=B;else if(G[E++]=I[t],K[I[t]]++,u--,3>u)for(;0<u--;)G[E++]=I[t],K[I[t]]++;else for(;0<u;)B=6>u?u:6,B>u-3&&B<u&&(B=u-3),G[E++]=16,G[E++]=B-3,K[16]++,u-=B}d=F?G.subarray(0,E):G.slice(0,E);ka=qa(K,7);for(z=0;19>z;z++)ra[z]=ka[gb[z]];for(W=19;4<W&&0===ra[W-1];W--);Ha=sa(ka);C.d(U-257,5,x);C.d(V-1,5,x);C.d(W-4,4,x);for(z=0;z<W;z++)C.d(ra[z],3,x);z=0;for(Ia=d.length;z<
Ia;z++)if(X=d[z],C.d(Ha[X],ka[X],x),16<=X){z++;switch(X){case 16:la=2;break;case 17:la=3;break;case 18:la=7;break;default:l("invalid code: "+X)}C.d(d[z],la,x)}var La=[Fa,ba],Ma=[Ga,ca],L,Na,ea,ua,Oa,Pa,Qa,Ra;Oa=La[0];Pa=La[1];Qa=Ma[0];Ra=Ma[1];L=0;for(Na=M.length;L<Na;++L)if(ea=M[L],C.d(Oa[ea],Pa[ea],x),256<ea)C.d(M[++L],M[++L],x),ua=M[++L],C.d(Qa[ua],Ra[ua],x),C.d(M[++L],M[++L],x);else if(256===ea)break;this.a=C.finish();this.b=this.a.length;break;default:l("invalid compression type")}return this.a};
function ta(d,a){this.length=d;this.H=a}
var va=function(){function d(b){switch(x){case 3===b:return[257,b-3,0];case 4===b:return[258,b-4,0];case 5===b:return[259,b-5,0];case 6===b:return[260,b-6,0];case 7===b:return[261,b-7,0];case 8===b:return[262,b-8,0];case 9===b:return[263,b-9,0];case 10===b:return[264,b-10,0];case 12>=b:return[265,b-11,1];case 14>=b:return[266,b-13,1];case 16>=b:return[267,b-15,1];case 18>=b:return[268,b-17,1];case 22>=b:return[269,b-19,2];case 26>=b:return[270,b-23,2];case 30>=b:return[271,b-27,2];case 34>=b:return[272,
b-31,2];case 42>=b:return[273,b-35,3];case 50>=b:return[274,b-43,3];case 58>=b:return[275,b-51,3];case 66>=b:return[276,b-59,3];case 82>=b:return[277,b-67,4];case 98>=b:return[278,b-83,4];case 114>=b:return[279,b-99,4];case 130>=b:return[280,b-115,4];case 162>=b:return[281,b-131,5];case 194>=b:return[282,b-163,5];case 226>=b:return[283,b-195,5];case 257>=b:return[284,b-227,5];case 258===b:return[285,b-258,0];default:l("invalid length: "+b)}}var a=[],c,e;for(c=3;258>=c;c++)e=d(c),a[c]=e[2]<<24|e[1]<<
16|e[0];return a}(),wa=F?new Uint32Array(va):va;
function pa(d,a){function c(b,c){var a=b.H,d=[],e=0,f;f=wa[b.length];d[e++]=f&65535;d[e++]=f>>16&255;d[e++]=f>>24;var g;switch(x){case 1===a:g=[0,a-1,0];break;case 2===a:g=[1,a-2,0];break;case 3===a:g=[2,a-3,0];break;case 4===a:g=[3,a-4,0];break;case 6>=a:g=[4,a-5,1];break;case 8>=a:g=[5,a-7,1];break;case 12>=a:g=[6,a-9,2];break;case 16>=a:g=[7,a-13,2];break;case 24>=a:g=[8,a-17,3];break;case 32>=a:g=[9,a-25,3];break;case 48>=a:g=[10,a-33,4];break;case 64>=a:g=[11,a-49,4];break;case 96>=a:g=[12,a-
65,5];break;case 128>=a:g=[13,a-97,5];break;case 192>=a:g=[14,a-129,6];break;case 256>=a:g=[15,a-193,6];break;case 384>=a:g=[16,a-257,7];break;case 512>=a:g=[17,a-385,7];break;case 768>=a:g=[18,a-513,8];break;case 1024>=a:g=[19,a-769,8];break;case 1536>=a:g=[20,a-1025,9];break;case 2048>=a:g=[21,a-1537,9];break;case 3072>=a:g=[22,a-2049,10];break;case 4096>=a:g=[23,a-3073,10];break;case 6144>=a:g=[24,a-4097,11];break;case 8192>=a:g=[25,a-6145,11];break;case 12288>=a:g=[26,a-8193,12];break;case 16384>=
a:g=[27,a-12289,12];break;case 24576>=a:g=[28,a-16385,13];break;case 32768>=a:g=[29,a-24577,13];break;default:l("invalid distance")}f=g;d[e++]=f[0];d[e++]=f[1];d[e++]=f[2];var h,k;h=0;for(k=d.length;h<k;++h)p[m++]=d[h];w[d[0]]++;y[d[3]]++;s=b.length+c-1;r=null}var e,b,f,g,h,k={},n,q,r,p=F?new Uint16Array(2*a.length):[],m=0,s=0,w=new (F?Uint32Array:Array)(286),y=new (F?Uint32Array:Array)(30),ja=d.w,A;if(!F){for(f=0;285>=f;)w[f++]=0;for(f=0;29>=f;)y[f++]=0}w[256]=1;e=0;for(b=a.length;e<b;++e){f=h=0;
for(g=3;f<g&&e+f!==b;++f)h=h<<8|a[e+f];k[h]===v&&(k[h]=[]);n=k[h];if(!(0<s--)){for(;0<n.length&&32768<e-n[0];)n.shift();if(e+3>=b){r&&c(r,-1);f=0;for(g=b-e;f<g;++f)A=a[e+f],p[m++]=A,++w[A];break}0<n.length?(q=xa(a,e,n),r?r.length<q.length?(A=a[e-1],p[m++]=A,++w[A],c(q,0)):c(r,-1):q.length<ja?r=q:c(q,0)):r?c(r,-1):(A=a[e],p[m++]=A,++w[A])}n.push(e)}p[m++]=256;w[256]++;d.M=w;d.L=y;return F?p.subarray(0,m):p}
function xa(d,a,c){var e,b,f=0,g,h,k,n,q=d.length;h=0;n=c.length;a:for(;h<n;h++){e=c[n-h-1];g=3;if(3<f){for(k=f;3<k;k--)if(d[e+k-1]!==d[a+k-1])continue a;g=f}for(;258>g&&a+g<q&&d[e+g]===d[a+g];)++g;g>f&&(b=e,f=g);if(258===g)break}return new ta(f,a-b)}
function qa(d,a){var c=d.length,e=new ha(572),b=new (F?Uint8Array:Array)(c),f,g,h,k,n;if(!F)for(k=0;k<c;k++)b[k]=0;for(k=0;k<c;++k)0<d[k]&&e.push(k,d[k]);f=Array(e.length/2);g=new (F?Uint32Array:Array)(e.length/2);if(1===f.length)return b[e.pop().index]=1,b;k=0;for(n=e.length/2;k<n;++k)f[k]=e.pop(),g[k]=f[k].value;h=ya(g,g.length,a);k=0;for(n=f.length;k<n;++k)b[f[k].index]=h[k];return b}
function ya(d,a,c){function e(b){var c=k[b][n[b]];c===a?(e(b+1),e(b+1)):--g[c];++n[b]}var b=new (F?Uint16Array:Array)(c),f=new (F?Uint8Array:Array)(c),g=new (F?Uint8Array:Array)(a),h=Array(c),k=Array(c),n=Array(c),q=(1<<c)-a,r=1<<c-1,p,m,s,w,y;b[c-1]=a;for(m=0;m<c;++m)q<r?f[m]=0:(f[m]=1,q-=r),q<<=1,b[c-2-m]=(b[c-1-m]/2|0)+a;b[0]=f[0];h[0]=Array(b[0]);k[0]=Array(b[0]);for(m=1;m<c;++m)b[m]>2*b[m-1]+f[m]&&(b[m]=2*b[m-1]+f[m]),h[m]=Array(b[m]),k[m]=Array(b[m]);for(p=0;p<a;++p)g[p]=c;for(s=0;s<b[c-1];++s)h[c-
1][s]=d[s],k[c-1][s]=s;for(p=0;p<c;++p)n[p]=0;1===f[c-1]&&(--g[0],++n[c-1]);for(m=c-2;0<=m;--m){w=p=0;y=n[m+1];for(s=0;s<b[m];s++)w=h[m+1][y]+h[m+1][y+1],w>d[p]?(h[m][s]=w,k[m][s]=a,y+=2):(h[m][s]=d[p],k[m][s]=p,++p);n[m]=0;1===f[m]&&e(m)}return g}
function sa(d){var a=new (F?Uint16Array:Array)(d.length),c=[],e=[],b=0,f,g,h,k;f=0;for(g=d.length;f<g;f++)c[d[f]]=(c[d[f]]|0)+1;f=1;for(g=16;f<=g;f++)e[f]=b,b+=c[f]|0,b<<=1;f=0;for(g=d.length;f<g;f++){b=e[d[f]];e[d[f]]+=1;h=a[f]=0;for(k=d[f];h<k;h++)a[f]=a[f]<<1|b&1,b>>>=1}return a};function T(d,a){this.l=[];this.m=32768;this.e=this.g=this.c=this.q=0;this.input=F?new Uint8Array(d):d;this.s=!1;this.n=za;this.C=!1;if(a||!(a={}))a.index&&(this.c=a.index),a.bufferSize&&(this.m=a.bufferSize),a.bufferType&&(this.n=a.bufferType),a.resize&&(this.C=a.resize);switch(this.n){case Aa:this.b=32768;this.a=new (F?Uint8Array:Array)(32768+this.m+258);break;case za:this.b=0;this.a=new (F?Uint8Array:Array)(this.m);this.f=this.K;this.t=this.I;this.o=this.J;break;default:l(Error("invalid inflate mode"))}}
var Aa=0,za=1,Ba={F:Aa,D:za};
T.prototype.p=function(){for(;!this.s;){var d=Y(this,3);d&1&&(this.s=x);d>>>=1;switch(d){case 0:var a=this.input,c=this.c,e=this.a,b=this.b,f=a.length,g=v,h=v,k=e.length,n=v;this.e=this.g=0;c+1>=f&&l(Error("invalid uncompressed block header: LEN"));g=a[c++]|a[c++]<<8;c+1>=f&&l(Error("invalid uncompressed block header: NLEN"));h=a[c++]|a[c++]<<8;g===~h&&l(Error("invalid uncompressed block header: length verify"));c+g>a.length&&l(Error("input buffer is broken"));switch(this.n){case Aa:for(;b+g>e.length;){n=
k-b;g-=n;if(F)e.set(a.subarray(c,c+n),b),b+=n,c+=n;else for(;n--;)e[b++]=a[c++];this.b=b;e=this.f();b=this.b}break;case za:for(;b+g>e.length;)e=this.f({v:2});break;default:l(Error("invalid inflate mode"))}if(F)e.set(a.subarray(c,c+g),b),b+=g,c+=g;else for(;g--;)e[b++]=a[c++];this.c=c;this.b=b;this.a=e;break;case 1:this.o(Ca,Da);break;case 2:Sa(this);break;default:l(Error("unknown BTYPE: "+d))}}return this.t()};
var Ta=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15],Ua=F?new Uint16Array(Ta):Ta,Va=[3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258,258,258],Wa=F?new Uint16Array(Va):Va,Xa=[0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0,0,0],Ya=F?new Uint8Array(Xa):Xa,Za=[1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577],$a=F?new Uint16Array(Za):Za,ab=[0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,
10,11,11,12,12,13,13],bb=F?new Uint8Array(ab):ab,cb=new (F?Uint8Array:Array)(288),Z,db;Z=0;for(db=cb.length;Z<db;++Z)cb[Z]=143>=Z?8:255>=Z?9:279>=Z?7:8;var Ca=R(cb),eb=new (F?Uint8Array:Array)(30),fb,hb;fb=0;for(hb=eb.length;fb<hb;++fb)eb[fb]=5;var Da=R(eb);function Y(d,a){for(var c=d.g,e=d.e,b=d.input,f=d.c,g=b.length,h;e<a;)f>=g&&l(Error("input buffer is broken")),c|=b[f++]<<e,e+=8;h=c&(1<<a)-1;d.g=c>>>a;d.e=e-a;d.c=f;return h}
function ib(d,a){for(var c=d.g,e=d.e,b=d.input,f=d.c,g=b.length,h=a[0],k=a[1],n,q;e<k&&!(f>=g);)c|=b[f++]<<e,e+=8;n=h[c&(1<<k)-1];q=n>>>16;d.g=c>>q;d.e=e-q;d.c=f;return n&65535}
function Sa(d){function a(a,b,c){var d,e=this.z,f,g;for(g=0;g<a;)switch(d=ib(this,b),d){case 16:for(f=3+Y(this,2);f--;)c[g++]=e;break;case 17:for(f=3+Y(this,3);f--;)c[g++]=0;e=0;break;case 18:for(f=11+Y(this,7);f--;)c[g++]=0;e=0;break;default:e=c[g++]=d}this.z=e;return c}var c=Y(d,5)+257,e=Y(d,5)+1,b=Y(d,4)+4,f=new (F?Uint8Array:Array)(Ua.length),g,h,k,n;for(n=0;n<b;++n)f[Ua[n]]=Y(d,3);if(!F){n=b;for(b=f.length;n<b;++n)f[Ua[n]]=0}g=R(f);h=new (F?Uint8Array:Array)(c);k=new (F?Uint8Array:Array)(e);
d.z=0;d.o(R(a.call(d,c,g,h)),R(a.call(d,e,g,k)))}T.prototype.o=function(d,a){var c=this.a,e=this.b;this.u=d;for(var b=c.length-258,f,g,h,k;256!==(f=ib(this,d));)if(256>f)e>=b&&(this.b=e,c=this.f(),e=this.b),c[e++]=f;else{g=f-257;k=Wa[g];0<Ya[g]&&(k+=Y(this,Ya[g]));f=ib(this,a);h=$a[f];0<bb[f]&&(h+=Y(this,bb[f]));e>=b&&(this.b=e,c=this.f(),e=this.b);for(;k--;)c[e]=c[e++-h]}for(;8<=this.e;)this.e-=8,this.c--;this.b=e};
T.prototype.J=function(d,a){var c=this.a,e=this.b;this.u=d;for(var b=c.length,f,g,h,k;256!==(f=ib(this,d));)if(256>f)e>=b&&(c=this.f(),b=c.length),c[e++]=f;else{g=f-257;k=Wa[g];0<Ya[g]&&(k+=Y(this,Ya[g]));f=ib(this,a);h=$a[f];0<bb[f]&&(h+=Y(this,bb[f]));e+k>b&&(c=this.f(),b=c.length);for(;k--;)c[e]=c[e++-h]}for(;8<=this.e;)this.e-=8,this.c--;this.b=e};
T.prototype.f=function(){var d=new (F?Uint8Array:Array)(this.b-32768),a=this.b-32768,c,e,b=this.a;if(F)d.set(b.subarray(32768,d.length));else{c=0;for(e=d.length;c<e;++c)d[c]=b[c+32768]}this.l.push(d);this.q+=d.length;if(F)b.set(b.subarray(a,a+32768));else for(c=0;32768>c;++c)b[c]=b[a+c];this.b=32768;return b};
T.prototype.K=function(d){var a,c=this.input.length/this.c+1|0,e,b,f,g=this.input,h=this.a;d&&("number"===typeof d.v&&(c=d.v),"number"===typeof d.G&&(c+=d.G));2>c?(e=(g.length-this.c)/this.u[2],f=258*(e/2)|0,b=f<h.length?h.length+f:h.length<<1):b=h.length*c;F?(a=new Uint8Array(b),a.set(h)):a=h;return this.a=a};
T.prototype.t=function(){var d=0,a=this.a,c=this.l,e,b=new (F?Uint8Array:Array)(this.q+(this.b-32768)),f,g,h,k;if(0===c.length)return F?this.a.subarray(32768,this.b):this.a.slice(32768,this.b);f=0;for(g=c.length;f<g;++f){e=c[f];h=0;for(k=e.length;h<k;++h)b[d++]=e[h]}f=32768;for(g=this.b;f<g;++f)b[d++]=a[f];this.l=[];return this.buffer=b};
T.prototype.I=function(){var d,a=this.b;F?this.C?(d=new Uint8Array(a),d.set(this.a.subarray(0,a))):d=this.a.subarray(0,a):(this.a.length>a&&(this.a.length=a),d=this.a);return this.buffer=d};function jb(d){if("string"===typeof d){var a=d.split(""),c,e;c=0;for(e=a.length;c<e;c++)a[c]=(a[c].charCodeAt(0)&255)>>>0;d=a}for(var b=1,f=0,g=d.length,h,k=0;0<g;){h=1024<g?1024:g;g-=h;do b+=d[k++],f+=b;while(--h);b%=65521;f%=65521}return(f<<16|b)>>>0};function kb(d,a){var c,e;this.input=d;this.c=0;if(a||!(a={}))a.index&&(this.c=a.index),a.verify&&(this.N=a.verify);c=d[this.c++];e=d[this.c++];switch(c&15){case lb:this.method=lb;break;default:l(Error("unsupported compression method"))}0!==((c<<8)+e)%31&&l(Error("invalid fcheck flag:"+((c<<8)+e)%31));e&32&&l(Error("fdict flag is not supported"));this.B=new T(d,{index:this.c,bufferSize:a.bufferSize,bufferType:a.bufferType,resize:a.resize})}
kb.prototype.p=function(){var d=this.input,a,c;a=this.B.p();this.c=this.B.c;this.N&&(c=(d[this.c++]<<24|d[this.c++]<<16|d[this.c++]<<8|d[this.c++])>>>0,c!==jb(a)&&l(Error("invalid adler-32 checksum")));return a};var lb=8;function mb(d,a){this.input=d;this.a=new (F?Uint8Array:Array)(32768);this.h=$.k;var c={},e;if((a||!(a={}))&&"number"===typeof a.compressionType)this.h=a.compressionType;for(e in a)c[e]=a[e];c.outputBuffer=this.a;this.A=new ia(this.input,c)}var $=na;
mb.prototype.j=function(){var d,a,c,e,b,f,g,h=0;g=this.a;d=lb;switch(d){case lb:a=Math.LOG2E*Math.log(32768)-8;break;default:l(Error("invalid compression method"))}c=a<<4|d;g[h++]=c;switch(d){case lb:switch(this.h){case $.NONE:b=0;break;case $.r:b=1;break;case $.k:b=2;break;default:l(Error("unsupported compression type"))}break;default:l(Error("invalid compression method"))}e=b<<6|0;g[h++]=e|31-(256*c+e)%31;f=jb(this.input);this.A.b=h;g=this.A.j();h=g.length;F&&(g=new Uint8Array(g.buffer),g.length<=
h+4&&(this.a=new Uint8Array(g.length+4),this.a.set(g),g=this.a),g=g.subarray(0,h+4));g[h++]=f>>24&255;g[h++]=f>>16&255;g[h++]=f>>8&255;g[h++]=f&255;return g};function nb(d,a){var c,e,b,f;if(Object.keys)c=Object.keys(a);else for(e in c=[],b=0,a)c[b++]=e;b=0;for(f=c.length;b<f;++b)e=c[b],D(d+"."+e,a[e])};D("Zlib.Inflate",kb);D("Zlib.Inflate.prototype.decompress",kb.prototype.p);nb("Zlib.Inflate.BufferType",{ADAPTIVE:Ba.D,BLOCK:Ba.F});D("Zlib.Deflate",mb);D("Zlib.Deflate.compress",function(d,a){return(new mb(d,a)).j()});D("Zlib.Deflate.prototype.compress",mb.prototype.j);nb("Zlib.Deflate.CompressionType",{NONE:$.NONE,FIXED:$.r,DYNAMIC:$.k});}).call(this); //@ sourceMappingURL=zlib.min.js.map

},{}],32:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * This object contains configuration values.
 * @requires enums
 * @property {Integer} prefer_hash_algorithm
 * @property {Integer} encryption_cipher
 * @property {Integer} compression
 * @property {Boolean} show_version
 * @property {Boolean} show_comment
 * @property {Boolean} integrity_protect
 * @property {String} keyserver
 * @property {Boolean} debug If enabled, debug messages will be printed
 * @module config/config
 */

var enums = require('../enums.js');

module.exports = {
  prefer_hash_algorithm: enums.hash.sha256,
  encryption_cipher: enums.symmetric.aes256,
  compression: enums.compression.zip,
  integrity_protect: true,
  rsa_blinding: true,
  useWebCrypto: true,

  show_version: true,
  show_comment: true,
  versionstring: "OpenPGP.js v1.0.1",
  commentstring: "http://openpgpjs.org",

  keyserver: "keyserver.linux.it", // "pgp.mit.edu:11371"
  node_store: './openpgp.store',

  debug: false
};

},{"../enums.js":60}],33:[function(require,module,exports){
/**
 * @see module:config/config
 * @module config
 */
module.exports = require('./config.js');

},{"./config.js":32}],34:[function(require,module,exports){
// Modified by Recurity Labs GmbH 

// modified version of http://www.hanewin.net/encrypt/PGdecode.js:

/* OpenPGP encryption using RSA/AES
 * Copyright 2005-2006 Herbert Hanewinkel, www.haneWIN.de
 * version 2.0, check www.haneWIN.de for the latest version

 * This software is provided as-is, without express or implied warranty.  
 * Permission to use, copy, modify, distribute or sell this software, with or
 * without fee, for any purpose and by any individual or organization, is hereby
 * granted, provided that the above copyright notice and this paragraph appear 
 * in all copies. Distribution as a part of an application or binary must
 * include the above copyright notice in the documentation and/or other
 * materials provided with the application or distribution.
 */

/**
 * @requires crypto/cipher
 * @requires util
 * @module crypto/cfb
 */

'use strict';

var util = require('../util.js'),
  cipher = require('./cipher');

module.exports = {

  /**
   * This function encrypts a given with the specified prefixrandom 
   * using the specified blockcipher to encrypt a message
   * @param {String} prefixrandom random bytes of block_size length provided 
   *  as a string to be used in prefixing the data
   * @param {String} cipherfn the algorithm cipher class to encrypt
   *  data in one block_size encryption, {@link module:crypto/cipher}.
   * @param {String} plaintext data to be encrypted provided as a string
   * @param {String} key binary string representation of key to be used to encrypt the plaintext.
   * This will be passed to the cipherfn
   * @param {Boolean} resync a boolean value specifying if a resync of the
   *  IV should be used or not. The encrypteddatapacket uses the 
   *  "old" style with a resync. Encryption within an 
   *  encryptedintegrityprotecteddata packet is not resyncing the IV.
   * @return {String} a string with the encrypted data
   */
  encrypt: function(prefixrandom, cipherfn, plaintext, key, resync) {
    cipherfn = new cipher[cipherfn](key);
    var block_size = cipherfn.blockSize;

    var FR = new Uint8Array(block_size);
    var FRE = new Uint8Array(block_size);

    prefixrandom = prefixrandom + prefixrandom.charAt(block_size - 2) + prefixrandom.charAt(block_size - 1);
    var ciphertext = new Uint8Array(plaintext.length + 2 + block_size * 2);
    var i, n, begin;
    var offset = resync ? 0 : 2;

    // 1.  The feedback register (FR) is set to the IV, which is all zeros.
    for (i = 0; i < block_size; i++) {
      FR[i] = 0;
    }

    // 2.  FR is encrypted to produce FRE (FR Encrypted).  This is the
    //     encryption of an all-zero value.
    FRE = cipherfn.encrypt(FR);
    // 3.  FRE is xored with the first BS octets of random data prefixed to
    //     the plaintext to produce C[1] through C[BS], the first BS octets
    //     of ciphertext.
    for (i = 0; i < block_size; i++) {
      ciphertext[i] = FRE[i] ^ prefixrandom.charCodeAt(i);
    }

    // 4.  FR is loaded with C[1] through C[BS].
    FR.set(ciphertext.subarray(0, block_size));

    // 5.  FR is encrypted to produce FRE, the encryption of the first BS
    //     octets of ciphertext.
    FRE = cipherfn.encrypt(FR);

    // 6.  The left two octets of FRE get xored with the next two octets of
    //     data that were prefixed to the plaintext.  This produces C[BS+1]
    //     and C[BS+2], the next two octets of ciphertext.
    ciphertext[block_size] = FRE[0] ^ prefixrandom.charCodeAt(block_size);
    ciphertext[block_size + 1] = FRE[1] ^ prefixrandom.charCodeAt(block_size + 1);

    if (resync) {
      // 7.  (The resync step) FR is loaded with C[3] through C[BS+2].
      FR.set(ciphertext.subarray(2, block_size + 2));
    } else {
      FR.set(ciphertext.subarray(0, block_size));
    }
    // 8.  FR is encrypted to produce FRE.
    FRE = cipherfn.encrypt(FR);

    // 9.  FRE is xored with the first BS octets of the given plaintext, now
    //     that we have finished encrypting the BS+2 octets of prefixed
    //     data.  This produces C[BS+3] through C[BS+(BS+2)], the next BS
    //     octets of ciphertext.
    for (i = 0; i < block_size; i++) {
      ciphertext[block_size + 2 + i] = FRE[i + offset] ^ plaintext.charCodeAt(i);
    }
    for (n = block_size; n < plaintext.length + offset; n += block_size) {
      // 10. FR is loaded with C[BS+3] to C[BS + (BS+2)] (which is C11-C18 for
      // an 8-octet block).
      begin = n + 2 - offset;
      FR.set(ciphertext.subarray(begin, begin + block_size));

      // 11. FR is encrypted to produce FRE.
      FRE = cipherfn.encrypt(FR);

      // 12. FRE is xored with the next BS octets of plaintext, to produce
      // the next BS octets of ciphertext.  These are loaded into FR, and
      // the process is repeated until the plaintext is used up.
      for (i = 0; i < block_size; i++) {
        ciphertext[block_size + begin + i] = FRE[i] ^ plaintext.charCodeAt(n + i - offset);
      }
    }

    ciphertext = ciphertext.subarray(0, plaintext.length + 2 + block_size);
    return util.Uint8Array2str(ciphertext);
  },

  /**
   * Decrypts the prefixed data for the Modification Detection Code (MDC) computation
   * @param {String} cipherfn.encrypt Cipher function to use,
   *  @see module:crypto/cipher.
   * @param {String} key binary string representation of key to be used to check the mdc
   * This will be passed to the cipherfn
   * @param {String} ciphertext The encrypted data
   * @return {String} plaintext Data of D(ciphertext) with blocksize length +2
   */
  mdc: function(cipherfn, key, ciphertext) {
    cipherfn = new cipher[cipherfn](key);
    var block_size = cipherfn.blockSize;

    var iblock = new Uint8Array(block_size);
    var ablock = new Uint8Array(block_size);
    var i;


    // initialisation vector
    for (i = 0; i < block_size; i++) {
      iblock[i] = 0;
    }

    iblock = cipherfn.encrypt(iblock);
    for (i = 0; i < block_size; i++) {
      ablock[i] = ciphertext.charCodeAt(i);
      iblock[i] ^= ablock[i];
    }

    ablock = cipherfn.encrypt(ablock);

    return util.bin2str(iblock) +
      String.fromCharCode(ablock[0] ^ ciphertext.charCodeAt(block_size)) +
      String.fromCharCode(ablock[1] ^ ciphertext.charCodeAt(block_size + 1));
  },
  /**
   * This function decrypts a given plaintext using the specified
   * blockcipher to decrypt a message
   * @param {String} cipherfn the algorithm cipher class to decrypt
   *  data in one block_size encryption, {@link module:crypto/cipher}.
   * @param {String} key binary string representation of key to be used to decrypt the ciphertext.
   * This will be passed to the cipherfn
   * @param {String} ciphertext to be decrypted provided as a string
   * @param {Boolean} resync a boolean value specifying if a resync of the
   *  IV should be used or not. The encrypteddatapacket uses the 
   *  "old" style with a resync. Decryption within an 
   *  encryptedintegrityprotecteddata packet is not resyncing the IV.
   * @return {String} a string with the plaintext data
   */

  decrypt: function(cipherfn, key, ciphertext, resync) {
    cipherfn = new cipher[cipherfn](key);
    var block_size = cipherfn.blockSize;

    var iblock = new Uint8Array(block_size);
    var ablock = new Uint8Array(block_size);
    var i, n = '';
    var text = '';

    // initialisation vector
    for (i = 0; i < block_size; i++) {
      iblock[i] = 0;
    }

    iblock = cipherfn.encrypt(iblock);
    for (i = 0; i < block_size; i++) {
      ablock[i] = ciphertext.charCodeAt(i);
      iblock[i] ^= ablock[i];
    }

    ablock = cipherfn.encrypt(ablock);

    // test check octets
    if (iblock[block_size - 2] != (ablock[0] ^ ciphertext.charCodeAt(block_size)) ||
        iblock[block_size - 1] != (ablock[1] ^ ciphertext.charCodeAt(block_size + 1))) {
      throw new Error('CFB decrypt: invalid key');
    }

    /*  RFC4880: Tag 18 and Resync:
		 *  [...] Unlike the Symmetrically Encrypted Data Packet, no
		 *  special CFB resynchronization is done after encrypting this prefix
		 *  data.  See "OpenPGP CFB Mode" below for more details.

		 */

    if (resync) {
      for (i = 0; i < block_size; i++) {
        iblock[i] = ciphertext.charCodeAt(i + 2);
      }
      for (n = block_size + 2; n < ciphertext.length; n += block_size) {
        ablock = cipherfn.encrypt(iblock);

        for (i = 0; i < block_size && i + n < ciphertext.length; i++) {
          iblock[i] = ciphertext.charCodeAt(n + i);
          text += String.fromCharCode(ablock[i] ^ iblock[i]);
        }
      }
    } else {
      for (i = 0; i < block_size; i++) {
        iblock[i] = ciphertext.charCodeAt(i);
      }
      for (n = block_size; n < ciphertext.length; n += block_size) {
        ablock = cipherfn.encrypt(iblock);
        for (i = 0; i < block_size && i + n < ciphertext.length; i++) {
          iblock[i] = ciphertext.charCodeAt(n + i);
          text += String.fromCharCode(ablock[i] ^ iblock[i]);
        }
      }
    }

    n = resync ? 0 : 2;
    
    text = text.substring(n, ciphertext.length - block_size - 2 + n);

    return text;
  },


  normalEncrypt: function(cipherfn, key, plaintext, iv) {
    cipherfn = new cipher[cipherfn](key);
    var block_size = cipherfn.blockSize;

    var blocki = '';
    var blockc = '';
    var pos = 0;
    var cyphertext = '';
    var tempBlock = '';
    blockc = iv.substring(0, block_size);
    while (plaintext.length > block_size * pos) {
      var encblock = cipherfn.encrypt(util.str2bin(blockc));
      blocki = plaintext.substring((pos * block_size), (pos * block_size) + block_size);
      for (var i = 0; i < blocki.length; i++) {
        tempBlock += String.fromCharCode(blocki.charCodeAt(i) ^ encblock[i]);
      }
      blockc = tempBlock;
      tempBlock = '';
      cyphertext += blockc;
      pos++;
    }
    return cyphertext;
  },

  normalDecrypt: function(cipherfn, key, ciphertext, iv) {
    cipherfn = new cipher[cipherfn](key);
    var block_size = cipherfn.blockSize;

    var blockp = '';
    var pos = 0;
    var plaintext = '';
    var offset = 0;
    var i;
    if (iv === null)
      for (i = 0; i < block_size; i++) {
        blockp += String.fromCharCode(0);
      }
    else
      blockp = iv.substring(0, block_size);
    while (ciphertext.length > (block_size * pos)) {
      var decblock = cipherfn.encrypt(util.str2bin(blockp));
      blockp = ciphertext.substring((pos * (block_size)) + offset, (pos * (block_size)) + (block_size) + offset);
      for (i = 0; i < blockp.length; i++) {
        plaintext += String.fromCharCode(blockp.charCodeAt(i) ^ decblock[i]);
      }
      pos++;
    }

    return plaintext;
  }
};

},{"../util.js":95,"./cipher":39}],35:[function(require,module,exports){
/* Rijndael (AES) Encryption
 * Copyright 2005 Herbert Hanewinkel, www.haneWIN.de
 * version 1.1, check www.haneWIN.de for the latest version

 * This software is provided as-is, without express or implied warranty.  
 * Permission to use, copy, modify, distribute or sell this software, with or
 * without fee, for any purpose and by any individual or organization, is hereby
 * granted, provided that the above copyright notice and this paragraph appear 
 * in all copies. Distribution as a part of an application or binary must
 * include the above copyright notice in the documentation and/or other
 * materials provided with the application or distribution.
 */

/**
 * @requires util
 * @module crypto/cipher/aes
 */

'use strict';

var util = require('../../util.js');

// The round constants used in subkey expansion
var Rcon = new Uint8Array([
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4,
    0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
]);

// Precomputed lookup table for the SBox
var S = new Uint8Array([
    99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171,
    118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164,
    114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113,
    216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226,
    235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214,
    179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203,
    190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69,
    249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245,
    188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68,
    23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42,
    144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73,
    6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109,
    141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37,
    46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62,
    181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225,
    248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
    140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187,
    22
]);

var T1 = new Uint32Array([
    0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6,
    0x0df2f2ff, 0xbd6b6bd6, 0xb16f6fde, 0x54c5c591,
    0x50303060, 0x03010102, 0xa96767ce, 0x7d2b2b56,
    0x19fefee7, 0x62d7d7b5, 0xe6abab4d, 0x9a7676ec,
    0x45caca8f, 0x9d82821f, 0x40c9c989, 0x877d7dfa,
    0x15fafaef, 0xeb5959b2, 0xc947478e, 0x0bf0f0fb,
    0xecadad41, 0x67d4d4b3, 0xfda2a25f, 0xeaafaf45,
    0xbf9c9c23, 0xf7a4a453, 0x967272e4, 0x5bc0c09b,
    0xc2b7b775, 0x1cfdfde1, 0xae93933d, 0x6a26264c,
    0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83,
    0x5c343468, 0xf4a5a551, 0x34e5e5d1, 0x08f1f1f9,
    0x937171e2, 0x73d8d8ab, 0x53313162, 0x3f15152a,
    0x0c040408, 0x52c7c795, 0x65232346, 0x5ec3c39d,
    0x28181830, 0xa1969637, 0x0f05050a, 0xb59a9a2f,
    0x0907070e, 0x36121224, 0x9b80801b, 0x3de2e2df,
    0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea,
    0x1b090912, 0x9e83831d, 0x742c2c58, 0x2e1a1a34,
    0x2d1b1b36, 0xb26e6edc, 0xee5a5ab4, 0xfba0a05b,
    0xf65252a4, 0x4d3b3b76, 0x61d6d6b7, 0xceb3b37d,
    0x7b292952, 0x3ee3e3dd, 0x712f2f5e, 0x97848413,
    0xf55353a6, 0x68d1d1b9, 0x00000000, 0x2cededc1,
    0x60202040, 0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6,
    0xbe6a6ad4, 0x46cbcb8d, 0xd9bebe67, 0x4b393972,
    0xde4a4a94, 0xd44c4c98, 0xe85858b0, 0x4acfcf85,
    0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed,
    0xc5434386, 0xd74d4d9a, 0x55333366, 0x94858511,
    0xcf45458a, 0x10f9f9e9, 0x06020204, 0x817f7ffe,
    0xf05050a0, 0x443c3c78, 0xba9f9f25, 0xe3a8a84b,
    0xf35151a2, 0xfea3a35d, 0xc0404080, 0x8a8f8f05,
    0xad92923f, 0xbc9d9d21, 0x48383870, 0x04f5f5f1,
    0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142,
    0x30101020, 0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf,
    0x4ccdcd81, 0x140c0c18, 0x35131326, 0x2fececc3,
    0xe15f5fbe, 0xa2979735, 0xcc444488, 0x3917172e,
    0x57c4c493, 0xf2a7a755, 0x827e7efc, 0x473d3d7a,
    0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6,
    0xa06060c0, 0x98818119, 0xd14f4f9e, 0x7fdcdca3,
    0x66222244, 0x7e2a2a54, 0xab90903b, 0x8388880b,
    0xca46468c, 0x29eeeec7, 0xd3b8b86b, 0x3c141428,
    0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad,
    0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14,
    0xdb494992, 0x0a06060c, 0x6c242448, 0xe45c5cb8,
    0x5dc2c29f, 0x6ed3d3bd, 0xefacac43, 0xa66262c4,
    0xa8919139, 0xa4959531, 0x37e4e4d3, 0x8b7979f2,
    0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda,
    0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949,
    0xb46c6cd8, 0xfa5656ac, 0x07f4f4f3, 0x25eaeacf,
    0xaf6565ca, 0x8e7a7af4, 0xe9aeae47, 0x18080810,
    0xd5baba6f, 0x887878f0, 0x6f25254a, 0x722e2e5c,
    0x241c1c38, 0xf1a6a657, 0xc7b4b473, 0x51c6c697,
    0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e,
    0xdd4b4b96, 0xdcbdbd61, 0x868b8b0d, 0x858a8a0f,
    0x907070e0, 0x423e3e7c, 0xc4b5b571, 0xaa6666cc,
    0xd8484890, 0x05030306, 0x01f6f6f7, 0x120e0e1c,
    0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969,
    0x91868617, 0x58c1c199, 0x271d1d3a, 0xb99e9e27,
    0x38e1e1d9, 0x13f8f8eb, 0xb398982b, 0x33111122,
    0xbb6969d2, 0x70d9d9a9, 0x898e8e07, 0xa7949433,
    0xb69b9b2d, 0x221e1e3c, 0x92878715, 0x20e9e9c9,
    0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5,
    0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a,
    0xdabfbf65, 0x31e6e6d7, 0xc6424284, 0xb86868d0,
    0xc3414182, 0xb0999929, 0x772d2d5a, 0x110f0f1e,
    0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d, 0x3a16162c
]);

var T2 = new Uint32Array([
    0x6363c6a5, 0x7c7cf884, 0x7777ee99, 0x7b7bf68d,
    0xf2f2ff0d, 0x6b6bd6bd, 0x6f6fdeb1, 0xc5c59154,
    0x30306050, 0x01010203, 0x6767cea9, 0x2b2b567d,
    0xfefee719, 0xd7d7b562, 0xabab4de6, 0x7676ec9a,
    0xcaca8f45, 0x82821f9d, 0xc9c98940, 0x7d7dfa87,
    0xfafaef15, 0x5959b2eb, 0x47478ec9, 0xf0f0fb0b,
    0xadad41ec, 0xd4d4b367, 0xa2a25ffd, 0xafaf45ea,
    0x9c9c23bf, 0xa4a453f7, 0x7272e496, 0xc0c09b5b,
    0xb7b775c2, 0xfdfde11c, 0x93933dae, 0x26264c6a,
    0x36366c5a, 0x3f3f7e41, 0xf7f7f502, 0xcccc834f,
    0x3434685c, 0xa5a551f4, 0xe5e5d134, 0xf1f1f908,
    0x7171e293, 0xd8d8ab73, 0x31316253, 0x15152a3f,
    0x0404080c, 0xc7c79552, 0x23234665, 0xc3c39d5e,
    0x18183028, 0x969637a1, 0x05050a0f, 0x9a9a2fb5,
    0x07070e09, 0x12122436, 0x80801b9b, 0xe2e2df3d,
    0xebebcd26, 0x27274e69, 0xb2b27fcd, 0x7575ea9f,
    0x0909121b, 0x83831d9e, 0x2c2c5874, 0x1a1a342e,
    0x1b1b362d, 0x6e6edcb2, 0x5a5ab4ee, 0xa0a05bfb,
    0x5252a4f6, 0x3b3b764d, 0xd6d6b761, 0xb3b37dce,
    0x2929527b, 0xe3e3dd3e, 0x2f2f5e71, 0x84841397,
    0x5353a6f5, 0xd1d1b968, 0x00000000, 0xededc12c,
    0x20204060, 0xfcfce31f, 0xb1b179c8, 0x5b5bb6ed,
    0x6a6ad4be, 0xcbcb8d46, 0xbebe67d9, 0x3939724b,
    0x4a4a94de, 0x4c4c98d4, 0x5858b0e8, 0xcfcf854a,
    0xd0d0bb6b, 0xefefc52a, 0xaaaa4fe5, 0xfbfbed16,
    0x434386c5, 0x4d4d9ad7, 0x33336655, 0x85851194,
    0x45458acf, 0xf9f9e910, 0x02020406, 0x7f7ffe81,
    0x5050a0f0, 0x3c3c7844, 0x9f9f25ba, 0xa8a84be3,
    0x5151a2f3, 0xa3a35dfe, 0x404080c0, 0x8f8f058a,
    0x92923fad, 0x9d9d21bc, 0x38387048, 0xf5f5f104,
    0xbcbc63df, 0xb6b677c1, 0xdadaaf75, 0x21214263,
    0x10102030, 0xffffe51a, 0xf3f3fd0e, 0xd2d2bf6d,
    0xcdcd814c, 0x0c0c1814, 0x13132635, 0xececc32f,
    0x5f5fbee1, 0x979735a2, 0x444488cc, 0x17172e39,
    0xc4c49357, 0xa7a755f2, 0x7e7efc82, 0x3d3d7a47,
    0x6464c8ac, 0x5d5dbae7, 0x1919322b, 0x7373e695,
    0x6060c0a0, 0x81811998, 0x4f4f9ed1, 0xdcdca37f,
    0x22224466, 0x2a2a547e, 0x90903bab, 0x88880b83,
    0x46468cca, 0xeeeec729, 0xb8b86bd3, 0x1414283c,
    0xdedea779, 0x5e5ebce2, 0x0b0b161d, 0xdbdbad76,
    0xe0e0db3b, 0x32326456, 0x3a3a744e, 0x0a0a141e,
    0x494992db, 0x06060c0a, 0x2424486c, 0x5c5cb8e4,
    0xc2c29f5d, 0xd3d3bd6e, 0xacac43ef, 0x6262c4a6,
    0x919139a8, 0x959531a4, 0xe4e4d337, 0x7979f28b,
    0xe7e7d532, 0xc8c88b43, 0x37376e59, 0x6d6ddab7,
    0x8d8d018c, 0xd5d5b164, 0x4e4e9cd2, 0xa9a949e0,
    0x6c6cd8b4, 0x5656acfa, 0xf4f4f307, 0xeaeacf25,
    0x6565caaf, 0x7a7af48e, 0xaeae47e9, 0x08081018,
    0xbaba6fd5, 0x7878f088, 0x25254a6f, 0x2e2e5c72,
    0x1c1c3824, 0xa6a657f1, 0xb4b473c7, 0xc6c69751,
    0xe8e8cb23, 0xdddda17c, 0x7474e89c, 0x1f1f3e21,
    0x4b4b96dd, 0xbdbd61dc, 0x8b8b0d86, 0x8a8a0f85,
    0x7070e090, 0x3e3e7c42, 0xb5b571c4, 0x6666ccaa,
    0x484890d8, 0x03030605, 0xf6f6f701, 0x0e0e1c12,
    0x6161c2a3, 0x35356a5f, 0x5757aef9, 0xb9b969d0,
    0x86861791, 0xc1c19958, 0x1d1d3a27, 0x9e9e27b9,
    0xe1e1d938, 0xf8f8eb13, 0x98982bb3, 0x11112233,
    0x6969d2bb, 0xd9d9a970, 0x8e8e0789, 0x949433a7,
    0x9b9b2db6, 0x1e1e3c22, 0x87871592, 0xe9e9c920,
    0xcece8749, 0x5555aaff, 0x28285078, 0xdfdfa57a,
    0x8c8c038f, 0xa1a159f8, 0x89890980, 0x0d0d1a17,
    0xbfbf65da, 0xe6e6d731, 0x424284c6, 0x6868d0b8,
    0x414182c3, 0x999929b0, 0x2d2d5a77, 0x0f0f1e11,
    0xb0b07bcb, 0x5454a8fc, 0xbbbb6dd6, 0x16162c3a
]);

var T3 = new Uint32Array([
    0x63c6a563, 0x7cf8847c, 0x77ee9977, 0x7bf68d7b,
    0xf2ff0df2, 0x6bd6bd6b, 0x6fdeb16f, 0xc59154c5,
    0x30605030, 0x01020301, 0x67cea967, 0x2b567d2b,
    0xfee719fe, 0xd7b562d7, 0xab4de6ab, 0x76ec9a76,
    0xca8f45ca, 0x821f9d82, 0xc98940c9, 0x7dfa877d,
    0xfaef15fa, 0x59b2eb59, 0x478ec947, 0xf0fb0bf0,
    0xad41ecad, 0xd4b367d4, 0xa25ffda2, 0xaf45eaaf,
    0x9c23bf9c, 0xa453f7a4, 0x72e49672, 0xc09b5bc0,
    0xb775c2b7, 0xfde11cfd, 0x933dae93, 0x264c6a26,
    0x366c5a36, 0x3f7e413f, 0xf7f502f7, 0xcc834fcc,
    0x34685c34, 0xa551f4a5, 0xe5d134e5, 0xf1f908f1,
    0x71e29371, 0xd8ab73d8, 0x31625331, 0x152a3f15,
    0x04080c04, 0xc79552c7, 0x23466523, 0xc39d5ec3,
    0x18302818, 0x9637a196, 0x050a0f05, 0x9a2fb59a,
    0x070e0907, 0x12243612, 0x801b9b80, 0xe2df3de2,
    0xebcd26eb, 0x274e6927, 0xb27fcdb2, 0x75ea9f75,
    0x09121b09, 0x831d9e83, 0x2c58742c, 0x1a342e1a,
    0x1b362d1b, 0x6edcb26e, 0x5ab4ee5a, 0xa05bfba0,
    0x52a4f652, 0x3b764d3b, 0xd6b761d6, 0xb37dceb3,
    0x29527b29, 0xe3dd3ee3, 0x2f5e712f, 0x84139784,
    0x53a6f553, 0xd1b968d1, 0x00000000, 0xedc12ced,
    0x20406020, 0xfce31ffc, 0xb179c8b1, 0x5bb6ed5b,
    0x6ad4be6a, 0xcb8d46cb, 0xbe67d9be, 0x39724b39,
    0x4a94de4a, 0x4c98d44c, 0x58b0e858, 0xcf854acf,
    0xd0bb6bd0, 0xefc52aef, 0xaa4fe5aa, 0xfbed16fb,
    0x4386c543, 0x4d9ad74d, 0x33665533, 0x85119485,
    0x458acf45, 0xf9e910f9, 0x02040602, 0x7ffe817f,
    0x50a0f050, 0x3c78443c, 0x9f25ba9f, 0xa84be3a8,
    0x51a2f351, 0xa35dfea3, 0x4080c040, 0x8f058a8f,
    0x923fad92, 0x9d21bc9d, 0x38704838, 0xf5f104f5,
    0xbc63dfbc, 0xb677c1b6, 0xdaaf75da, 0x21426321,
    0x10203010, 0xffe51aff, 0xf3fd0ef3, 0xd2bf6dd2,
    0xcd814ccd, 0x0c18140c, 0x13263513, 0xecc32fec,
    0x5fbee15f, 0x9735a297, 0x4488cc44, 0x172e3917,
    0xc49357c4, 0xa755f2a7, 0x7efc827e, 0x3d7a473d,
    0x64c8ac64, 0x5dbae75d, 0x19322b19, 0x73e69573,
    0x60c0a060, 0x81199881, 0x4f9ed14f, 0xdca37fdc,
    0x22446622, 0x2a547e2a, 0x903bab90, 0x880b8388,
    0x468cca46, 0xeec729ee, 0xb86bd3b8, 0x14283c14,
    0xdea779de, 0x5ebce25e, 0x0b161d0b, 0xdbad76db,
    0xe0db3be0, 0x32645632, 0x3a744e3a, 0x0a141e0a,
    0x4992db49, 0x060c0a06, 0x24486c24, 0x5cb8e45c,
    0xc29f5dc2, 0xd3bd6ed3, 0xac43efac, 0x62c4a662,
    0x9139a891, 0x9531a495, 0xe4d337e4, 0x79f28b79,
    0xe7d532e7, 0xc88b43c8, 0x376e5937, 0x6ddab76d,
    0x8d018c8d, 0xd5b164d5, 0x4e9cd24e, 0xa949e0a9,
    0x6cd8b46c, 0x56acfa56, 0xf4f307f4, 0xeacf25ea,
    0x65caaf65, 0x7af48e7a, 0xae47e9ae, 0x08101808,
    0xba6fd5ba, 0x78f08878, 0x254a6f25, 0x2e5c722e,
    0x1c38241c, 0xa657f1a6, 0xb473c7b4, 0xc69751c6,
    0xe8cb23e8, 0xdda17cdd, 0x74e89c74, 0x1f3e211f,
    0x4b96dd4b, 0xbd61dcbd, 0x8b0d868b, 0x8a0f858a,
    0x70e09070, 0x3e7c423e, 0xb571c4b5, 0x66ccaa66,
    0x4890d848, 0x03060503, 0xf6f701f6, 0x0e1c120e,
    0x61c2a361, 0x356a5f35, 0x57aef957, 0xb969d0b9,
    0x86179186, 0xc19958c1, 0x1d3a271d, 0x9e27b99e,
    0xe1d938e1, 0xf8eb13f8, 0x982bb398, 0x11223311,
    0x69d2bb69, 0xd9a970d9, 0x8e07898e, 0x9433a794,
    0x9b2db69b, 0x1e3c221e, 0x87159287, 0xe9c920e9,
    0xce8749ce, 0x55aaff55, 0x28507828, 0xdfa57adf,
    0x8c038f8c, 0xa159f8a1, 0x89098089, 0x0d1a170d,
    0xbf65dabf, 0xe6d731e6, 0x4284c642, 0x68d0b868,
    0x4182c341, 0x9929b099, 0x2d5a772d, 0x0f1e110f,
    0xb07bcbb0, 0x54a8fc54, 0xbb6dd6bb, 0x162c3a16
]);

var T4 = new Uint32Array([
    0xc6a56363, 0xf8847c7c, 0xee997777, 0xf68d7b7b,
    0xff0df2f2, 0xd6bd6b6b, 0xdeb16f6f, 0x9154c5c5,
    0x60503030, 0x02030101, 0xcea96767, 0x567d2b2b,
    0xe719fefe, 0xb562d7d7, 0x4de6abab, 0xec9a7676,
    0x8f45caca, 0x1f9d8282, 0x8940c9c9, 0xfa877d7d,
    0xef15fafa, 0xb2eb5959, 0x8ec94747, 0xfb0bf0f0,
    0x41ecadad, 0xb367d4d4, 0x5ffda2a2, 0x45eaafaf,
    0x23bf9c9c, 0x53f7a4a4, 0xe4967272, 0x9b5bc0c0,
    0x75c2b7b7, 0xe11cfdfd, 0x3dae9393, 0x4c6a2626,
    0x6c5a3636, 0x7e413f3f, 0xf502f7f7, 0x834fcccc,
    0x685c3434, 0x51f4a5a5, 0xd134e5e5, 0xf908f1f1,
    0xe2937171, 0xab73d8d8, 0x62533131, 0x2a3f1515,
    0x080c0404, 0x9552c7c7, 0x46652323, 0x9d5ec3c3,
    0x30281818, 0x37a19696, 0x0a0f0505, 0x2fb59a9a,
    0x0e090707, 0x24361212, 0x1b9b8080, 0xdf3de2e2,
    0xcd26ebeb, 0x4e692727, 0x7fcdb2b2, 0xea9f7575,
    0x121b0909, 0x1d9e8383, 0x58742c2c, 0x342e1a1a,
    0x362d1b1b, 0xdcb26e6e, 0xb4ee5a5a, 0x5bfba0a0,
    0xa4f65252, 0x764d3b3b, 0xb761d6d6, 0x7dceb3b3,
    0x527b2929, 0xdd3ee3e3, 0x5e712f2f, 0x13978484,
    0xa6f55353, 0xb968d1d1, 0x00000000, 0xc12ceded,
    0x40602020, 0xe31ffcfc, 0x79c8b1b1, 0xb6ed5b5b,
    0xd4be6a6a, 0x8d46cbcb, 0x67d9bebe, 0x724b3939,
    0x94de4a4a, 0x98d44c4c, 0xb0e85858, 0x854acfcf,
    0xbb6bd0d0, 0xc52aefef, 0x4fe5aaaa, 0xed16fbfb,
    0x86c54343, 0x9ad74d4d, 0x66553333, 0x11948585,
    0x8acf4545, 0xe910f9f9, 0x04060202, 0xfe817f7f,
    0xa0f05050, 0x78443c3c, 0x25ba9f9f, 0x4be3a8a8,
    0xa2f35151, 0x5dfea3a3, 0x80c04040, 0x058a8f8f,
    0x3fad9292, 0x21bc9d9d, 0x70483838, 0xf104f5f5,
    0x63dfbcbc, 0x77c1b6b6, 0xaf75dada, 0x42632121,
    0x20301010, 0xe51affff, 0xfd0ef3f3, 0xbf6dd2d2,
    0x814ccdcd, 0x18140c0c, 0x26351313, 0xc32fecec,
    0xbee15f5f, 0x35a29797, 0x88cc4444, 0x2e391717,
    0x9357c4c4, 0x55f2a7a7, 0xfc827e7e, 0x7a473d3d,
    0xc8ac6464, 0xbae75d5d, 0x322b1919, 0xe6957373,
    0xc0a06060, 0x19988181, 0x9ed14f4f, 0xa37fdcdc,
    0x44662222, 0x547e2a2a, 0x3bab9090, 0x0b838888,
    0x8cca4646, 0xc729eeee, 0x6bd3b8b8, 0x283c1414,
    0xa779dede, 0xbce25e5e, 0x161d0b0b, 0xad76dbdb,
    0xdb3be0e0, 0x64563232, 0x744e3a3a, 0x141e0a0a,
    0x92db4949, 0x0c0a0606, 0x486c2424, 0xb8e45c5c,
    0x9f5dc2c2, 0xbd6ed3d3, 0x43efacac, 0xc4a66262,
    0x39a89191, 0x31a49595, 0xd337e4e4, 0xf28b7979,
    0xd532e7e7, 0x8b43c8c8, 0x6e593737, 0xdab76d6d,
    0x018c8d8d, 0xb164d5d5, 0x9cd24e4e, 0x49e0a9a9,
    0xd8b46c6c, 0xacfa5656, 0xf307f4f4, 0xcf25eaea,
    0xcaaf6565, 0xf48e7a7a, 0x47e9aeae, 0x10180808,
    0x6fd5baba, 0xf0887878, 0x4a6f2525, 0x5c722e2e,
    0x38241c1c, 0x57f1a6a6, 0x73c7b4b4, 0x9751c6c6,
    0xcb23e8e8, 0xa17cdddd, 0xe89c7474, 0x3e211f1f,
    0x96dd4b4b, 0x61dcbdbd, 0x0d868b8b, 0x0f858a8a,
    0xe0907070, 0x7c423e3e, 0x71c4b5b5, 0xccaa6666,
    0x90d84848, 0x06050303, 0xf701f6f6, 0x1c120e0e,
    0xc2a36161, 0x6a5f3535, 0xaef95757, 0x69d0b9b9,
    0x17918686, 0x9958c1c1, 0x3a271d1d, 0x27b99e9e,
    0xd938e1e1, 0xeb13f8f8, 0x2bb39898, 0x22331111,
    0xd2bb6969, 0xa970d9d9, 0x07898e8e, 0x33a79494,
    0x2db69b9b, 0x3c221e1e, 0x15928787, 0xc920e9e9,
    0x8749cece, 0xaaff5555, 0x50782828, 0xa57adfdf,
    0x038f8c8c, 0x59f8a1a1, 0x09808989, 0x1a170d0d,
    0x65dabfbf, 0xd731e6e6, 0x84c64242, 0xd0b86868,
    0x82c34141, 0x29b09999, 0x5a772d2d, 0x1e110f0f,
    0x7bcbb0b0, 0xa8fc5454, 0x6dd6bbbb, 0x2c3a1616
]);

function B0(x) {
  return (x & 255);
}

function B1(x) {
  return ((x >> 8) & 255);
}

function B2(x) {
  return ((x >> 16) & 255);
}

function B3(x) {
  return ((x >> 24) & 255);
}

function F1(x0, x1, x2, x3) {
  return B1(T1[x0 & 255]) | (B1(T1[(x1 >> 8) & 255]) << 8) | (B1(T1[(x2 >> 16) & 255]) << 16) | (B1(T1[x3 >>> 24]) << 24);
}

function packBytes(octets) {
  var i, j;
  var len = octets.length;
  var b = new Array(len / 4);

  if (!octets || len % 4) return;

  for (i = 0, j = 0; j < len; j += 4) {
    b[i++] = octets[j] | (octets[j + 1] << 8) | (octets[j + 2] << 16) | (octets[j + 3] << 24);
  }

  return b;
}

function unpackBytes(packed) {
  var j;
  var i = 0,
    l = packed.length;
  var r = new Array(l * 4);

  for (j = 0; j < l; j++) {
    r[i++] = B0(packed[j]);
    r[i++] = B1(packed[j]);
    r[i++] = B2(packed[j]);
    r[i++] = B3(packed[j]);
  }
  return r;
}

// ------------------------------------------------

var maxkc = 8;
var maxrk = 14;

function keyExpansion(key) {
  var kc, i, j, r, t;
  var rounds;
  var keySched = new Array(maxrk + 1);
  var keylen = key.length;
  var k = new Array(maxkc);
  var tk = new Array(maxkc);
  var rconpointer = 0;

  if (keylen == 16) {
    rounds = 10;
    kc = 4;
  } else if (keylen == 24) {
    rounds = 12;
    kc = 6;
  } else if (keylen == 32) {
    rounds = 14;
    kc = 8;
  } else {
    throw new Error('Invalid key-length for AES key:' + keylen);
  }

  for (i = 0; i < maxrk + 1; i++) {
    keySched[i] = new Uint32Array(4);
  }

  for (i = 0, j = 0; j < keylen; j++, i += 4) {
    k[j] = key.charCodeAt(i) | (key.charCodeAt(i + 1) << 8) | (key.charCodeAt(i + 2) << 16) | (key.charCodeAt(i + 3) << 24);
  }

  for (j = kc - 1; j >= 0; j--) {
    tk[j] = k[j];
  }

  r = 0;
  t = 0;
  for (j = 0; (j < kc) && (r < rounds + 1);) {
    for (; (j < kc) && (t < 4); j++, t++) {
      keySched[r][t] = tk[j];
    }
    if (t == 4) {
      r++;
      t = 0;
    }
  }

  while (r < rounds + 1) {
    var temp = tk[kc - 1];

    tk[0] ^= S[B1(temp)] | (S[B2(temp)] << 8) | (S[B3(temp)] << 16) | (S[B0(temp)] << 24);
    tk[0] ^= Rcon[rconpointer++];

    if (kc != 8) {
      for (j = 1; j < kc; j++) {
        tk[j] ^= tk[j - 1];
      }
    } else {
      for (j = 1; j < kc / 2; j++) {
        tk[j] ^= tk[j - 1];
      }

      temp = tk[kc / 2 - 1];
      tk[kc / 2] ^= S[B0(temp)] | (S[B1(temp)] << 8) | (S[B2(temp)] << 16) | (S[B3(temp)] << 24);

      for (j = kc / 2 + 1; j < kc; j++) {
        tk[j] ^= tk[j - 1];
      }
    }

    for (j = 0; (j < kc) && (r < rounds + 1);) {
      for (; (j < kc) && (t < 4); j++, t++) {
        keySched[r][t] = tk[j];
      }
      if (t == 4) {
        r++;
        t = 0;
      }
    }
  }

  return {
    rounds: rounds,
    rk: keySched
  };
}

function AESencrypt(block, ctx, t) {
  var r, rounds, b;

  b = packBytes(block);
  rounds = ctx.rounds;

  for (r = 0; r < rounds - 1; r++) {
    t[0] = b[0] ^ ctx.rk[r][0];
    t[1] = b[1] ^ ctx.rk[r][1];
    t[2] = b[2] ^ ctx.rk[r][2];
    t[3] = b[3] ^ ctx.rk[r][3];

    b[0] = T1[t[0] & 255] ^ T2[(t[1] >> 8) & 255] ^ T3[(t[2] >> 16) & 255] ^ T4[t[3] >>> 24];
    b[1] = T1[t[1] & 255] ^ T2[(t[2] >> 8) & 255] ^ T3[(t[3] >> 16) & 255] ^ T4[t[0] >>> 24];
    b[2] = T1[t[2] & 255] ^ T2[(t[3] >> 8) & 255] ^ T3[(t[0] >> 16) & 255] ^ T4[t[1] >>> 24];
    b[3] = T1[t[3] & 255] ^ T2[(t[0] >> 8) & 255] ^ T3[(t[1] >> 16) & 255] ^ T4[t[2] >>> 24];
  }

  // last round is special
  r = rounds - 1;

  t[0] = b[0] ^ ctx.rk[r][0];
  t[1] = b[1] ^ ctx.rk[r][1];
  t[2] = b[2] ^ ctx.rk[r][2];
  t[3] = b[3] ^ ctx.rk[r][3];

  b[0] = F1(t[0], t[1], t[2], t[3]) ^ ctx.rk[rounds][0];
  b[1] = F1(t[1], t[2], t[3], t[0]) ^ ctx.rk[rounds][1];
  b[2] = F1(t[2], t[3], t[0], t[1]) ^ ctx.rk[rounds][2];
  b[3] = F1(t[3], t[0], t[1], t[2]) ^ ctx.rk[rounds][3];

  return unpackBytes(b);
}

function makeClass(length) {

  var c = function(key) {
    this.key = keyExpansion(key);
    this._temp = new Uint32Array(this.blockSize / 4);

    this.encrypt = function(block) {
      return AESencrypt(block, this.key, this._temp);
    };
  };

  c.blockSize = c.prototype.blockSize = 16;
  c.keySize = c.prototype.keySize = length / 8;

  return c;
}

module.exports = {};

var types = [128, 192, 256];

for (var i in types) {
  module.exports[types[i]] = makeClass(types[i]);
}

},{"../../util.js":95}],36:[function(require,module,exports){
/* Modified by Recurity Labs GmbH 
 * 
 * Originally written by nklein software (nklein.com)
 */

/**
 *  @module crypto/cipher/blowfish
 */

/* 
 * Javascript implementation based on Bruce Schneier's reference implementation.
 *
 *
 * The constructor doesn't do much of anything.  It's just here
 * so we can start defining properties and methods and such.
 */
function Blowfish() {}

/*
 * Declare the block size so that protocols know what size
 * Initialization Vector (IV) they will need.
 */
Blowfish.prototype.BLOCKSIZE = 8;

/*
 * These are the default SBOXES.
 */
Blowfish.prototype.SBOXES = [
  [
      0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
      0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16,
      0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658,
      0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
      0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
      0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60,
      0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6,
      0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
      0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c,
      0x7a325381, 0x28958677, 0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193,
      0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032, 0xef845d5d, 0xe98575b1,
      0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
      0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a,
      0x670c9c61, 0xabd388f0, 0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3,
      0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176,
      0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe,
      0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706,
      0x1bfedf72, 0x429b023d, 0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b,
      0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7, 0xe3fe501a, 0xb6794c3b,
      0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
      0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f, 0x6dfc511f, 0x9b30952c,
      0xcc814544, 0xaf5ebd09, 0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3,
      0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb, 0x5579c0bd, 0x1a60320a,
      0xd6a100c6, 0x402c7279, 0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8,
      0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab, 0x323db5fa, 0xfd238760,
      0x53317b48, 0x3e00df82, 0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db,
      0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573, 0x695b27b0, 0xbbca58c8,
      0xe1ffa35d, 0xb8f011a0, 0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
      0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790, 0xe1ddf2da, 0xa4cb7e33,
      0x62fb1341, 0xcee4c6e8, 0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4,
      0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0, 0xd08ed1d0, 0xafc725e0,
      0x8e3c5b2f, 0x8e7594b7, 0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c,
      0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad, 0x2f2f2218, 0xbe0e1777,
      0xea752dfe, 0x8b021fa1, 0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299,
      0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9, 0x165fa266, 0x80957705,
      0x93cc7314, 0x211a1477, 0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf,
      0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49, 0x00250e2d, 0x2071b35e,
      0x226800bb, 0x57b8e0af, 0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa,
      0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5, 0x83260376, 0x6295cfa9,
      0x11c81968, 0x4e734a41, 0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
      0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400, 0x08ba6fb5, 0x571be91f,
      0xf296ec6b, 0x2a0dd915, 0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664,
      0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a
  ],
  [
      0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623, 0xad6ea6b0, 0x49a7df7d,
      0x9cee60b8, 0x8fedb266, 0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1,
      0x193602a5, 0x75094c29, 0xa0591340, 0xe4183a3e, 0x3f54989a, 0x5b429d65,
      0x6b8fe4d6, 0x99f73fd6, 0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1,
      0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e, 0x09686b3f, 0x3ebaefc9,
      0x3c971814, 0x6b6a70a1, 0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737,
      0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8, 0xb03ada37, 0xf0500c0d,
      0xf01c1f04, 0x0200b3ff, 0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd,
      0xd19113f9, 0x7ca92ff6, 0x94324773, 0x22f54701, 0x3ae5e581, 0x37c2dadc,
      0xc8b57634, 0x9af3dda7, 0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41,
      0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331, 0x4e548b38, 0x4f6db908,
      0x6f420d03, 0xf60a04bf, 0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af,
      0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e, 0x5512721f, 0x2e6b7124,
      0x501adde6, 0x9f84cd87, 0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c,
      0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2, 0xef1c1847, 0x3215d908,
      0xdd433b37, 0x24c2ba16, 0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd,
      0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b, 0x043556f1, 0xd7a3c76b,
      0x3c11183b, 0x5924a509, 0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e,
      0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3, 0x771fe71c, 0x4e3d06fa,
      0x2965dcb9, 0x99e71d0f, 0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a,
      0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4, 0xf2f74ea7, 0x361d2b3d,
      0x1939260f, 0x19c27960, 0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66,
      0xe3bc4595, 0xa67bc883, 0xb17f37d1, 0x018cff28, 0xc332ddef, 0xbe6c5aa5,
      0x65582185, 0x68ab9802, 0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84,
      0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510, 0x13cca830, 0xeb61bd96,
      0x0334fe1e, 0xaa0363cf, 0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14,
      0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e, 0x648b1eaf, 0x19bdf0ca,
      0xa02369b9, 0x655abb50, 0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7,
      0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8, 0xf837889a, 0x97e32d77,
      0x11ed935f, 0x16681281, 0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99,
      0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696, 0xcdb30aeb, 0x532e3054,
      0x8fd948e4, 0x6dbc3128, 0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73,
      0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0, 0x45eee2b6, 0xa3aaabea,
      0xdb6c4f15, 0xfacb4fd0, 0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105,
      0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250, 0xcf62a1f2, 0x5b8d2646,
      0xfc8883a0, 0xc1c7b6a3, 0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285,
      0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00, 0x58428d2a, 0x0c55f5ea,
      0x1dadf43e, 0x233f7061, 0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb,
      0x7cde3759, 0xcbee7460, 0x4085f2a7, 0xce77326e, 0xa6078084, 0x19f8509e,
      0xe8efd855, 0x61d99735, 0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc,
      0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9, 0xdb73dbd3, 0x105588cd,
      0x675fda79, 0xe3674340, 0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20,
      0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7
  ],
  [
      0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934, 0x411520f7, 0x7602d4f7,
      0xbcf46b2e, 0xd4a20068, 0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af,
      0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840, 0x4d95fc1d, 0x96b591af,
      0x70f4ddd3, 0x66a02f45, 0xbfbc09ec, 0x03bd9785, 0x7fac6dd0, 0x31cb8504,
      0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a, 0x28507825, 0x530429f4,
      0x0a2c86da, 0xe9b66dfb, 0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee,
      0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6, 0xaace1e7c, 0xd3375fec,
      0xce78a399, 0x406b2a42, 0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b,
      0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2, 0x3a6efa74, 0xdd5b4332,
      0x6841e7f7, 0xca7820fb, 0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527,
      0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b, 0x55a867bc, 0xa1159a58,
      0xcca92963, 0x99e1db33, 0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c,
      0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3, 0x95c11548, 0xe4c66d22,
      0x48c1133f, 0xc70f86dc, 0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17,
      0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564, 0x257b7834, 0x602a9c60,
      0xdff8e8a3, 0x1f636c1b, 0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115,
      0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922, 0x85b2a20e, 0xe6ba0d99,
      0xde720c8c, 0x2da2f728, 0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0,
      0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e, 0x0a476341, 0x992eff74,
      0x3a6f6eab, 0xf4f8fd37, 0xa812dc60, 0xa1ebddf8, 0x991be14c, 0xdb6e6b0d,
      0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804, 0xf1290dc7, 0xcc00ffa3,
      0xb5390f92, 0x690fed0b, 0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3,
      0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb, 0x37392eb3, 0xcc115979,
      0x8026e297, 0xf42e312d, 0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c,
      0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350, 0x1a6b1018, 0x11caedfa,
      0x3d25bdd8, 0xe2e1c3c9, 0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a,
      0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe, 0x9dbc8057, 0xf0f7c086,
      0x60787bf8, 0x6003604d, 0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
      0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f, 0x77a057be, 0xbde8ae24,
      0x55464299, 0xbf582e61, 0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2,
      0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9, 0x7aeb2661, 0x8b1ddf84,
      0x846a0e79, 0x915f95e2, 0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c,
      0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e, 0xb77f19b6, 0xe0a9dc09,
      0x662d09a1, 0xc4324633, 0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10,
      0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169, 0xdcb7da83, 0x573906fe,
      0xa1e2ce9b, 0x4fcd7f52, 0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027,
      0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5, 0xf0177a28, 0xc0f586e0,
      0x006058aa, 0x30dc7d62, 0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634,
      0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76, 0x6f05e409, 0x4b7c0188,
      0x39720a3d, 0x7c927c24, 0x86e3725f, 0x724d9db9, 0x1ac15bb4, 0xd39eb8fc,
      0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4, 0x1e50ef5e, 0xb161e6f8,
      0xa28514d9, 0x6c51133c, 0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837,
      0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0
  ],
  [
      0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b, 0x5cb0679e, 0x4fa33742,
      0xd3822740, 0x99bc9bbe, 0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b,
      0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4, 0x5748ab2f, 0xbc946e79,
      0xc6a376d2, 0x6549c2c8, 0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6,
      0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304, 0xa1fad5f0, 0x6a2d519a,
      0x63ef8ce2, 0x9a86ee22, 0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4,
      0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6, 0x2826a2f9, 0xa73a3ae1,
      0x4ba99586, 0xef5562e9, 0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59,
      0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593, 0xe990fd5a, 0x9e34d797,
      0x2cf0b7d9, 0x022b8b51, 0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28,
      0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c, 0xe029ac71, 0xe019a5e6,
      0x47b0acfd, 0xed93fa9b, 0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
      0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c, 0x15056dd4, 0x88f46dba,
      0x03a16125, 0x0564f0bd, 0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a,
      0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319, 0x7533d928, 0xb155fdf5,
      0x03563482, 0x8aba3cbb, 0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f,
      0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991, 0xea7a90c2, 0xfb3e7bce,
      0x5121ce64, 0x774fbe32, 0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680,
      0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166, 0xb39a460a, 0x6445c0dd,
      0x586cdecf, 0x1c20c8ae, 0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb,
      0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5, 0x72eacea8, 0xfa6484bb,
      0x8d6612ae, 0xbf3c6f47, 0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370,
      0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d, 0x4040cb08, 0x4eb4e2cc,
      0x34d2466a, 0x0115af84, 0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048,
      0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8, 0x611560b1, 0xe7933fdc,
      0xbb3a792b, 0x344525bd, 0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9,
      0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7, 0x1a908749, 0xd44fbd9a,
      0xd0dadecb, 0xd50ada38, 0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
      0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c, 0xbf97222c, 0x15e6fc2a,
      0x0f91fc71, 0x9b941525, 0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1,
      0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442, 0xe0ec6e0e, 0x1698db3b,
      0x4c98a0be, 0x3278e964, 0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
      0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8, 0xdf359f8d, 0x9b992f2e,
      0xe60b6f47, 0x0fe3f11d, 0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f,
      0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299, 0xf523f357, 0xa6327623,
      0x93a83531, 0x56cccd02, 0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc,
      0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614, 0xe6c6c7bd, 0x327a140a,
      0x45e1d006, 0xc3f27b9a, 0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6,
      0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b, 0x53113ec0, 0x1640e3d3,
      0x38abbd60, 0x2547adf0, 0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
      0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e, 0x1948c25c, 0x02fb8a8c,
      0x01c36ae4, 0xd6ebe1f9, 0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f,
      0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6
  ]
];

//*
//* This is the default PARRAY
//*
Blowfish.prototype.PARRAY = [
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
    0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
    0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b
];

//*
//* This is the number of rounds the cipher will go
//*
Blowfish.prototype.NN = 16;

//*
//* This function is needed to get rid of problems
//* with the high-bit getting set.  If we don't do
//* this, then sometimes ( aa & 0x00FFFFFFFF ) is not
//* equal to ( bb & 0x00FFFFFFFF ) even when they
//* agree bit-for-bit for the first 32 bits.
//*
Blowfish.prototype._clean = function(xx) {
  if (xx < 0) {
    var yy = xx & 0x7FFFFFFF;
    xx = yy + 0x80000000;
  }
  return xx;
};

//*
//* This is the mixing function that uses the sboxes
//*
Blowfish.prototype._F = function(xx) {
  var aa;
  var bb;
  var cc;
  var dd;
  var yy;

  dd = xx & 0x00FF;
  xx >>>= 8;
  cc = xx & 0x00FF;
  xx >>>= 8;
  bb = xx & 0x00FF;
  xx >>>= 8;
  aa = xx & 0x00FF;

  yy = this.sboxes[0][aa] + this.sboxes[1][bb];
  yy = yy ^ this.sboxes[2][cc];
  yy = yy + this.sboxes[3][dd];

  return yy;
};

//*
//* This method takes an array with two values, left and right
//* and does NN rounds of Blowfish on them.
//*
Blowfish.prototype._encrypt_block = function(vals) {
  var dataL = vals[0];
  var dataR = vals[1];

  var ii;

  for (ii = 0; ii < this.NN; ++ii) {
    dataL = dataL ^ this.parray[ii];
    dataR = this._F(dataL) ^ dataR;

    var tmp = dataL;
    dataL = dataR;
    dataR = tmp;
  }

  dataL = dataL ^ this.parray[this.NN + 0];
  dataR = dataR ^ this.parray[this.NN + 1];

  vals[0] = this._clean(dataR);
  vals[1] = this._clean(dataL);
};

//*
//* This method takes a vector of numbers and turns them
//* into long words so that they can be processed by the
//* real algorithm.
//*
//* Maybe I should make the real algorithm above take a vector
//* instead.  That will involve more looping, but it won't require
//* the F() method to deconstruct the vector.
//*
Blowfish.prototype.encrypt_block = function(vector) {
  var ii;
  var vals = [0, 0];
  var off = this.BLOCKSIZE / 2;
  for (ii = 0; ii < this.BLOCKSIZE / 2; ++ii) {
    vals[0] = (vals[0] << 8) | (vector[ii + 0] & 0x00FF);
    vals[1] = (vals[1] << 8) | (vector[ii + off] & 0x00FF);
  }

  this._encrypt_block(vals);

  var ret = [];
  for (ii = 0; ii < this.BLOCKSIZE / 2; ++ii) {
    ret[ii + 0] = (vals[0] >>> (24 - 8 * (ii)) & 0x00FF);
    ret[ii + off] = (vals[1] >>> (24 - 8 * (ii)) & 0x00FF);
    // vals[ 0 ] = ( vals[ 0 ] >>> 8 );
    // vals[ 1 ] = ( vals[ 1 ] >>> 8 );
  }

  return ret;
};

//*
//* This method takes an array with two values, left and right
//* and undoes NN rounds of Blowfish on them.
//*
Blowfish.prototype._decrypt_block = function(vals) {
  var dataL = vals[0];
  var dataR = vals[1];

  var ii;

  for (ii = this.NN + 1; ii > 1; --ii) {
    dataL = dataL ^ this.parray[ii];
    dataR = this._F(dataL) ^ dataR;

    var tmp = dataL;
    dataL = dataR;
    dataR = tmp;
  }

  dataL = dataL ^ this.parray[1];
  dataR = dataR ^ this.parray[0];

  vals[0] = this._clean(dataR);
  vals[1] = this._clean(dataL);
};

//*
//* This method takes a key array and initializes the
//* sboxes and parray for this encryption.
//*
Blowfish.prototype.init = function(key) {
  var ii;
  var jj = 0;

  this.parray = [];
  for (ii = 0; ii < this.NN + 2; ++ii) {
    var data = 0x00000000;
    var kk;
    for (kk = 0; kk < 4; ++kk) {
      data = (data << 8) | (key[jj] & 0x00FF);
      if (++jj >= key.length) {
        jj = 0;
      }
    }
    this.parray[ii] = this.PARRAY[ii] ^ data;
  }

  this.sboxes = [];
  for (ii = 0; ii < 4; ++ii) {
    this.sboxes[ii] = [];
    for (jj = 0; jj < 256; ++jj) {
      this.sboxes[ii][jj] = this.SBOXES[ii][jj];
    }
  }

  var vals = [0x00000000, 0x00000000];

  for (ii = 0; ii < this.NN + 2; ii += 2) {
    this._encrypt_block(vals);
    this.parray[ii + 0] = vals[0];
    this.parray[ii + 1] = vals[1];
  }

  for (ii = 0; ii < 4; ++ii) {
    for (jj = 0; jj < 256; jj += 2) {
      this._encrypt_block(vals);
      this.sboxes[ii][jj + 0] = vals[0];
      this.sboxes[ii][jj + 1] = vals[1];
    }
  }
};

var util = require('../../util.js');

// added by Recurity Labs

function BFencrypt(block, key) {
  var bf = new Blowfish();
  bf.init(util.str2bin(key));
  return bf.encrypt_block(block);
}

function BF(key) {
  this.bf = new Blowfish();
  this.bf.init(util.str2bin(key));

  this.encrypt = function(block) {
    return this.bf.encrypt_block(block);
  };
}


module.exports = BF;
module.exports.keySize = BF.prototype.keySize = 16;
module.exports.blockSize = BF.prototype.blockSize = 16;

},{"../../util.js":95}],37:[function(require,module,exports){
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Copyright 2010 pjacobs@xeekr.com . All rights reserved.

// Modified by Recurity Labs GmbH

// fixed/modified by Herbert Hanewinkel, www.haneWIN.de
// check www.haneWIN.de for the latest version

// cast5.js is a Javascript implementation of CAST-128, as defined in RFC 2144.
// CAST-128 is a common OpenPGP cipher.


// CAST5 constructor

/** @module crypto/cipher/cast5 */



function openpgp_symenc_cast5() {
  this.BlockSize = 8;
  this.KeySize = 16;

  this.setKey = function(key) {
    this.masking = new Array(16);
    this.rotate = new Array(16);

    this.reset();

    if (key.length == this.KeySize) {
      this.keySchedule(key);
    } else {
      throw new Error('CAST-128: keys must be 16 bytes');
    }
    return true;
  };

  this.reset = function() {
    for (var i = 0; i < 16; i++) {
      this.masking[i] = 0;
      this.rotate[i] = 0;
    }
  };

  this.getBlockSize = function() {
    return BlockSize;
  };

  this.encrypt = function(src) {
    var dst = new Array(src.length);

    for (var i = 0; i < src.length; i += 8) {
      var l = src[i] << 24 | src[i + 1] << 16 | src[i + 2] << 8 | src[i + 3];
      var r = src[i + 4] << 24 | src[i + 5] << 16 | src[i + 6] << 8 | src[i + 7];
      var t;

      t = r;
      r = l ^ f1(r, this.masking[0], this.rotate[0]);
      l = t;
      t = r;
      r = l ^ f2(r, this.masking[1], this.rotate[1]);
      l = t;
      t = r;
      r = l ^ f3(r, this.masking[2], this.rotate[2]);
      l = t;
      t = r;
      r = l ^ f1(r, this.masking[3], this.rotate[3]);
      l = t;

      t = r;
      r = l ^ f2(r, this.masking[4], this.rotate[4]);
      l = t;
      t = r;
      r = l ^ f3(r, this.masking[5], this.rotate[5]);
      l = t;
      t = r;
      r = l ^ f1(r, this.masking[6], this.rotate[6]);
      l = t;
      t = r;
      r = l ^ f2(r, this.masking[7], this.rotate[7]);
      l = t;

      t = r;
      r = l ^ f3(r, this.masking[8], this.rotate[8]);
      l = t;
      t = r;
      r = l ^ f1(r, this.masking[9], this.rotate[9]);
      l = t;
      t = r;
      r = l ^ f2(r, this.masking[10], this.rotate[10]);
      l = t;
      t = r;
      r = l ^ f3(r, this.masking[11], this.rotate[11]);
      l = t;

      t = r;
      r = l ^ f1(r, this.masking[12], this.rotate[12]);
      l = t;
      t = r;
      r = l ^ f2(r, this.masking[13], this.rotate[13]);
      l = t;
      t = r;
      r = l ^ f3(r, this.masking[14], this.rotate[14]);
      l = t;
      t = r;
      r = l ^ f1(r, this.masking[15], this.rotate[15]);
      l = t;

      dst[i] = (r >>> 24) & 255;
      dst[i + 1] = (r >>> 16) & 255;
      dst[i + 2] = (r >>> 8) & 255;
      dst[i + 3] = r & 255;
      dst[i + 4] = (l >>> 24) & 255;
      dst[i + 5] = (l >>> 16) & 255;
      dst[i + 6] = (l >>> 8) & 255;
      dst[i + 7] = l & 255;
    }

    return dst;
  };

  this.decrypt = function(src) {
    var dst = new Array(src.length);

    for (var i = 0; i < src.length; i += 8) {
      var l = src[i] << 24 | src[i + 1] << 16 | src[i + 2] << 8 | src[i + 3];
      var r = src[i + 4] << 24 | src[i + 5] << 16 | src[i + 6] << 8 | src[i + 7];
      var t;

      t = r;
      r = l ^ f1(r, this.masking[15], this.rotate[15]);
      l = t;
      t = r;
      r = l ^ f3(r, this.masking[14], this.rotate[14]);
      l = t;
      t = r;
      r = l ^ f2(r, this.masking[13], this.rotate[13]);
      l = t;
      t = r;
      r = l ^ f1(r, this.masking[12], this.rotate[12]);
      l = t;

      t = r;
      r = l ^ f3(r, this.masking[11], this.rotate[11]);
      l = t;
      t = r;
      r = l ^ f2(r, this.masking[10], this.rotate[10]);
      l = t;
      t = r;
      r = l ^ f1(r, this.masking[9], this.rotate[9]);
      l = t;
      t = r;
      r = l ^ f3(r, this.masking[8], this.rotate[8]);
      l = t;

      t = r;
      r = l ^ f2(r, this.masking[7], this.rotate[7]);
      l = t;
      t = r;
      r = l ^ f1(r, this.masking[6], this.rotate[6]);
      l = t;
      t = r;
      r = l ^ f3(r, this.masking[5], this.rotate[5]);
      l = t;
      t = r;
      r = l ^ f2(r, this.masking[4], this.rotate[4]);
      l = t;

      t = r;
      r = l ^ f1(r, this.masking[3], this.rotate[3]);
      l = t;
      t = r;
      r = l ^ f3(r, this.masking[2], this.rotate[2]);
      l = t;
      t = r;
      r = l ^ f2(r, this.masking[1], this.rotate[1]);
      l = t;
      t = r;
      r = l ^ f1(r, this.masking[0], this.rotate[0]);
      l = t;

      dst[i] = (r >>> 24) & 255;
      dst[i + 1] = (r >>> 16) & 255;
      dst[i + 2] = (r >>> 8) & 255;
      dst[i + 3] = r & 255;
      dst[i + 4] = (l >>> 24) & 255;
      dst[i + 5] = (l >> 16) & 255;
      dst[i + 6] = (l >> 8) & 255;
      dst[i + 7] = l & 255;
    }

    return dst;
  };
  var scheduleA = new Array(4);

  scheduleA[0] = new Array(4);
  scheduleA[0][0] = new Array(4, 0, 0xd, 0xf, 0xc, 0xe, 0x8);
  scheduleA[0][1] = new Array(5, 2, 16 + 0, 16 + 2, 16 + 1, 16 + 3, 0xa);
  scheduleA[0][2] = new Array(6, 3, 16 + 7, 16 + 6, 16 + 5, 16 + 4, 9);
  scheduleA[0][3] = new Array(7, 1, 16 + 0xa, 16 + 9, 16 + 0xb, 16 + 8, 0xb);

  scheduleA[1] = new Array(4);
  scheduleA[1][0] = new Array(0, 6, 16 + 5, 16 + 7, 16 + 4, 16 + 6, 16 + 0);
  scheduleA[1][1] = new Array(1, 4, 0, 2, 1, 3, 16 + 2);
  scheduleA[1][2] = new Array(2, 5, 7, 6, 5, 4, 16 + 1);
  scheduleA[1][3] = new Array(3, 7, 0xa, 9, 0xb, 8, 16 + 3);

  scheduleA[2] = new Array(4);
  scheduleA[2][0] = new Array(4, 0, 0xd, 0xf, 0xc, 0xe, 8);
  scheduleA[2][1] = new Array(5, 2, 16 + 0, 16 + 2, 16 + 1, 16 + 3, 0xa);
  scheduleA[2][2] = new Array(6, 3, 16 + 7, 16 + 6, 16 + 5, 16 + 4, 9);
  scheduleA[2][3] = new Array(7, 1, 16 + 0xa, 16 + 9, 16 + 0xb, 16 + 8, 0xb);


  scheduleA[3] = new Array(4);
  scheduleA[3][0] = new Array(0, 6, 16 + 5, 16 + 7, 16 + 4, 16 + 6, 16 + 0);
  scheduleA[3][1] = new Array(1, 4, 0, 2, 1, 3, 16 + 2);
  scheduleA[3][2] = new Array(2, 5, 7, 6, 5, 4, 16 + 1);
  scheduleA[3][3] = new Array(3, 7, 0xa, 9, 0xb, 8, 16 + 3);

  var scheduleB = new Array(4);

  scheduleB[0] = new Array(4);
  scheduleB[0][0] = new Array(16 + 8, 16 + 9, 16 + 7, 16 + 6, 16 + 2);
  scheduleB[0][1] = new Array(16 + 0xa, 16 + 0xb, 16 + 5, 16 + 4, 16 + 6);
  scheduleB[0][2] = new Array(16 + 0xc, 16 + 0xd, 16 + 3, 16 + 2, 16 + 9);
  scheduleB[0][3] = new Array(16 + 0xe, 16 + 0xf, 16 + 1, 16 + 0, 16 + 0xc);

  scheduleB[1] = new Array(4);
  scheduleB[1][0] = new Array(3, 2, 0xc, 0xd, 8);
  scheduleB[1][1] = new Array(1, 0, 0xe, 0xf, 0xd);
  scheduleB[1][2] = new Array(7, 6, 8, 9, 3);
  scheduleB[1][3] = new Array(5, 4, 0xa, 0xb, 7);


  scheduleB[2] = new Array(4);
  scheduleB[2][0] = new Array(16 + 3, 16 + 2, 16 + 0xc, 16 + 0xd, 16 + 9);
  scheduleB[2][1] = new Array(16 + 1, 16 + 0, 16 + 0xe, 16 + 0xf, 16 + 0xc);
  scheduleB[2][2] = new Array(16 + 7, 16 + 6, 16 + 8, 16 + 9, 16 + 2);
  scheduleB[2][3] = new Array(16 + 5, 16 + 4, 16 + 0xa, 16 + 0xb, 16 + 6);


  scheduleB[3] = new Array(4);
  scheduleB[3][0] = new Array(8, 9, 7, 6, 3);
  scheduleB[3][1] = new Array(0xa, 0xb, 5, 4, 7);
  scheduleB[3][2] = new Array(0xc, 0xd, 3, 2, 8);
  scheduleB[3][3] = new Array(0xe, 0xf, 1, 0, 0xd);

  // changed 'in' to 'inn' (in javascript 'in' is a reserved word)
  this.keySchedule = function(inn) {
    var t = new Array(8);
    var k = new Array(32);

    var i, j;

    for (i = 0; i < 4; i++) {
      j = i * 4;
      t[i] = inn[j] << 24 | inn[j + 1] << 16 | inn[j + 2] << 8 | inn[j + 3];
    }

    var x = [6, 7, 4, 5];
    var ki = 0;
    var w;

    for (var half = 0; half < 2; half++) {
      for (var round = 0; round < 4; round++) {
        for (j = 0; j < 4; j++) {
          var a = scheduleA[round][j];
          w = t[a[1]];

          w ^= sBox[4][(t[a[2] >>> 2] >>> (24 - 8 * (a[2] & 3))) & 0xff];
          w ^= sBox[5][(t[a[3] >>> 2] >>> (24 - 8 * (a[3] & 3))) & 0xff];
          w ^= sBox[6][(t[a[4] >>> 2] >>> (24 - 8 * (a[4] & 3))) & 0xff];
          w ^= sBox[7][(t[a[5] >>> 2] >>> (24 - 8 * (a[5] & 3))) & 0xff];
          w ^= sBox[x[j]][(t[a[6] >>> 2] >>> (24 - 8 * (a[6] & 3))) & 0xff];
          t[a[0]] = w;
        }

        for (j = 0; j < 4; j++) {
          var b = scheduleB[round][j];
          w = sBox[4][(t[b[0] >>> 2] >>> (24 - 8 * (b[0] & 3))) & 0xff];

          w ^= sBox[5][(t[b[1] >>> 2] >>> (24 - 8 * (b[1] & 3))) & 0xff];
          w ^= sBox[6][(t[b[2] >>> 2] >>> (24 - 8 * (b[2] & 3))) & 0xff];
          w ^= sBox[7][(t[b[3] >>> 2] >>> (24 - 8 * (b[3] & 3))) & 0xff];
          w ^= sBox[4 + j][(t[b[4] >>> 2] >>> (24 - 8 * (b[4] & 3))) & 0xff];
          k[ki] = w;
          ki++;
        }
      }
    }

    for (i = 0; i < 16; i++) {
      this.masking[i] = k[i];
      this.rotate[i] = k[16 + i] & 0x1f;
    }
  };

  // These are the three 'f' functions. See RFC 2144, section 2.2.

  function f1(d, m, r) {
    var t = m + d;
    var I = (t << r) | (t >>> (32 - r));
    return ((sBox[0][I >>> 24] ^ sBox[1][(I >>> 16) & 255]) - sBox[2][(I >>> 8) & 255]) + sBox[3][I & 255];
  }

  function f2(d, m, r) {
    var t = m ^ d;
    var I = (t << r) | (t >>> (32 - r));
    return ((sBox[0][I >>> 24] - sBox[1][(I >>> 16) & 255]) + sBox[2][(I >>> 8) & 255]) ^ sBox[3][I & 255];
  }

  function f3(d, m, r) {
    var t = m - d;
    var I = (t << r) | (t >>> (32 - r));
    return ((sBox[0][I >>> 24] + sBox[1][(I >>> 16) & 255]) ^ sBox[2][(I >>> 8) & 255]) - sBox[3][I & 255];
  }

  var sBox = new Array(8);
  sBox[0] = new Array(
    0x30fb40d4, 0x9fa0ff0b, 0x6beccd2f, 0x3f258c7a, 0x1e213f2f, 0x9c004dd3, 0x6003e540, 0xcf9fc949,
    0xbfd4af27, 0x88bbbdb5, 0xe2034090, 0x98d09675, 0x6e63a0e0, 0x15c361d2, 0xc2e7661d, 0x22d4ff8e,
    0x28683b6f, 0xc07fd059, 0xff2379c8, 0x775f50e2, 0x43c340d3, 0xdf2f8656, 0x887ca41a, 0xa2d2bd2d,
    0xa1c9e0d6, 0x346c4819, 0x61b76d87, 0x22540f2f, 0x2abe32e1, 0xaa54166b, 0x22568e3a, 0xa2d341d0,
    0x66db40c8, 0xa784392f, 0x004dff2f, 0x2db9d2de, 0x97943fac, 0x4a97c1d8, 0x527644b7, 0xb5f437a7,
    0xb82cbaef, 0xd751d159, 0x6ff7f0ed, 0x5a097a1f, 0x827b68d0, 0x90ecf52e, 0x22b0c054, 0xbc8e5935,
    0x4b6d2f7f, 0x50bb64a2, 0xd2664910, 0xbee5812d, 0xb7332290, 0xe93b159f, 0xb48ee411, 0x4bff345d,
    0xfd45c240, 0xad31973f, 0xc4f6d02e, 0x55fc8165, 0xd5b1caad, 0xa1ac2dae, 0xa2d4b76d, 0xc19b0c50,
    0x882240f2, 0x0c6e4f38, 0xa4e4bfd7, 0x4f5ba272, 0x564c1d2f, 0xc59c5319, 0xb949e354, 0xb04669fe,
    0xb1b6ab8a, 0xc71358dd, 0x6385c545, 0x110f935d, 0x57538ad5, 0x6a390493, 0xe63d37e0, 0x2a54f6b3,
    0x3a787d5f, 0x6276a0b5, 0x19a6fcdf, 0x7a42206a, 0x29f9d4d5, 0xf61b1891, 0xbb72275e, 0xaa508167,
    0x38901091, 0xc6b505eb, 0x84c7cb8c, 0x2ad75a0f, 0x874a1427, 0xa2d1936b, 0x2ad286af, 0xaa56d291,
    0xd7894360, 0x425c750d, 0x93b39e26, 0x187184c9, 0x6c00b32d, 0x73e2bb14, 0xa0bebc3c, 0x54623779,
    0x64459eab, 0x3f328b82, 0x7718cf82, 0x59a2cea6, 0x04ee002e, 0x89fe78e6, 0x3fab0950, 0x325ff6c2,
    0x81383f05, 0x6963c5c8, 0x76cb5ad6, 0xd49974c9, 0xca180dcf, 0x380782d5, 0xc7fa5cf6, 0x8ac31511,
    0x35e79e13, 0x47da91d0, 0xf40f9086, 0xa7e2419e, 0x31366241, 0x051ef495, 0xaa573b04, 0x4a805d8d,
    0x548300d0, 0x00322a3c, 0xbf64cddf, 0xba57a68e, 0x75c6372b, 0x50afd341, 0xa7c13275, 0x915a0bf5,
    0x6b54bfab, 0x2b0b1426, 0xab4cc9d7, 0x449ccd82, 0xf7fbf265, 0xab85c5f3, 0x1b55db94, 0xaad4e324,
    0xcfa4bd3f, 0x2deaa3e2, 0x9e204d02, 0xc8bd25ac, 0xeadf55b3, 0xd5bd9e98, 0xe31231b2, 0x2ad5ad6c,
    0x954329de, 0xadbe4528, 0xd8710f69, 0xaa51c90f, 0xaa786bf6, 0x22513f1e, 0xaa51a79b, 0x2ad344cc,
    0x7b5a41f0, 0xd37cfbad, 0x1b069505, 0x41ece491, 0xb4c332e6, 0x032268d4, 0xc9600acc, 0xce387e6d,
    0xbf6bb16c, 0x6a70fb78, 0x0d03d9c9, 0xd4df39de, 0xe01063da, 0x4736f464, 0x5ad328d8, 0xb347cc96,
    0x75bb0fc3, 0x98511bfb, 0x4ffbcc35, 0xb58bcf6a, 0xe11f0abc, 0xbfc5fe4a, 0xa70aec10, 0xac39570a,
    0x3f04442f, 0x6188b153, 0xe0397a2e, 0x5727cb79, 0x9ceb418f, 0x1cacd68d, 0x2ad37c96, 0x0175cb9d,
    0xc69dff09, 0xc75b65f0, 0xd9db40d8, 0xec0e7779, 0x4744ead4, 0xb11c3274, 0xdd24cb9e, 0x7e1c54bd,
    0xf01144f9, 0xd2240eb1, 0x9675b3fd, 0xa3ac3755, 0xd47c27af, 0x51c85f4d, 0x56907596, 0xa5bb15e6,
    0x580304f0, 0xca042cf1, 0x011a37ea, 0x8dbfaadb, 0x35ba3e4a, 0x3526ffa0, 0xc37b4d09, 0xbc306ed9,
    0x98a52666, 0x5648f725, 0xff5e569d, 0x0ced63d0, 0x7c63b2cf, 0x700b45e1, 0xd5ea50f1, 0x85a92872,
    0xaf1fbda7, 0xd4234870, 0xa7870bf3, 0x2d3b4d79, 0x42e04198, 0x0cd0ede7, 0x26470db8, 0xf881814c,
    0x474d6ad7, 0x7c0c5e5c, 0xd1231959, 0x381b7298, 0xf5d2f4db, 0xab838653, 0x6e2f1e23, 0x83719c9e,
    0xbd91e046, 0x9a56456e, 0xdc39200c, 0x20c8c571, 0x962bda1c, 0xe1e696ff, 0xb141ab08, 0x7cca89b9,
    0x1a69e783, 0x02cc4843, 0xa2f7c579, 0x429ef47d, 0x427b169c, 0x5ac9f049, 0xdd8f0f00, 0x5c8165bf);

  sBox[1] = new Array(
    0x1f201094, 0xef0ba75b, 0x69e3cf7e, 0x393f4380, 0xfe61cf7a, 0xeec5207a, 0x55889c94, 0x72fc0651,
    0xada7ef79, 0x4e1d7235, 0xd55a63ce, 0xde0436ba, 0x99c430ef, 0x5f0c0794, 0x18dcdb7d, 0xa1d6eff3,
    0xa0b52f7b, 0x59e83605, 0xee15b094, 0xe9ffd909, 0xdc440086, 0xef944459, 0xba83ccb3, 0xe0c3cdfb,
    0xd1da4181, 0x3b092ab1, 0xf997f1c1, 0xa5e6cf7b, 0x01420ddb, 0xe4e7ef5b, 0x25a1ff41, 0xe180f806,
    0x1fc41080, 0x179bee7a, 0xd37ac6a9, 0xfe5830a4, 0x98de8b7f, 0x77e83f4e, 0x79929269, 0x24fa9f7b,
    0xe113c85b, 0xacc40083, 0xd7503525, 0xf7ea615f, 0x62143154, 0x0d554b63, 0x5d681121, 0xc866c359,
    0x3d63cf73, 0xcee234c0, 0xd4d87e87, 0x5c672b21, 0x071f6181, 0x39f7627f, 0x361e3084, 0xe4eb573b,
    0x602f64a4, 0xd63acd9c, 0x1bbc4635, 0x9e81032d, 0x2701f50c, 0x99847ab4, 0xa0e3df79, 0xba6cf38c,
    0x10843094, 0x2537a95e, 0xf46f6ffe, 0xa1ff3b1f, 0x208cfb6a, 0x8f458c74, 0xd9e0a227, 0x4ec73a34,
    0xfc884f69, 0x3e4de8df, 0xef0e0088, 0x3559648d, 0x8a45388c, 0x1d804366, 0x721d9bfd, 0xa58684bb,
    0xe8256333, 0x844e8212, 0x128d8098, 0xfed33fb4, 0xce280ae1, 0x27e19ba5, 0xd5a6c252, 0xe49754bd,
    0xc5d655dd, 0xeb667064, 0x77840b4d, 0xa1b6a801, 0x84db26a9, 0xe0b56714, 0x21f043b7, 0xe5d05860,
    0x54f03084, 0x066ff472, 0xa31aa153, 0xdadc4755, 0xb5625dbf, 0x68561be6, 0x83ca6b94, 0x2d6ed23b,
    0xeccf01db, 0xa6d3d0ba, 0xb6803d5c, 0xaf77a709, 0x33b4a34c, 0x397bc8d6, 0x5ee22b95, 0x5f0e5304,
    0x81ed6f61, 0x20e74364, 0xb45e1378, 0xde18639b, 0x881ca122, 0xb96726d1, 0x8049a7e8, 0x22b7da7b,
    0x5e552d25, 0x5272d237, 0x79d2951c, 0xc60d894c, 0x488cb402, 0x1ba4fe5b, 0xa4b09f6b, 0x1ca815cf,
    0xa20c3005, 0x8871df63, 0xb9de2fcb, 0x0cc6c9e9, 0x0beeff53, 0xe3214517, 0xb4542835, 0x9f63293c,
    0xee41e729, 0x6e1d2d7c, 0x50045286, 0x1e6685f3, 0xf33401c6, 0x30a22c95, 0x31a70850, 0x60930f13,
    0x73f98417, 0xa1269859, 0xec645c44, 0x52c877a9, 0xcdff33a6, 0xa02b1741, 0x7cbad9a2, 0x2180036f,
    0x50d99c08, 0xcb3f4861, 0xc26bd765, 0x64a3f6ab, 0x80342676, 0x25a75e7b, 0xe4e6d1fc, 0x20c710e6,
    0xcdf0b680, 0x17844d3b, 0x31eef84d, 0x7e0824e4, 0x2ccb49eb, 0x846a3bae, 0x8ff77888, 0xee5d60f6,
    0x7af75673, 0x2fdd5cdb, 0xa11631c1, 0x30f66f43, 0xb3faec54, 0x157fd7fa, 0xef8579cc, 0xd152de58,
    0xdb2ffd5e, 0x8f32ce19, 0x306af97a, 0x02f03ef8, 0x99319ad5, 0xc242fa0f, 0xa7e3ebb0, 0xc68e4906,
    0xb8da230c, 0x80823028, 0xdcdef3c8, 0xd35fb171, 0x088a1bc8, 0xbec0c560, 0x61a3c9e8, 0xbca8f54d,
    0xc72feffa, 0x22822e99, 0x82c570b4, 0xd8d94e89, 0x8b1c34bc, 0x301e16e6, 0x273be979, 0xb0ffeaa6,
    0x61d9b8c6, 0x00b24869, 0xb7ffce3f, 0x08dc283b, 0x43daf65a, 0xf7e19798, 0x7619b72f, 0x8f1c9ba4,
    0xdc8637a0, 0x16a7d3b1, 0x9fc393b7, 0xa7136eeb, 0xc6bcc63e, 0x1a513742, 0xef6828bc, 0x520365d6,
    0x2d6a77ab, 0x3527ed4b, 0x821fd216, 0x095c6e2e, 0xdb92f2fb, 0x5eea29cb, 0x145892f5, 0x91584f7f,
    0x5483697b, 0x2667a8cc, 0x85196048, 0x8c4bacea, 0x833860d4, 0x0d23e0f9, 0x6c387e8a, 0x0ae6d249,
    0xb284600c, 0xd835731d, 0xdcb1c647, 0xac4c56ea, 0x3ebd81b3, 0x230eabb0, 0x6438bc87, 0xf0b5b1fa,
    0x8f5ea2b3, 0xfc184642, 0x0a036b7a, 0x4fb089bd, 0x649da589, 0xa345415e, 0x5c038323, 0x3e5d3bb9,
    0x43d79572, 0x7e6dd07c, 0x06dfdf1e, 0x6c6cc4ef, 0x7160a539, 0x73bfbe70, 0x83877605, 0x4523ecf1);

  sBox[2] = new Array(
    0x8defc240, 0x25fa5d9f, 0xeb903dbf, 0xe810c907, 0x47607fff, 0x369fe44b, 0x8c1fc644, 0xaececa90,
    0xbeb1f9bf, 0xeefbcaea, 0xe8cf1950, 0x51df07ae, 0x920e8806, 0xf0ad0548, 0xe13c8d83, 0x927010d5,
    0x11107d9f, 0x07647db9, 0xb2e3e4d4, 0x3d4f285e, 0xb9afa820, 0xfade82e0, 0xa067268b, 0x8272792e,
    0x553fb2c0, 0x489ae22b, 0xd4ef9794, 0x125e3fbc, 0x21fffcee, 0x825b1bfd, 0x9255c5ed, 0x1257a240,
    0x4e1a8302, 0xbae07fff, 0x528246e7, 0x8e57140e, 0x3373f7bf, 0x8c9f8188, 0xa6fc4ee8, 0xc982b5a5,
    0xa8c01db7, 0x579fc264, 0x67094f31, 0xf2bd3f5f, 0x40fff7c1, 0x1fb78dfc, 0x8e6bd2c1, 0x437be59b,
    0x99b03dbf, 0xb5dbc64b, 0x638dc0e6, 0x55819d99, 0xa197c81c, 0x4a012d6e, 0xc5884a28, 0xccc36f71,
    0xb843c213, 0x6c0743f1, 0x8309893c, 0x0feddd5f, 0x2f7fe850, 0xd7c07f7e, 0x02507fbf, 0x5afb9a04,
    0xa747d2d0, 0x1651192e, 0xaf70bf3e, 0x58c31380, 0x5f98302e, 0x727cc3c4, 0x0a0fb402, 0x0f7fef82,
    0x8c96fdad, 0x5d2c2aae, 0x8ee99a49, 0x50da88b8, 0x8427f4a0, 0x1eac5790, 0x796fb449, 0x8252dc15,
    0xefbd7d9b, 0xa672597d, 0xada840d8, 0x45f54504, 0xfa5d7403, 0xe83ec305, 0x4f91751a, 0x925669c2,
    0x23efe941, 0xa903f12e, 0x60270df2, 0x0276e4b6, 0x94fd6574, 0x927985b2, 0x8276dbcb, 0x02778176,
    0xf8af918d, 0x4e48f79e, 0x8f616ddf, 0xe29d840e, 0x842f7d83, 0x340ce5c8, 0x96bbb682, 0x93b4b148,
    0xef303cab, 0x984faf28, 0x779faf9b, 0x92dc560d, 0x224d1e20, 0x8437aa88, 0x7d29dc96, 0x2756d3dc,
    0x8b907cee, 0xb51fd240, 0xe7c07ce3, 0xe566b4a1, 0xc3e9615e, 0x3cf8209d, 0x6094d1e3, 0xcd9ca341,
    0x5c76460e, 0x00ea983b, 0xd4d67881, 0xfd47572c, 0xf76cedd9, 0xbda8229c, 0x127dadaa, 0x438a074e,
    0x1f97c090, 0x081bdb8a, 0x93a07ebe, 0xb938ca15, 0x97b03cff, 0x3dc2c0f8, 0x8d1ab2ec, 0x64380e51,
    0x68cc7bfb, 0xd90f2788, 0x12490181, 0x5de5ffd4, 0xdd7ef86a, 0x76a2e214, 0xb9a40368, 0x925d958f,
    0x4b39fffa, 0xba39aee9, 0xa4ffd30b, 0xfaf7933b, 0x6d498623, 0x193cbcfa, 0x27627545, 0x825cf47a,
    0x61bd8ba0, 0xd11e42d1, 0xcead04f4, 0x127ea392, 0x10428db7, 0x8272a972, 0x9270c4a8, 0x127de50b,
    0x285ba1c8, 0x3c62f44f, 0x35c0eaa5, 0xe805d231, 0x428929fb, 0xb4fcdf82, 0x4fb66a53, 0x0e7dc15b,
    0x1f081fab, 0x108618ae, 0xfcfd086d, 0xf9ff2889, 0x694bcc11, 0x236a5cae, 0x12deca4d, 0x2c3f8cc5,
    0xd2d02dfe, 0xf8ef5896, 0xe4cf52da, 0x95155b67, 0x494a488c, 0xb9b6a80c, 0x5c8f82bc, 0x89d36b45,
    0x3a609437, 0xec00c9a9, 0x44715253, 0x0a874b49, 0xd773bc40, 0x7c34671c, 0x02717ef6, 0x4feb5536,
    0xa2d02fff, 0xd2bf60c4, 0xd43f03c0, 0x50b4ef6d, 0x07478cd1, 0x006e1888, 0xa2e53f55, 0xb9e6d4bc,
    0xa2048016, 0x97573833, 0xd7207d67, 0xde0f8f3d, 0x72f87b33, 0xabcc4f33, 0x7688c55d, 0x7b00a6b0,
    0x947b0001, 0x570075d2, 0xf9bb88f8, 0x8942019e, 0x4264a5ff, 0x856302e0, 0x72dbd92b, 0xee971b69,
    0x6ea22fde, 0x5f08ae2b, 0xaf7a616d, 0xe5c98767, 0xcf1febd2, 0x61efc8c2, 0xf1ac2571, 0xcc8239c2,
    0x67214cb8, 0xb1e583d1, 0xb7dc3e62, 0x7f10bdce, 0xf90a5c38, 0x0ff0443d, 0x606e6dc6, 0x60543a49,
    0x5727c148, 0x2be98a1d, 0x8ab41738, 0x20e1be24, 0xaf96da0f, 0x68458425, 0x99833be5, 0x600d457d,
    0x282f9350, 0x8334b362, 0xd91d1120, 0x2b6d8da0, 0x642b1e31, 0x9c305a00, 0x52bce688, 0x1b03588a,
    0xf7baefd5, 0x4142ed9c, 0xa4315c11, 0x83323ec5, 0xdfef4636, 0xa133c501, 0xe9d3531c, 0xee353783);

  sBox[3] = new Array(
    0x9db30420, 0x1fb6e9de, 0xa7be7bef, 0xd273a298, 0x4a4f7bdb, 0x64ad8c57, 0x85510443, 0xfa020ed1,
    0x7e287aff, 0xe60fb663, 0x095f35a1, 0x79ebf120, 0xfd059d43, 0x6497b7b1, 0xf3641f63, 0x241e4adf,
    0x28147f5f, 0x4fa2b8cd, 0xc9430040, 0x0cc32220, 0xfdd30b30, 0xc0a5374f, 0x1d2d00d9, 0x24147b15,
    0xee4d111a, 0x0fca5167, 0x71ff904c, 0x2d195ffe, 0x1a05645f, 0x0c13fefe, 0x081b08ca, 0x05170121,
    0x80530100, 0xe83e5efe, 0xac9af4f8, 0x7fe72701, 0xd2b8ee5f, 0x06df4261, 0xbb9e9b8a, 0x7293ea25,
    0xce84ffdf, 0xf5718801, 0x3dd64b04, 0xa26f263b, 0x7ed48400, 0x547eebe6, 0x446d4ca0, 0x6cf3d6f5,
    0x2649abdf, 0xaea0c7f5, 0x36338cc1, 0x503f7e93, 0xd3772061, 0x11b638e1, 0x72500e03, 0xf80eb2bb,
    0xabe0502e, 0xec8d77de, 0x57971e81, 0xe14f6746, 0xc9335400, 0x6920318f, 0x081dbb99, 0xffc304a5,
    0x4d351805, 0x7f3d5ce3, 0xa6c866c6, 0x5d5bcca9, 0xdaec6fea, 0x9f926f91, 0x9f46222f, 0x3991467d,
    0xa5bf6d8e, 0x1143c44f, 0x43958302, 0xd0214eeb, 0x022083b8, 0x3fb6180c, 0x18f8931e, 0x281658e6,
    0x26486e3e, 0x8bd78a70, 0x7477e4c1, 0xb506e07c, 0xf32d0a25, 0x79098b02, 0xe4eabb81, 0x28123b23,
    0x69dead38, 0x1574ca16, 0xdf871b62, 0x211c40b7, 0xa51a9ef9, 0x0014377b, 0x041e8ac8, 0x09114003,
    0xbd59e4d2, 0xe3d156d5, 0x4fe876d5, 0x2f91a340, 0x557be8de, 0x00eae4a7, 0x0ce5c2ec, 0x4db4bba6,
    0xe756bdff, 0xdd3369ac, 0xec17b035, 0x06572327, 0x99afc8b0, 0x56c8c391, 0x6b65811c, 0x5e146119,
    0x6e85cb75, 0xbe07c002, 0xc2325577, 0x893ff4ec, 0x5bbfc92d, 0xd0ec3b25, 0xb7801ab7, 0x8d6d3b24,
    0x20c763ef, 0xc366a5fc, 0x9c382880, 0x0ace3205, 0xaac9548a, 0xeca1d7c7, 0x041afa32, 0x1d16625a,
    0x6701902c, 0x9b757a54, 0x31d477f7, 0x9126b031, 0x36cc6fdb, 0xc70b8b46, 0xd9e66a48, 0x56e55a79,
    0x026a4ceb, 0x52437eff, 0x2f8f76b4, 0x0df980a5, 0x8674cde3, 0xedda04eb, 0x17a9be04, 0x2c18f4df,
    0xb7747f9d, 0xab2af7b4, 0xefc34d20, 0x2e096b7c, 0x1741a254, 0xe5b6a035, 0x213d42f6, 0x2c1c7c26,
    0x61c2f50f, 0x6552daf9, 0xd2c231f8, 0x25130f69, 0xd8167fa2, 0x0418f2c8, 0x001a96a6, 0x0d1526ab,
    0x63315c21, 0x5e0a72ec, 0x49bafefd, 0x187908d9, 0x8d0dbd86, 0x311170a7, 0x3e9b640c, 0xcc3e10d7,
    0xd5cad3b6, 0x0caec388, 0xf73001e1, 0x6c728aff, 0x71eae2a1, 0x1f9af36e, 0xcfcbd12f, 0xc1de8417,
    0xac07be6b, 0xcb44a1d8, 0x8b9b0f56, 0x013988c3, 0xb1c52fca, 0xb4be31cd, 0xd8782806, 0x12a3a4e2,
    0x6f7de532, 0x58fd7eb6, 0xd01ee900, 0x24adffc2, 0xf4990fc5, 0x9711aac5, 0x001d7b95, 0x82e5e7d2,
    0x109873f6, 0x00613096, 0xc32d9521, 0xada121ff, 0x29908415, 0x7fbb977f, 0xaf9eb3db, 0x29c9ed2a,
    0x5ce2a465, 0xa730f32c, 0xd0aa3fe8, 0x8a5cc091, 0xd49e2ce7, 0x0ce454a9, 0xd60acd86, 0x015f1919,
    0x77079103, 0xdea03af6, 0x78a8565e, 0xdee356df, 0x21f05cbe, 0x8b75e387, 0xb3c50651, 0xb8a5c3ef,
    0xd8eeb6d2, 0xe523be77, 0xc2154529, 0x2f69efdf, 0xafe67afb, 0xf470c4b2, 0xf3e0eb5b, 0xd6cc9876,
    0x39e4460c, 0x1fda8538, 0x1987832f, 0xca007367, 0xa99144f8, 0x296b299e, 0x492fc295, 0x9266beab,
    0xb5676e69, 0x9bd3ddda, 0xdf7e052f, 0xdb25701c, 0x1b5e51ee, 0xf65324e6, 0x6afce36c, 0x0316cc04,
    0x8644213e, 0xb7dc59d0, 0x7965291f, 0xccd6fd43, 0x41823979, 0x932bcdf6, 0xb657c34d, 0x4edfd282,
    0x7ae5290c, 0x3cb9536b, 0x851e20fe, 0x9833557e, 0x13ecf0b0, 0xd3ffb372, 0x3f85c5c1, 0x0aef7ed2);

  sBox[4] = new Array(
    0x7ec90c04, 0x2c6e74b9, 0x9b0e66df, 0xa6337911, 0xb86a7fff, 0x1dd358f5, 0x44dd9d44, 0x1731167f,
    0x08fbf1fa, 0xe7f511cc, 0xd2051b00, 0x735aba00, 0x2ab722d8, 0x386381cb, 0xacf6243a, 0x69befd7a,
    0xe6a2e77f, 0xf0c720cd, 0xc4494816, 0xccf5c180, 0x38851640, 0x15b0a848, 0xe68b18cb, 0x4caadeff,
    0x5f480a01, 0x0412b2aa, 0x259814fc, 0x41d0efe2, 0x4e40b48d, 0x248eb6fb, 0x8dba1cfe, 0x41a99b02,
    0x1a550a04, 0xba8f65cb, 0x7251f4e7, 0x95a51725, 0xc106ecd7, 0x97a5980a, 0xc539b9aa, 0x4d79fe6a,
    0xf2f3f763, 0x68af8040, 0xed0c9e56, 0x11b4958b, 0xe1eb5a88, 0x8709e6b0, 0xd7e07156, 0x4e29fea7,
    0x6366e52d, 0x02d1c000, 0xc4ac8e05, 0x9377f571, 0x0c05372a, 0x578535f2, 0x2261be02, 0xd642a0c9,
    0xdf13a280, 0x74b55bd2, 0x682199c0, 0xd421e5ec, 0x53fb3ce8, 0xc8adedb3, 0x28a87fc9, 0x3d959981,
    0x5c1ff900, 0xfe38d399, 0x0c4eff0b, 0x062407ea, 0xaa2f4fb1, 0x4fb96976, 0x90c79505, 0xb0a8a774,
    0xef55a1ff, 0xe59ca2c2, 0xa6b62d27, 0xe66a4263, 0xdf65001f, 0x0ec50966, 0xdfdd55bc, 0x29de0655,
    0x911e739a, 0x17af8975, 0x32c7911c, 0x89f89468, 0x0d01e980, 0x524755f4, 0x03b63cc9, 0x0cc844b2,
    0xbcf3f0aa, 0x87ac36e9, 0xe53a7426, 0x01b3d82b, 0x1a9e7449, 0x64ee2d7e, 0xcddbb1da, 0x01c94910,
    0xb868bf80, 0x0d26f3fd, 0x9342ede7, 0x04a5c284, 0x636737b6, 0x50f5b616, 0xf24766e3, 0x8eca36c1,
    0x136e05db, 0xfef18391, 0xfb887a37, 0xd6e7f7d4, 0xc7fb7dc9, 0x3063fcdf, 0xb6f589de, 0xec2941da,
    0x26e46695, 0xb7566419, 0xf654efc5, 0xd08d58b7, 0x48925401, 0xc1bacb7f, 0xe5ff550f, 0xb6083049,
    0x5bb5d0e8, 0x87d72e5a, 0xab6a6ee1, 0x223a66ce, 0xc62bf3cd, 0x9e0885f9, 0x68cb3e47, 0x086c010f,
    0xa21de820, 0xd18b69de, 0xf3f65777, 0xfa02c3f6, 0x407edac3, 0xcbb3d550, 0x1793084d, 0xb0d70eba,
    0x0ab378d5, 0xd951fb0c, 0xded7da56, 0x4124bbe4, 0x94ca0b56, 0x0f5755d1, 0xe0e1e56e, 0x6184b5be,
    0x580a249f, 0x94f74bc0, 0xe327888e, 0x9f7b5561, 0xc3dc0280, 0x05687715, 0x646c6bd7, 0x44904db3,
    0x66b4f0a3, 0xc0f1648a, 0x697ed5af, 0x49e92ff6, 0x309e374f, 0x2cb6356a, 0x85808573, 0x4991f840,
    0x76f0ae02, 0x083be84d, 0x28421c9a, 0x44489406, 0x736e4cb8, 0xc1092910, 0x8bc95fc6, 0x7d869cf4,
    0x134f616f, 0x2e77118d, 0xb31b2be1, 0xaa90b472, 0x3ca5d717, 0x7d161bba, 0x9cad9010, 0xaf462ba2,
    0x9fe459d2, 0x45d34559, 0xd9f2da13, 0xdbc65487, 0xf3e4f94e, 0x176d486f, 0x097c13ea, 0x631da5c7,
    0x445f7382, 0x175683f4, 0xcdc66a97, 0x70be0288, 0xb3cdcf72, 0x6e5dd2f3, 0x20936079, 0x459b80a5,
    0xbe60e2db, 0xa9c23101, 0xeba5315c, 0x224e42f2, 0x1c5c1572, 0xf6721b2c, 0x1ad2fff3, 0x8c25404e,
    0x324ed72f, 0x4067b7fd, 0x0523138e, 0x5ca3bc78, 0xdc0fd66e, 0x75922283, 0x784d6b17, 0x58ebb16e,
    0x44094f85, 0x3f481d87, 0xfcfeae7b, 0x77b5ff76, 0x8c2302bf, 0xaaf47556, 0x5f46b02a, 0x2b092801,
    0x3d38f5f7, 0x0ca81f36, 0x52af4a8a, 0x66d5e7c0, 0xdf3b0874, 0x95055110, 0x1b5ad7a8, 0xf61ed5ad,
    0x6cf6e479, 0x20758184, 0xd0cefa65, 0x88f7be58, 0x4a046826, 0x0ff6f8f3, 0xa09c7f70, 0x5346aba0,
    0x5ce96c28, 0xe176eda3, 0x6bac307f, 0x376829d2, 0x85360fa9, 0x17e3fe2a, 0x24b79767, 0xf5a96b20,
    0xd6cd2595, 0x68ff1ebf, 0x7555442c, 0xf19f06be, 0xf9e0659a, 0xeeb9491d, 0x34010718, 0xbb30cab8,
    0xe822fe15, 0x88570983, 0x750e6249, 0xda627e55, 0x5e76ffa8, 0xb1534546, 0x6d47de08, 0xefe9e7d4);

  sBox[5] = new Array(
    0xf6fa8f9d, 0x2cac6ce1, 0x4ca34867, 0xe2337f7c, 0x95db08e7, 0x016843b4, 0xeced5cbc, 0x325553ac,
    0xbf9f0960, 0xdfa1e2ed, 0x83f0579d, 0x63ed86b9, 0x1ab6a6b8, 0xde5ebe39, 0xf38ff732, 0x8989b138,
    0x33f14961, 0xc01937bd, 0xf506c6da, 0xe4625e7e, 0xa308ea99, 0x4e23e33c, 0x79cbd7cc, 0x48a14367,
    0xa3149619, 0xfec94bd5, 0xa114174a, 0xeaa01866, 0xa084db2d, 0x09a8486f, 0xa888614a, 0x2900af98,
    0x01665991, 0xe1992863, 0xc8f30c60, 0x2e78ef3c, 0xd0d51932, 0xcf0fec14, 0xf7ca07d2, 0xd0a82072,
    0xfd41197e, 0x9305a6b0, 0xe86be3da, 0x74bed3cd, 0x372da53c, 0x4c7f4448, 0xdab5d440, 0x6dba0ec3,
    0x083919a7, 0x9fbaeed9, 0x49dbcfb0, 0x4e670c53, 0x5c3d9c01, 0x64bdb941, 0x2c0e636a, 0xba7dd9cd,
    0xea6f7388, 0xe70bc762, 0x35f29adb, 0x5c4cdd8d, 0xf0d48d8c, 0xb88153e2, 0x08a19866, 0x1ae2eac8,
    0x284caf89, 0xaa928223, 0x9334be53, 0x3b3a21bf, 0x16434be3, 0x9aea3906, 0xefe8c36e, 0xf890cdd9,
    0x80226dae, 0xc340a4a3, 0xdf7e9c09, 0xa694a807, 0x5b7c5ecc, 0x221db3a6, 0x9a69a02f, 0x68818a54,
    0xceb2296f, 0x53c0843a, 0xfe893655, 0x25bfe68a, 0xb4628abc, 0xcf222ebf, 0x25ac6f48, 0xa9a99387,
    0x53bddb65, 0xe76ffbe7, 0xe967fd78, 0x0ba93563, 0x8e342bc1, 0xe8a11be9, 0x4980740d, 0xc8087dfc,
    0x8de4bf99, 0xa11101a0, 0x7fd37975, 0xda5a26c0, 0xe81f994f, 0x9528cd89, 0xfd339fed, 0xb87834bf,
    0x5f04456d, 0x22258698, 0xc9c4c83b, 0x2dc156be, 0x4f628daa, 0x57f55ec5, 0xe2220abe, 0xd2916ebf,
    0x4ec75b95, 0x24f2c3c0, 0x42d15d99, 0xcd0d7fa0, 0x7b6e27ff, 0xa8dc8af0, 0x7345c106, 0xf41e232f,
    0x35162386, 0xe6ea8926, 0x3333b094, 0x157ec6f2, 0x372b74af, 0x692573e4, 0xe9a9d848, 0xf3160289,
    0x3a62ef1d, 0xa787e238, 0xf3a5f676, 0x74364853, 0x20951063, 0x4576698d, 0xb6fad407, 0x592af950,
    0x36f73523, 0x4cfb6e87, 0x7da4cec0, 0x6c152daa, 0xcb0396a8, 0xc50dfe5d, 0xfcd707ab, 0x0921c42f,
    0x89dff0bb, 0x5fe2be78, 0x448f4f33, 0x754613c9, 0x2b05d08d, 0x48b9d585, 0xdc049441, 0xc8098f9b,
    0x7dede786, 0xc39a3373, 0x42410005, 0x6a091751, 0x0ef3c8a6, 0x890072d6, 0x28207682, 0xa9a9f7be,
    0xbf32679d, 0xd45b5b75, 0xb353fd00, 0xcbb0e358, 0x830f220a, 0x1f8fb214, 0xd372cf08, 0xcc3c4a13,
    0x8cf63166, 0x061c87be, 0x88c98f88, 0x6062e397, 0x47cf8e7a, 0xb6c85283, 0x3cc2acfb, 0x3fc06976,
    0x4e8f0252, 0x64d8314d, 0xda3870e3, 0x1e665459, 0xc10908f0, 0x513021a5, 0x6c5b68b7, 0x822f8aa0,
    0x3007cd3e, 0x74719eef, 0xdc872681, 0x073340d4, 0x7e432fd9, 0x0c5ec241, 0x8809286c, 0xf592d891,
    0x08a930f6, 0x957ef305, 0xb7fbffbd, 0xc266e96f, 0x6fe4ac98, 0xb173ecc0, 0xbc60b42a, 0x953498da,
    0xfba1ae12, 0x2d4bd736, 0x0f25faab, 0xa4f3fceb, 0xe2969123, 0x257f0c3d, 0x9348af49, 0x361400bc,
    0xe8816f4a, 0x3814f200, 0xa3f94043, 0x9c7a54c2, 0xbc704f57, 0xda41e7f9, 0xc25ad33a, 0x54f4a084,
    0xb17f5505, 0x59357cbe, 0xedbd15c8, 0x7f97c5ab, 0xba5ac7b5, 0xb6f6deaf, 0x3a479c3a, 0x5302da25,
    0x653d7e6a, 0x54268d49, 0x51a477ea, 0x5017d55b, 0xd7d25d88, 0x44136c76, 0x0404a8c8, 0xb8e5a121,
    0xb81a928a, 0x60ed5869, 0x97c55b96, 0xeaec991b, 0x29935913, 0x01fdb7f1, 0x088e8dfa, 0x9ab6f6f5,
    0x3b4cbf9f, 0x4a5de3ab, 0xe6051d35, 0xa0e1d855, 0xd36b4cf1, 0xf544edeb, 0xb0e93524, 0xbebb8fbd,
    0xa2d762cf, 0x49c92f54, 0x38b5f331, 0x7128a454, 0x48392905, 0xa65b1db8, 0x851c97bd, 0xd675cf2f);

  sBox[6] = new Array(
    0x85e04019, 0x332bf567, 0x662dbfff, 0xcfc65693, 0x2a8d7f6f, 0xab9bc912, 0xde6008a1, 0x2028da1f,
    0x0227bce7, 0x4d642916, 0x18fac300, 0x50f18b82, 0x2cb2cb11, 0xb232e75c, 0x4b3695f2, 0xb28707de,
    0xa05fbcf6, 0xcd4181e9, 0xe150210c, 0xe24ef1bd, 0xb168c381, 0xfde4e789, 0x5c79b0d8, 0x1e8bfd43,
    0x4d495001, 0x38be4341, 0x913cee1d, 0x92a79c3f, 0x089766be, 0xbaeeadf4, 0x1286becf, 0xb6eacb19,
    0x2660c200, 0x7565bde4, 0x64241f7a, 0x8248dca9, 0xc3b3ad66, 0x28136086, 0x0bd8dfa8, 0x356d1cf2,
    0x107789be, 0xb3b2e9ce, 0x0502aa8f, 0x0bc0351e, 0x166bf52a, 0xeb12ff82, 0xe3486911, 0xd34d7516,
    0x4e7b3aff, 0x5f43671b, 0x9cf6e037, 0x4981ac83, 0x334266ce, 0x8c9341b7, 0xd0d854c0, 0xcb3a6c88,
    0x47bc2829, 0x4725ba37, 0xa66ad22b, 0x7ad61f1e, 0x0c5cbafa, 0x4437f107, 0xb6e79962, 0x42d2d816,
    0x0a961288, 0xe1a5c06e, 0x13749e67, 0x72fc081a, 0xb1d139f7, 0xf9583745, 0xcf19df58, 0xbec3f756,
    0xc06eba30, 0x07211b24, 0x45c28829, 0xc95e317f, 0xbc8ec511, 0x38bc46e9, 0xc6e6fa14, 0xbae8584a,
    0xad4ebc46, 0x468f508b, 0x7829435f, 0xf124183b, 0x821dba9f, 0xaff60ff4, 0xea2c4e6d, 0x16e39264,
    0x92544a8b, 0x009b4fc3, 0xaba68ced, 0x9ac96f78, 0x06a5b79a, 0xb2856e6e, 0x1aec3ca9, 0xbe838688,
    0x0e0804e9, 0x55f1be56, 0xe7e5363b, 0xb3a1f25d, 0xf7debb85, 0x61fe033c, 0x16746233, 0x3c034c28,
    0xda6d0c74, 0x79aac56c, 0x3ce4e1ad, 0x51f0c802, 0x98f8f35a, 0x1626a49f, 0xeed82b29, 0x1d382fe3,
    0x0c4fb99a, 0xbb325778, 0x3ec6d97b, 0x6e77a6a9, 0xcb658b5c, 0xd45230c7, 0x2bd1408b, 0x60c03eb7,
    0xb9068d78, 0xa33754f4, 0xf430c87d, 0xc8a71302, 0xb96d8c32, 0xebd4e7be, 0xbe8b9d2d, 0x7979fb06,
    0xe7225308, 0x8b75cf77, 0x11ef8da4, 0xe083c858, 0x8d6b786f, 0x5a6317a6, 0xfa5cf7a0, 0x5dda0033,
    0xf28ebfb0, 0xf5b9c310, 0xa0eac280, 0x08b9767a, 0xa3d9d2b0, 0x79d34217, 0x021a718d, 0x9ac6336a,
    0x2711fd60, 0x438050e3, 0x069908a8, 0x3d7fedc4, 0x826d2bef, 0x4eeb8476, 0x488dcf25, 0x36c9d566,
    0x28e74e41, 0xc2610aca, 0x3d49a9cf, 0xbae3b9df, 0xb65f8de6, 0x92aeaf64, 0x3ac7d5e6, 0x9ea80509,
    0xf22b017d, 0xa4173f70, 0xdd1e16c3, 0x15e0d7f9, 0x50b1b887, 0x2b9f4fd5, 0x625aba82, 0x6a017962,
    0x2ec01b9c, 0x15488aa9, 0xd716e740, 0x40055a2c, 0x93d29a22, 0xe32dbf9a, 0x058745b9, 0x3453dc1e,
    0xd699296e, 0x496cff6f, 0x1c9f4986, 0xdfe2ed07, 0xb87242d1, 0x19de7eae, 0x053e561a, 0x15ad6f8c,
    0x66626c1c, 0x7154c24c, 0xea082b2a, 0x93eb2939, 0x17dcb0f0, 0x58d4f2ae, 0x9ea294fb, 0x52cf564c,
    0x9883fe66, 0x2ec40581, 0x763953c3, 0x01d6692e, 0xd3a0c108, 0xa1e7160e, 0xe4f2dfa6, 0x693ed285,
    0x74904698, 0x4c2b0edd, 0x4f757656, 0x5d393378, 0xa132234f, 0x3d321c5d, 0xc3f5e194, 0x4b269301,
    0xc79f022f, 0x3c997e7e, 0x5e4f9504, 0x3ffafbbd, 0x76f7ad0e, 0x296693f4, 0x3d1fce6f, 0xc61e45be,
    0xd3b5ab34, 0xf72bf9b7, 0x1b0434c0, 0x4e72b567, 0x5592a33d, 0xb5229301, 0xcfd2a87f, 0x60aeb767,
    0x1814386b, 0x30bcc33d, 0x38a0c07d, 0xfd1606f2, 0xc363519b, 0x589dd390, 0x5479f8e6, 0x1cb8d647,
    0x97fd61a9, 0xea7759f4, 0x2d57539d, 0x569a58cf, 0xe84e63ad, 0x462e1b78, 0x6580f87e, 0xf3817914,
    0x91da55f4, 0x40a230f3, 0xd1988f35, 0xb6e318d2, 0x3ffa50bc, 0x3d40f021, 0xc3c0bdae, 0x4958c24c,
    0x518f36b2, 0x84b1d370, 0x0fedce83, 0x878ddada, 0xf2a279c7, 0x94e01be8, 0x90716f4b, 0x954b8aa3);

  sBox[7] = new Array(
    0xe216300d, 0xbbddfffc, 0xa7ebdabd, 0x35648095, 0x7789f8b7, 0xe6c1121b, 0x0e241600, 0x052ce8b5,
    0x11a9cfb0, 0xe5952f11, 0xece7990a, 0x9386d174, 0x2a42931c, 0x76e38111, 0xb12def3a, 0x37ddddfc,
    0xde9adeb1, 0x0a0cc32c, 0xbe197029, 0x84a00940, 0xbb243a0f, 0xb4d137cf, 0xb44e79f0, 0x049eedfd,
    0x0b15a15d, 0x480d3168, 0x8bbbde5a, 0x669ded42, 0xc7ece831, 0x3f8f95e7, 0x72df191b, 0x7580330d,
    0x94074251, 0x5c7dcdfa, 0xabbe6d63, 0xaa402164, 0xb301d40a, 0x02e7d1ca, 0x53571dae, 0x7a3182a2,
    0x12a8ddec, 0xfdaa335d, 0x176f43e8, 0x71fb46d4, 0x38129022, 0xce949ad4, 0xb84769ad, 0x965bd862,
    0x82f3d055, 0x66fb9767, 0x15b80b4e, 0x1d5b47a0, 0x4cfde06f, 0xc28ec4b8, 0x57e8726e, 0x647a78fc,
    0x99865d44, 0x608bd593, 0x6c200e03, 0x39dc5ff6, 0x5d0b00a3, 0xae63aff2, 0x7e8bd632, 0x70108c0c,
    0xbbd35049, 0x2998df04, 0x980cf42a, 0x9b6df491, 0x9e7edd53, 0x06918548, 0x58cb7e07, 0x3b74ef2e,
    0x522fffb1, 0xd24708cc, 0x1c7e27cd, 0xa4eb215b, 0x3cf1d2e2, 0x19b47a38, 0x424f7618, 0x35856039,
    0x9d17dee7, 0x27eb35e6, 0xc9aff67b, 0x36baf5b8, 0x09c467cd, 0xc18910b1, 0xe11dbf7b, 0x06cd1af8,
    0x7170c608, 0x2d5e3354, 0xd4de495a, 0x64c6d006, 0xbcc0c62c, 0x3dd00db3, 0x708f8f34, 0x77d51b42,
    0x264f620f, 0x24b8d2bf, 0x15c1b79e, 0x46a52564, 0xf8d7e54e, 0x3e378160, 0x7895cda5, 0x859c15a5,
    0xe6459788, 0xc37bc75f, 0xdb07ba0c, 0x0676a3ab, 0x7f229b1e, 0x31842e7b, 0x24259fd7, 0xf8bef472,
    0x835ffcb8, 0x6df4c1f2, 0x96f5b195, 0xfd0af0fc, 0xb0fe134c, 0xe2506d3d, 0x4f9b12ea, 0xf215f225,
    0xa223736f, 0x9fb4c428, 0x25d04979, 0x34c713f8, 0xc4618187, 0xea7a6e98, 0x7cd16efc, 0x1436876c,
    0xf1544107, 0xbedeee14, 0x56e9af27, 0xa04aa441, 0x3cf7c899, 0x92ecbae6, 0xdd67016d, 0x151682eb,
    0xa842eedf, 0xfdba60b4, 0xf1907b75, 0x20e3030f, 0x24d8c29e, 0xe139673b, 0xefa63fb8, 0x71873054,
    0xb6f2cf3b, 0x9f326442, 0xcb15a4cc, 0xb01a4504, 0xf1e47d8d, 0x844a1be5, 0xbae7dfdc, 0x42cbda70,
    0xcd7dae0a, 0x57e85b7a, 0xd53f5af6, 0x20cf4d8c, 0xcea4d428, 0x79d130a4, 0x3486ebfb, 0x33d3cddc,
    0x77853b53, 0x37effcb5, 0xc5068778, 0xe580b3e6, 0x4e68b8f4, 0xc5c8b37e, 0x0d809ea2, 0x398feb7c,
    0x132a4f94, 0x43b7950e, 0x2fee7d1c, 0x223613bd, 0xdd06caa2, 0x37df932b, 0xc4248289, 0xacf3ebc3,
    0x5715f6b7, 0xef3478dd, 0xf267616f, 0xc148cbe4, 0x9052815e, 0x5e410fab, 0xb48a2465, 0x2eda7fa4,
    0xe87b40e4, 0xe98ea084, 0x5889e9e1, 0xefd390fc, 0xdd07d35b, 0xdb485694, 0x38d7e5b2, 0x57720101,
    0x730edebc, 0x5b643113, 0x94917e4f, 0x503c2fba, 0x646f1282, 0x7523d24a, 0xe0779695, 0xf9c17a8f,
    0x7a5b2121, 0xd187b896, 0x29263a4d, 0xba510cdf, 0x81f47c9f, 0xad1163ed, 0xea7b5965, 0x1a00726e,
    0x11403092, 0x00da6d77, 0x4a0cdd61, 0xad1f4603, 0x605bdfb0, 0x9eedc364, 0x22ebe6a8, 0xcee7d28a,
    0xa0e736a0, 0x5564a6b9, 0x10853209, 0xc7eb8f37, 0x2de705ca, 0x8951570f, 0xdf09822b, 0xbd691a6c,
    0xaa12e4f2, 0x87451c0f, 0xe0f6a27a, 0x3ada4819, 0x4cf1764f, 0x0d771c2b, 0x67cdb156, 0x350d8384,
    0x5938fa0f, 0x42399ef3, 0x36997b07, 0x0e84093d, 0x4aa93e61, 0x8360d87b, 0x1fa98b0c, 0x1149382c,
    0xe97625a5, 0x0614d1b7, 0x0e25244b, 0x0c768347, 0x589e8d82, 0x0d2059d1, 0xa466bb1e, 0xf8da0a82,
    0x04f19130, 0xba6e4ec0, 0x99265164, 0x1ee7230d, 0x50b2ad80, 0xeaee6801, 0x8db2a283, 0xea8bf59e);

}
var util = require('../../util.js');

function cast5(key) {
  this.cast5 = new openpgp_symenc_cast5();
  this.cast5.setKey(util.str2bin(key));

  this.encrypt = function(block) {
    return this.cast5.encrypt(block);
  };
}

module.exports = cast5;
module.exports.blockSize = cast5.prototype.blockSize = 8;
module.exports.keySize = cast5.prototype.keySize = 16;

},{"../../util.js":95}],38:[function(require,module,exports){
//Paul Tero, July 2001
//http://www.tero.co.uk/des/
//
//Optimised for performance with large blocks by Michael Hayworth, November 2001
//http://www.netdealing.com
//
// Modified by Recurity Labs GmbH

//THIS SOFTWARE IS PROVIDED "AS IS" AND
//ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
//FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
//OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
//LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
//OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
//SUCH DAMAGE.

//des
//this takes the key, the message, and whether to encrypt or decrypt

/**
 * @module crypto/cipher/des
 */


function des(keys, message, encrypt, mode, iv, padding) {
  //declaring this locally speeds things up a bit
  var spfunction1 = new Array(0x1010400, 0, 0x10000, 0x1010404, 0x1010004, 0x10404, 0x4, 0x10000, 0x400, 0x1010400,
    0x1010404, 0x400, 0x1000404, 0x1010004, 0x1000000, 0x4, 0x404, 0x1000400, 0x1000400, 0x10400, 0x10400, 0x1010000,
    0x1010000, 0x1000404, 0x10004, 0x1000004, 0x1000004, 0x10004, 0, 0x404, 0x10404, 0x1000000, 0x10000, 0x1010404, 0x4,
    0x1010000, 0x1010400, 0x1000000, 0x1000000, 0x400, 0x1010004, 0x10000, 0x10400, 0x1000004, 0x400, 0x4, 0x1000404,
    0x10404, 0x1010404, 0x10004, 0x1010000, 0x1000404, 0x1000004, 0x404, 0x10404, 0x1010400, 0x404, 0x1000400,
    0x1000400, 0, 0x10004, 0x10400, 0, 0x1010004);
  var spfunction2 = new Array(-0x7fef7fe0, -0x7fff8000, 0x8000, 0x108020, 0x100000, 0x20, -0x7fefffe0, -0x7fff7fe0, -
    0x7fffffe0, -0x7fef7fe0, -0x7fef8000, -0x80000000, -0x7fff8000, 0x100000, 0x20, -0x7fefffe0, 0x108000, 0x100020, -
    0x7fff7fe0, 0, -0x80000000, 0x8000, 0x108020, -0x7ff00000, 0x100020, -0x7fffffe0, 0, 0x108000, 0x8020, -0x7fef8000, -
    0x7ff00000, 0x8020, 0, 0x108020, -0x7fefffe0, 0x100000, -0x7fff7fe0, -0x7ff00000, -0x7fef8000, 0x8000, -0x7ff00000, -
    0x7fff8000, 0x20, -0x7fef7fe0, 0x108020, 0x20, 0x8000, -0x80000000, 0x8020, -0x7fef8000, 0x100000, -0x7fffffe0,
    0x100020, -0x7fff7fe0, -0x7fffffe0, 0x100020, 0x108000, 0, -0x7fff8000, 0x8020, -0x80000000, -0x7fefffe0, -
    0x7fef7fe0, 0x108000);
  var spfunction3 = new Array(0x208, 0x8020200, 0, 0x8020008, 0x8000200, 0, 0x20208, 0x8000200, 0x20008, 0x8000008,
    0x8000008, 0x20000, 0x8020208, 0x20008, 0x8020000, 0x208, 0x8000000, 0x8, 0x8020200, 0x200, 0x20200, 0x8020000,
    0x8020008, 0x20208, 0x8000208, 0x20200, 0x20000, 0x8000208, 0x8, 0x8020208, 0x200, 0x8000000, 0x8020200, 0x8000000,
    0x20008, 0x208, 0x20000, 0x8020200, 0x8000200, 0, 0x200, 0x20008, 0x8020208, 0x8000200, 0x8000008, 0x200, 0,
    0x8020008, 0x8000208, 0x20000, 0x8000000, 0x8020208, 0x8, 0x20208, 0x20200, 0x8000008, 0x8020000, 0x8000208, 0x208,
    0x8020000, 0x20208, 0x8, 0x8020008, 0x20200);
  var spfunction4 = new Array(0x802001, 0x2081, 0x2081, 0x80, 0x802080, 0x800081, 0x800001, 0x2001, 0, 0x802000,
    0x802000, 0x802081, 0x81, 0, 0x800080, 0x800001, 0x1, 0x2000, 0x800000, 0x802001, 0x80, 0x800000, 0x2001, 0x2080,
    0x800081, 0x1, 0x2080, 0x800080, 0x2000, 0x802080, 0x802081, 0x81, 0x800080, 0x800001, 0x802000, 0x802081, 0x81, 0,
    0, 0x802000, 0x2080, 0x800080, 0x800081, 0x1, 0x802001, 0x2081, 0x2081, 0x80, 0x802081, 0x81, 0x1, 0x2000, 0x800001,
    0x2001, 0x802080, 0x800081, 0x2001, 0x2080, 0x800000, 0x802001, 0x80, 0x800000, 0x2000, 0x802080);
  var spfunction5 = new Array(0x100, 0x2080100, 0x2080000, 0x42000100, 0x80000, 0x100, 0x40000000, 0x2080000,
    0x40080100, 0x80000, 0x2000100, 0x40080100, 0x42000100, 0x42080000, 0x80100, 0x40000000, 0x2000000, 0x40080000,
    0x40080000, 0, 0x40000100, 0x42080100, 0x42080100, 0x2000100, 0x42080000, 0x40000100, 0, 0x42000000, 0x2080100,
    0x2000000, 0x42000000, 0x80100, 0x80000, 0x42000100, 0x100, 0x2000000, 0x40000000, 0x2080000, 0x42000100,
    0x40080100, 0x2000100, 0x40000000, 0x42080000, 0x2080100, 0x40080100, 0x100, 0x2000000, 0x42080000, 0x42080100,
    0x80100, 0x42000000, 0x42080100, 0x2080000, 0, 0x40080000, 0x42000000, 0x80100, 0x2000100, 0x40000100, 0x80000, 0,
    0x40080000, 0x2080100, 0x40000100);
  var spfunction6 = new Array(0x20000010, 0x20400000, 0x4000, 0x20404010, 0x20400000, 0x10, 0x20404010, 0x400000,
    0x20004000, 0x404010, 0x400000, 0x20000010, 0x400010, 0x20004000, 0x20000000, 0x4010, 0, 0x400010, 0x20004010,
    0x4000, 0x404000, 0x20004010, 0x10, 0x20400010, 0x20400010, 0, 0x404010, 0x20404000, 0x4010, 0x404000, 0x20404000,
    0x20000000, 0x20004000, 0x10, 0x20400010, 0x404000, 0x20404010, 0x400000, 0x4010, 0x20000010, 0x400000, 0x20004000,
    0x20000000, 0x4010, 0x20000010, 0x20404010, 0x404000, 0x20400000, 0x404010, 0x20404000, 0, 0x20400010, 0x10, 0x4000,
    0x20400000, 0x404010, 0x4000, 0x400010, 0x20004010, 0, 0x20404000, 0x20000000, 0x400010, 0x20004010);
  var spfunction7 = new Array(0x200000, 0x4200002, 0x4000802, 0, 0x800, 0x4000802, 0x200802, 0x4200800, 0x4200802,
    0x200000, 0, 0x4000002, 0x2, 0x4000000, 0x4200002, 0x802, 0x4000800, 0x200802, 0x200002, 0x4000800, 0x4000002,
    0x4200000, 0x4200800, 0x200002, 0x4200000, 0x800, 0x802, 0x4200802, 0x200800, 0x2, 0x4000000, 0x200800, 0x4000000,
    0x200800, 0x200000, 0x4000802, 0x4000802, 0x4200002, 0x4200002, 0x2, 0x200002, 0x4000000, 0x4000800, 0x200000,
    0x4200800, 0x802, 0x200802, 0x4200800, 0x802, 0x4000002, 0x4200802, 0x4200000, 0x200800, 0, 0x2, 0x4200802, 0,
    0x200802, 0x4200000, 0x800, 0x4000002, 0x4000800, 0x800, 0x200002);
  var spfunction8 = new Array(0x10001040, 0x1000, 0x40000, 0x10041040, 0x10000000, 0x10001040, 0x40, 0x10000000,
    0x40040, 0x10040000, 0x10041040, 0x41000, 0x10041000, 0x41040, 0x1000, 0x40, 0x10040000, 0x10000040, 0x10001000,
    0x1040, 0x41000, 0x40040, 0x10040040, 0x10041000, 0x1040, 0, 0, 0x10040040, 0x10000040, 0x10001000, 0x41040,
    0x40000, 0x41040, 0x40000, 0x10041000, 0x1000, 0x40, 0x10040040, 0x1000, 0x41040, 0x10001000, 0x40, 0x10000040,
    0x10040000, 0x10040040, 0x10000000, 0x40000, 0x10001040, 0, 0x10041040, 0x40040, 0x10000040, 0x10040000, 0x10001000,
    0x10001040, 0, 0x10041040, 0x41000, 0x41000, 0x1040, 0x1040, 0x40040, 0x10000000, 0x10041000);

  //create the 16 or 48 subkeys we will need
  var m = 0,
    i, j, temp, temp2, right1, right2, left, right, looping;
  var cbcleft, cbcleft2, cbcright, cbcright2;
  var endloop, loopinc;
  var len = message.length;
  var chunk = 0;
  //set up the loops for single and triple des
  var iterations = keys.length == 32 ? 3 : 9; //single or triple des
  if (iterations == 3) {
    looping = encrypt ? new Array(0, 32, 2) : new Array(30, -2, -2);
  } else {
    looping = encrypt ? new Array(0, 32, 2, 62, 30, -2, 64, 96, 2) : new Array(94, 62, -2, 32, 64, 2, 30, -2, -2);
  }

  //pad the message depending on the padding parameter
  //only add padding if encrypting - note that you need to use the same padding option for both encrypt and decrypt
  if (encrypt) {
    message = des_addPadding(message, padding);
    len = message.length;
  }

  //store the result here
  result = "";
  tempresult = "";

  if (mode == 1) { //CBC mode
    cbcleft = (iv.charCodeAt(m++) << 24) | (iv.charCodeAt(m++) << 16) | (iv.charCodeAt(m++) << 8) | iv.charCodeAt(m++);
    cbcright = (iv.charCodeAt(m++) << 24) | (iv.charCodeAt(m++) << 16) | (iv.charCodeAt(m++) << 8) | iv.charCodeAt(m++);
    m = 0;
  }

  //loop through each 64 bit chunk of the message
  while (m < len) {
    left = (message.charCodeAt(m++) << 24) | (message.charCodeAt(m++) << 16) | (message.charCodeAt(m++) << 8) | message
      .charCodeAt(m++);
    right = (message.charCodeAt(m++) << 24) | (message.charCodeAt(m++) << 16) | (message.charCodeAt(m++) << 8) |
      message.charCodeAt(m++);

    //for Cipher Block Chaining mode, xor the message with the previous result
    if (mode == 1) {
      if (encrypt) {
        left ^= cbcleft;
        right ^= cbcright;
      } else {
        cbcleft2 = cbcleft;
        cbcright2 = cbcright;
        cbcleft = left;
        cbcright = right;
      }
    }

    //first each 64 but chunk of the message must be permuted according to IP
    temp = ((left >>> 4) ^ right) & 0x0f0f0f0f;
    right ^= temp;
    left ^= (temp << 4);
    temp = ((left >>> 16) ^ right) & 0x0000ffff;
    right ^= temp;
    left ^= (temp << 16);
    temp = ((right >>> 2) ^ left) & 0x33333333;
    left ^= temp;
    right ^= (temp << 2);
    temp = ((right >>> 8) ^ left) & 0x00ff00ff;
    left ^= temp;
    right ^= (temp << 8);
    temp = ((left >>> 1) ^ right) & 0x55555555;
    right ^= temp;
    left ^= (temp << 1);

    left = ((left << 1) | (left >>> 31));
    right = ((right << 1) | (right >>> 31));

    //do this either 1 or 3 times for each chunk of the message
    for (j = 0; j < iterations; j += 3) {
      endloop = looping[j + 1];
      loopinc = looping[j + 2];
      //now go through and perform the encryption or decryption  
      for (i = looping[j]; i != endloop; i += loopinc) { //for efficiency
        right1 = right ^ keys[i];
        right2 = ((right >>> 4) | (right << 28)) ^ keys[i + 1];
        //the result is attained by passing these bytes through the S selection functions
        temp = left;
        left = right;
        right = temp ^ (spfunction2[(right1 >>> 24) & 0x3f] | spfunction4[(right1 >>> 16) & 0x3f] | spfunction6[(right1 >>>
          8) & 0x3f] | spfunction8[right1 & 0x3f] | spfunction1[(right2 >>> 24) & 0x3f] | spfunction3[(right2 >>> 16) &
          0x3f] | spfunction5[(right2 >>> 8) & 0x3f] | spfunction7[right2 & 0x3f]);
      }
      temp = left;
      left = right;
      right = temp; //unreverse left and right
    } //for either 1 or 3 iterations

    //move then each one bit to the right
    left = ((left >>> 1) | (left << 31));
    right = ((right >>> 1) | (right << 31));

    //now perform IP-1, which is IP in the opposite direction
    temp = ((left >>> 1) ^ right) & 0x55555555;
    right ^= temp;
    left ^= (temp << 1);
    temp = ((right >>> 8) ^ left) & 0x00ff00ff;
    left ^= temp;
    right ^= (temp << 8);
    temp = ((right >>> 2) ^ left) & 0x33333333;
    left ^= temp;
    right ^= (temp << 2);
    temp = ((left >>> 16) ^ right) & 0x0000ffff;
    right ^= temp;
    left ^= (temp << 16);
    temp = ((left >>> 4) ^ right) & 0x0f0f0f0f;
    right ^= temp;
    left ^= (temp << 4);

    //for Cipher Block Chaining mode, xor the message with the previous result
    if (mode == 1) {
      if (encrypt) {
        cbcleft = left;
        cbcright = right;
      } else {
        left ^= cbcleft2;
        right ^= cbcright2;
      }
    }
    tempresult += String.fromCharCode((left >>> 24), ((left >>> 16) & 0xff), ((left >>> 8) & 0xff), (left & 0xff), (
      right >>> 24), ((right >>> 16) & 0xff), ((right >>> 8) & 0xff), (right & 0xff));

    chunk += 8;
    if (chunk == 512) {
      result += tempresult;
      tempresult = "";
      chunk = 0;
    }
  } //for every 8 characters, or 64 bits in the message

  //return the result as an array
  result += tempresult;

  //only remove padding if decrypting - note that you need to use the same padding option for both encrypt and decrypt
  if (!encrypt) {
    result = des_removePadding(result, padding);
  }

  return result;
} //end of des



//des_createKeys
//this takes as input a 64 bit key (even though only 56 bits are used)
//as an array of 2 integers, and returns 16 48 bit keys

function des_createKeys(key) {
  //declaring this locally speeds things up a bit
  pc2bytes0 = new Array(0, 0x4, 0x20000000, 0x20000004, 0x10000, 0x10004, 0x20010000, 0x20010004, 0x200, 0x204,
    0x20000200, 0x20000204, 0x10200, 0x10204, 0x20010200, 0x20010204);
  pc2bytes1 = new Array(0, 0x1, 0x100000, 0x100001, 0x4000000, 0x4000001, 0x4100000, 0x4100001, 0x100, 0x101, 0x100100,
    0x100101, 0x4000100, 0x4000101, 0x4100100, 0x4100101);
  pc2bytes2 = new Array(0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808, 0, 0x8, 0x800, 0x808,
    0x1000000, 0x1000008, 0x1000800, 0x1000808);
  pc2bytes3 = new Array(0, 0x200000, 0x8000000, 0x8200000, 0x2000, 0x202000, 0x8002000, 0x8202000, 0x20000, 0x220000,
    0x8020000, 0x8220000, 0x22000, 0x222000, 0x8022000, 0x8222000);
  pc2bytes4 = new Array(0, 0x40000, 0x10, 0x40010, 0, 0x40000, 0x10, 0x40010, 0x1000, 0x41000, 0x1010, 0x41010, 0x1000,
    0x41000, 0x1010, 0x41010);
  pc2bytes5 = new Array(0, 0x400, 0x20, 0x420, 0, 0x400, 0x20, 0x420, 0x2000000, 0x2000400, 0x2000020, 0x2000420,
    0x2000000, 0x2000400, 0x2000020, 0x2000420);
  pc2bytes6 = new Array(0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002, 0, 0x10000000,
    0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002);
  pc2bytes7 = new Array(0, 0x10000, 0x800, 0x10800, 0x20000000, 0x20010000, 0x20000800, 0x20010800, 0x20000, 0x30000,
    0x20800, 0x30800, 0x20020000, 0x20030000, 0x20020800, 0x20030800);
  pc2bytes8 = new Array(0, 0x40000, 0, 0x40000, 0x2, 0x40002, 0x2, 0x40002, 0x2000000, 0x2040000, 0x2000000, 0x2040000,
    0x2000002, 0x2040002, 0x2000002, 0x2040002);
  pc2bytes9 = new Array(0, 0x10000000, 0x8, 0x10000008, 0, 0x10000000, 0x8, 0x10000008, 0x400, 0x10000400, 0x408,
    0x10000408, 0x400, 0x10000400, 0x408, 0x10000408);
  pc2bytes10 = new Array(0, 0x20, 0, 0x20, 0x100000, 0x100020, 0x100000, 0x100020, 0x2000, 0x2020, 0x2000, 0x2020,
    0x102000, 0x102020, 0x102000, 0x102020);
  pc2bytes11 = new Array(0, 0x1000000, 0x200, 0x1000200, 0x200000, 0x1200000, 0x200200, 0x1200200, 0x4000000, 0x5000000,
    0x4000200, 0x5000200, 0x4200000, 0x5200000, 0x4200200, 0x5200200);
  pc2bytes12 = new Array(0, 0x1000, 0x8000000, 0x8001000, 0x80000, 0x81000, 0x8080000, 0x8081000, 0x10, 0x1010,
    0x8000010, 0x8001010, 0x80010, 0x81010, 0x8080010, 0x8081010);
  pc2bytes13 = new Array(0, 0x4, 0x100, 0x104, 0, 0x4, 0x100, 0x104, 0x1, 0x5, 0x101, 0x105, 0x1, 0x5, 0x101, 0x105);

  //how many iterations (1 for des, 3 for triple des)
  var iterations = key.length > 8 ? 3 : 1; //changed by Paul 16/6/2007 to use Triple DES for 9+ byte keys
  //stores the return keys
  var keys = new Array(32 * iterations);
  //now define the left shifts which need to be done
  var shifts = new Array(0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0);
  //other variables
  var lefttemp, righttemp, m = 0,
    n = 0,
    temp;

  for (var j = 0; j < iterations; j++) { //either 1 or 3 iterations
    left = (key.charCodeAt(m++) << 24) | (key.charCodeAt(m++) << 16) | (key.charCodeAt(m++) << 8) | key.charCodeAt(m++);
    right = (key.charCodeAt(m++) << 24) | (key.charCodeAt(m++) << 16) | (key.charCodeAt(m++) << 8) | key.charCodeAt(m++);

    temp = ((left >>> 4) ^ right) & 0x0f0f0f0f;
    right ^= temp;
    left ^= (temp << 4);
    temp = ((right >>> -16) ^ left) & 0x0000ffff;
    left ^= temp;
    right ^= (temp << -16);
    temp = ((left >>> 2) ^ right) & 0x33333333;
    right ^= temp;
    left ^= (temp << 2);
    temp = ((right >>> -16) ^ left) & 0x0000ffff;
    left ^= temp;
    right ^= (temp << -16);
    temp = ((left >>> 1) ^ right) & 0x55555555;
    right ^= temp;
    left ^= (temp << 1);
    temp = ((right >>> 8) ^ left) & 0x00ff00ff;
    left ^= temp;
    right ^= (temp << 8);
    temp = ((left >>> 1) ^ right) & 0x55555555;
    right ^= temp;
    left ^= (temp << 1);

    //the right side needs to be shifted and to get the last four bits of the left side
    temp = (left << 8) | ((right >>> 20) & 0x000000f0);
    //left needs to be put upside down
    left = (right << 24) | ((right << 8) & 0xff0000) | ((right >>> 8) & 0xff00) | ((right >>> 24) & 0xf0);
    right = temp;

    //now go through and perform these shifts on the left and right keys
    for (i = 0; i < shifts.length; i++) {
      //shift the keys either one or two bits to the left
      if (shifts[i]) {
        left = (left << 2) | (left >>> 26);
        right = (right << 2) | (right >>> 26);
      } else {
        left = (left << 1) | (left >>> 27);
        right = (right << 1) | (right >>> 27);
      }
      left &= -0xf;
      right &= -0xf;

      //now apply PC-2, in such a way that E is easier when encrypting or decrypting
      //this conversion will look like PC-2 except only the last 6 bits of each byte are used
      //rather than 48 consecutive bits and the order of lines will be according to 
      //how the S selection functions will be applied: S2, S4, S6, S8, S1, S3, S5, S7
      lefttemp = pc2bytes0[left >>> 28] | pc2bytes1[(left >>> 24) & 0xf] | pc2bytes2[(left >>> 20) & 0xf] | pc2bytes3[(
        left >>> 16) & 0xf] | pc2bytes4[(left >>> 12) & 0xf] | pc2bytes5[(left >>> 8) & 0xf] | pc2bytes6[(left >>> 4) &
        0xf];
      righttemp = pc2bytes7[right >>> 28] | pc2bytes8[(right >>> 24) & 0xf] | pc2bytes9[(right >>> 20) & 0xf] |
        pc2bytes10[(right >>> 16) & 0xf] | pc2bytes11[(right >>> 12) & 0xf] | pc2bytes12[(right >>> 8) & 0xf] |
        pc2bytes13[(right >>> 4) & 0xf];
      temp = ((righttemp >>> 16) ^ lefttemp) & 0x0000ffff;
      keys[n++] = lefttemp ^ temp;
      keys[n++] = righttemp ^ (temp << 16);
    }
  } //for each iterations
  //return the keys we've created
  return keys;
} //end of des_createKeys


function des_addPadding(message, padding) {
  var padLength = 8 - (message.length % 8);
  if ((padding == 2) && (padLength < 8)) { //pad the message with spaces
    message += "        ".substr(0, padLength);
  } else if (padding == 1) { //PKCS7 padding
    message += String.fromCharCode(padLength, padLength, padLength, padLength, padLength, padLength, padLength,
      padLength).substr(0, padLength);
  } else if (!padding && (padLength < 8)) { //pad the message out with null bytes
    message += "\0\0\0\0\0\0\0\0".substr(0, padLength);
  }
  return message;
}

function des_removePadding(message, padding) {
  if (padding == 2) { // space padded
    message = message.replace(/ *$/g, "");
  } else if (padding == 1) { // PKCS7
    var padCount = message.charCodeAt(message.length - 1);
    message = message.substr(0, message.length - padCount);
  } else if (!padding) { // null padding
    message = message.replace(/\0*$/g, "");
  }
  return message;
}


var util = require('../../util.js');

// added by Recurity Labs

function Des(key) {
  this.key = [];

  for (var i = 0; i < 3; i++) {
    this.key.push(key.substr(i * 8, 8));
  }

  this.encrypt = function(block) {
    return util.str2bin(des(des_createKeys(this.key[2]),
      des(des_createKeys(this.key[1]),
      des(des_createKeys(this.key[0]),
      util.bin2str(block), true, 0, null, null),
      false, 0, null, null), true, 0, null, null));
  };
}

Des.keySize = Des.prototype.keySize = 24;
Des.blockSize = Des.prototype.blockSize = 8;

// This is "original" DES - Des is actually Triple DES.
// This is only exported so we can unit test.

function OriginalDes(key) {
  this.key = key;

  this.encrypt = function(block, padding) {
    var keys = des_createKeys(this.key);
    return util.str2bin(des(keys, util.bin2str(block), true, 0, null, padding));
  };

  this.decrypt = function(block, padding) {
    var keys = des_createKeys(this.key);
    return util.str2bin(des(keys, util.bin2str(block), false, 0, null, padding));
  };
}

module.exports = {
  /** @static */
  des: Des,
  /** @static */
  originalDes: OriginalDes
};

},{"../../util.js":95}],39:[function(require,module,exports){
/**
 * @requires crypto/cipher/aes
 * @requires crypto/cipher/blowfish
 * @requires crypto/cipher/cast5
 * @requires crypto/cipher/twofish
 * @module crypto/cipher
 */

var desModule = require('./des.js');

module.exports = {
  /** @see module:crypto/cipher/des.originalDes */
  des: desModule.originalDes,
  /** @see module:crypto/cipher/des.des */
  tripledes: desModule.des,
  /** @see module:crypto/cipher/cast5 */
  cast5: require('./cast5.js'),
  /** @see module:crypto/cipher/twofish */
  twofish: require('./twofish.js'),
  /** @see module:crypto/cipher/blowfish */
  blowfish: require('./blowfish.js'),
  /** Not implemented */
  idea: function() {
    throw new Error('IDEA symmetric-key algorithm not implemented');
  }
};

var aes = require('./aes.js');

for (var i in aes) {
  module.exports['aes' + i] = aes[i];
}

},{"./aes.js":35,"./blowfish.js":36,"./cast5.js":37,"./des.js":38,"./twofish.js":40}],40:[function(require,module,exports){
/* Modified by Recurity Labs GmbH 
 * 
 * Cipher.js
 * A block-cipher algorithm implementation on JavaScript
 * See Cipher.readme.txt for further information.
 *
 * Copyright(c) 2009 Atsushi Oka [ http://oka.nu/ ]
 * This script file is distributed under the LGPL
 *
 * ACKNOWLEDGMENT
 *
 *     The main subroutines are written by Michiel van Everdingen.
 * 
 *     Michiel van Everdingen
 *     http://home.versatel.nl/MAvanEverdingen/index.html
 * 
 *     All rights for these routines are reserved to Michiel van Everdingen.
 *
 */

/**
 * @module crypto/cipher/twofish
 */



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Math
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var MAXINT = 0xFFFFFFFF;

function rotw(w, n) {
  return (w << n | w >>> (32 - n)) & MAXINT;
}

function getW(a, i) {
  return a[i] | a[i + 1] << 8 | a[i + 2] << 16 | a[i + 3] << 24;
}

function setW(a, i, w) {
  a.splice(i, 4, w & 0xFF, (w >>> 8) & 0xFF, (w >>> 16) & 0xFF, (w >>> 24) & 0xFF);
}

function setWInv(a, i, w) {
  a.splice(i, 4, (w >>> 24) & 0xFF, (w >>> 16) & 0xFF, (w >>> 8) & 0xFF, w & 0xFF);
}

function getB(x, n) {
  return (x >>> (n * 8)) & 0xFF;
}

// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Twofish
// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

function createTwofish() {
  //
  var keyBytes = null;
  var dataBytes = null;
  var dataOffset = -1;
  // var dataLength = -1;
  var algorithmName = null;
  // var idx2 = -1;
  //

  algorithmName = "twofish";

  var tfsKey = [];
  var tfsM = [
    [],
    [],
    [],
    []
  ];

  function tfsInit(key) {
    keyBytes = key;
    var i, a, b, c, d, meKey = [],
      moKey = [],
      inKey = [];
    var kLen;
    var sKey = [];
    var f01, f5b, fef;

    var q0 = [
      [8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4],
      [2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5]
    ];
    var q1 = [
      [14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13],
      [1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8]
    ];
    var q2 = [
      [11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1],
      [4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15]
    ];
    var q3 = [
      [13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10],
      [11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10]
    ];
    var ror4 = [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15];
    var ashx = [0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7];
    var q = [
      [],
      []
    ];
    var m = [
      [],
      [],
      [],
      []
    ];

    function ffm5b(x) {
      return x ^ (x >> 2) ^ [0, 90, 180, 238][x & 3];
    }

    function ffmEf(x) {
      return x ^ (x >> 1) ^ (x >> 2) ^ [0, 238, 180, 90][x & 3];
    }

    function mdsRem(p, q) {
      var i, t, u;
      for (i = 0; i < 8; i++) {
        t = q >>> 24;
        q = ((q << 8) & MAXINT) | p >>> 24;
        p = (p << 8) & MAXINT;
        u = t << 1;
        if (t & 128) {
          u ^= 333;
        }
        q ^= t ^ (u << 16);
        u ^= t >>> 1;
        if (t & 1) {
          u ^= 166;
        }
        q ^= u << 24 | u << 8;
      }
      return q;
    }

    function qp(n, x) {
      var a, b, c, d;
      a = x >> 4;
      b = x & 15;
      c = q0[n][a ^ b];
      d = q1[n][ror4[b] ^ ashx[a]];
      return q3[n][ror4[d] ^ ashx[c]] << 4 | q2[n][c ^ d];
    }

    function hFun(x, key) {
      var a = getB(x, 0),
        b = getB(x, 1),
        c = getB(x, 2),
        d = getB(x, 3);
      switch (kLen) {
        case 4:
          a = q[1][a] ^ getB(key[3], 0);
          b = q[0][b] ^ getB(key[3], 1);
          c = q[0][c] ^ getB(key[3], 2);
          d = q[1][d] ^ getB(key[3], 3);
        case 3:
          a = q[1][a] ^ getB(key[2], 0);
          b = q[1][b] ^ getB(key[2], 1);
          c = q[0][c] ^ getB(key[2], 2);
          d = q[0][d] ^ getB(key[2], 3);
        case 2:
          a = q[0][q[0][a] ^ getB(key[1], 0)] ^ getB(key[0], 0);
          b = q[0][q[1][b] ^ getB(key[1], 1)] ^ getB(key[0], 1);
          c = q[1][q[0][c] ^ getB(key[1], 2)] ^ getB(key[0], 2);
          d = q[1][q[1][d] ^ getB(key[1], 3)] ^ getB(key[0], 3);
      }
      return m[0][a] ^ m[1][b] ^ m[2][c] ^ m[3][d];
    }

    keyBytes = keyBytes.slice(0, 32);
    i = keyBytes.length;
    while (i != 16 && i != 24 && i != 32)
      keyBytes[i++] = 0;

    for (i = 0; i < keyBytes.length; i += 4) {
      inKey[i >> 2] = getW(keyBytes, i);
    }
    for (i = 0; i < 256; i++) {
      q[0][i] = qp(0, i);
      q[1][i] = qp(1, i);
    }
    for (i = 0; i < 256; i++) {
      f01 = q[1][i];
      f5b = ffm5b(f01);
      fef = ffmEf(f01);
      m[0][i] = f01 + (f5b << 8) + (fef << 16) + (fef << 24);
      m[2][i] = f5b + (fef << 8) + (f01 << 16) + (fef << 24);
      f01 = q[0][i];
      f5b = ffm5b(f01);
      fef = ffmEf(f01);
      m[1][i] = fef + (fef << 8) + (f5b << 16) + (f01 << 24);
      m[3][i] = f5b + (f01 << 8) + (fef << 16) + (f5b << 24);
    }

    kLen = inKey.length / 2;
    for (i = 0; i < kLen; i++) {
      a = inKey[i + i];
      meKey[i] = a;
      b = inKey[i + i + 1];
      moKey[i] = b;
      sKey[kLen - i - 1] = mdsRem(a, b);
    }
    for (i = 0; i < 40; i += 2) {
      a = 0x1010101 * i;
      b = a + 0x1010101;
      a = hFun(a, meKey);
      b = rotw(hFun(b, moKey), 8);
      tfsKey[i] = (a + b) & MAXINT;
      tfsKey[i + 1] = rotw(a + 2 * b, 9);
    }
    for (i = 0; i < 256; i++) {
      a = b = c = d = i;
      switch (kLen) {
        case 4:
          a = q[1][a] ^ getB(sKey[3], 0);
          b = q[0][b] ^ getB(sKey[3], 1);
          c = q[0][c] ^ getB(sKey[3], 2);
          d = q[1][d] ^ getB(sKey[3], 3);
        case 3:
          a = q[1][a] ^ getB(sKey[2], 0);
          b = q[1][b] ^ getB(sKey[2], 1);
          c = q[0][c] ^ getB(sKey[2], 2);
          d = q[0][d] ^ getB(sKey[2], 3);
        case 2:
          tfsM[0][i] = m[0][q[0][q[0][a] ^ getB(sKey[1], 0)] ^ getB(sKey[0], 0)];
          tfsM[1][i] = m[1][q[0][q[1][b] ^ getB(sKey[1], 1)] ^ getB(sKey[0], 1)];
          tfsM[2][i] = m[2][q[1][q[0][c] ^ getB(sKey[1], 2)] ^ getB(sKey[0], 2)];
          tfsM[3][i] = m[3][q[1][q[1][d] ^ getB(sKey[1], 3)] ^ getB(sKey[0], 3)];
      }
    }
  }

  function tfsG0(x) {
    return tfsM[0][getB(x, 0)] ^ tfsM[1][getB(x, 1)] ^ tfsM[2][getB(x, 2)] ^ tfsM[3][getB(x, 3)];
  }

  function tfsG1(x) {
    return tfsM[0][getB(x, 3)] ^ tfsM[1][getB(x, 0)] ^ tfsM[2][getB(x, 1)] ^ tfsM[3][getB(x, 2)];
  }

  function tfsFrnd(r, blk) {
    var a = tfsG0(blk[0]);
    var b = tfsG1(blk[1]);
    blk[2] = rotw(blk[2] ^ (a + b + tfsKey[4 * r + 8]) & MAXINT, 31);
    blk[3] = rotw(blk[3], 1) ^ (a + 2 * b + tfsKey[4 * r + 9]) & MAXINT;
    a = tfsG0(blk[2]);
    b = tfsG1(blk[3]);
    blk[0] = rotw(blk[0] ^ (a + b + tfsKey[4 * r + 10]) & MAXINT, 31);
    blk[1] = rotw(blk[1], 1) ^ (a + 2 * b + tfsKey[4 * r + 11]) & MAXINT;
  }

  function tfsIrnd(i, blk) {
    var a = tfsG0(blk[0]);
    var b = tfsG1(blk[1]);
    blk[2] = rotw(blk[2], 1) ^ (a + b + tfsKey[4 * i + 10]) & MAXINT;
    blk[3] = rotw(blk[3] ^ (a + 2 * b + tfsKey[4 * i + 11]) & MAXINT, 31);
    a = tfsG0(blk[2]);
    b = tfsG1(blk[3]);
    blk[0] = rotw(blk[0], 1) ^ (a + b + tfsKey[4 * i + 8]) & MAXINT;
    blk[1] = rotw(blk[1] ^ (a + 2 * b + tfsKey[4 * i + 9]) & MAXINT, 31);
  }

  function tfsClose() {
    tfsKey = [];
    tfsM = [
      [],
      [],
      [],
      []
    ];
  }

  function tfsEncrypt(data, offset) {
    dataBytes = data;
    dataOffset = offset;
    var blk = [getW(dataBytes, dataOffset) ^ tfsKey[0],
        getW(dataBytes, dataOffset + 4) ^ tfsKey[1],
        getW(dataBytes, dataOffset + 8) ^ tfsKey[2],
        getW(dataBytes, dataOffset + 12) ^ tfsKey[3]
    ];
    for (var j = 0; j < 8; j++) {
      tfsFrnd(j, blk);
    }
    setW(dataBytes, dataOffset, blk[2] ^ tfsKey[4]);
    setW(dataBytes, dataOffset + 4, blk[3] ^ tfsKey[5]);
    setW(dataBytes, dataOffset + 8, blk[0] ^ tfsKey[6]);
    setW(dataBytes, dataOffset + 12, blk[1] ^ tfsKey[7]);
    dataOffset += 16;
    return dataBytes;
  }

  function tfsDecrypt(data, offset) {
    dataBytes = data;
    dataOffset = offset;
    var blk = [getW(dataBytes, dataOffset) ^ tfsKey[4],
        getW(dataBytes, dataOffset + 4) ^ tfsKey[5],
        getW(dataBytes, dataOffset + 8) ^ tfsKey[6],
        getW(dataBytes, dataOffset + 12) ^ tfsKey[7]
    ];
    for (var j = 7; j >= 0; j--) {
      tfsIrnd(j, blk);
    }
    setW(dataBytes, dataOffset, blk[2] ^ tfsKey[0]);
    setW(dataBytes, dataOffset + 4, blk[3] ^ tfsKey[1]);
    setW(dataBytes, dataOffset + 8, blk[0] ^ tfsKey[2]);
    setW(dataBytes, dataOffset + 12, blk[1] ^ tfsKey[3]);
    dataOffset += 16;
  }

  // added by Recurity Labs

  function tfsFinal() {
    return dataBytes;
  }

  return {
    name: "twofish",
    blocksize: 128 / 8,
    open: tfsInit,
    close: tfsClose,
    encrypt: tfsEncrypt,
    decrypt: tfsDecrypt,
    // added by Recurity Labs
    finalize: tfsFinal
  };
}

var util = require('../../util.js');

// added by Recurity Labs

function TFencrypt(block, key) {
  var block_copy = toArray(block);
  var tf = createTwofish();
  tf.open(util.str2bin(key), 0);
  var result = tf.encrypt(block_copy, 0);
  tf.close();
  return result;
}

function TF(key) {
  this.tf = createTwofish();
  this.tf.open(util.str2bin(key), 0);

  this.encrypt = function(block) {
    return this.tf.encrypt(toArray(block), 0);
  };
}

function toArray(typedArray) {
  // Array.apply([], typedArray) does not work in PhantomJS 1.9
  var result = [];
  for (var i = 0; i < typedArray.length; i++) {
    result[i] = typedArray[i];
  }
  return result;
}


module.exports = TF;
module.exports.keySize = TF.prototype.keySize = 32;
module.exports.blockSize = TF.prototype.blockSize = 16;

},{"../../util.js":95}],41:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

// The GPG4Browsers crypto interface

/**
 * @requires crypto/cipher
 * @requires crypto/public_key
 * @requires crypto/random
 * @requires type/mpi
 * @module crypto/crypto
 */

var random = require('./random.js'),
  cipher = require('./cipher'),
  publicKey = require('./public_key'),
  type_mpi = require('../type/mpi.js'),
  BigInteger = require('./public_key/jsbn.js');


module.exports = {
  /**
   * Encrypts data using the specified public key multiprecision integers
   * and the specified algorithm.
   * @param {module:enums.publicKey} algo Algorithm to be used (See {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1})
   * @param {Array<module:type/mpi>} publicMPIs Algorithm dependent multiprecision integers
   * @param {module:type/mpi} data Data to be encrypted as MPI
   * @return {Array<module:type/mpi>} if RSA an module:type/mpi;
   * if elgamal encryption an array of two module:type/mpi is returned; otherwise null
   */
  publicKeyEncrypt: function(algo, publicMPIs, data) {
    var result = (function() {
      var m;
      switch (algo) {
        case 'rsa_encrypt':
        case 'rsa_encrypt_sign':
          var rsa = new publicKey.rsa();
          var n = publicMPIs[0].toBigInteger();
          var e = publicMPIs[1].toBigInteger();
          m = data.toBigInteger();
          return [rsa.encrypt(m, e, n)];

        case 'elgamal':
          var elgamal = new publicKey.elgamal();
          var p = publicMPIs[0].toBigInteger();
          var g = publicMPIs[1].toBigInteger();
          var y = publicMPIs[2].toBigInteger();
          m = data.toBigInteger();
          return elgamal.encrypt(m, g, p, y);

        default:
          return [];
      }
    })();

    return result.map(function(bn) {
      var mpi = new type_mpi();
      mpi.fromBigInteger(bn);
      return mpi;
    });
  },

  /**
   * Decrypts data using the specified public key multiprecision integers of the private key,
   * the specified secretMPIs of the private key and the specified algorithm.
   * @param {module:enums.publicKey} algo Algorithm to be used (See {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1})
   * @param {Array<module:type/mpi>} publicMPIs Algorithm dependent multiprecision integers
   * of the public key part of the private key
   * @param {Array<module:type/mpi>} secretMPIs Algorithm dependent multiprecision integers
   * of the private key used
   * @param {module:type/mpi} data Data to be encrypted as MPI
   * @return {module:type/mpi} returns a big integer containing the decrypted data; otherwise null
   */

  publicKeyDecrypt: function(algo, keyIntegers, dataIntegers) {
    var p;

    var bn = (function() {
      switch (algo) {
        case 'rsa_encrypt_sign':
        case 'rsa_encrypt':
          var rsa = new publicKey.rsa();
          // 0 and 1 are the public key.
          var n = keyIntegers[0].toBigInteger();
          var e = keyIntegers[1].toBigInteger();
          // 2 to 5 are the private key.
          var d = keyIntegers[2].toBigInteger();
          p = keyIntegers[3].toBigInteger();
          var q = keyIntegers[4].toBigInteger();
          var u = keyIntegers[5].toBigInteger();
          var m = dataIntegers[0].toBigInteger();
          return rsa.decrypt(m, n, e, d, p, q, u);
        case 'elgamal':
          var elgamal = new publicKey.elgamal();
          var x = keyIntegers[3].toBigInteger();
          var c1 = dataIntegers[0].toBigInteger();
          var c2 = dataIntegers[1].toBigInteger();
          p = keyIntegers[0].toBigInteger();
          return elgamal.decrypt(c1, c2, p, x);
        default:
          return null;
      }
    })();

    var result = new type_mpi();
    result.fromBigInteger(bn);
    return result;
  },

  /** Returns the number of integers comprising the private key of an algorithm
   * @param {String} algo The public key algorithm
   * @return {Integer} The number of integers.
   */
  getPrivateMpiCount: function(algo) {
    switch (algo) {
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
      case 'rsa_sign':
        //   Algorithm-Specific Fields for RSA secret keys:
        //   - multiprecision integer (MPI) of RSA secret exponent d.
        //   - MPI of RSA secret prime value p.
        //   - MPI of RSA secret prime value q (p < q).
        //   - MPI of u, the multiplicative inverse of p, mod q.
        return 4;
      case 'elgamal':
        // Algorithm-Specific Fields for Elgamal secret keys:
        //   - MPI of Elgamal secret exponent x.
        return 1;
      case 'dsa':
        // Algorithm-Specific Fields for DSA secret keys:
        //   - MPI of DSA secret exponent x.
        return 1;
      default:
        throw new Error('Unknown algorithm');
    }
  },

  getPublicMpiCount: function(algo) {
    // - A series of multiprecision integers comprising the key material:
    //   Algorithm-Specific Fields for RSA public keys:
    //       - a multiprecision integer (MPI) of RSA public modulus n;
    //       - an MPI of RSA public encryption exponent e.
    switch (algo) {
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
      case 'rsa_sign':
        return 2;

        //   Algorithm-Specific Fields for Elgamal public keys:
        //     - MPI of Elgamal prime p;
        //     - MPI of Elgamal group generator g;
        //     - MPI of Elgamal public key value y (= g**x mod p where x  is secret).
      case 'elgamal':
        return 3;

        //   Algorithm-Specific Fields for DSA public keys:
        //       - MPI of DSA prime p;
        //       - MPI of DSA group order q (q is a prime divisor of p-1);
        //       - MPI of DSA group generator g;
        //       - MPI of DSA public-key value y (= g**x mod p where x  is secret).
      case 'dsa':
        return 4;

      default:
        throw new Error('Unknown algorithm.');
    }
  },
  
  generateMpi: function(algo, bits, prng) {
    switch (algo) {
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
      case 'rsa_sign':
        //remember "publicKey" refers to the crypto/public_key dir
        var rsa = new publicKey.rsa();
        return rsa.generate(bits, "10001", prng).then(function(keyObject) {
          var output = [];
          output.push(keyObject.n);
          output.push(keyObject.ee);
          output.push(keyObject.d);
          output.push(keyObject.p);
          output.push(keyObject.q);
          output.push(keyObject.u);
          return mapResult(output);
        });
      default:
        throw new Error('Unsupported algorithm for key generation.');
    }

    function mapResult(result) {
      return result.map(function(bn) {
        var mpi = new type_mpi();
        mpi.fromBigInteger(bn);
        return mpi;
      });
    }
  },


  /**
   * generate random byte prefix as string for the specified algorithm
   * @param {module:enums.symmetric} algo Algorithm to use (see {@link http://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2})
   * @return {String} Random bytes with length equal to the block
   * size of the cipher
   */
  getPrefixRandom: function(algo) {
    return random.getRandomBytes(cipher[algo].blockSize);
  },

  /**
   * Generating a session key for the specified symmetric algorithm
   * @param {module:enums.symmetric} algo Algorithm to use (see {@link http://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2})
   * @return {String} Random bytes as a string to be used as a key
   */
  generateSessionKey: function(algo) {
    return random.getRandomBytes(cipher[algo].keySize);
  }
};

},{"../type/mpi.js":93,"./cipher":39,"./public_key":53,"./public_key/jsbn.js":54,"./random.js":56}],42:[function(require,module,exports){
/**
 * Secure Hash Algorithm with 160-bit digest (SHA-1) implementation.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2014 Digital Bazaar, Inc.
 */

var sha1 = module.exports = {};
var util = require('./forge_util.js');

// sha-1 padding bytes not initialized yet
var _padding = null;
var _initialized = false;

/**
 * Initializes the constant tables.
 */
function _init() {
  // create padding
  _padding = String.fromCharCode(128);
  _padding += util.fillString(String.fromCharCode(0x00), 64);

  // now initialized
  _initialized = true;
}

/**
 * Creates a SHA-1 message digest object.
 *
 * @return a message digest object.
 */
sha1.create = function() {
  // do initialization as necessary
  if(!_initialized) {
    _init();
  }

  // SHA-1 state contains five 32-bit integers
  var _state = null;

  // input buffer
  var _input = util.createBuffer();

  // used for word storage
  var _w = new Array(80);

  // message digest object
  var md = {
    algorithm: 'sha1',
    blockLength: 64,
    digestLength: 20,
    // 56-bit length of message so far (does not including padding)
    messageLength: 0,
    // true 64-bit message length as two 32-bit ints
    messageLength64: [0, 0]
  };

  /**
   * Starts the digest.
   *
   * @return this digest object.
   */
  md.start = function() {
    md.messageLength = 0;
    md.messageLength64 = [0, 0];
    _input = util.createBuffer();
    _state = {
      h0: 0x67452301,
      h1: 0xEFCDAB89,
      h2: 0x98BADCFE,
      h3: 0x10325476,
      h4: 0xC3D2E1F0
    };
    return md;
  };
  // start digest automatically for first time
  md.start();

  /**
   * Updates the digest with the given message input. The given input can
   * treated as raw input (no encoding will be applied) or an encoding of
   * 'utf8' maybe given to encode the input using UTF-8.
   *
   * @param msg the message input to update with.
   * @param encoding the encoding to use (default: 'raw', other: 'utf8').
   *
   * @return this digest object.
   */
  md.update = function(msg, encoding) {
    if(encoding === 'utf8') {
      msg = util.encodeUtf8(msg);
    }

    // update message length
    md.messageLength += msg.length;
    md.messageLength64[0] += (msg.length / 0x100000000) >>> 0;
    md.messageLength64[1] += msg.length >>> 0;

    // add bytes to input buffer
    _input.putBytes(msg);

    // process bytes
    _update(_state, _w, _input);

    // compact input buffer every 2K or if empty
    if(_input.read > 2048 || _input.length() === 0) {
      _input.compact();
    }

    return md;
  };

   /**
    * Produces the digest.
    *
    * @return a byte buffer containing the digest value.
    */
   md.digest = function() {
    /* Note: Here we copy the remaining bytes in the input buffer and
    add the appropriate SHA-1 padding. Then we do the final update
    on a copy of the state so that if the user wants to get
    intermediate digests they can do so. */

    /* Determine the number of bytes that must be added to the message
    to ensure its length is congruent to 448 mod 512. In other words,
    the data to be digested must be a multiple of 512 bits (or 128 bytes).
    This data includes the message, some padding, and the length of the
    message. Since the length of the message will be encoded as 8 bytes (64
    bits), that means that the last segment of the data must have 56 bytes
    (448 bits) of message and padding. Therefore, the length of the message
    plus the padding must be congruent to 448 mod 512 because
    512 - 128 = 448.
    In order to fill up the message length it must be filled with
    padding that begins with 1 bit followed by all 0 bits. Padding
    must *always* be present, so if the message length is already
    congruent to 448 mod 512, then 512 padding bits must be added. */

    // 512 bits == 64 bytes, 448 bits == 56 bytes, 64 bits = 8 bytes
    // _padding starts with 1 byte with first bit is set in it which
    // is byte value 128, then there may be up to 63 other pad bytes
    var padBytes = util.createBuffer();
    padBytes.putBytes(_input.bytes());
    // 64 - (remaining msg + 8 bytes msg length) mod 64
    padBytes.putBytes(
      _padding.substr(0, 64 - ((md.messageLength64[1] + 8) & 0x3F)));

    /* Now append length of the message. The length is appended in bits
    as a 64-bit number in big-endian order. Since we store the length in
    bytes, we must multiply the 64-bit length by 8 (or left shift by 3). */
    padBytes.putInt32(
      (md.messageLength64[0] << 3) | (md.messageLength64[0] >>> 28));
    padBytes.putInt32(md.messageLength64[1] << 3);
    var s2 = {
      h0: _state.h0,
      h1: _state.h1,
      h2: _state.h2,
      h3: _state.h3,
      h4: _state.h4
    };
    _update(s2, _w, padBytes);
    var rval = util.createBuffer();
    rval.putInt32(s2.h0);
    rval.putInt32(s2.h1);
    rval.putInt32(s2.h2);
    rval.putInt32(s2.h3);
    rval.putInt32(s2.h4);
    return rval;
  };

  return md;
};



/**
 * Updates a SHA-1 state with the given byte buffer.
 *
 * @param s the SHA-1 state to update.
 * @param w the array to use to store words.
 * @param bytes the byte buffer to update with.
 */
function _update(s, w, bytes) {
  // consume 512 bit (64 byte) chunks
  var t, a, b, c, d, e, f, i;
  var len = bytes.length();
  while(len >= 64) {
    // the w array will be populated with sixteen 32-bit big-endian words
    // and then extended into 80 32-bit words according to SHA-1 algorithm
    // and for 32-79 using Max Locktyukhin's optimization

    // initialize hash value for this chunk
    a = s.h0;
    b = s.h1;
    c = s.h2;
    d = s.h3;
    e = s.h4;

    // round 1
    for(i = 0; i < 16; ++i) {
      t = bytes.getInt32();
      w[i] = t;
      f = d ^ (b & (c ^ d));
      t = ((a << 5) | (a >>> 27)) + f + e + 0x5A827999 + t;
      e = d;
      d = c;
      c = (b << 30) | (b >>> 2);
      b = a;
      a = t;
    }
    for(; i < 20; ++i) {
      t = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]);
      t = (t << 1) | (t >>> 31);
      w[i] = t;
      f = d ^ (b & (c ^ d));
      t = ((a << 5) | (a >>> 27)) + f + e + 0x5A827999 + t;
      e = d;
      d = c;
      c = (b << 30) | (b >>> 2);
      b = a;
      a = t;
    }
    // round 2
    for(; i < 32; ++i) {
      t = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]);
      t = (t << 1) | (t >>> 31);
      w[i] = t;
      f = b ^ c ^ d;
      t = ((a << 5) | (a >>> 27)) + f + e + 0x6ED9EBA1 + t;
      e = d;
      d = c;
      c = (b << 30) | (b >>> 2);
      b = a;
      a = t;
    }
    for(; i < 40; ++i) {
      t = (w[i - 6] ^ w[i - 16] ^ w[i - 28] ^ w[i - 32]);
      t = (t << 2) | (t >>> 30);
      w[i] = t;
      f = b ^ c ^ d;
      t = ((a << 5) | (a >>> 27)) + f + e + 0x6ED9EBA1 + t;
      e = d;
      d = c;
      c = (b << 30) | (b >>> 2);
      b = a;
      a = t;
    }
    // round 3
    for(; i < 60; ++i) {
      t = (w[i - 6] ^ w[i - 16] ^ w[i - 28] ^ w[i - 32]);
      t = (t << 2) | (t >>> 30);
      w[i] = t;
      f = (b & c) | (d & (b ^ c));
      t = ((a << 5) | (a >>> 27)) + f + e + 0x8F1BBCDC + t;
      e = d;
      d = c;
      c = (b << 30) | (b >>> 2);
      b = a;
      a = t;
    }
    // round 4
    for(; i < 80; ++i) {
      t = (w[i - 6] ^ w[i - 16] ^ w[i - 28] ^ w[i - 32]);
      t = (t << 2) | (t >>> 30);
      w[i] = t;
      f = b ^ c ^ d;
      t = ((a << 5) | (a >>> 27)) + f + e + 0xCA62C1D6 + t;
      e = d;
      d = c;
      c = (b << 30) | (b >>> 2);
      b = a;
      a = t;
    }

    // update hash state
    s.h0 = (s.h0 + a) | 0;
    s.h1 = (s.h1 + b) | 0;
    s.h2 = (s.h2 + c) | 0;
    s.h3 = (s.h3 + d) | 0;
    s.h4 = (s.h4 + e) | 0;

    len -= 64;
  }
}

},{"./forge_util.js":44}],43:[function(require,module,exports){
/**
 * Secure Hash Algorithm with 256-bit digest (SHA-256) implementation.
 *
 * See FIPS 180-2 for details.
 *
 * This implementation is currently limited to message lengths (in bytes) that
 * are up to 32-bits in size.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2012 Digital Bazaar, Inc.
 */

var sha256 = module.exports = {};
var util = require('./forge_util.js');

// sha-256 padding bytes not initialized yet
var _padding = null;
var _initialized = false;

// table of constants
var _k = null;

/**
 * Initializes the constant tables.
 */
var _init = function() {
  // create padding
  _padding = String.fromCharCode(128);
  _padding += util.fillString(String.fromCharCode(0x00), 64);

  // create K table for SHA-256
  _k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  // now initialized
  _initialized = true;
};

/**
 * Updates a SHA-256 state with the given byte buffer.
 *
 * @param s the SHA-256 state to update.
 * @param w the array to use to store words.
 * @param bytes the byte buffer to update with.
 */
var _update = function(s, w, bytes) {
  // consume 512 bit (64 byte) chunks
  var t1, t2, s0, s1, ch, maj, i, a, b, c, d, e, f, g, h;
  var len = bytes.length();
  while (len >= 64) {
    // the w array will be populated with sixteen 32-bit big-endian words
    // and then extended into 64 32-bit words according to SHA-256
    for (i = 0; i < 16; ++i) {
      w[i] = bytes.getInt32();
    }
    for (; i < 64; ++i) {
      // XOR word 2 words ago rot right 17, rot right 19, shft right 10
      t1 = w[i - 2];
      t1 =
        ((t1 >>> 17) | (t1 << 15)) ^
        ((t1 >>> 19) | (t1 << 13)) ^
        (t1 >>> 10);
      // XOR word 15 words ago rot right 7, rot right 18, shft right 3
      t2 = w[i - 15];
      t2 =
        ((t2 >>> 7) | (t2 << 25)) ^
        ((t2 >>> 18) | (t2 << 14)) ^
        (t2 >>> 3);
      // sum(t1, word 7 ago, t2, word 16 ago) modulo 2^32
      w[i] = (t1 + w[i - 7] + t2 + w[i - 16]) & 0xFFFFFFFF;
    }

    // initialize hash value for this chunk
    a = s.h0;
    b = s.h1;
    c = s.h2;
    d = s.h3;
    e = s.h4;
    f = s.h5;
    g = s.h6;
    h = s.h7;

    // round function
    for (i = 0; i < 64; ++i) {
      // Sum1(e)
      s1 =
        ((e >>> 6) | (e << 26)) ^
        ((e >>> 11) | (e << 21)) ^
        ((e >>> 25) | (e << 7));
      // Ch(e, f, g) (optimized the same way as SHA-1)
      ch = g ^ (e & (f ^ g));
      // Sum0(a)
      s0 =
        ((a >>> 2) | (a << 30)) ^
        ((a >>> 13) | (a << 19)) ^
        ((a >>> 22) | (a << 10));
      // Maj(a, b, c) (optimized the same way as SHA-1)
      maj = (a & b) | (c & (a ^ b));

      // main algorithm
      t1 = h + s1 + ch + _k[i] + w[i];
      t2 = s0 + maj;
      h = g;
      g = f;
      f = e;
      e = (d + t1) & 0xFFFFFFFF;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) & 0xFFFFFFFF;
    }

    // update hash state
    s.h0 = (s.h0 + a) & 0xFFFFFFFF;
    s.h1 = (s.h1 + b) & 0xFFFFFFFF;
    s.h2 = (s.h2 + c) & 0xFFFFFFFF;
    s.h3 = (s.h3 + d) & 0xFFFFFFFF;
    s.h4 = (s.h4 + e) & 0xFFFFFFFF;
    s.h5 = (s.h5 + f) & 0xFFFFFFFF;
    s.h6 = (s.h6 + g) & 0xFFFFFFFF;
    s.h7 = (s.h7 + h) & 0xFFFFFFFF;
    len -= 64;
  }
};

/**
 * Creates a SHA-256 message digest object.
 *
 * @return a message digest object.
 */
sha256.create = function() {
  // do initialization as necessary
  if (!_initialized) {
    _init();
  }

  // SHA-256 state contains eight 32-bit integers
  var _state = null;

  // input buffer
  var _input = util.createBuffer();

  // used for word storage
  var _w = new Array(64);

  // message digest object
  var md = {
    algorithm: 'sha256',
    blockLength: 64,
    digestLength: 32,
    // length of message so far (does not including padding)
    messageLength: 0
  };

  /**
   * Starts the digest.
   *
   * @return this digest object.
   */
  md.start = function() {
    md.messageLength = 0;
    _input = util.createBuffer();
    _state = {
      h0: 0x6A09E667,
      h1: 0xBB67AE85,
      h2: 0x3C6EF372,
      h3: 0xA54FF53A,
      h4: 0x510E527F,
      h5: 0x9B05688C,
      h6: 0x1F83D9AB,
      h7: 0x5BE0CD19
    };
    return md;
  };
  // start digest automatically for first time
  md.start();

  /**
   * Updates the digest with the given message input. The given input can
   * treated as raw input (no encoding will be applied) or an encoding of
   * 'utf8' maybe given to encode the input using UTF-8.
   *
   * @param msg the message input to update with.
   * @param encoding the encoding to use (default: 'raw', other: 'utf8').
   *
   * @return this digest object.
   */
  md.update = function(msg, encoding) {
    if (encoding === 'utf8') {
      msg = util.encodeUtf8(msg);
    }

    // update message length
    md.messageLength += msg.length;

    // add bytes to input buffer
    _input.putBytes(msg);

    // process bytes
    _update(_state, _w, _input);

    // compact input buffer every 2K or if empty
    if (_input.read > 2048 || _input.length() === 0) {
      _input.compact();
    }

    return md;
  };

  /**
   * Produces the digest.
   *
   * @return a byte buffer containing the digest value.
   */
  md.digest = function() {
    /* Note: Here we copy the remaining bytes in the input buffer and
      add the appropriate SHA-256 padding. Then we do the final update
      on a copy of the state so that if the user wants to get
      intermediate digests they can do so. */

    /* Determine the number of bytes that must be added to the message
      to ensure its length is congruent to 448 mod 512. In other words,
      a 64-bit integer that gives the length of the message will be
      appended to the message and whatever the length of the message is
      plus 64 bits must be a multiple of 512. So the length of the
      message must be congruent to 448 mod 512 because 512 - 64 = 448.

      In order to fill up the message length it must be filled with
      padding that begins with 1 bit followed by all 0 bits. Padding
      must *always* be present, so if the message length is already
      congruent to 448 mod 512, then 512 padding bits must be added. */

    // 512 bits == 64 bytes, 448 bits == 56 bytes, 64 bits = 8 bytes
    // _padding starts with 1 byte with first bit is set in it which
    // is byte value 128, then there may be up to 63 other pad bytes
    var len = md.messageLength;
    var padBytes = util.createBuffer();
    padBytes.putBytes(_input.bytes());
    padBytes.putBytes(_padding.substr(0, 64 - ((len + 8) % 64)));

    /* Now append length of the message. The length is appended in bits
      as a 64-bit number in big-endian order. Since we store the length
      in bytes, we must multiply it by 8 (or left shift by 3). So here
      store the high 3 bits in the low end of the first 32-bits of the
      64-bit number and the lower 5 bits in the high end of the second
      32-bits. */
    padBytes.putInt32((len >>> 29) & 0xFF);
    padBytes.putInt32((len << 3) & 0xFFFFFFFF);
    var s2 = {
      h0: _state.h0,
      h1: _state.h1,
      h2: _state.h2,
      h3: _state.h3,
      h4: _state.h4,
      h5: _state.h5,
      h6: _state.h6,
      h7: _state.h7
    };
    _update(s2, _w, padBytes);
    var rval = util.createBuffer();
    rval.putInt32(s2.h0);
    rval.putInt32(s2.h1);
    rval.putInt32(s2.h2);
    rval.putInt32(s2.h3);
    rval.putInt32(s2.h4);
    rval.putInt32(s2.h5);
    rval.putInt32(s2.h6);
    rval.putInt32(s2.h7);
    return rval;
  };

  return md;
};
},{"./forge_util.js":44}],44:[function(require,module,exports){
/**
 * Utility functions for web applications.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2012 Digital Bazaar, Inc.
 */

/* Utilities API */
var util = module.exports = {};

// define isArray
util.isArray = Array.isArray || function(x) {
  return Object.prototype.toString.call(x) === '[object Array]';
};

// define isArrayBuffer
util.isArrayBuffer = function(x) {
  return typeof ArrayBuffer !== 'undefined' && x instanceof ArrayBuffer;
};

// define isArrayBufferView
var _arrayBufferViews = [];
if(typeof Int8Array !== 'undefined') {
  _arrayBufferViews.push(Int8Array);
}
if(typeof Uint8Array !== 'undefined') {
  _arrayBufferViews.push(Uint8Array);
}
if(typeof Uint8ClampedArray !== 'undefined') {
  _arrayBufferViews.push(Uint8ClampedArray);
}
if(typeof Int16Array !== 'undefined') {
  _arrayBufferViews.push(Int16Array);
}
if(typeof Uint16Array !== 'undefined') {
  _arrayBufferViews.push(Uint16Array);
}
if(typeof Int32Array !== 'undefined') {
  _arrayBufferViews.push(Int32Array);
}
if(typeof Uint32Array !== 'undefined') {
  _arrayBufferViews.push(Uint32Array);
}
if(typeof Float32Array !== 'undefined') {
  _arrayBufferViews.push(Float32Array);
}
if(typeof Float64Array !== 'undefined') {
  _arrayBufferViews.push(Float64Array);
}
util.isArrayBufferView = function(x) {
  for(var i = 0; i < _arrayBufferViews.length; ++i) {
    if(x instanceof _arrayBufferViews[i]) {
      return true;
    }
  }
  return false;
};

/**
 * Constructor for a byte buffer.
 *
 * @param [b] the bytes to wrap (either encoded as string, one byte per
 *          character, or as an ArrayBuffer or Typed Array).
 */
util.ByteBuffer = function(b) {
  // the data in this buffer
  this.data = '';
  // the pointer for reading from this buffer
  this.read = 0;

  if(typeof b === 'string') {
    this.data = b;
  }
  else if(util.isArrayBuffer(b) || util.isArrayBufferView(b)) {
    // convert native buffer to forge buffer
    // FIXME: support native buffers internally instead
    var arr = new Uint8Array(b);
    try {
      this.data = String.fromCharCode.apply(null, arr);
    }
    catch(e) {
      for(var i = 0; i < arr.length; ++i) {
        this.putByte(arr[i]);
      }
    }
  }
};

/**
 * Gets the number of bytes in this buffer.
 *
 * @return the number of bytes in this buffer.
 */
util.ByteBuffer.prototype.length = function() {
  return this.data.length - this.read;
};

/**
 * Gets whether or not this buffer is empty.
 *
 * @return true if this buffer is empty, false if not.
 */
util.ByteBuffer.prototype.isEmpty = function() {
  return this.length() <= 0;
};

/**
 * Puts a byte in this buffer.
 *
 * @param b the byte to put.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.putByte = function(b) {
  this.data += String.fromCharCode(b);
  return this;
};

/**
 * Puts a byte in this buffer N times.
 *
 * @param b the byte to put.
 * @param n the number of bytes of value b to put.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.fillWithByte = function(b, n) {
  b = String.fromCharCode(b);
  var d = this.data;
  while(n > 0) {
    if(n & 1) {
      d += b;
    }
    n >>>= 1;
    if(n > 0) {
      b += b;
    }
  }
  this.data = d;
  return this;
};

/**
 * Puts bytes in this buffer.
 *
 * @param bytes the bytes (as a UTF-8 encoded string) to put.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.putBytes = function(bytes) {
  this.data += bytes;
  return this;
};

/**
 * Puts a UTF-16 encoded string into this buffer.
 *
 * @param str the string to put.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.putString = function(str) {
  this.data += util.encodeUtf8(str);
  return this;
};

/**
 * Puts a 16-bit integer in this buffer in big-endian order.
 *
 * @param i the 16-bit integer.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.putInt16 = function(i) {
  this.data +=
    String.fromCharCode(i >> 8 & 0xFF) +
    String.fromCharCode(i & 0xFF);
  return this;
};

/**
 * Puts a 24-bit integer in this buffer in big-endian order.
 *
 * @param i the 24-bit integer.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.putInt24 = function(i) {
  this.data +=
    String.fromCharCode(i >> 16 & 0xFF) +
    String.fromCharCode(i >> 8 & 0xFF) +
    String.fromCharCode(i & 0xFF);
  return this;
};

/**
 * Puts a 32-bit integer in this buffer in big-endian order.
 *
 * @param i the 32-bit integer.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.putInt32 = function(i) {
  this.data +=
    String.fromCharCode(i >> 24 & 0xFF) +
    String.fromCharCode(i >> 16 & 0xFF) +
    String.fromCharCode(i >> 8 & 0xFF) +
    String.fromCharCode(i & 0xFF);
  return this;
};

/**
 * Puts a 16-bit integer in this buffer in little-endian order.
 *
 * @param i the 16-bit integer.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.putInt16Le = function(i) {
  this.data +=
    String.fromCharCode(i & 0xFF) +
    String.fromCharCode(i >> 8 & 0xFF);
  return this;
};

/**
 * Puts a 24-bit integer in this buffer in little-endian order.
 *
 * @param i the 24-bit integer.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.putInt24Le = function(i) {
  this.data +=
    String.fromCharCode(i & 0xFF) +
    String.fromCharCode(i >> 8 & 0xFF) +
    String.fromCharCode(i >> 16 & 0xFF);
  return this;
};

/**
 * Puts a 32-bit integer in this buffer in little-endian order.
 *
 * @param i the 32-bit integer.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.putInt32Le = function(i) {
  this.data +=
    String.fromCharCode(i & 0xFF) +
    String.fromCharCode(i >> 8 & 0xFF) +
    String.fromCharCode(i >> 16 & 0xFF) +
    String.fromCharCode(i >> 24 & 0xFF);
  return this;
};

/**
 * Puts an n-bit integer in this buffer in big-endian order.
 *
 * @param i the n-bit integer.
 * @param n the number of bits in the integer.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.putInt = function(i, n) {
  do {
    n -= 8;
    this.data += String.fromCharCode((i >> n) & 0xFF);
  }
  while(n > 0);
  return this;
};

/**
 * Puts a signed n-bit integer in this buffer in big-endian order. Two's
 * complement representation is used.
 *
 * @param i the n-bit integer.
 * @param n the number of bits in the integer.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.putSignedInt = function(i, n) {
  if(i < 0) {
    i += 2 << (n - 1);
  }
  return this.putInt(i, n);
};

/**
 * Puts the given buffer into this buffer.
 *
 * @param buffer the buffer to put into this one.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.putBuffer = function(buffer) {
  this.data += buffer.getBytes();
  return this;
};

/**
 * Gets a byte from this buffer and advances the read pointer by 1.
 *
 * @return the byte.
 */
util.ByteBuffer.prototype.getByte = function() {
  return this.data.charCodeAt(this.read++);
};

/**
 * Gets a uint16 from this buffer in big-endian order and advances the read
 * pointer by 2.
 *
 * @return the uint16.
 */
util.ByteBuffer.prototype.getInt16 = function() {
  var rval = (
    this.data.charCodeAt(this.read) << 8 ^
    this.data.charCodeAt(this.read + 1));
  this.read += 2;
  return rval;
};

/**
 * Gets a uint24 from this buffer in big-endian order and advances the read
 * pointer by 3.
 *
 * @return the uint24.
 */
util.ByteBuffer.prototype.getInt24 = function() {
  var rval = (
    this.data.charCodeAt(this.read) << 16 ^
    this.data.charCodeAt(this.read + 1) << 8 ^
    this.data.charCodeAt(this.read + 2));
  this.read += 3;
  return rval;
};

/**
 * Gets a uint32 from this buffer in big-endian order and advances the read
 * pointer by 4.
 *
 * @return the word.
 */
util.ByteBuffer.prototype.getInt32 = function() {
  var rval = (
    this.data.charCodeAt(this.read) << 24 ^
    this.data.charCodeAt(this.read + 1) << 16 ^
    this.data.charCodeAt(this.read + 2) << 8 ^
    this.data.charCodeAt(this.read + 3));
  this.read += 4;
  return rval;
};

/**
 * Gets a uint16 from this buffer in little-endian order and advances the read
 * pointer by 2.
 *
 * @return the uint16.
 */
util.ByteBuffer.prototype.getInt16Le = function() {
  var rval = (
    this.data.charCodeAt(this.read) ^
    this.data.charCodeAt(this.read + 1) << 8);
  this.read += 2;
  return rval;
};

/**
 * Gets a uint24 from this buffer in little-endian order and advances the read
 * pointer by 3.
 *
 * @return the uint24.
 */
util.ByteBuffer.prototype.getInt24Le = function() {
  var rval = (
    this.data.charCodeAt(this.read) ^
    this.data.charCodeAt(this.read + 1) << 8 ^
    this.data.charCodeAt(this.read + 2) << 16);
  this.read += 3;
  return rval;
};

/**
 * Gets a uint32 from this buffer in little-endian order and advances the read
 * pointer by 4.
 *
 * @return the word.
 */
util.ByteBuffer.prototype.getInt32Le = function() {
  var rval = (
    this.data.charCodeAt(this.read) ^
    this.data.charCodeAt(this.read + 1) << 8 ^
    this.data.charCodeAt(this.read + 2) << 16 ^
    this.data.charCodeAt(this.read + 3) << 24);
  this.read += 4;
  return rval;
};

/**
 * Gets an n-bit integer from this buffer in big-endian order and advances the
 * read pointer by n/8.
 *
 * @param n the number of bits in the integer.
 *
 * @return the integer.
 */
util.ByteBuffer.prototype.getInt = function(n) {
  var rval = 0;
  do {
    rval = (rval << 8) + this.data.charCodeAt(this.read++);
    n -= 8;
  }
  while(n > 0);
  return rval;
};

/**
 * Gets a signed n-bit integer from this buffer in big-endian order, using
 * two's complement, and advances the read pointer by n/8.
 *
 * @param n the number of bits in the integer.
 *
 * @return the integer.
 */
util.ByteBuffer.prototype.getSignedInt = function(n) {
  var x = this.getInt(n);
  var max = 2 << (n - 2);
  if(x >= max) {
    x -= max << 1;
  }
  return x;
};

/**
 * Reads bytes out into a UTF-8 string and clears them from the buffer.
 *
 * @param count the number of bytes to read, undefined or null for all.
 *
 * @return a UTF-8 string of bytes.
 */
util.ByteBuffer.prototype.getBytes = function(count) {
  var rval;
  if(count) {
    // read count bytes
    count = Math.min(this.length(), count);
    rval = this.data.slice(this.read, this.read + count);
    this.read += count;
  }
  else if(count === 0) {
    rval = '';
  }
  else {
    // read all bytes, optimize to only copy when needed
    rval = (this.read === 0) ? this.data : this.data.slice(this.read);
    this.clear();
  }
  return rval;
};

/**
 * Gets a UTF-8 encoded string of the bytes from this buffer without modifying
 * the read pointer.
 *
 * @param count the number of bytes to get, omit to get all.
 *
 * @return a string full of UTF-8 encoded characters.
 */
util.ByteBuffer.prototype.bytes = function(count) {
  return (typeof(count) === 'undefined' ?
    this.data.slice(this.read) :
    this.data.slice(this.read, this.read + count));
};

/**
 * Gets a byte at the given index without modifying the read pointer.
 *
 * @param i the byte index.
 *
 * @return the byte.
 */
util.ByteBuffer.prototype.at = function(i) {
  return this.data.charCodeAt(this.read + i);
};

/**
 * Puts a byte at the given index without modifying the read pointer.
 *
 * @param i the byte index.
 * @param b the byte to put.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.setAt = function(i, b) {
  this.data = this.data.substr(0, this.read + i) +
    String.fromCharCode(b) +
    this.data.substr(this.read + i + 1);
  return this;
};

/**
 * Gets the last byte without modifying the read pointer.
 *
 * @return the last byte.
 */
util.ByteBuffer.prototype.last = function() {
  return this.data.charCodeAt(this.data.length - 1);
};

/**
 * Creates a copy of this buffer.
 *
 * @return the copy.
 */
util.ByteBuffer.prototype.copy = function() {
  var c = util.createBuffer(this.data);
  c.read = this.read;
  return c;
};

/**
 * Compacts this buffer.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.compact = function() {
  if(this.read > 0) {
    this.data = this.data.slice(this.read);
    this.read = 0;
  }
  return this;
};

/**
 * Clears this buffer.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.clear = function() {
  this.data = '';
  this.read = 0;
  return this;
};

/**
 * Shortens this buffer by triming bytes off of the end of this buffer.
 *
 * @param count the number of bytes to trim off.
 *
 * @return this buffer.
 */
util.ByteBuffer.prototype.truncate = function(count) {
  var len = Math.max(0, this.length() - count);
  this.data = this.data.substr(this.read, len);
  this.read = 0;
  return this;
};

/**
 * Converts this buffer to a hexadecimal string.
 *
 * @return a hexadecimal string.
 */
util.ByteBuffer.prototype.toHex = function() {
  var rval = '';
  for(var i = this.read; i < this.data.length; ++i) {
    var b = this.data.charCodeAt(i);
    if(b < 16) {
      rval += '0';
    }
    rval += b.toString(16);
  }
  return rval;
};

/**
 * Converts this buffer to a UTF-16 string (standard JavaScript string).
 *
 * @return a UTF-16 string.
 */
util.ByteBuffer.prototype.toString = function() {
  return util.decodeUtf8(this.bytes());
};

/**
 * Creates a buffer that stores bytes. A value may be given to put into the
 * buffer that is either a string of bytes or a UTF-16 string that will
 * be encoded using UTF-8 (to do the latter, specify 'utf8' as the encoding).
 *
 * @param [input] the bytes to wrap (as a string) or a UTF-16 string to encode
 *          as UTF-8.
 * @param [encoding] (default: 'raw', other: 'utf8').
 */
util.createBuffer = function(input, encoding) {
  encoding = encoding || 'raw';
  if(input !== undefined && encoding === 'utf8') {
    input = util.encodeUtf8(input);
  }
  return new util.ByteBuffer(input);
};

/**
 * Fills a string with a particular value. If you want the string to be a byte
 * string, pass in String.fromCharCode(theByte).
 *
 * @param c the character to fill the string with, use String.fromCharCode
 *          to fill the string with a byte value.
 * @param n the number of characters of value c to fill with.
 *
 * @return the filled string.
 */
util.fillString = function(c, n) {
  var s = '';
  while(n > 0) {
    if(n & 1) {
      s += c;
    }
    n >>>= 1;
    if(n > 0) {
      c += c;
    }
  }
  return s;
};

/**
 * Performs a per byte XOR between two byte strings and returns the result as a
 * string of bytes.
 *
 * @param s1 first string of bytes.
 * @param s2 second string of bytes.
 * @param n the number of bytes to XOR.
 *
 * @return the XOR'd result.
 */
util.xorBytes = function(s1, s2, n) {
  var s3 = '';
  var b = '';
  var t = '';
  var i = 0;
  var c = 0;
  for(; n > 0; --n, ++i) {
    b = s1.charCodeAt(i) ^ s2.charCodeAt(i);
    if(c >= 10) {
      s3 += t;
      t = '';
      c = 0;
    }
    t += String.fromCharCode(b);
    ++c;
  }
  s3 += t;
  return s3;
};

/**
 * Converts a hex string into a UTF-8 string of bytes.
 *
 * @param hex the hexadecimal string to convert.
 *
 * @return the string of bytes.
 */
util.hexToBytes = function(hex) {
  var rval = '';
  var i = 0;
  if(hex.length & 1 == 1) {
    // odd number of characters, convert first character alone
    i = 1;
    rval += String.fromCharCode(parseInt(hex[0], 16));
  }
  // convert 2 characters (1 byte) at a time
  for(; i < hex.length; i += 2) {
    rval += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  return rval;
};

/**
 * Converts a UTF-8 byte string into a string of hexadecimal characters.
 *
 * @param bytes the byte string to convert.
 *
 * @return the string of hexadecimal characters.
 */
util.bytesToHex = function(bytes) {
  return util.createBuffer(bytes).toHex();
};

/**
 * Converts an 32-bit integer to 4-big-endian byte string.
 *
 * @param i the integer.
 *
 * @return the byte string.
 */
util.int32ToBytes = function(i) {
  return (
    String.fromCharCode(i >> 24 & 0xFF) +
    String.fromCharCode(i >> 16 & 0xFF) +
    String.fromCharCode(i >> 8 & 0xFF) +
    String.fromCharCode(i & 0xFF));
};

// base64 characters, reverse mapping
var _base64 =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
var _base64Idx = [
/*43 -43 = 0*/
/*'+',  1,  2,  3,'/' */
   62, -1, -1, -1, 63,

/*'0','1','2','3','4','5','6','7','8','9' */
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61,

/*15, 16, 17,'=', 19, 20, 21 */
  -1, -1, -1, 64, -1, -1, -1,

/*65 - 43 = 22*/
/*'A','B','C','D','E','F','G','H','I','J','K','L','M', */
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,

/*'N','O','P','Q','R','S','T','U','V','W','X','Y','Z' */
   13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,

/*91 - 43 = 48 */
/*48, 49, 50, 51, 52, 53 */
  -1, -1, -1, -1, -1, -1,

/*97 - 43 = 54*/
/*'a','b','c','d','e','f','g','h','i','j','k','l','m' */
   26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,

/*'n','o','p','q','r','s','t','u','v','w','x','y','z' */
   39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
];

/**
 * Base64 encodes a UTF-8 string of bytes.
 *
 * @param input the UTF-8 string of bytes to encode.
 * @param maxline the maximum number of encoded bytes per line to use,
 *          defaults to none.
 *
 * @return the base64-encoded output.
 */
util.encode64 = function(input, maxline) {
  var line = '';
  var output = '';
  var chr1, chr2, chr3;
  var i = 0;
  while(i < input.length) {
    chr1 = input.charCodeAt(i++);
    chr2 = input.charCodeAt(i++);
    chr3 = input.charCodeAt(i++);

    // encode 4 character group
    line += _base64.charAt(chr1 >> 2);
    line += _base64.charAt(((chr1 & 3) << 4) | (chr2 >> 4));
    if(isNaN(chr2)) {
      line += '==';
    }
    else {
      line += _base64.charAt(((chr2 & 15) << 2) | (chr3 >> 6));
      line += isNaN(chr3) ? '=' : _base64.charAt(chr3 & 63);
    }

    if(maxline && line.length > maxline) {
      output += line.substr(0, maxline) + '\r\n';
      line = line.substr(maxline);
    }
  }
  output += line;

  return output;
};

/**
 * Base64 decodes a string into a UTF-8 string of bytes.
 *
 * @param input the base64-encoded input.
 *
 * @return the raw bytes.
 */
util.decode64 = function(input) {
  // remove all non-base64 characters
  input = input.replace(/[^A-Za-z0-9\+\/\=]/g, '');

  var output = '';
  var enc1, enc2, enc3, enc4;
  var i = 0;

  while(i < input.length) {
    enc1 = _base64Idx[input.charCodeAt(i++) - 43];
    enc2 = _base64Idx[input.charCodeAt(i++) - 43];
    enc3 = _base64Idx[input.charCodeAt(i++) - 43];
    enc4 = _base64Idx[input.charCodeAt(i++) - 43];

    output += String.fromCharCode((enc1 << 2) | (enc2 >> 4));
    if(enc3 !== 64) {
      // decoded at least 2 bytes
      output += String.fromCharCode(((enc2 & 15) << 4) | (enc3 >> 2));
      if(enc4 !== 64) {
        // decoded 3 bytes
        output += String.fromCharCode(((enc3 & 3) << 6) | enc4);
      }
    }
  }

  return output;
};

/**
 * UTF-8 encodes the given UTF-16 encoded string (a standard JavaScript
 * string). Non-ASCII characters will be encoded as multiple bytes according
 * to UTF-8.
 *
 * @param str the string to encode.
 *
 * @return the UTF-8 encoded string.
 */
util.encodeUtf8 = function(str) {
  return unescape(encodeURIComponent(str));
};

/**
 * Decodes a UTF-8 encoded string into a UTF-16 string.
 *
 * @param str the string to encode.
 *
 * @return the UTF-16 encoded string (standard JavaScript string).
 */
util.decodeUtf8 = function(str) {
  return decodeURIComponent(escape(str));
};

},{}],45:[function(require,module,exports){
/**
 * @requires crypto/hash/sha
 * @module crypto/hash
 */
var sha = require('./sha.js'),
  forge_sha1 = require('./forge_sha1.js'),
  forge_sha256 = require('./forge_sha256.js');

module.exports = {
  /** @see module:crypto/hash/md5 */
  md5: require('./md5.js'),
  /** @see module:crypto/hash/sha.sha1 */
  sha1: sha.sha1,
  /** @see module:crypto/hash/sha.sha224 */
  sha224: sha.sha224,
  /** @see module:crypto/hash/sha.sha256 */
  sha256: sha.sha256,
  /** @see module:crypto/hash/sha.sha384 */
  sha384: sha.sha384,
  /** @see module:crypto/hash/sha.sha512 */
  sha512: sha.sha512,
  /** @see module:crypto/hash/ripe-md */
  ripemd: require('./ripe-md.js'),

  forge_sha1: forge_sha1,
  forge_sha256: forge_sha256,

  /**
   * Create a hash on the specified data using the specified algorithm
   * @param {module:enums.hash} algo Hash algorithm type (see {@link http://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @param {String} data Data to be hashed
   * @return {String} hash value
   */
  digest: function(algo, data) {
    switch (algo) {
      case 1:
        // - MD5 [HAC]
        return this.md5(data);
      case 2:
        // - SHA-1 [FIPS180]
        return this.sha1(data);
      case 3:
        // - RIPE-MD/160 [HAC]
        return this.ripemd(data);
      case 8:
        // - SHA256 [FIPS180]
        var sha256 = forge_sha256.create();
        sha256.update(data);
        return sha256.digest().getBytes();
      case 9:
        // - SHA384 [FIPS180]
        return this.sha384(data);
      case 10:
        // - SHA512 [FIPS180]
        return this.sha512(data);
      case 11:
        // - SHA224 [FIPS180]
        return this.sha224(data);
      default:
        throw new Error('Invalid hash function.');
    }
  },

  /**
   * Returns the hash size in bytes of the specified hash algorithm type
   * @param {module:enums.hash} algo Hash algorithm type (See {@link http://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @return {Integer} Size in bytes of the resulting hash
   */
  getHashByteLength: function(algo) {
    switch (algo) {
      case 1:
        // - MD5 [HAC]
        return 16;
      case 2:
        // - SHA-1 [FIPS180]
      case 3:
        // - RIPE-MD/160 [HAC]
        return 20;
      case 8:
        // - SHA256 [FIPS180]
        return 32;
      case 9:
        // - SHA384 [FIPS180]
        return 48;
      case 10:
        // - SHA512 [FIPS180]
        return 64;
      case 11:
        // - SHA224 [FIPS180]
        return 28;
      default:
        throw new Error('Invalid hash algorithm.');
    }
  }
};

},{"./forge_sha1.js":42,"./forge_sha256.js":43,"./md5.js":46,"./ripe-md.js":47,"./sha.js":48}],46:[function(require,module,exports){
/**
 * A fast MD5 JavaScript implementation
 * Copyright (c) 2012 Joseph Myers
 * http://www.myersdaily.org/joseph/javascript/md5-text.html
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purposes and without
 * fee is hereby granted provided that this copyright notice
 * appears in all copies.
 *
 * Of course, this soft is provided "as is" without express or implied
 * warranty of any kind.
 */

/**
 * @requires util
 * @module crypto/hash/md5
 */

var util = require('../../util.js');

/**
 * MD5 hash
 * @param {String} entree string to hash
 */
module.exports = function (entree) {
  var hex = md5(entree);
  var bin = util.hex2bin(hex);
  return bin;
};

function md5cycle(x, k) {
  var a = x[0],
    b = x[1],
    c = x[2],
    d = x[3];

  a = ff(a, b, c, d, k[0], 7, -680876936);
  d = ff(d, a, b, c, k[1], 12, -389564586);
  c = ff(c, d, a, b, k[2], 17, 606105819);
  b = ff(b, c, d, a, k[3], 22, -1044525330);
  a = ff(a, b, c, d, k[4], 7, -176418897);
  d = ff(d, a, b, c, k[5], 12, 1200080426);
  c = ff(c, d, a, b, k[6], 17, -1473231341);
  b = ff(b, c, d, a, k[7], 22, -45705983);
  a = ff(a, b, c, d, k[8], 7, 1770035416);
  d = ff(d, a, b, c, k[9], 12, -1958414417);
  c = ff(c, d, a, b, k[10], 17, -42063);
  b = ff(b, c, d, a, k[11], 22, -1990404162);
  a = ff(a, b, c, d, k[12], 7, 1804603682);
  d = ff(d, a, b, c, k[13], 12, -40341101);
  c = ff(c, d, a, b, k[14], 17, -1502002290);
  b = ff(b, c, d, a, k[15], 22, 1236535329);

  a = gg(a, b, c, d, k[1], 5, -165796510);
  d = gg(d, a, b, c, k[6], 9, -1069501632);
  c = gg(c, d, a, b, k[11], 14, 643717713);
  b = gg(b, c, d, a, k[0], 20, -373897302);
  a = gg(a, b, c, d, k[5], 5, -701558691);
  d = gg(d, a, b, c, k[10], 9, 38016083);
  c = gg(c, d, a, b, k[15], 14, -660478335);
  b = gg(b, c, d, a, k[4], 20, -405537848);
  a = gg(a, b, c, d, k[9], 5, 568446438);
  d = gg(d, a, b, c, k[14], 9, -1019803690);
  c = gg(c, d, a, b, k[3], 14, -187363961);
  b = gg(b, c, d, a, k[8], 20, 1163531501);
  a = gg(a, b, c, d, k[13], 5, -1444681467);
  d = gg(d, a, b, c, k[2], 9, -51403784);
  c = gg(c, d, a, b, k[7], 14, 1735328473);
  b = gg(b, c, d, a, k[12], 20, -1926607734);

  a = hh(a, b, c, d, k[5], 4, -378558);
  d = hh(d, a, b, c, k[8], 11, -2022574463);
  c = hh(c, d, a, b, k[11], 16, 1839030562);
  b = hh(b, c, d, a, k[14], 23, -35309556);
  a = hh(a, b, c, d, k[1], 4, -1530992060);
  d = hh(d, a, b, c, k[4], 11, 1272893353);
  c = hh(c, d, a, b, k[7], 16, -155497632);
  b = hh(b, c, d, a, k[10], 23, -1094730640);
  a = hh(a, b, c, d, k[13], 4, 681279174);
  d = hh(d, a, b, c, k[0], 11, -358537222);
  c = hh(c, d, a, b, k[3], 16, -722521979);
  b = hh(b, c, d, a, k[6], 23, 76029189);
  a = hh(a, b, c, d, k[9], 4, -640364487);
  d = hh(d, a, b, c, k[12], 11, -421815835);
  c = hh(c, d, a, b, k[15], 16, 530742520);
  b = hh(b, c, d, a, k[2], 23, -995338651);

  a = ii(a, b, c, d, k[0], 6, -198630844);
  d = ii(d, a, b, c, k[7], 10, 1126891415);
  c = ii(c, d, a, b, k[14], 15, -1416354905);
  b = ii(b, c, d, a, k[5], 21, -57434055);
  a = ii(a, b, c, d, k[12], 6, 1700485571);
  d = ii(d, a, b, c, k[3], 10, -1894986606);
  c = ii(c, d, a, b, k[10], 15, -1051523);
  b = ii(b, c, d, a, k[1], 21, -2054922799);
  a = ii(a, b, c, d, k[8], 6, 1873313359);
  d = ii(d, a, b, c, k[15], 10, -30611744);
  c = ii(c, d, a, b, k[6], 15, -1560198380);
  b = ii(b, c, d, a, k[13], 21, 1309151649);
  a = ii(a, b, c, d, k[4], 6, -145523070);
  d = ii(d, a, b, c, k[11], 10, -1120210379);
  c = ii(c, d, a, b, k[2], 15, 718787259);
  b = ii(b, c, d, a, k[9], 21, -343485551);

  x[0] = add32(a, x[0]);
  x[1] = add32(b, x[1]);
  x[2] = add32(c, x[2]);
  x[3] = add32(d, x[3]);

}

function cmn(q, a, b, x, s, t) {
  a = add32(add32(a, q), add32(x, t));
  return add32((a << s) | (a >>> (32 - s)), b);
}

function ff(a, b, c, d, x, s, t) {
  return cmn((b & c) | ((~b) & d), a, b, x, s, t);
}

function gg(a, b, c, d, x, s, t) {
  return cmn((b & d) | (c & (~d)), a, b, x, s, t);
}

function hh(a, b, c, d, x, s, t) {
  return cmn(b ^ c ^ d, a, b, x, s, t);
}

function ii(a, b, c, d, x, s, t) {
  return cmn(c ^ (b | (~d)), a, b, x, s, t);
}

function md51(s) {
  txt = '';
  var n = s.length,
    state = [1732584193, -271733879, -1732584194, 271733878],
    i;
  for (i = 64; i <= s.length; i += 64) {
    md5cycle(state, md5blk(s.substring(i - 64, i)));
  }
  s = s.substring(i - 64);
  var tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  for (i = 0; i < s.length; i++)
    tail[i >> 2] |= s.charCodeAt(i) << ((i % 4) << 3);
  tail[i >> 2] |= 0x80 << ((i % 4) << 3);
  if (i > 55) {
    md5cycle(state, tail);
    for (i = 0; i < 16; i++) tail[i] = 0;
  }
  tail[14] = n * 8;
  md5cycle(state, tail);
  return state;
}

/* there needs to be support for Unicode here,
 * unless we pretend that we can redefine the MD-5
 * algorithm for multi-byte characters (perhaps
 * by adding every four 16-bit characters and
 * shortening the sum to 32 bits). Otherwise
 * I suggest performing MD-5 as if every character
 * was two bytes--e.g., 0040 0025 = @%--but then
 * how will an ordinary MD-5 sum be matched?
 * There is no way to standardize text to something
 * like UTF-8 before transformation; speed cost is
 * utterly prohibitive. The JavaScript standard
 * itself needs to look at this: it should start
 * providing access to strings as preformed UTF-8
 * 8-bit unsigned value arrays.
 */
function md5blk(s) { /* I figured global was faster.   */
  var md5blks = [],
    i; /* Andy King said do it this way. */
  for (i = 0; i < 64; i += 4) {
    md5blks[i >> 2] = s.charCodeAt(i) + (s.charCodeAt(i + 1) << 8) + (s.charCodeAt(i + 2) << 16) + (s.charCodeAt(i + 3) <<
      24);
  }
  return md5blks;
}

var hex_chr = '0123456789abcdef'.split('');

function rhex(n) {
  var s = '',
    j = 0;
  for (; j < 4; j++)
    s += hex_chr[(n >> (j * 8 + 4)) & 0x0F] + hex_chr[(n >> (j * 8)) & 0x0F];
  return s;
}

function hex(x) {
  for (var i = 0; i < x.length; i++)
    x[i] = rhex(x[i]);
  return x.join('');
}

function md5(s) {
  return hex(md51(s));
}

/* this function is much faster,
so if possible we use it. Some IEs
are the only ones I know of that
need the idiotic second function,
generated by an if clause.  */

function add32(a, b) {
  return (a + b) & 0xFFFFFFFF;
}

if (md5('hello') != '5d41402abc4b2a76b9719d911017c592') {
  function add32(x, y) {
    var lsw = (x & 0xFFFF) + (y & 0xFFFF),
      msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
  }
}

},{"../../util.js":95}],47:[function(require,module,exports){
/*
 * CryptoMX Tools
 * Copyright (C) 2004 - 2006 Derek Buitenhuis
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* Modified by Recurity Labs GmbH
 */

/**
 * @module crypto/hash/ripe-md
 */

var RMDsize = 160;
var X = [];

function ROL(x, n) {
  return new Number((x << n) | (x >>> (32 - n)));
}

function F(x, y, z) {
  return new Number(x ^ y ^ z);
}

function G(x, y, z) {
  return new Number((x & y) | (~x & z));
}

function H(x, y, z) {
  return new Number((x | ~y) ^ z);
}

function I(x, y, z) {
  return new Number((x & z) | (y & ~z));
}

function J(x, y, z) {
  return new Number(x ^ (y | ~z));
}

function mixOneRound(a, b, c, d, e, x, s, roundNumber) {
  switch (roundNumber) {
    case 0:
      a += F(b, c, d) + x + 0x00000000;
      break;
    case 1:
      a += G(b, c, d) + x + 0x5a827999;
      break;
    case 2:
      a += H(b, c, d) + x + 0x6ed9eba1;
      break;
    case 3:
      a += I(b, c, d) + x + 0x8f1bbcdc;
      break;
    case 4:
      a += J(b, c, d) + x + 0xa953fd4e;
      break;
    case 5:
      a += J(b, c, d) + x + 0x50a28be6;
      break;
    case 6:
      a += I(b, c, d) + x + 0x5c4dd124;
      break;
    case 7:
      a += H(b, c, d) + x + 0x6d703ef3;
      break;
    case 8:
      a += G(b, c, d) + x + 0x7a6d76e9;
      break;
    case 9:
      a += F(b, c, d) + x + 0x00000000;
      break;

    default:
      throw new Error("Bogus round number");
      break;
  }

  a = ROL(a, s) + e;
  c = ROL(c, 10);

  a &= 0xffffffff;
  b &= 0xffffffff;
  c &= 0xffffffff;
  d &= 0xffffffff;
  e &= 0xffffffff;

  var retBlock = [];
  retBlock[0] = a;
  retBlock[1] = b;
  retBlock[2] = c;
  retBlock[3] = d;
  retBlock[4] = e;
  retBlock[5] = x;
  retBlock[6] = s;

  return retBlock;
}

function MDinit(MDbuf) {
  MDbuf[0] = 0x67452301;
  MDbuf[1] = 0xefcdab89;
  MDbuf[2] = 0x98badcfe;
  MDbuf[3] = 0x10325476;
  MDbuf[4] = 0xc3d2e1f0;
}

var ROLs = [
  [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
  [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12],
  [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5],
  [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12],
  [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6],
  [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6],
  [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11],
  [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5],
  [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8],
  [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
];

var indexes = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8],
  [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12],
  [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2],
  [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13],
  [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12],
  [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2],
  [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13],
  [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14],
  [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
];

function compress(MDbuf, X) {
  blockA = [];
  blockB = [];

  var retBlock;

  var i, j;

  for (i = 0; i < 5; i++) {
    blockA[i] = new Number(MDbuf[i]);
    blockB[i] = new Number(MDbuf[i]);
  }

  var step = 0;
  for (j = 0; j < 5; j++) {
    for (i = 0; i < 16; i++) {
      retBlock = mixOneRound(
        blockA[(step + 0) % 5],
        blockA[(step + 1) % 5],
        blockA[(step + 2) % 5],
        blockA[(step + 3) % 5],
        blockA[(step + 4) % 5],
        X[indexes[j][i]],
        ROLs[j][i],
        j);

      blockA[(step + 0) % 5] = retBlock[0];
      blockA[(step + 1) % 5] = retBlock[1];
      blockA[(step + 2) % 5] = retBlock[2];
      blockA[(step + 3) % 5] = retBlock[3];
      blockA[(step + 4) % 5] = retBlock[4];

      step += 4;
    }
  }

  step = 0;
  for (j = 5; j < 10; j++) {
    for (i = 0; i < 16; i++) {
      retBlock = mixOneRound(
        blockB[(step + 0) % 5],
        blockB[(step + 1) % 5],
        blockB[(step + 2) % 5],
        blockB[(step + 3) % 5],
        blockB[(step + 4) % 5],
        X[indexes[j][i]],
        ROLs[j][i],
        j);

      blockB[(step + 0) % 5] = retBlock[0];
      blockB[(step + 1) % 5] = retBlock[1];
      blockB[(step + 2) % 5] = retBlock[2];
      blockB[(step + 3) % 5] = retBlock[3];
      blockB[(step + 4) % 5] = retBlock[4];

      step += 4;
    }
  }

  blockB[3] += blockA[2] + MDbuf[1];
  MDbuf[1] = MDbuf[2] + blockA[3] + blockB[4];
  MDbuf[2] = MDbuf[3] + blockA[4] + blockB[0];
  MDbuf[3] = MDbuf[4] + blockA[0] + blockB[1];
  MDbuf[4] = MDbuf[0] + blockA[1] + blockB[2];
  MDbuf[0] = blockB[3];
}

function zeroX(X) {
  for (var i = 0; i < 16; i++) {
    X[i] = 0;
  }
}

function MDfinish(MDbuf, strptr, lswlen, mswlen) {
  var X = new Array(16);
  zeroX(X);

  var j = 0;
  for (var i = 0; i < (lswlen & 63); i++) {
    X[i >>> 2] ^= (strptr.charCodeAt(j++) & 255) << (8 * (i & 3));
  }

  X[(lswlen >>> 2) & 15] ^= 1 << (8 * (lswlen & 3) + 7);

  if ((lswlen & 63) > 55) {
    compress(MDbuf, X);
    X = new Array(16);
    zeroX(X);
  }

  X[14] = lswlen << 3;
  X[15] = (lswlen >>> 29) | (mswlen << 3);

  compress(MDbuf, X);
}

function BYTES_TO_DWORD(fourChars) {
  var tmp = (fourChars.charCodeAt(3) & 255) << 24;
  tmp |= (fourChars.charCodeAt(2) & 255) << 16;
  tmp |= (fourChars.charCodeAt(1) & 255) << 8;
  tmp |= (fourChars.charCodeAt(0) & 255);

  return tmp;
}

function RMD(message) {
  var MDbuf = new Array(RMDsize / 32);
  var hashcode = new Array(RMDsize / 8);
  var length;
  var nbytes;

  MDinit(MDbuf);
  length = message.length;

  var X = new Array(16);
  zeroX(X);

  var i, j = 0;
  for (nbytes = length; nbytes > 63; nbytes -= 64) {
    for (i = 0; i < 16; i++) {
      X[i] = BYTES_TO_DWORD(message.substr(j, 4));
      j += 4;
    }
    compress(MDbuf, X);
  }

  MDfinish(MDbuf, message.substr(j), length, 0);

  for (i = 0; i < RMDsize / 8; i += 4) {
    hashcode[i] = MDbuf[i >>> 2] & 255;
    hashcode[i + 1] = (MDbuf[i >>> 2] >>> 8) & 255;
    hashcode[i + 2] = (MDbuf[i >>> 2] >>> 16) & 255;
    hashcode[i + 3] = (MDbuf[i >>> 2] >>> 24) & 255;
  }

  return hashcode;
}


function RMDstring(message) {
  var hashcode = RMD(message);
  var retString = "";

  for (var i = 0; i < RMDsize / 8; i++) {
    retString += String.fromCharCode(hashcode[i]);
  }

  return retString;
}

module.exports = RMDstring;

},{}],48:[function(require,module,exports){
/* A JavaScript implementation of the SHA family of hashes, as defined in FIPS 
 * PUB 180-2 as well as the corresponding HMAC implementation as defined in
 * FIPS PUB 198a
 *
 * Version 1.3 Copyright Brian Turek 2008-2010
 * Distributed under the BSD License
 * See http://jssha.sourceforge.net/ for more information
 *
 * Several functions taken from Paul Johnson
 */

/* Modified by Recurity Labs GmbH
 * 
 * This code has been slightly modified direct string output:
 * - bin2bstr has been added
 * - following wrappers of this library have been added:
 *   - str_sha1
 *   - str_sha256
 *   - str_sha224
 *   - str_sha384
 *   - str_sha512
 */

/**
 * @module crypto/hash/sha
 */

var jsSHA = (function() {

  /*
   * Configurable variables. Defaults typically work
   */
  /* Number of Bits Per character (8 for ASCII, 16 for Unicode) */
  var charSize = 8,
    /* base-64 pad character. "=" for strict RFC compliance */
    b64pad = "",
    /* hex output format. 0 - lowercase; 1 - uppercase */
    hexCase = 0,

    /*
     * Int_64 is a object for 2 32-bit numbers emulating a 64-bit number
     *
     * @constructor
     * @param {Number} msint_32 The most significant 32-bits of a 64-bit number
     * @param {Number} lsint_32 The least significant 32-bits of a 64-bit number
     */
    Int_64 = function(msint_32, lsint_32) {
      this.highOrder = msint_32;
      this.lowOrder = lsint_32;
    },

    /*
     * Convert a string to an array of big-endian words
     * If charSize is ASCII, characters >255 have their hi-byte silently
     * ignored.
     *
     * @param {String} str String to be converted to binary representation
     * @return Integer array representation of the parameter
     */
    str2binb = function(str) {
      var bin = [],
        mask = (1 << charSize) - 1,
        length = str.length * charSize,
        i;

      for (i = 0; i < length; i += charSize) {
        bin[i >> 5] |= (str.charCodeAt(i / charSize) & mask) <<
          (32 - charSize - (i % 32));
      }

      return bin;
    },

    /*
     * Convert a hex string to an array of big-endian words
     *
     * @param {String} str String to be converted to binary representation
     * @return Integer array representation of the parameter
     */
    hex2binb = function(str) {
      var bin = [],
        length = str.length,
        i, num;

      for (i = 0; i < length; i += 2) {
        num = parseInt(str.substr(i, 2), 16);
        if (!isNaN(num)) {
          bin[i >> 3] |= num << (24 - (4 * (i % 8)));
        } else {
          throw new Error("INVALID HEX STRING");
        }
      }

      return bin;
    },

    /*
     * Convert an array of big-endian words to a hex string.
     *
     * @private
     * @param {Array} binarray Array of integers to be converted to hexidecimal
     *  representation
     * @return Hexidecimal representation of the parameter in String form
     */
    binb2hex = function(binarray) {
      var hex_tab = (hexCase) ? "0123456789ABCDEF" : "0123456789abcdef",
        str = "",
        length = binarray.length * 4,
        i, srcByte;

      for (i = 0; i < length; i += 1) {
        srcByte = binarray[i >> 2] >> ((3 - (i % 4)) * 8);
        str += hex_tab.charAt((srcByte >> 4) & 0xF) +
          hex_tab.charAt(srcByte & 0xF);
      }

      return str;
    },

    /*
     * Convert an array of big-endian words to a base-64 string
     *
     * @private
     * @param {Array} binarray Array of integers to be converted to base-64
     *  representation
     * @return Base-64 encoded representation of the parameter in String form
     */
    binb2b64 = function(binarray) {
      var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" +
        "0123456789+/",
        str = "",
        length = binarray.length * 4,
        i, j,
        triplet;

      for (i = 0; i < length; i += 3) {
        triplet = (((binarray[i >> 2] >> 8 * (3 - i % 4)) & 0xFF) << 16) |
          (((binarray[i + 1 >> 2] >> 8 * (3 - (i + 1) % 4)) & 0xFF) << 8) |
          ((binarray[i + 2 >> 2] >> 8 * (3 - (i + 2) % 4)) & 0xFF);
        for (j = 0; j < 4; j += 1) {
          if (i * 8 + j * 6 <= binarray.length * 32) {
            str += tab.charAt((triplet >> 6 * (3 - j)) & 0x3F);
          } else {
            str += b64pad;
          }
        }
      }
      return str;
    },

    /*
     * Convert an array of big-endian words to a string
     */
    binb2str = function(bin) {
      var str = "";
      var mask = (1 << 8) - 1;
      for (var i = 0; i < bin.length * 32; i += 8)
        str += String.fromCharCode((bin[i >> 5] >>> (24 - i % 32)) & mask);
      return str;
    },
    /*
     * The 32-bit implementation of circular rotate left
     *
     * @private
     * @param {Number} x The 32-bit integer argument
     * @param {Number} n The number of bits to shift
     * @return The x shifted circularly by n bits
     */
    rotl_32 = function(x, n) {
      return (x << n) | (x >>> (32 - n));
    },

    /*
     * The 32-bit implementation of circular rotate right
     *
     * @private
     * @param {Number} x The 32-bit integer argument
     * @param {Number} n The number of bits to shift
     * @return The x shifted circularly by n bits
     */
    rotr_32 = function(x, n) {
      return (x >>> n) | (x << (32 - n));
    },

    /*
     * The 64-bit implementation of circular rotate right
     *
     * @private
     * @param {Int_64} x The 64-bit integer argument
     * @param {Number} n The number of bits to shift
     * @return The x shifted circularly by n bits
     */
    rotr_64 = function(x, n) {
      if (n <= 32) {
        return new Int_64(
        (x.highOrder >>> n) | (x.lowOrder << (32 - n)), (x.lowOrder >>> n) | (x.highOrder << (32 - n)));
      } else {
        return new Int_64(
        (x.lowOrder >>> n) | (x.highOrder << (32 - n)), (x.highOrder >>> n) | (x.lowOrder << (32 - n)));
      }
    },

    /*
     * The 32-bit implementation of shift right
     *
     * @private
     * @param {Number} x The 32-bit integer argument
     * @param {Number} n The number of bits to shift
     * @return The x shifted by n bits
     */
    shr_32 = function(x, n) {
      return x >>> n;
    },

    /*
     * The 64-bit implementation of shift right
     *
     * @private
     * @param {Int_64} x The 64-bit integer argument
     * @param {Number} n The number of bits to shift
     * @return The x shifted by n bits
     */
    shr_64 = function(x, n) {
      if (n <= 32) {
        return new Int_64(
          x.highOrder >>> n,
          x.lowOrder >>> n | (x.highOrder << (32 - n)));
      } else {
        return new Int_64(
          0,
          x.highOrder << (32 - n));
      }
    },

    /*
     * The 32-bit implementation of the NIST specified Parity function
     *
     * @private
     * @param {Number} x The first 32-bit integer argument
     * @param {Number} y The second 32-bit integer argument
     * @param {Number} z The third 32-bit integer argument
     * @return The NIST specified output of the function
     */
    parity_32 = function(x, y, z) {
      return x ^ y ^ z;
    },

    /*
     * The 32-bit implementation of the NIST specified Ch function
     *
     * @private
     * @param {Number} x The first 32-bit integer argument
     * @param {Number} y The second 32-bit integer argument
     * @param {Number} z The third 32-bit integer argument
     * @return The NIST specified output of the function
     */
    ch_32 = function(x, y, z) {
      return (x & y) ^ (~x & z);
    },

    /*
     * The 64-bit implementation of the NIST specified Ch function
     *
     * @private
     * @param {Int_64} x The first 64-bit integer argument
     * @param {Int_64} y The second 64-bit integer argument
     * @param {Int_64} z The third 64-bit integer argument
     * @return The NIST specified output of the function
     */
    ch_64 = function(x, y, z) {
      return new Int_64(
      (x.highOrder & y.highOrder) ^ (~x.highOrder & z.highOrder), (x.lowOrder & y.lowOrder) ^ (~x.lowOrder & z.lowOrder));
    },

    /*
     * The 32-bit implementation of the NIST specified Maj function
     *
     * @private
     * @param {Number} x The first 32-bit integer argument
     * @param {Number} y The second 32-bit integer argument
     * @param {Number} z The third 32-bit integer argument
     * @return The NIST specified output of the function
     */
    maj_32 = function(x, y, z) {
      return (x & y) ^ (x & z) ^ (y & z);
    },

    /*
     * The 64-bit implementation of the NIST specified Maj function
     *
     * @private
     * @param {Int_64} x The first 64-bit integer argument
     * @param {Int_64} y The second 64-bit integer argument
     * @param {Int_64} z The third 64-bit integer argument
     * @return The NIST specified output of the function
     */
    maj_64 = function(x, y, z) {
      return new Int_64(
      (x.highOrder & y.highOrder) ^
        (x.highOrder & z.highOrder) ^
        (y.highOrder & z.highOrder), (x.lowOrder & y.lowOrder) ^
        (x.lowOrder & z.lowOrder) ^
        (y.lowOrder & z.lowOrder));
    },

    /*
     * The 32-bit implementation of the NIST specified Sigma0 function
     *
     * @private
     * @param {Number} x The 32-bit integer argument
     * @return The NIST specified output of the function
     */
    sigma0_32 = function(x) {
      return rotr_32(x, 2) ^ rotr_32(x, 13) ^ rotr_32(x, 22);
    },

    /*
     * The 64-bit implementation of the NIST specified Sigma0 function
     *
     * @private
     * @param {Int_64} x The 64-bit integer argument
     * @return The NIST specified output of the function
     */
    sigma0_64 = function(x) {
      var rotr28 = rotr_64(x, 28),
        rotr34 = rotr_64(x, 34),
        rotr39 = rotr_64(x, 39);

      return new Int_64(
        rotr28.highOrder ^ rotr34.highOrder ^ rotr39.highOrder,
        rotr28.lowOrder ^ rotr34.lowOrder ^ rotr39.lowOrder);
    },

    /*
     * The 32-bit implementation of the NIST specified Sigma1 function
     *
     * @private
     * @param {Number} x The 32-bit integer argument
     * @return The NIST specified output of the function
     */
    sigma1_32 = function(x) {
      return rotr_32(x, 6) ^ rotr_32(x, 11) ^ rotr_32(x, 25);
    },

    /*
     * The 64-bit implementation of the NIST specified Sigma1 function
     *
     * @private
     * @param {Int_64} x The 64-bit integer argument
     * @return The NIST specified output of the function
     */
    sigma1_64 = function(x) {
      var rotr14 = rotr_64(x, 14),
        rotr18 = rotr_64(x, 18),
        rotr41 = rotr_64(x, 41);

      return new Int_64(
        rotr14.highOrder ^ rotr18.highOrder ^ rotr41.highOrder,
        rotr14.lowOrder ^ rotr18.lowOrder ^ rotr41.lowOrder);
    },

    /*
     * The 32-bit implementation of the NIST specified Gamma0 function
     *
     * @private
     * @param {Number} x The 32-bit integer argument
     * @return The NIST specified output of the function
     */
    gamma0_32 = function(x) {
      return rotr_32(x, 7) ^ rotr_32(x, 18) ^ shr_32(x, 3);
    },

    /*
     * The 64-bit implementation of the NIST specified Gamma0 function
     *
     * @private
     * @param {Int_64} x The 64-bit integer argument
     * @return The NIST specified output of the function
     */
    gamma0_64 = function(x) {
      var rotr1 = rotr_64(x, 1),
        rotr8 = rotr_64(x, 8),
        shr7 = shr_64(x, 7);

      return new Int_64(
        rotr1.highOrder ^ rotr8.highOrder ^ shr7.highOrder,
        rotr1.lowOrder ^ rotr8.lowOrder ^ shr7.lowOrder);
    },

    /*
     * The 32-bit implementation of the NIST specified Gamma1 function
     *
     * @private
     * @param {Number} x The 32-bit integer argument
     * @return The NIST specified output of the function
     */
    gamma1_32 = function(x) {
      return rotr_32(x, 17) ^ rotr_32(x, 19) ^ shr_32(x, 10);
    },

    /*
     * The 64-bit implementation of the NIST specified Gamma1 function
     *
     * @private
     * @param {Int_64} x The 64-bit integer argument
     * @return The NIST specified output of the function
     */
    gamma1_64 = function(x) {
      var rotr19 = rotr_64(x, 19),
        rotr61 = rotr_64(x, 61),
        shr6 = shr_64(x, 6);

      return new Int_64(
        rotr19.highOrder ^ rotr61.highOrder ^ shr6.highOrder,
        rotr19.lowOrder ^ rotr61.lowOrder ^ shr6.lowOrder);
    },

    /*
     * Add two 32-bit integers, wrapping at 2^32. This uses 16-bit operations
     * internally to work around bugs in some JS interpreters.
     *
     * @private
     * @param {Number} x The first 32-bit integer argument to be added
     * @param {Number} y The second 32-bit integer argument to be added
     * @return The sum of x + y
     */
    safeAdd_32_2 = function(x, y) {
      var lsw = (x & 0xFFFF) + (y & 0xFFFF),
        msw = (x >>> 16) + (y >>> 16) + (lsw >>> 16);

      return ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);
    },

    /*
     * Add four 32-bit integers, wrapping at 2^32. This uses 16-bit operations
     * internally to work around bugs in some JS interpreters.
     *
     * @private
     * @param {Number} a The first 32-bit integer argument to be added
     * @param {Number} b The second 32-bit integer argument to be added
     * @param {Number} c The third 32-bit integer argument to be added
     * @param {Number} d The fourth 32-bit integer argument to be added
     * @return The sum of a + b + c + d
     */
    safeAdd_32_4 = function(a, b, c, d) {
      var lsw = (a & 0xFFFF) + (b & 0xFFFF) + (c & 0xFFFF) + (d & 0xFFFF),
        msw = (a >>> 16) + (b >>> 16) + (c >>> 16) + (d >>> 16) +
          (lsw >>> 16);

      return ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);
    },

    /*
     * Add five 32-bit integers, wrapping at 2^32. This uses 16-bit operations
     * internally to work around bugs in some JS interpreters.
     *
     * @private
     * @param {Number} a The first 32-bit integer argument to be added
     * @param {Number} b The second 32-bit integer argument to be added
     * @param {Number} c The third 32-bit integer argument to be added
     * @param {Number} d The fourth 32-bit integer argument to be added
     * @param {Number} e The fifth 32-bit integer argument to be added
     * @return The sum of a + b + c + d + e
     */
    safeAdd_32_5 = function(a, b, c, d, e) {
      var lsw = (a & 0xFFFF) + (b & 0xFFFF) + (c & 0xFFFF) + (d & 0xFFFF) +
        (e & 0xFFFF),
        msw = (a >>> 16) + (b >>> 16) + (c >>> 16) + (d >>> 16) +
          (e >>> 16) + (lsw >>> 16);

      return ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);
    },

    /*
     * Add two 64-bit integers, wrapping at 2^64. This uses 16-bit operations
     * internally to work around bugs in some JS interpreters.
     *
     * @private
     * @param {Int_64} x The first 64-bit integer argument to be added
     * @param {Int_64} y The second 64-bit integer argument to be added
     * @return The sum of x + y
     */
    safeAdd_64_2 = function(x, y) {
      var lsw, msw, lowOrder, highOrder;

      lsw = (x.lowOrder & 0xFFFF) + (y.lowOrder & 0xFFFF);
      msw = (x.lowOrder >>> 16) + (y.lowOrder >>> 16) + (lsw >>> 16);
      lowOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

      lsw = (x.highOrder & 0xFFFF) + (y.highOrder & 0xFFFF) + (msw >>> 16);
      msw = (x.highOrder >>> 16) + (y.highOrder >>> 16) + (lsw >>> 16);
      highOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

      return new Int_64(highOrder, lowOrder);
    },

    /*
     * Add four 64-bit integers, wrapping at 2^64. This uses 16-bit operations
     * internally to work around bugs in some JS interpreters.
     *
     * @private
     * @param {Int_64} a The first 64-bit integer argument to be added
     * @param {Int_64} b The second 64-bit integer argument to be added
     * @param {Int_64} c The third 64-bit integer argument to be added
     * @param {Int_64} d The fouth 64-bit integer argument to be added
     * @return The sum of a + b + c + d
     */
    safeAdd_64_4 = function(a, b, c, d) {
      var lsw, msw, lowOrder, highOrder;

      lsw = (a.lowOrder & 0xFFFF) + (b.lowOrder & 0xFFFF) +
        (c.lowOrder & 0xFFFF) + (d.lowOrder & 0xFFFF);
      msw = (a.lowOrder >>> 16) + (b.lowOrder >>> 16) +
        (c.lowOrder >>> 16) + (d.lowOrder >>> 16) + (lsw >>> 16);
      lowOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

      lsw = (a.highOrder & 0xFFFF) + (b.highOrder & 0xFFFF) +
        (c.highOrder & 0xFFFF) + (d.highOrder & 0xFFFF) + (msw >>> 16);
      msw = (a.highOrder >>> 16) + (b.highOrder >>> 16) +
        (c.highOrder >>> 16) + (d.highOrder >>> 16) + (lsw >>> 16);
      highOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

      return new Int_64(highOrder, lowOrder);
    },

    /*
     * Add five 64-bit integers, wrapping at 2^64. This uses 16-bit operations
     * internally to work around bugs in some JS interpreters.
     *
     * @private
     * @param {Int_64} a The first 64-bit integer argument to be added
     * @param {Int_64} b The second 64-bit integer argument to be added
     * @param {Int_64} c The third 64-bit integer argument to be added
     * @param {Int_64} d The fouth 64-bit integer argument to be added
     * @param {Int_64} e The fouth 64-bit integer argument to be added
     * @return The sum of a + b + c + d + e
     */
    safeAdd_64_5 = function(a, b, c, d, e) {
      var lsw, msw, lowOrder, highOrder;

      lsw = (a.lowOrder & 0xFFFF) + (b.lowOrder & 0xFFFF) +
        (c.lowOrder & 0xFFFF) + (d.lowOrder & 0xFFFF) +
        (e.lowOrder & 0xFFFF);
      msw = (a.lowOrder >>> 16) + (b.lowOrder >>> 16) +
        (c.lowOrder >>> 16) + (d.lowOrder >>> 16) + (e.lowOrder >>> 16) +
        (lsw >>> 16);
      lowOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

      lsw = (a.highOrder & 0xFFFF) + (b.highOrder & 0xFFFF) +
        (c.highOrder & 0xFFFF) + (d.highOrder & 0xFFFF) +
        (e.highOrder & 0xFFFF) + (msw >>> 16);
      msw = (a.highOrder >>> 16) + (b.highOrder >>> 16) +
        (c.highOrder >>> 16) + (d.highOrder >>> 16) +
        (e.highOrder >>> 16) + (lsw >>> 16);
      highOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

      return new Int_64(highOrder, lowOrder);
    },

    /*
     * Calculates the SHA-1 hash of the string set at instantiation
     *
     * @private
     * @param {Array} message The binary array representation of the string to
     *    hash
     * @param {Number} messageLen The number of bits in the message
     * @return The array of integers representing the SHA-1 hash of message
     */
    coreSHA1 = function(message, messageLen) {
      var W = [],
        a, b, c, d, e, T, ch = ch_32,
        parity = parity_32,
        maj = maj_32,
        rotl = rotl_32,
        safeAdd_2 = safeAdd_32_2,
        i, t,
        safeAdd_5 = safeAdd_32_5,
        appendedMessageLength,
        H = [
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
        ],
        K = [
            0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
            0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
            0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
            0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
            0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
            0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
            0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
            0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
            0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
            0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
            0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
            0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
            0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
            0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
            0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
            0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
            0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
            0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
            0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
            0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6
        ];

      /* Append '1' at the end of the binary string */
      message[messageLen >> 5] |= 0x80 << (24 - (messageLen % 32));
      /* Append length of binary string in the position such that the new
		length is a multiple of 512.  Logic does not work for even multiples
		of 512 but there can never be even multiples of 512 */
      message[(((messageLen + 65) >> 9) << 4) + 15] = messageLen;

      appendedMessageLength = message.length;

      for (i = 0; i < appendedMessageLength; i += 16) {
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];

        for (t = 0; t < 80; t += 1) {
          if (t < 16) {
            W[t] = message[t + i];
          } else {
            W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
          }

          if (t < 20) {
            T = safeAdd_5(rotl(a, 5), ch(b, c, d), e, K[t], W[t]);
          } else if (t < 40) {
            T = safeAdd_5(rotl(a, 5), parity(b, c, d), e, K[t], W[t]);
          } else if (t < 60) {
            T = safeAdd_5(rotl(a, 5), maj(b, c, d), e, K[t], W[t]);
          } else {
            T = safeAdd_5(rotl(a, 5), parity(b, c, d), e, K[t], W[t]);
          }

          e = d;
          d = c;
          c = rotl(b, 30);
          b = a;
          a = T;
        }

        H[0] = safeAdd_2(a, H[0]);
        H[1] = safeAdd_2(b, H[1]);
        H[2] = safeAdd_2(c, H[2]);
        H[3] = safeAdd_2(d, H[3]);
        H[4] = safeAdd_2(e, H[4]);
      }

      return H;
    },

    /*
     * Calculates the desired SHA-2 hash of the string set at instantiation
     *
     * @private
     * @param {Array} The binary array representation of the string to hash
     * @param {Number} The number of bits in message
     * @param {String} variant The desired SHA-2 variant
     * @return The array of integers representing the SHA-2 hash of message
     */
    coreSHA2 = function(message, messageLen, variant) {
      var a, b, c, d, e, f, g, h, T1, T2, H, numRounds, lengthPosition, i, t,
        binaryStringInc, binaryStringMult, safeAdd_2, safeAdd_4, safeAdd_5,
        gamma0, gamma1, sigma0, sigma1, ch, maj, Int, K, W = [],
        appendedMessageLength;

      /* Set up the various function handles and variable for the specific 
       * variant */
      if (variant === "SHA-224" || variant === "SHA-256") {
        /* 32-bit variant */
        numRounds = 64;
        lengthPosition = (((messageLen + 65) >> 9) << 4) + 15;
        binaryStringInc = 16;
        binaryStringMult = 1;
        Int = Number;
        safeAdd_2 = safeAdd_32_2;
        safeAdd_4 = safeAdd_32_4;
        safeAdd_5 = safeAdd_32_5;
        gamma0 = gamma0_32;
        gamma1 = gamma1_32;
        sigma0 = sigma0_32;
        sigma1 = sigma1_32;
        maj = maj_32;
        ch = ch_32;
        K = [
            0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
            0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
            0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
            0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
            0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
            0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
            0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
            0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
            0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
            0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
            0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
            0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
            0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
            0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
            0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
            0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
        ];

        if (variant === "SHA-224") {
          H = [
              0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
              0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
          ];
        } else {
          H = [
              0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
              0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
          ];
        }
      } else if (variant === "SHA-384" || variant === "SHA-512") {
        /* 64-bit variant */
        numRounds = 80;
        lengthPosition = (((messageLen + 128) >> 10) << 5) + 31;
        binaryStringInc = 32;
        binaryStringMult = 2;
        Int = Int_64;
        safeAdd_2 = safeAdd_64_2;
        safeAdd_4 = safeAdd_64_4;
        safeAdd_5 = safeAdd_64_5;
        gamma0 = gamma0_64;
        gamma1 = gamma1_64;
        sigma0 = sigma0_64;
        sigma1 = sigma1_64;
        maj = maj_64;
        ch = ch_64;

        K = [
            new Int(0x428a2f98, 0xd728ae22), new Int(0x71374491, 0x23ef65cd),
            new Int(0xb5c0fbcf, 0xec4d3b2f), new Int(0xe9b5dba5, 0x8189dbbc),
            new Int(0x3956c25b, 0xf348b538), new Int(0x59f111f1, 0xb605d019),
            new Int(0x923f82a4, 0xaf194f9b), new Int(0xab1c5ed5, 0xda6d8118),
            new Int(0xd807aa98, 0xa3030242), new Int(0x12835b01, 0x45706fbe),
            new Int(0x243185be, 0x4ee4b28c), new Int(0x550c7dc3, 0xd5ffb4e2),
            new Int(0x72be5d74, 0xf27b896f), new Int(0x80deb1fe, 0x3b1696b1),
            new Int(0x9bdc06a7, 0x25c71235), new Int(0xc19bf174, 0xcf692694),
            new Int(0xe49b69c1, 0x9ef14ad2), new Int(0xefbe4786, 0x384f25e3),
            new Int(0x0fc19dc6, 0x8b8cd5b5), new Int(0x240ca1cc, 0x77ac9c65),
            new Int(0x2de92c6f, 0x592b0275), new Int(0x4a7484aa, 0x6ea6e483),
            new Int(0x5cb0a9dc, 0xbd41fbd4), new Int(0x76f988da, 0x831153b5),
            new Int(0x983e5152, 0xee66dfab), new Int(0xa831c66d, 0x2db43210),
            new Int(0xb00327c8, 0x98fb213f), new Int(0xbf597fc7, 0xbeef0ee4),
            new Int(0xc6e00bf3, 0x3da88fc2), new Int(0xd5a79147, 0x930aa725),
            new Int(0x06ca6351, 0xe003826f), new Int(0x14292967, 0x0a0e6e70),
            new Int(0x27b70a85, 0x46d22ffc), new Int(0x2e1b2138, 0x5c26c926),
            new Int(0x4d2c6dfc, 0x5ac42aed), new Int(0x53380d13, 0x9d95b3df),
            new Int(0x650a7354, 0x8baf63de), new Int(0x766a0abb, 0x3c77b2a8),
            new Int(0x81c2c92e, 0x47edaee6), new Int(0x92722c85, 0x1482353b),
            new Int(0xa2bfe8a1, 0x4cf10364), new Int(0xa81a664b, 0xbc423001),
            new Int(0xc24b8b70, 0xd0f89791), new Int(0xc76c51a3, 0x0654be30),
            new Int(0xd192e819, 0xd6ef5218), new Int(0xd6990624, 0x5565a910),
            new Int(0xf40e3585, 0x5771202a), new Int(0x106aa070, 0x32bbd1b8),
            new Int(0x19a4c116, 0xb8d2d0c8), new Int(0x1e376c08, 0x5141ab53),
            new Int(0x2748774c, 0xdf8eeb99), new Int(0x34b0bcb5, 0xe19b48a8),
            new Int(0x391c0cb3, 0xc5c95a63), new Int(0x4ed8aa4a, 0xe3418acb),
            new Int(0x5b9cca4f, 0x7763e373), new Int(0x682e6ff3, 0xd6b2b8a3),
            new Int(0x748f82ee, 0x5defb2fc), new Int(0x78a5636f, 0x43172f60),
            new Int(0x84c87814, 0xa1f0ab72), new Int(0x8cc70208, 0x1a6439ec),
            new Int(0x90befffa, 0x23631e28), new Int(0xa4506ceb, 0xde82bde9),
            new Int(0xbef9a3f7, 0xb2c67915), new Int(0xc67178f2, 0xe372532b),
            new Int(0xca273ece, 0xea26619c), new Int(0xd186b8c7, 0x21c0c207),
            new Int(0xeada7dd6, 0xcde0eb1e), new Int(0xf57d4f7f, 0xee6ed178),
            new Int(0x06f067aa, 0x72176fba), new Int(0x0a637dc5, 0xa2c898a6),
            new Int(0x113f9804, 0xbef90dae), new Int(0x1b710b35, 0x131c471b),
            new Int(0x28db77f5, 0x23047d84), new Int(0x32caab7b, 0x40c72493),
            new Int(0x3c9ebe0a, 0x15c9bebc), new Int(0x431d67c4, 0x9c100d4c),
            new Int(0x4cc5d4be, 0xcb3e42b6), new Int(0x597f299c, 0xfc657e2a),
            new Int(0x5fcb6fab, 0x3ad6faec), new Int(0x6c44198c, 0x4a475817)
        ];

        if (variant === "SHA-384") {
          H = [
              new Int(0xcbbb9d5d, 0xc1059ed8), new Int(0x0629a292a, 0x367cd507),
              new Int(0x9159015a, 0x3070dd17), new Int(0x0152fecd8, 0xf70e5939),
              new Int(0x67332667, 0xffc00b31), new Int(0x98eb44a87, 0x68581511),
              new Int(0xdb0c2e0d, 0x64f98fa7), new Int(0x047b5481d, 0xbefa4fa4)
          ];
        } else {
          H = [
              new Int(0x6a09e667, 0xf3bcc908), new Int(0xbb67ae85, 0x84caa73b),
              new Int(0x3c6ef372, 0xfe94f82b), new Int(0xa54ff53a, 0x5f1d36f1),
              new Int(0x510e527f, 0xade682d1), new Int(0x9b05688c, 0x2b3e6c1f),
              new Int(0x1f83d9ab, 0xfb41bd6b), new Int(0x5be0cd19, 0x137e2179)
          ];
        }
      }

      /* Append '1' at the end of the binary string */
      message[messageLen >> 5] |= 0x80 << (24 - messageLen % 32);
      /* Append length of binary string in the position such that the new
       * length is correct */
      message[lengthPosition] = messageLen;

      appendedMessageLength = message.length;

      for (i = 0; i < appendedMessageLength; i += binaryStringInc) {
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];
        f = H[5];
        g = H[6];
        h = H[7];

        for (t = 0; t < numRounds; t += 1) {
          if (t < 16) {
            /* Bit of a hack - for 32-bit, the second term is ignored */
            W[t] = new Int(message[t * binaryStringMult + i],
              message[t * binaryStringMult + i + 1]);
          } else {
            W[t] = safeAdd_4(
              gamma1(W[t - 2]), W[t - 7],
              gamma0(W[t - 15]), W[t - 16]);
          }

          T1 = safeAdd_5(h, sigma1(e), ch(e, f, g), K[t], W[t]);
          T2 = safeAdd_2(sigma0(a), maj(a, b, c));
          h = g;
          g = f;
          f = e;
          e = safeAdd_2(d, T1);
          d = c;
          c = b;
          b = a;
          a = safeAdd_2(T1, T2);
        }

        H[0] = safeAdd_2(a, H[0]);
        H[1] = safeAdd_2(b, H[1]);
        H[2] = safeAdd_2(c, H[2]);
        H[3] = safeAdd_2(d, H[3]);
        H[4] = safeAdd_2(e, H[4]);
        H[5] = safeAdd_2(f, H[5]);
        H[6] = safeAdd_2(g, H[6]);
        H[7] = safeAdd_2(h, H[7]);
      }

      switch (variant) {
        case "SHA-224":
          return [
            H[0], H[1], H[2], H[3],
            H[4], H[5], H[6]];
        case "SHA-256":
          return H;
        case "SHA-384":
          return [
            H[0].highOrder, H[0].lowOrder,
            H[1].highOrder, H[1].lowOrder,
            H[2].highOrder, H[2].lowOrder,
            H[3].highOrder, H[3].lowOrder,
            H[4].highOrder, H[4].lowOrder,
            H[5].highOrder, H[5].lowOrder];
        case "SHA-512":
          return [
            H[0].highOrder, H[0].lowOrder,
            H[1].highOrder, H[1].lowOrder,
            H[2].highOrder, H[2].lowOrder,
            H[3].highOrder, H[3].lowOrder,
            H[4].highOrder, H[4].lowOrder,
            H[5].highOrder, H[5].lowOrder,
            H[6].highOrder, H[6].lowOrder,
            H[7].highOrder, H[7].lowOrder];
        default:
          /* This should never be reached */
          throw new Error('Unknown SHA variant');
      }
    },

    /*
     * jsSHA is the workhorse of the library.  Instantiate it with the string to
     * be hashed as the parameter
     *
     * @constructor
     * @param {String} srcString The string to be hashed
     * @param {String} inputFormat The format of srcString, ASCII or HEX
     */
    jsSHA = function(srcString, inputFormat) {

      this.sha1 = null;
      this.sha224 = null;
      this.sha256 = null;
      this.sha384 = null;
      this.sha512 = null;

      this.strBinLen = null;
      this.strToHash = null;

      /* Convert the input string into the correct type */
      if ("HEX" === inputFormat) {
        if (0 !== (srcString.length % 2)) {
          throw new Error("TEXT MUST BE IN BYTE INCREMENTS");
        }
        this.strBinLen = srcString.length * 4;
        this.strToHash = hex2binb(srcString);
      } else if (("ASCII" === inputFormat) ||
        ('undefined' === typeof(inputFormat))) {
        this.strBinLen = srcString.length * charSize;
        this.strToHash = str2binb(srcString);
      } else {
        throw new Error("UNKNOWN TEXT INPUT TYPE");
      }
    };

  jsSHA.prototype = {
    /*
     * Returns the desired SHA hash of the string specified at instantiation
     * using the specified parameters
     *
     * @param {String} variant The desired SHA variant (SHA-1, SHA-224,
     *    SHA-256, SHA-384, or SHA-512)
     * @param {String} format The desired output formatting (B64 or HEX)
     * @return The string representation of the hash in the format specified
     */
    getHash: function(variant, format) {
      var formatFunc = null,
        message = this.strToHash.slice();

      switch (format) {
        case "HEX":
          formatFunc = binb2hex;
          break;
        case "B64":
          formatFunc = binb2b64;
          break;
        case "ASCII":
          formatFunc = binb2str;
          break;
        default:
          throw new Error("FORMAT NOT RECOGNIZED");
      }

      switch (variant) {
        case "SHA-1":
          if (null === this.sha1) {
            this.sha1 = coreSHA1(message, this.strBinLen);
          }
          return formatFunc(this.sha1);
        case "SHA-224":
          if (null === this.sha224) {
            this.sha224 = coreSHA2(message, this.strBinLen, variant);
          }
          return formatFunc(this.sha224);
        case "SHA-256":
          if (null === this.sha256) {
            this.sha256 = coreSHA2(message, this.strBinLen, variant);
          }
          return formatFunc(this.sha256);
        case "SHA-384":
          if (null === this.sha384) {
            this.sha384 = coreSHA2(message, this.strBinLen, variant);
          }
          return formatFunc(this.sha384);
        case "SHA-512":
          if (null === this.sha512) {
            this.sha512 = coreSHA2(message, this.strBinLen, variant);
          }
          return formatFunc(this.sha512);
        default:
          throw new Error("HASH NOT RECOGNIZED");
      }
    },

    /*
     * Returns the desired HMAC of the string specified at instantiation
     * using the key and variant param.
     *
     * @param {String} key The key used to calculate the HMAC
     * @param {String} inputFormat The format of key, ASCII or HEX
     * @param {String} variant The desired SHA variant (SHA-1, SHA-224,
     *    SHA-256, SHA-384, or SHA-512)
     * @param {String} outputFormat The desired output formatting
     *    (B64 or HEX)
     * @return The string representation of the hash in the format specified
     */
    getHMAC: function(key, inputFormat, variant, outputFormat) {
      var formatFunc, keyToUse, blockByteSize, blockBitSize, i,
        retVal, lastArrayIndex, keyBinLen, hashBitSize,
        keyWithIPad = [],
        keyWithOPad = [];

      /* Validate the output format selection */
      switch (outputFormat) {
        case "HEX":
          formatFunc = binb2hex;
          break;
        case "B64":
          formatFunc = binb2b64;
          break;
        case "ASCII":
          formatFunc = binb2str;
          break;
        default:
          throw new Error("FORMAT NOT RECOGNIZED");
      }

      /* Validate the hash variant selection and set needed variables */
      switch (variant) {
        case "SHA-1":
          blockByteSize = 64;
          hashBitSize = 160;
          break;
        case "SHA-224":
          blockByteSize = 64;
          hashBitSize = 224;
          break;
        case "SHA-256":
          blockByteSize = 64;
          hashBitSize = 256;
          break;
        case "SHA-384":
          blockByteSize = 128;
          hashBitSize = 384;
          break;
        case "SHA-512":
          blockByteSize = 128;
          hashBitSize = 512;
          break;
        default:
          throw new Error("HASH NOT RECOGNIZED");
      }

      /* Validate input format selection */
      if ("HEX" === inputFormat) {
        /* Nibbles must come in pairs */
        if (0 !== (key.length % 2)) {
          throw new Error("KEY MUST BE IN BYTE INCREMENTS");
        }
        keyToUse = hex2binb(key);
        keyBinLen = key.length * 4;
      } else if ("ASCII" === inputFormat) {
        keyToUse = str2binb(key);
        keyBinLen = key.length * charSize;
      } else {
        throw new Error("UNKNOWN KEY INPUT TYPE");
      }

      /* These are used multiple times, calculate and store them */
      blockBitSize = blockByteSize * 8;
      lastArrayIndex = (blockByteSize / 4) - 1;

      /* Figure out what to do with the key based on its size relative to
       * the hash's block size */
      if (blockByteSize < (keyBinLen / 8)) {
        if ("SHA-1" === variant) {
          keyToUse = coreSHA1(keyToUse, keyBinLen);
        } else {
          keyToUse = coreSHA2(keyToUse, keyBinLen, variant);
        }
        /* For all variants, the block size is bigger than the output
         * size so there will never be a useful byte at the end of the
         * string */
        keyToUse[lastArrayIndex] &= 0xFFFFFF00;
      } else if (blockByteSize > (keyBinLen / 8)) {
        /* If the blockByteSize is greater than the key length, there
         * will always be at LEAST one "useless" byte at the end of the
         * string */
        keyToUse[lastArrayIndex] &= 0xFFFFFF00;
      }

      /* Create ipad and opad */
      for (i = 0; i <= lastArrayIndex; i += 1) {
        keyWithIPad[i] = keyToUse[i] ^ 0x36363636;
        keyWithOPad[i] = keyToUse[i] ^ 0x5C5C5C5C;
      }

      /* Calculate the HMAC */
      if ("SHA-1" === variant) {
        retVal = coreSHA1(
          keyWithIPad.concat(this.strToHash),
          blockBitSize + this.strBinLen);
        retVal = coreSHA1(
          keyWithOPad.concat(retVal),
          blockBitSize + hashBitSize);
      } else {
        retVal = coreSHA2(
          keyWithIPad.concat(this.strToHash),
          blockBitSize + this.strBinLen, variant);
        retVal = coreSHA2(
          keyWithOPad.concat(retVal),
          blockBitSize + hashBitSize, variant);
      }

      return (formatFunc(retVal));
    }
  };

  return jsSHA;
}());

module.exports = {
  /** SHA1 hash */
  sha1: function(str) {
    var shaObj = new jsSHA(str, "ASCII");
    return shaObj.getHash("SHA-1", "ASCII");
  },
  /** SHA224 hash */
  sha224: function(str) {
    var shaObj = new jsSHA(str, "ASCII");
    return shaObj.getHash("SHA-224", "ASCII");
  },
  /** SHA256 hash */
  sha256: function(str) {
    var shaObj = new jsSHA(str, "ASCII");
    return shaObj.getHash("SHA-256", "ASCII");
  },
  /** SHA384 hash */
  sha384: function(str) {
    var shaObj = new jsSHA(str, "ASCII");
    return shaObj.getHash("SHA-384", "ASCII");

  },
  /** SHA512 hash */
  sha512: function(str) {
    var shaObj = new jsSHA(str, "ASCII");
    return shaObj.getHash("SHA-512", "ASCII");
  }
};

},{}],49:[function(require,module,exports){
/**
 * @see module:crypto/crypto
 * @module crypto
 */
module.exports = {
  /** @see module:crypto/cipher */
  cipher: require('./cipher'),
  /** @see module:crypto/hash */
  hash: require('./hash'),
  /** @see module:crypto/cfb */
  cfb: require('./cfb.js'),
  /** @see module:crypto/public_key */
  publicKey: require('./public_key'),
  /** @see module:crypto/signature */
  signature: require('./signature.js'),
  /** @see module:crypto/random */
  random: require('./random.js'),
  /** @see module:crypto/pkcs1 */
  pkcs1: require('./pkcs1.js')
};

var crypto = require('./crypto.js');

for (var i in crypto)
  module.exports[i] = crypto[i];

},{"./cfb.js":34,"./cipher":39,"./crypto.js":41,"./hash":45,"./pkcs1.js":50,"./public_key":53,"./random.js":56,"./signature.js":57}],50:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * PKCS1 encoding
 * @requires crypto/crypto
 * @requires crypto/hash
 * @requires crypto/public_key/jsbn
 * @requires crypto/random
 * @requires util
 * @module crypto/pkcs1
 */

/**
 * ASN1 object identifiers for hashes (See {@link http://tools.ietf.org/html/rfc4880#section-5.2.2})
 */
var hash_headers = [];
hash_headers[1] = [0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04,
    0x10
];
hash_headers[2] = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
hash_headers[3] = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14];
hash_headers[8] = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    0x04, 0x20
];
hash_headers[9] = [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00,
    0x04, 0x30
];
hash_headers[10] = [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40
];
hash_headers[11] = [0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
    0x00, 0x04, 0x1C
];

var crypto = require('./crypto.js'),
  random = require('./random.js'),
  util = require('../util.js'),
  BigInteger = require('./public_key/jsbn.js'),
  hash = require('./hash');

/**
 * Create padding with secure random data
 * @private
 * @param  {Integer} length Length of the padding in bytes
 * @return {String}        Padding as string
 */
function getPkcs1Padding(length) {
  var result = '';
  var randomByte;
  while (result.length < length) {
    randomByte = random.getSecureRandomOctet();
    if (randomByte !== 0) {
      result += String.fromCharCode(randomByte);
    }
  }
  return result;
}


module.exports = {
  eme: {
    /**
     * create a EME-PKCS1-v1_5 padding (See {@link http://tools.ietf.org/html/rfc4880#section-13.1.1|RFC 4880 13.1.1})
     * @param {String} M message to be encoded
     * @param {Integer} k the length in octets of the key modulus
     * @return {String} EME-PKCS1 padded message
     */
    encode: function(M, k) {
      var mLen = M.length;
      // length checking
      if (mLen > k - 11) {
        throw new Error('Message too long');
      }
      // Generate an octet string PS of length k - mLen - 3 consisting of
      // pseudo-randomly generated nonzero octets
      var PS = getPkcs1Padding(k - mLen - 3);
      // Concatenate PS, the message M, and other padding to form an
      // encoded message EM of length k octets as EM = 0x00 || 0x02 || PS || 0x00 || M.
      var EM = String.fromCharCode(0) +
               String.fromCharCode(2) +
               PS +
               String.fromCharCode(0) +
               M;
      return EM;
    },
    /**
     * decodes a EME-PKCS1-v1_5 padding (See {@link http://tools.ietf.org/html/rfc4880#section-13.1.2|RFC 4880 13.1.2})
     * @param {String} EM encoded message, an octet string
     * @return {String} message, an octet string
     */
    decode: function(EM) {
      // leading zeros truncated by jsbn
      if (EM.charCodeAt(0) !== 0) {
        EM = String.fromCharCode(0) + EM;
      }
      var firstOct = EM.charCodeAt(0);
      var secondOct = EM.charCodeAt(1);
      var i = 2;
      while (EM.charCodeAt(i) !== 0 && i < EM.length) {
        i++;
      }
      var psLen = i - 2;
      var separator = EM.charCodeAt(i++);
      if (firstOct === 0 && secondOct === 2 && psLen >= 8 && separator === 0) {
        return EM.substr(i);
      } else {
        throw new Error('Decryption error');
      }
    }
  },

  emsa: {
    /**
     * create a EMSA-PKCS1-v1_5 padding (See {@link http://tools.ietf.org/html/rfc4880#section-13.1.3|RFC 4880 13.1.3})
     * @param {Integer} algo Hash algorithm type used
     * @param {String} M message to be encoded
     * @param {Integer} emLen intended length in octets of the encoded message
     * @returns {String} encoded message
     */
    encode: function(algo, M, emLen) {
      var i;
      // Apply the hash function to the message M to produce a hash value H
      var H = hash.digest(algo, M);
      if (H.length !== hash.getHashByteLength(algo)) {
        throw new Error('Invalid hash length');
      }
      // produce an ASN.1 DER value for the hash function used.
      // Let T be the full hash prefix
      var T = '';
      for (i = 0; i < hash_headers[algo].length; i++) {
        T += String.fromCharCode(hash_headers[algo][i]);
      }
      // add hash value to prefix
      T += H;
      // and let tLen be the length in octets of T
      var tLen = T.length;
      if (emLen < tLen + 11) {
        throw new Error('Intended encoded message length too short');
      }
      // an octet string PS consisting of emLen - tLen - 3 octets with hexadecimal value 0xFF
      // The length of PS will be at least 8 octets
      var PS = '';
      for (i = 0; i < (emLen - tLen - 3); i++) {
        PS += String.fromCharCode(0xff);
      }
      // Concatenate PS, the hash prefix T, and other padding to form the
      // encoded message EM as EM = 0x00 || 0x01 || PS || 0x00 || T.
      var EM = String.fromCharCode(0x00) +
               String.fromCharCode(0x01) +
               PS +
               String.fromCharCode(0x00) +
               T;
      return new BigInteger(util.hexstrdump(EM), 16);
    }
  }
};

},{"../util.js":95,"./crypto.js":41,"./hash":45,"./public_key/jsbn.js":54,"./random.js":56}],51:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
//
// A Digital signature algorithm implementation

/**
 * @requires crypto/hash
 * @requires crypto/public_key/jsbn
 * @requires crypto/random
 * @requires util
 * @module crypto/public_key/dsa
 */

var BigInteger = require('./jsbn.js'),
  random = require('../random.js'),
  hashModule = require('../hash'),
  util = require('../../util.js'),
  config = require('../../config');

function DSA() {
  // s1 = ((g**s) mod p) mod q
  // s1 = ((s**-1)*(sha-1(m)+(s1*x) mod q)
  function sign(hashalgo, m, g, p, q, x) {
    // If the output size of the chosen hash is larger than the number of
    // bits of q, the hash result is truncated to fit by taking the number
    // of leftmost bits equal to the number of bits of q.  This (possibly
    // truncated) hash function result is treated as a number and used
    // directly in the DSA signature algorithm.
    var hashed_data = util.getLeftNBits(hashModule.digest(hashalgo, m), q.bitLength());
    var hash = new BigInteger(util.hexstrdump(hashed_data), 16);
    // FIPS-186-4, section 4.6:
    // The values of r and s shall be checked to determine if r = 0 or s = 0.
    // If either r = 0 or s = 0, a new value of k shall be generated, and the
    // signature shall be recalculated. It is extremely unlikely that r = 0 
    // or s = 0 if signatures are generated properly.
    var k, s1, s2;
    while (true) {
      k = random.getRandomBigIntegerInRange(BigInteger.ONE, q.subtract(BigInteger.ONE));
      s1 = (g.modPow(k, p)).mod(q);
      s2 = (k.modInverse(q).multiply(hash.add(x.multiply(s1)))).mod(q);
      if (s1 != 0 && s2 != 0) {
        break;
      }
    }
    var result = [];
    result[0] = s1.toMPI();
    result[1] = s2.toMPI();
    return result;
  }

  function select_hash_algorithm(q) {
    var usersetting = config.prefer_hash_algorithm;
    /*
     * 1024-bit key, 160-bit q, SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512 hash
     * 2048-bit key, 224-bit q, SHA-224, SHA-256, SHA-384, or SHA-512 hash
     * 2048-bit key, 256-bit q, SHA-256, SHA-384, or SHA-512 hash
     * 3072-bit key, 256-bit q, SHA-256, SHA-384, or SHA-512 hash
     */
    switch (Math.round(q.bitLength() / 8)) {
      case 20:
        // 1024 bit
        if (usersetting != 2 &&
          usersetting > 11 &&
          usersetting != 10 &&
          usersetting < 8)
          return 2; // prefer sha1
        return usersetting;
      case 28:
        // 2048 bit
        if (usersetting > 11 &&
          usersetting < 8)
          return 11;
        return usersetting;
      case 32:
        // 4096 bit // prefer sha224
        if (usersetting > 10 &&
          usersetting < 8)
          return 8; // prefer sha256
        return usersetting;
      default:
        util.print_debug("DSA select hash algorithm: returning null for an unknown length of q");
        return null;

    }
  }
  this.select_hash_algorithm = select_hash_algorithm;

  function verify(hashalgo, s1, s2, m, p, q, g, y) {
    var hashed_data = util.getLeftNBits(hashModule.digest(hashalgo, m), q.bitLength());
    var hash = new BigInteger(util.hexstrdump(hashed_data), 16);
    if (BigInteger.ZERO.compareTo(s1) >= 0 ||
      s1.compareTo(q) >= 0 ||
      BigInteger.ZERO.compareTo(s2) >= 0 ||
      s2.compareTo(q) >= 0) {
      util.print_debug("invalid DSA Signature");
      return null;
    }
    var w = s2.modInverse(q);
    if (BigInteger.ZERO.compareTo(w) == 0) {
      util.print_debug("invalid DSA Signature");
      return null;
    }
    var u1 = hash.multiply(w).mod(q);
    var u2 = s1.multiply(w).mod(q);
    return g.modPow(u1, p).multiply(y.modPow(u2, p)).mod(p).mod(q);
  }

  /*
	 * unused code. This can be used as a start to write a key generator
	 * function.
	
  function generateKey(bitcount) {
    var qi = new BigInteger(bitcount, primeCenterie);
    var pi = generateP(q, 512);
    var gi = generateG(p, q, bitcount);
    var xi;
    do {
      xi = new BigInteger(q.bitCount(), rand);
    } while (x.compareTo(BigInteger.ZERO) != 1 && x.compareTo(q) != -1);
    var yi = g.modPow(x, p);
    return {x: xi, q: qi, p: pi, g: gi, y: yi};
  }

  function generateP(q, bitlength, randomfn) {
    if (bitlength % 64 != 0) {
      return false;
    }
    var pTemp;
    var pTemp2;
    do {
      pTemp = randomfn(bitcount, true);
      pTemp2 = pTemp.subtract(BigInteger.ONE);
      pTemp = pTemp.subtract(pTemp2.remainder(q));
    } while (!pTemp.isProbablePrime(primeCenterie) || pTemp.bitLength() != l);
    return pTemp;
  }
	
  function generateG(p, q, bitlength, randomfn) {
    var aux = p.subtract(BigInteger.ONE);
    var pow = aux.divide(q);
    var gTemp;
    do {
      gTemp = randomfn(bitlength);
    } while (gTemp.compareTo(aux) != -1 && gTemp.compareTo(BigInteger.ONE) != 1);
    return gTemp.modPow(pow, p);
  }

  function generateK(q, bitlength, randomfn) {
    var tempK;
    do {
      tempK = randomfn(bitlength, false);
    } while (tempK.compareTo(q) != -1 && tempK.compareTo(BigInteger.ZERO) != 1);
    return tempK;
  }

  function generateR(q,p) {
    k = generateK(q);
    var r = g.modPow(k, p).mod(q);
    return r;
  }

  function generateS(hashfn,k,r,m,q,x) {
    var hash = hashfn(m);
    s = (k.modInverse(q).multiply(hash.add(x.multiply(r)))).mod(q);
    return s;
  } */
  this.sign = sign;
  this.verify = verify;
  // this.generate = generateKey;
}

module.exports = DSA;

},{"../../config":33,"../../util.js":95,"../hash":45,"../random.js":56,"./jsbn.js":54}],52:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
//
// ElGamal implementation

/**
 * @requires crypto/public_key/jsbn
 * @requires crypto/random
 * @requires util
 * @module crypto/public_key/elgamal
 */

var BigInteger = require('./jsbn.js'),
  random = require('../random.js'),
  util = require('../../util.js');

function Elgamal() {

  function encrypt(m, g, p, y) {
    //  choose k in {2,...,p-2}
    var pMinus2 = p.subtract(BigInteger.TWO);
    var k = random.getRandomBigIntegerInRange(BigInteger.ONE, pMinus2);
    k = k.mod(pMinus2).add(BigInteger.ONE);
    var c = [];
    c[0] = g.modPow(k, p);
    c[1] = y.modPow(k, p).multiply(m).mod(p);
    return c;
  }

  function decrypt(c1, c2, p, x) {
    util.print_debug("Elgamal Decrypt:\nc1:" + util.hexstrdump(c1.toMPI()) + "\n" +
      "c2:" + util.hexstrdump(c2.toMPI()) + "\n" +
      "p:" + util.hexstrdump(p.toMPI()) + "\n" +
      "x:" + util.hexstrdump(x.toMPI()));
    return (c1.modPow(x, p).modInverse(p)).multiply(c2).mod(p);
    //var c = c1.pow(x).modInverse(p); // c0^-a mod p
    //return c.multiply(c2).mod(p);
  }

  // signing and signature verification using Elgamal is not required by OpenPGP.
  this.encrypt = encrypt;
  this.decrypt = decrypt;
}

module.exports = Elgamal;

},{"../../util.js":95,"../random.js":56,"./jsbn.js":54}],53:[function(require,module,exports){
/**
 * @requires crypto/public_key/dsa
 * @requires crypto/public_key/elgamal
 * @requires crypto/public_key/rsa
 * @module crypto/public_key
 */
module.exports = {
  /** @see module:crypto/public_key/rsa */
  rsa: require('./rsa.js'),
  /** @see module:crypto/public_key/elgamal */
  elgamal: require('./elgamal.js'),
  /** @see module:crypto/public_key/dsa */
  dsa: require('./dsa.js')
};

},{"./dsa.js":51,"./elgamal.js":52,"./rsa.js":55}],54:[function(require,module,exports){
/*
 * Copyright (c) 2003-2005  Tom Wu (tjw@cs.Stanford.EDU) 
 * All Rights Reserved.
 *
 * Modified by Recurity Labs GmbH 
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY 
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */


/**
 * @requires util
 * @module crypto/public_key/jsbn
 */

var util = require('../../util.js');

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary & 0xffffff) == 0xefcafe);

// (public) Constructor

function BigInteger(a, b, c) {
  if (a != null)
    if ("number" == typeof a) this.fromNumber(a, b, c);
    else if (b == null && "string" != typeof a) this.fromString(a, 256);
  else this.fromString(a, b);
}

// return new, unset BigInteger

function nbi() {
  return new BigInteger(null);
}

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)

function am1(i, x, w, j, c, n) {
  while (--n >= 0) {
    var v = x * this[i++] + w[j] + c;
    c = Math.floor(v / 0x4000000);
    w[j++] = v & 0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)

function am2(i, x, w, j, c, n) {
  var xl = x & 0x7fff,
    xh = x >> 15;
  while (--n >= 0) {
    var l = this[i] & 0x7fff;
    var h = this[i++] >> 15;
    var m = xh * l + h * xl;
    l = xl * l + ((m & 0x7fff) << 15) + w[j] + (c & 0x3fffffff);
    c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
    w[j++] = l & 0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.

function am3(i, x, w, j, c, n) {
  var xl = x & 0x3fff,
    xh = x >> 14;
  while (--n >= 0) {
    var l = this[i] & 0x3fff;
    var h = this[i++] >> 14;
    var m = xh * l + h * xl;
    l = xl * l + ((m & 0x3fff) << 14) + w[j] + c;
    c = (l >> 28) + (m >> 14) + xh * h;
    w[j++] = l & 0xfffffff;
  }
  return c;
}
/*if(j_lm && (navigator != undefined && 
	navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator != undefined && navigator.appName != "Netscape")) {*/
BigInteger.prototype.am = am1;
dbits = 26;
/*}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype.am = am3;
  dbits = 28;
}*/

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1 << dbits) - 1);
BigInteger.prototype.DV = (1 << dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2, BI_FP);
BigInteger.prototype.F1 = BI_FP - dbits;
BigInteger.prototype.F2 = 2 * dbits - BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr, vv;
rr = "0".charCodeAt(0);
for (vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) {
  return BI_RM.charAt(n);
}

function intAt(s, i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c == null) ? -1 : c;
}

// (protected) copy this to r

function bnpCopyTo(r) {
  for (var i = this.t - 1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV

function bnpFromInt(x) {
  this.t = 1;
  this.s = (x < 0) ? -1 : 0;
  if (x > 0) this[0] = x;
  else if (x < -1) this[0] = x + this.DV;
  else this.t = 0;
}

// return bigint initialized to value

function nbv(i) {
  var r = nbi();
  r.fromInt(i);
  return r;
}

// (protected) set from string and radix

function bnpFromString(s, b) {
  var k;
  if (b == 16) k = 4;
  else if (b == 8) k = 3;
  else if (b == 256) k = 8; // byte array
  else if (b == 2) k = 1;
  else if (b == 32) k = 5;
  else if (b == 4) k = 2;
  else {
    this.fromRadix(s, b);
    return;
  }
  this.t = 0;
  this.s = 0;
  var i = s.length,
    mi = false,
    sh = 0;
  while (--i >= 0) {
    var x = (k == 8) ? s[i] & 0xff : intAt(s, i);
    if (x < 0) {
      if (s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if (sh == 0)
      this[this.t++] = x;
    else if (sh + k > this.DB) {
      this[this.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
      this[this.t++] = (x >> (this.DB - sh));
    } else
      this[this.t - 1] |= x << sh;
    sh += k;
    if (sh >= this.DB) sh -= this.DB;
  }
  if (k == 8 && (s[0] & 0x80) != 0) {
    this.s = -1;
    if (sh > 0) this[this.t - 1] |= ((1 << (this.DB - sh)) - 1) << sh;
  }
  this.clamp();
  if (mi) BigInteger.ZERO.subTo(this, this);
}

// (protected) clamp off excess high words

function bnpClamp() {
  var c = this.s & this.DM;
  while (this.t > 0 && this[this.t - 1] == c)--this.t;
}

// (public) return string representation in given radix

function bnToString(b) {
  if (this.s < 0) return "-" + this.negate().toString(b);
  var k;
  if (b == 16) k = 4;
  else if (b == 8) k = 3;
  else if (b == 2) k = 1;
  else if (b == 32) k = 5;
  else if (b == 4) k = 2;
  else return this.toRadix(b);
  var km = (1 << k) - 1,
    d, m = false,
    r = "",
    i = this.t;
  var p = this.DB - (i * this.DB) % k;
  if (i-- > 0) {
    if (p < this.DB && (d = this[i] >> p) > 0) {
      m = true;
      r = int2char(d);
    }
    while (i >= 0) {
      if (p < k) {
        d = (this[i] & ((1 << p) - 1)) << (k - p);
        d |= this[--i] >> (p += this.DB - k);
      } else {
        d = (this[i] >> (p -= k)) & km;
        if (p <= 0) {
          p += this.DB;
          --i;
        }
      }
      if (d > 0) m = true;
      if (m) r += int2char(d);
    }
  }
  return m ? r : "0";
}

// (public) -this

function bnNegate() {
  var r = nbi();
  BigInteger.ZERO.subTo(this, r);
  return r;
}

// (public) |this|

function bnAbs() {
  return (this.s < 0) ? this.negate() : this;
}

// (public) return + if this > a, - if this < a, 0 if equal

function bnCompareTo(a) {
  var r = this.s - a.s;
  if (r != 0) return r;
  var i = this.t;
  r = i - a.t;
  if (r != 0) return (this.s < 0) ? -r : r;
  while (--i >= 0) if ((r = this[i] - a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x

function nbits(x) {
  var r = 1,
    t;
  if ((t = x >>> 16) != 0) {
    x = t;
    r += 16;
  }
  if ((t = x >> 8) != 0) {
    x = t;
    r += 8;
  }
  if ((t = x >> 4) != 0) {
    x = t;
    r += 4;
  }
  if ((t = x >> 2) != 0) {
    x = t;
    r += 2;
  }
  if ((t = x >> 1) != 0) {
    x = t;
    r += 1;
  }
  return r;
}

// (public) return the number of bits in "this"

function bnBitLength() {
  if (this.t <= 0) return 0;
  return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & this.DM));
}

// (protected) r = this << n*DB

function bnpDLShiftTo(n, r) {
  var i;
  for (i = this.t - 1; i >= 0; --i) r[i + n] = this[i];
  for (i = n - 1; i >= 0; --i) r[i] = 0;
  r.t = this.t + n;
  r.s = this.s;
}

// (protected) r = this >> n*DB

function bnpDRShiftTo(n, r) {
  for (var i = n; i < this.t; ++i) r[i - n] = this[i];
  r.t = Math.max(this.t - n, 0);
  r.s = this.s;
}

// (protected) r = this << n

function bnpLShiftTo(n, r) {
  var bs = n % this.DB;
  var cbs = this.DB - bs;
  var bm = (1 << cbs) - 1;
  var ds = Math.floor(n / this.DB),
    c = (this.s << bs) & this.DM,
    i;
  for (i = this.t - 1; i >= 0; --i) {
    r[i + ds + 1] = (this[i] >> cbs) | c;
    c = (this[i] & bm) << bs;
  }
  for (i = ds - 1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t + ds + 1;
  r.s = this.s;
  r.clamp();
}

// (protected) r = this >> n

function bnpRShiftTo(n, r) {
  r.s = this.s;
  var ds = Math.floor(n / this.DB);
  if (ds >= this.t) {
    r.t = 0;
    return;
  }
  var bs = n % this.DB;
  var cbs = this.DB - bs;
  var bm = (1 << bs) - 1;
  r[0] = this[ds] >> bs;
  for (var i = ds + 1; i < this.t; ++i) {
    r[i - ds - 1] |= (this[i] & bm) << cbs;
    r[i - ds] = this[i] >> bs;
  }
  if (bs > 0) r[this.t - ds - 1] |= (this.s & bm) << cbs;
  r.t = this.t - ds;
  r.clamp();
}

// (protected) r = this - a

function bnpSubTo(a, r) {
  var i = 0,
    c = 0,
    m = Math.min(a.t, this.t);
  while (i < m) {
    c += this[i] - a[i];
    r[i++] = c & this.DM;
    c >>= this.DB;
  }
  if (a.t < this.t) {
    c -= a.s;
    while (i < this.t) {
      c += this[i];
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    c += this.s;
  } else {
    c += this.s;
    while (i < a.t) {
      c -= a[i];
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = (c < 0) ? -1 : 0;
  if (c < -1) r[i++] = this.DV + c;
  else if (c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.

function bnpMultiplyTo(a, r) {
  var x = this.abs(),
    y = a.abs();
  var i = x.t;
  r.t = i + y.t;
  while (--i >= 0) r[i] = 0;
  for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
  r.s = 0;
  r.clamp();
  if (this.s != a.s) BigInteger.ZERO.subTo(r, r);
}

// (protected) r = this^2, r != this (HAC 14.16)

function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2 * x.t;
  while (--i >= 0) r[i] = 0;
  for (i = 0; i < x.t - 1; ++i) {
    var c = x.am(i, x[i], r, 2 * i, 0, 1);
    if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
      r[i + x.t] -= x.DV;
      r[i + x.t + 1] = 1;
    }
  }
  if (r.t > 0) r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
  r.s = 0;
  r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.

function bnpDivRemTo(m, q, r) {
  var pm = m.abs();
  if (pm.t <= 0) return;
  var pt = this.abs();
  if (pt.t < pm.t) {
    if (q != null) q.fromInt(0);
    if (r != null) this.copyTo(r);
    return;
  }
  if (r == null) r = nbi();
  var y = nbi(),
    ts = this.s,
    ms = m.s;
  var nsh = this.DB - nbits(pm[pm.t - 1]); // normalize modulus
  if (nsh > 0) {
    pm.lShiftTo(nsh, y);
    pt.lShiftTo(nsh, r);
  } else {
    pm.copyTo(y);
    pt.copyTo(r);
  }
  var ys = y.t;
  var y0 = y[ys - 1];
  if (y0 == 0) return;
  var yt = y0 * (1 << this.F1) + ((ys > 1) ? y[ys - 2] >> this.F2 : 0);
  var d1 = this.FV / yt,
    d2 = (1 << this.F1) / yt,
    e = 1 << this.F2;
  var i = r.t,
    j = i - ys,
    t = (q == null) ? nbi() : q;
  y.dlShiftTo(j, t);
  if (r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t, r);
  }
  BigInteger.ONE.dlShiftTo(ys, t);
  t.subTo(y, y); // "negative" y so we can replace sub with am later
  while (y.t < ys) y[y.t++] = 0;
  while (--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i] == y0) ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
    if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) { // Try it out
      y.dlShiftTo(j, t);
      r.subTo(t, r);
      while (r[i] < --qd) r.subTo(t, r);
    }
  }
  if (q != null) {
    r.drShiftTo(ys, q);
    if (ts != ms) BigInteger.ZERO.subTo(q, q);
  }
  r.t = ys;
  r.clamp();
  if (nsh > 0) r.rShiftTo(nsh, r); // Denormalize remainder
  if (ts < 0) BigInteger.ZERO.subTo(r, r);
}

// (public) this mod a

function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a, null, r);
  if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r, r);
  return r;
}

// Modular reduction using "classic" algorithm

function Classic(m) {
  this.m = m;
}

function cConvert(x) {
  if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
}

function cRevert(x) {
  return x;
}

function cReduce(x) {
  x.divRemTo(this.m, null, x);
}

function cMulTo(x, y, r) {
  x.multiplyTo(y, r);
  this.reduce(r);
}

function cSqrTo(x, r) {
  x.squareTo(r);
  this.reduce(r);
}

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.

function bnpInvDigit() {
  if (this.t < 1) return 0;
  var x = this[0];
  if ((x & 1) == 0) return 0;
  var y = x & 3; // y == 1/x mod 2^2
  y = (y * (2 - (x & 0xf) * y)) & 0xf; // y == 1/x mod 2^4
  y = (y * (2 - (x & 0xff) * y)) & 0xff; // y == 1/x mod 2^8
  y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff; // y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y * (2 - x * y % this.DV)) % this.DV; // y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y > 0) ? this.DV - y : -y;
}

// Montgomery reduction

function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp & 0x7fff;
  this.mph = this.mp >> 15;
  this.um = (1 << (m.DB - 15)) - 1;
  this.mt2 = 2 * m.t;
}

// xR mod m

function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t, r);
  r.divRemTo(this.m, null, r);
  if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r);
  return r;
}

// x/R mod m

function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)

function montReduce(x) {
  while (x.t <= this.mt2) // pad x so am has enough room later
    x[x.t++] = 0;
  for (var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i] & 0x7fff;
    var u0 = (j * this.mpl + (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) & x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i + this.m.t;
    x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
    // propagate carry
    while (x[j] >= x.DV) {
      x[j] -= x.DV;
      x[++j]++;
    }
  }
  x.clamp();
  x.drShiftTo(this.m.t, x);
  if (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
}

// r = "x^2/R mod m"; x != r

function montSqrTo(x, r) {
  x.squareTo(r);
  this.reduce(r);
}

// r = "xy/R mod m"; x,y != r

function montMulTo(x, y, r) {
  x.multiplyTo(y, r);
  this.reduce(r);
}

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even

function bnpIsEven() {
  return ((this.t > 0) ? (this[0] & 1) : this.s) == 0;
}

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)

function bnpExp(e, z) {
  if (e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(),
    r2 = nbi(),
    g = z.convert(this),
    i = nbits(e) - 1;
  g.copyTo(r);
  while (--i >= 0) {
    z.sqrTo(r, r2);
    if ((e & (1 << i)) > 0) z.mulTo(r2, g, r);
    else {
      var t = r;
      r = r2;
      r2 = t;
    }
  }
  return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32

function bnModPowInt(e, m) {
  var z;
  if (e < 256 || m.isEven()) z = new Classic(m);
  else z = new Montgomery(m);
  return this.exp(e, z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);
BigInteger.TWO = nbv(2);

module.exports = BigInteger;



















/*
 * Copyright (c) 2003-2005  Tom Wu (tjw@cs.Stanford.EDU) 
 * All Rights Reserved.
 *
 * Modified by Recurity Labs GmbH
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY 
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */


// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

// (public)
function bnClone() {
  var r = nbi();
  this.copyTo(r);
  return r;
}

// (public) return value as integer

function bnIntValue() {
  if (this.s < 0) {
    if (this.t == 1) return this[0] - this.DV;
    else if (this.t == 0) return -1;
  } else if (this.t == 1) return this[0];
  else if (this.t == 0) return 0;
  // assumes 16 < DB < 32
  return ((this[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0];
}

// (public) return value as byte

function bnByteValue() {
  return (this.t == 0) ? this.s : (this[0] << 24) >> 24;
}

// (public) return value as short (assumes DB>=16)

function bnShortValue() {
  return (this.t == 0) ? this.s : (this[0] << 16) >> 16;
}

// (protected) return x s.t. r^x < DV

function bnpChunkSize(r) {
  return Math.floor(Math.LN2 * this.DB / Math.log(r));
}

// (public) 0 if this == 0, 1 if this > 0

function bnSigNum() {
  if (this.s < 0) return -1;
  else if (this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
  else return 1;
}

// (protected) convert to radix string

function bnpToRadix(b) {
  if (b == null) b = 10;
  if (this.signum() == 0 || b < 2 || b > 36) return "0";
  var cs = this.chunkSize(b);
  var a = Math.pow(b, cs);
  var d = nbv(a),
    y = nbi(),
    z = nbi(),
    r = "";
  this.divRemTo(d, y, z);
  while (y.signum() > 0) {
    r = (a + z.intValue()).toString(b).substr(1) + r;
    y.divRemTo(d, y, z);
  }
  return z.intValue().toString(b) + r;
}

// (protected) convert from radix string

function bnpFromRadix(s, b) {
  this.fromInt(0);
  if (b == null) b = 10;
  var cs = this.chunkSize(b);
  var d = Math.pow(b, cs),
    mi = false,
    j = 0,
    w = 0;
  for (var i = 0; i < s.length; ++i) {
    var x = intAt(s, i);
    if (x < 0) {
      if (s.charAt(i) == "-" && this.signum() == 0) mi = true;
      continue;
    }
    w = b * w + x;
    if (++j >= cs) {
      this.dMultiply(d);
      this.dAddOffset(w, 0);
      j = 0;
      w = 0;
    }
  }
  if (j > 0) {
    this.dMultiply(Math.pow(b, j));
    this.dAddOffset(w, 0);
  }
  if (mi) BigInteger.ZERO.subTo(this, this);
}

// (protected) alternate constructor

function bnpFromNumber(a, b, c) {
  if ("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if (a < 2) this.fromInt(1);
    else {
      this.fromNumber(a, c);
      if (!this.testBit(a - 1)) // force MSB set
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this);
      if (this.isEven()) this.dAddOffset(1, 0); // force odd
      while (!this.isProbablePrime(b)) {
        this.dAddOffset(2, 0);
        if (this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a - 1), this);
      }
    }
  } else {
    // new BigInteger(int,RNG)
    var x = new Array(),
      t = a & 7;
    x.length = (a >> 3) + 1;
    b.nextBytes(x);
    if (t > 0) x[0] &= ((1 << t) - 1);
    else x[0] = 0;
    this.fromString(x, 256);
  }
}

// (public) convert to bigendian byte array

function bnToByteArray() {
  var i = this.t,
    r = new Array();
  r[0] = this.s;
  var p = this.DB - (i * this.DB) % 8,
    d, k = 0;
  if (i-- > 0) {
    if (p < this.DB && (d = this[i] >> p) != (this.s & this.DM) >> p)
      r[k++] = d | (this.s << (this.DB - p));
    while (i >= 0) {
      if (p < 8) {
        d = (this[i] & ((1 << p) - 1)) << (8 - p);
        d |= this[--i] >> (p += this.DB - 8);
      } else {
        d = (this[i] >> (p -= 8)) & 0xff;
        if (p <= 0) {
          p += this.DB;
          --i;
        }
      }
      //if((d&0x80) != 0) d |= -256;
      //if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
      if (k > 0 || d != this.s) r[k++] = d;
    }
  }
  return r;
}

function bnEquals(a) {
  return (this.compareTo(a) == 0);
}

function bnMin(a) {
  return (this.compareTo(a) < 0) ? this : a;
}

function bnMax(a) {
  return (this.compareTo(a) > 0) ? this : a;
}

// (protected) r = this op a (bitwise)

function bnpBitwiseTo(a, op, r) {
  var i, f, m = Math.min(a.t, this.t);
  for (i = 0; i < m; ++i) r[i] = op(this[i], a[i]);
  if (a.t < this.t) {
    f = a.s & this.DM;
    for (i = m; i < this.t; ++i) r[i] = op(this[i], f);
    r.t = this.t;
  } else {
    f = this.s & this.DM;
    for (i = m; i < a.t; ++i) r[i] = op(f, a[i]);
    r.t = a.t;
  }
  r.s = op(this.s, a.s);
  r.clamp();
}

// (public) this & a

function op_and(x, y) {
  return x & y;
}

function bnAnd(a) {
  var r = nbi();
  this.bitwiseTo(a, op_and, r);
  return r;
}

// (public) this | a

function op_or(x, y) {
  return x | y;
}

function bnOr(a) {
  var r = nbi();
  this.bitwiseTo(a, op_or, r);
  return r;
}

// (public) this ^ a

function op_xor(x, y) {
  return x ^ y;
}

function bnXor(a) {
  var r = nbi();
  this.bitwiseTo(a, op_xor, r);
  return r;
}

// (public) this & ~a

function op_andnot(x, y) {
  return x & ~y;
}

function bnAndNot(a) {
  var r = nbi();
  this.bitwiseTo(a, op_andnot, r);
  return r;
}

// (public) ~this

function bnNot() {
  var r = nbi();
  for (var i = 0; i < this.t; ++i) r[i] = this.DM & ~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}

// (public) this << n

function bnShiftLeft(n) {
  var r = nbi();
  if (n < 0) this.rShiftTo(-n, r);
  else this.lShiftTo(n, r);
  return r;
}

// (public) this >> n

function bnShiftRight(n) {
  var r = nbi();
  if (n < 0) this.lShiftTo(-n, r);
  else this.rShiftTo(n, r);
  return r;
}

// return index of lowest 1-bit in x, x < 2^31

function lbit(x) {
  if (x == 0) return -1;
  var r = 0;
  if ((x & 0xffff) == 0) {
    x >>= 16;
    r += 16;
  }
  if ((x & 0xff) == 0) {
    x >>= 8;
    r += 8;
  }
  if ((x & 0xf) == 0) {
    x >>= 4;
    r += 4;
  }
  if ((x & 3) == 0) {
    x >>= 2;
    r += 2;
  }
  if ((x & 1) == 0)++r;
  return r;
}

// (public) returns index of lowest 1-bit (or -1 if none)

function bnGetLowestSetBit() {
  for (var i = 0; i < this.t; ++i)
    if (this[i] != 0) return i * this.DB + lbit(this[i]);
  if (this.s < 0) return this.t * this.DB;
  return -1;
}

// return number of 1 bits in x

function cbit(x) {
  var r = 0;
  while (x != 0) {
    x &= x - 1;
    ++r;
  }
  return r;
}

// (public) return number of set bits

function bnBitCount() {
  var r = 0,
    x = this.s & this.DM;
  for (var i = 0; i < this.t; ++i) r += cbit(this[i] ^ x);
  return r;
}

// (public) true iff nth bit is set

function bnTestBit(n) {
  var j = Math.floor(n / this.DB);
  if (j >= this.t) return (this.s != 0);
  return ((this[j] & (1 << (n % this.DB))) != 0);
}

// (protected) this op (1<<n)

function bnpChangeBit(n, op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r, op, r);
  return r;
}

// (public) this | (1<<n)

function bnSetBit(n) {
  return this.changeBit(n, op_or);
}

// (public) this & ~(1<<n)

function bnClearBit(n) {
  return this.changeBit(n, op_andnot);
}

// (public) this ^ (1<<n)

function bnFlipBit(n) {
  return this.changeBit(n, op_xor);
}

// (protected) r = this + a

function bnpAddTo(a, r) {
  var i = 0,
    c = 0,
    m = Math.min(a.t, this.t);
  while (i < m) {
    c += this[i] + a[i];
    r[i++] = c & this.DM;
    c >>= this.DB;
  }
  if (a.t < this.t) {
    c += a.s;
    while (i < this.t) {
      c += this[i];
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    c += this.s;
  } else {
    c += this.s;
    while (i < a.t) {
      c += a[i];
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    c += a.s;
  }
  r.s = (c < 0) ? -1 : 0;
  if (c > 0) r[i++] = c;
  else if (c < -1) r[i++] = this.DV + c;
  r.t = i;
  r.clamp();
}

// (public) this + a

function bnAdd(a) {
  var r = nbi();
  this.addTo(a, r);
  return r;
}

// (public) this - a

function bnSubtract(a) {
  var r = nbi();
  this.subTo(a, r);
  return r;
}

// (public) this * a

function bnMultiply(a) {
  var r = nbi();
  this.multiplyTo(a, r);
  return r;
}

// (public) this^2

function bnSquare() {
  var r = nbi();
  this.squareTo(r);
  return r;
}

// (public) this / a

function bnDivide(a) {
  var r = nbi();
  this.divRemTo(a, r, null);
  return r;
}

// (public) this % a

function bnRemainder(a) {
  var r = nbi();
  this.divRemTo(a, null, r);
  return r;
}

// (public) [this/a,this%a]

function bnDivideAndRemainder(a) {
  var q = nbi(),
    r = nbi();
  this.divRemTo(a, q, r);
  return new Array(q, r);
}

// (protected) this *= n, this >= 0, 1 < n < DV

function bnpDMultiply(n) {
  this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
  ++this.t;
  this.clamp();
}

// (protected) this += n << w words, this >= 0

function bnpDAddOffset(n, w) {
  if (n == 0) return;
  while (this.t <= w) this[this.t++] = 0;
  this[w] += n;
  while (this[w] >= this.DV) {
    this[w] -= this.DV;
    if (++w >= this.t) this[this.t++] = 0;
    ++this[w];
  }
}

// A "null" reducer

function NullExp() {}

function nNop(x) {
  return x;
}

function nMulTo(x, y, r) {
  x.multiplyTo(y, r);
}

function nSqrTo(x, r) {
  x.squareTo(r);
}

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e

function bnPow(e) {
  return this.exp(e, new NullExp());
}

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.

function bnpMultiplyLowerTo(a, n, r) {
  var i = Math.min(this.t + a.t, n);
  r.s = 0; // assumes a,this >= 0
  r.t = i;
  while (i > 0) r[--i] = 0;
  var j;
  for (j = r.t - this.t; i < j; ++i) r[i + this.t] = this.am(0, a[i], r, i, 0, this.t);
  for (j = Math.min(a.t, n); i < j; ++i) this.am(0, a[i], r, i, 0, n - i);
  r.clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.

function bnpMultiplyUpperTo(a, n, r) {
  --n;
  var i = r.t = this.t + a.t - n;
  r.s = 0; // assumes a,this >= 0
  while (--i >= 0) r[i] = 0;
  for (i = Math.max(n - this.t, 0); i < a.t; ++i)
    r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n);
  r.clamp();
  r.drShiftTo(1, r);
}

// Barrett modular reduction

function Barrett(m) {
  // setup Barrett
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
  this.mu = this.r2.divide(m);
  this.m = m;
}

function barrettConvert(x) {
  if (x.s < 0 || x.t > 2 * this.m.t) return x.mod(this.m);
  else if (x.compareTo(this.m) < 0) return x;
  else {
    var r = nbi();
    x.copyTo(r);
    this.reduce(r);
    return r;
  }
}

function barrettRevert(x) {
  return x;
}

// x = x mod m (HAC 14.42)

function barrettReduce(x) {
  x.drShiftTo(this.m.t - 1, this.r2);
  if (x.t > this.m.t + 1) {
    x.t = this.m.t + 1;
    x.clamp();
  }
  this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
  this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
  while (x.compareTo(this.r2) < 0) x.dAddOffset(1, this.m.t + 1);
  x.subTo(this.r2, x);
  while (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
}

// r = x^2 mod m; x != r

function barrettSqrTo(x, r) {
  x.squareTo(r);
  this.reduce(r);
}

// r = x*y mod m; x,y != r

function barrettMulTo(x, y, r) {
  x.multiplyTo(y, r);
  this.reduce(r);
}

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)

function bnModPow(e, m) {
  var i = e.bitLength(),
    k, r = nbv(1),
    z;
  if (i <= 0) return r;
  else if (i < 18) k = 1;
  else if (i < 48) k = 3;
  else if (i < 144) k = 4;
  else if (i < 768) k = 5;
  else k = 6;
  if (i < 8)
    z = new Classic(m);
  else if (m.isEven())
    z = new Barrett(m);
  else
    z = new Montgomery(m);

  // precomputation
  var g = new Array(),
    n = 3,
    k1 = k - 1,
    km = (1 << k) - 1;
  g[1] = z.convert(this);
  if (k > 1) {
    var g2 = nbi();
    z.sqrTo(g[1], g2);
    while (n <= km) {
      g[n] = nbi();
      z.mulTo(g2, g[n - 2], g[n]);
      n += 2;
    }
  }

  var j = e.t - 1,
    w, is1 = true,
    r2 = nbi(),
    t;
  i = nbits(e[j]) - 1;
  while (j >= 0) {
    if (i >= k1) w = (e[j] >> (i - k1)) & km;
    else {
      w = (e[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
      if (j > 0) w |= e[j - 1] >> (this.DB + i - k1);
    }

    n = k;
    while ((w & 1) == 0) {
      w >>= 1;
      --n;
    }
    if ((i -= n) < 0) {
      i += this.DB;
      --j;
    }
    if (is1) { // ret == 1, don't bother squaring or multiplying it
      g[w].copyTo(r);
      is1 = false;
    } else {
      while (n > 1) {
        z.sqrTo(r, r2);
        z.sqrTo(r2, r);
        n -= 2;
      }
      if (n > 0) z.sqrTo(r, r2);
      else {
        t = r;
        r = r2;
        r2 = t;
      }
      z.mulTo(r2, g[w], r);
    }

    while (j >= 0 && (e[j] & (1 << i)) == 0) {
      z.sqrTo(r, r2);
      t = r;
      r = r2;
      r2 = t;
      if (--i < 0) {
        i = this.DB - 1;
        --j;
      }
    }
  }
  return z.revert(r);
}

// (public) gcd(this,a) (HAC 14.54)

function bnGCD(a) {
  var x = (this.s < 0) ? this.negate() : this.clone();
  var y = (a.s < 0) ? a.negate() : a.clone();
  if (x.compareTo(y) < 0) {
    var t = x;
    x = y;
    y = t;
  }
  var i = x.getLowestSetBit(),
    g = y.getLowestSetBit();
  if (g < 0) return x;
  if (i < g) g = i;
  if (g > 0) {
    x.rShiftTo(g, x);
    y.rShiftTo(g, y);
  }
  while (x.signum() > 0) {
    if ((i = x.getLowestSetBit()) > 0) x.rShiftTo(i, x);
    if ((i = y.getLowestSetBit()) > 0) y.rShiftTo(i, y);
    if (x.compareTo(y) >= 0) {
      x.subTo(y, x);
      x.rShiftTo(1, x);
    } else {
      y.subTo(x, y);
      y.rShiftTo(1, y);
    }
  }
  if (g > 0) y.lShiftTo(g, y);
  return y;
}

// (protected) this % n, n < 2^26

function bnpModInt(n) {
  if (n <= 0) return 0;
  var d = this.DV % n,
    r = (this.s < 0) ? n - 1 : 0;
  if (this.t > 0)
    if (d == 0) r = this[0] % n;
    else for (var i = this.t - 1; i >= 0; --i) r = (d * r + this[i]) % n;
  return r;
}

// (public) 1/this % m (HAC 14.61)

function bnModInverse(m) {
  var ac = m.isEven();
  if ((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
  var u = m.clone(),
    v = this.clone();
  var a = nbv(1),
    b = nbv(0),
    c = nbv(0),
    d = nbv(1);
  while (u.signum() != 0) {
    while (u.isEven()) {
      u.rShiftTo(1, u);
      if (ac) {
        if (!a.isEven() || !b.isEven()) {
          a.addTo(this, a);
          b.subTo(m, b);
        }
        a.rShiftTo(1, a);
      } else if (!b.isEven()) b.subTo(m, b);
      b.rShiftTo(1, b);
    }
    while (v.isEven()) {
      v.rShiftTo(1, v);
      if (ac) {
        if (!c.isEven() || !d.isEven()) {
          c.addTo(this, c);
          d.subTo(m, d);
        }
        c.rShiftTo(1, c);
      } else if (!d.isEven()) d.subTo(m, d);
      d.rShiftTo(1, d);
    }
    if (u.compareTo(v) >= 0) {
      u.subTo(v, u);
      if (ac) a.subTo(c, a);
      b.subTo(d, b);
    } else {
      v.subTo(u, v);
      if (ac) c.subTo(a, c);
      d.subTo(b, d);
    }
  }
  if (v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
  if (d.compareTo(m) >= 0) return d.subtract(m);
  if (d.signum() < 0) d.addTo(m, d);
  else return d;
  if (d.signum() < 0) return d.add(m);
  else return d;
}

var lowprimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
    103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
    229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359,
    367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499,
    503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647,
    653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
    821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971,
    977, 983, 991, 997
];
var lplim = (1 << 26) / lowprimes[lowprimes.length - 1];

// (public) test primality with certainty >= 1-.5^t

function bnIsProbablePrime(t) {
  var i, x = this.abs();
  if (x.t == 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
    for (i = 0; i < lowprimes.length; ++i)
      if (x[0] == lowprimes[i]) return true;
    return false;
  }
  if (x.isEven()) return false;
  i = 1;
  while (i < lowprimes.length) {
    var m = lowprimes[i],
      j = i + 1;
    while (j < lowprimes.length && m < lplim) m *= lowprimes[j++];
    m = x.modInt(m);
    while (i < j) if (m % lowprimes[i++] == 0) return false;
  }
  return x.millerRabin(t);
}

/* added by Recurity Labs */

function nbits(x) {
  var n = 1,
    t;
  if ((t = x >>> 16) != 0) {
    x = t;
    n += 16;
  }
  if ((t = x >> 8) != 0) {
    x = t;
    n += 8;
  }
  if ((t = x >> 4) != 0) {
    x = t;
    n += 4;
  }
  if ((t = x >> 2) != 0) {
    x = t;
    n += 2;
  }
  if ((t = x >> 1) != 0) {
    x = t;
    n += 1;
  }
  return n;
}

function bnToMPI() {
  var ba = this.toByteArray();
  var size = (ba.length - 1) * 8 + nbits(ba[0]);
  var result = "";
  result += String.fromCharCode((size & 0xFF00) >> 8);
  result += String.fromCharCode(size & 0xFF);
  result += util.bin2str(ba);
  return result;
}
/* END of addition */

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if (k <= 0) return false;
  var r = n1.shiftRight(k);
  t = (t + 1) >> 1;
  if (t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  var j, bases = [];
  for (var i = 0; i < t; ++i) {
    //Pick bases at random, instead of starting at 2
    for (;;) {
      j = lowprimes[Math.floor(Math.random() * lowprimes.length)];
      if (bases.indexOf(j) == -1) break;
    }
    bases.push(j);
    a.fromInt(j);
    var y = a.modPow(r, this);
    if (y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while (j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2, this);
        if (y.compareTo(BigInteger.ONE) == 0) return false;
      }
      if (y.compareTo(n1) != 0) return false;
    }
  }
  return true;
}

var BigInteger = require('./jsbn.js');

// protected
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;
BigInteger.prototype.toMPI = bnToMPI;

// JSBN-specific extension
BigInteger.prototype.square = bnSquare;

},{"../../util.js":95,"./jsbn.js":54}],55:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
//
// RSA implementation

/**
 * @requires crypto/public_key/jsbn
 * @requires crypto/random
 * @requires util
 * @module crypto/public_key/rsa
 */

var BigInteger = require('./jsbn.js'),
  util = require('../../util.js'),
  random = require('../random.js'),
  config = require('../../config');

function SecureRandom() {
  function nextBytes(byteArray) {
    for (var n = 0; n < byteArray.length; n++) {
      byteArray[n] = random.getSecureRandomOctet();
    }
  }
  this.nextBytes = nextBytes;
}

var blinder = BigInteger.ZERO;
var unblinder = BigInteger.ZERO;

function blind(m, n, e) {
  if (unblinder.bitLength() === n.bitLength()) {
    unblinder = unblinder.square().mod(n);
  } else {
    unblinder = random.getRandomBigIntegerInRange(BigInteger.TWO, n);
  }
  blinder = unblinder.modInverse(n).modPow(e, n);
  return m.multiply(blinder).mod(n);
}

function unblind(t, n) {
  return t.multiply(unblinder).mod(n);
}

function RSA() {
  /**
   * This function uses jsbn Big Num library to decrypt RSA
   * @param m
   *            message
   * @param n
   *            RSA public modulus n as BigInteger
   * @param e
   *            RSA public exponent as BigInteger
   * @param d
   *            RSA d as BigInteger
   * @param p
   *            RSA p as BigInteger
   * @param q
   *            RSA q as BigInteger
   * @param u
   *            RSA u as BigInteger
   * @return {BigInteger} The decrypted value of the message
   */
  function decrypt(m, n, e, d, p, q, u) {
    if (config.rsa_blinding) {
      m = blind(m, n, e);
    }
    var xp = m.mod(p).modPow(d.mod(p.subtract(BigInteger.ONE)), p);
    var xq = m.mod(q).modPow(d.mod(q.subtract(BigInteger.ONE)), q);
    util.print_debug("rsa.js decrypt\nxpn:" + util.hexstrdump(xp.toMPI()) + "\nxqn:" + util.hexstrdump(xq.toMPI()));

    var t = xq.subtract(xp);
    if (t[0] === 0) {
      t = xp.subtract(xq);
      t = t.multiply(u).mod(q);
      t = q.subtract(t);
    } else {
      t = t.multiply(u).mod(q);
    }
    t = t.multiply(p).add(xp);
    if (config.rsa_blinding) {
      t = unblind(t, n);
    }
    return t;
  }

  /**
   * encrypt message
   * @param m message as BigInteger
   * @param e public MPI part as BigInteger
   * @param n public MPI part as BigInteger
   * @return BigInteger
   */
  function encrypt(m, e, n) {
    return m.modPowInt(e, n);
  }

  /* Sign and Verify */
  function sign(m, d, n) {
    return m.modPow(d, n);
  }

  function verify(x, e, n) {
    return x.modPowInt(e, n);
  }

  // "empty" RSA key constructor

  function keyObject() {
    this.n = null;
    this.e = 0;
    this.ee = null;
    this.d = null;
    this.p = null;
    this.q = null;
    this.dmp1 = null;
    this.dmq1 = null;
    this.u = null;
  }

  // Generate a new random private key B bits long, using public expt E

  function generate(B, E, prng) {
    var webCrypto = util.getWebCrypto();

    //
    // Native RSA keygen using Web Crypto
    //

    if (webCrypto && typeof prng === "undefined") {
      var Euint32 = new Uint32Array([parseInt(E, 16)]); // get integer of exponent
      var Euint8 = new Uint8Array(Euint32.buffer); // get bytes of exponent
      var keyGenOpt;

      if (window.crypto.subtle) {
        // current standard spec
        keyGenOpt = {
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: B, // the specified keysize in bits
          publicExponent: Euint8.subarray(0, 3), // take three bytes (max 65537)
          hash: {
            name: 'SHA-1' // not required for actual RSA keys, but for crypto api 'sign' and 'verify'
          }
        };
        return webCrypto.generateKey(keyGenOpt, true, ['sign', 'verify']).then(exportKey).then(decodeKey);

      } else if (window.crypto.webkitSubtle) {
        // outdated spec implemented by Webkit
        keyGenOpt = {
          name: 'RSA-OAEP',
          modulusLength: B, // the specified keysize in bits
          publicExponent: Euint8.subarray(0, 3), // take three bytes (max 65537)
        };
        return webCrypto.generateKey(keyGenOpt, true, ['encrypt', 'decrypt']).then(exportKey).then(function(key) {
          if (key instanceof ArrayBuffer) {
            // parse raw ArrayBuffer bytes to jwk/json (WebKit/Safari quirk)
            return decodeKey(JSON.parse(String.fromCharCode.apply(null, new Uint8Array(key))));
          }
          return decodeKey(key);
        });
      }
    }

    function exportKey(keypair) {
      // export the generated keys as JsonWebKey (JWK)
      // https://tools.ietf.org/html/draft-ietf-jose-json-web-key-33
      return webCrypto.exportKey('jwk', keypair.privateKey);
    }

    function decodeKey(jwk) {
      // map JWK parameters to local BigInteger type system
      var key = new keyObject();
      key.n = toBigInteger(jwk.n);
      key.ee = new BigInteger(E, 16);
      key.d = toBigInteger(jwk.d);
      key.p = toBigInteger(jwk.p);
      key.q = toBigInteger(jwk.q);
      key.u = key.p.modInverse(key.q);

      function toBigInteger(base64url) {
        var base64 = base64url.replace(/\-/g, '+').replace(/_/g, '/');
        var hex = util.hexstrdump(atob(base64));
        return new BigInteger(hex, 16);
      }

      return key;
    }

    //
    // JS code
    //

    return new Promise(function(resolve) {
      var key = new keyObject();
      var rng = new SecureRandom();
      if (prng) {
        rng = prng;
      }
      var qs = B >> 1;
      key.e = parseInt(E, 16);
      key.ee = new BigInteger(E, 16);

      for (;;) {
        for (;;) {
          key.p = new BigInteger(B - qs, 1, rng);
          if (key.p.subtract(BigInteger.ONE).gcd(key.ee).compareTo(BigInteger.ONE) === 0 && key.p.isProbablePrime(10))
            break;
        }
        for (;;) {
          key.q = new BigInteger(qs, 1, rng);
          if (key.q.subtract(BigInteger.ONE).gcd(key.ee).compareTo(BigInteger.ONE) === 0 && key.q.isProbablePrime(10))
            break;
        }
        if (key.p.compareTo(key.q) <= 0) {
          var t = key.p;
          key.p = key.q;
          key.q = t;
        }
        var p1 = key.p.subtract(BigInteger.ONE);
        var q1 = key.q.subtract(BigInteger.ONE);
        var phi = p1.multiply(q1);
        if (phi.gcd(key.ee).compareTo(BigInteger.ONE) === 0) {
          key.n = key.p.multiply(key.q);
          key.d = key.ee.modInverse(phi);
          key.dmp1 = key.d.mod(p1);
          key.dmq1 = key.d.mod(q1);
          key.u = key.p.modInverse(key.q);
          break;
        }
      }

      resolve(key);
    });
  }

  this.encrypt = encrypt;
  this.decrypt = decrypt;
  this.verify = verify;
  this.sign = sign;
  this.generate = generate;
  this.keyObject = keyObject;
}

module.exports = RSA;

},{"../../config":33,"../../util.js":95,"../random.js":56,"./jsbn.js":54}],56:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA 

// The GPG4Browsers crypto interface

/**
 * @requires type/mpi
 * @module crypto/random
 */

var type_mpi = require('../type/mpi.js');
var nodeCrypto = null;

if (typeof window === 'undefined') {
  nodeCrypto = require('crypto');
}

module.exports = {
  /**
   * Retrieve secure random byte string of the specified length
   * @param {Integer} length Length in bytes to generate
   * @return {String} Random byte string
   */
  getRandomBytes: function(length) {
    var result = '';
    for (var i = 0; i < length; i++) {
      result += String.fromCharCode(this.getSecureRandomOctet());
    }
    return result;
  },

  /**
   * Return a secure random number in the specified range
   * @param {Integer} from Min of the random number
   * @param {Integer} to Max of the random number (max 32bit)
   * @return {Integer} A secure random number
   */
  getSecureRandom: function(from, to) {
    var randUint = this.getSecureRandomUint();
    var bits = ((to - from)).toString(2).length;
    while ((randUint & (Math.pow(2, bits) - 1)) > (to - from)) {
      randUint = this.getSecureRandomUint();
    }
    return from + (Math.abs(randUint & (Math.pow(2, bits) - 1)));
  },

  getSecureRandomOctet: function() {
    var buf = new Uint8Array(1);
    this.getRandomValues(buf);
    return buf[0];
  },

  getSecureRandomUint: function() {
    var buf = new Uint8Array(4);
    var dv = new DataView(buf.buffer);
    this.getRandomValues(buf);
    return dv.getUint32(0);
  },

  /**
   * Helper routine which calls platform specific crypto random generator
   * @param {Uint8Array} buf
   */
  getRandomValues: function(buf) {
    if (!(buf instanceof Uint8Array)) {
      throw new Error('Invalid type: buf not an Uint8Array');
    }
    if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(buf);
    } else if (typeof window !== 'undefined' && typeof window.msCrypto === 'object' && typeof window.msCrypto.getRandomValues === 'function') {
      window.msCrypto.getRandomValues(buf);
    } else if (nodeCrypto) {
      var bytes = nodeCrypto.randomBytes(buf.length);
      buf.set(bytes);
    } else if (this.randomBuffer.buffer) {
      this.randomBuffer.get(buf);
    } else {
      throw new Error('No secure random number generator available.');
    }
  },

  /**
   * Create a secure random big integer of bits length
   * @param {Integer} bits Bit length of the MPI to create
   * @return {BigInteger} Resulting big integer
   */
  getRandomBigInteger: function(bits) {
    if (bits < 1) {
      throw new Error('Illegal parameter value: bits < 1');
    }
    var numBytes = Math.floor((bits + 7) / 8);

    var randomBits = this.getRandomBytes(numBytes);
    if (bits % 8 > 0) {

      randomBits = String.fromCharCode(
      (Math.pow(2, bits % 8) - 1) &
        randomBits.charCodeAt(0)) +
        randomBits.substring(1);
    }
    var mpi = new type_mpi();
    mpi.fromBytes(randomBits);
    return mpi.toBigInteger();
  },

  getRandomBigIntegerInRange: function(min, max) {
    if (max.compareTo(min) <= 0) {
      throw new Error('Illegal parameter value: max <= min');
    }

    var range = max.subtract(min);
    var r = this.getRandomBigInteger(range.bitLength());
    while (r.compareTo(range) > 0) {
      r = this.getRandomBigInteger(range.bitLength());
    }
    return min.add(r);
  },

  randomBuffer: new RandomBuffer()

};

/**
 * Buffer for secure random numbers
 */
function RandomBuffer() {
  this.buffer = null;
  this.size = null;
}

/**
 * Initialize buffer
 * @param  {Integer} size size of buffer
 */
RandomBuffer.prototype.init = function(size) {
  this.buffer = new Uint8Array(size);
  this.size = 0;
};

/**
 * Concat array of secure random numbers to buffer
 * @param {Uint8Array} buf
 */
RandomBuffer.prototype.set = function(buf) {
  if (!this.buffer) {
    throw new Error('RandomBuffer is not initialized');
  }
  if (!(buf instanceof Uint8Array)) {
    throw new Error('Invalid type: buf not an Uint8Array');
  }
  var freeSpace = this.buffer.length - this.size;
  if (buf.length > freeSpace) {
    buf = buf.subarray(0, freeSpace);
  }
  // set buf with offset old size of buffer
  this.buffer.set(buf, this.size);
  this.size += buf.length;
};

/**
 * Take numbers out of buffer and copy to array
 * @param {Uint8Array} buf the destination array
 */
RandomBuffer.prototype.get = function(buf) {
  if (!this.buffer) {
    throw new Error('RandomBuffer is not initialized');
  }
  if (!(buf instanceof Uint8Array)) {
    throw new Error('Invalid type: buf not an Uint8Array');
  }
  if (this.size < buf.length) {
    throw new Error('Random number buffer depleted');
  }
  for (var i = 0; i < buf.length; i++) {
    buf[i] = this.buffer[--this.size];
    // clear buffer value
    this.buffer[this.size] = 0;
  }
};

},{"../type/mpi.js":93,"crypto":false}],57:[function(require,module,exports){
/**
 * @requires crypto/hash
 * @requires crypto/pkcs1
 * @requires crypto/public_key
 * @module crypto/signature */

var publicKey = require('./public_key'),
  pkcs1 = require('./pkcs1.js'),
  hashModule = require('./hash');

module.exports = {
  /**
   * 
   * @param {module:enums.publicKey} algo public Key algorithm
   * @param {module:enums.hash} hash_algo Hash algorithm
   * @param {Array<module:type/mpi>} msg_MPIs Signature multiprecision integers
   * @param {Array<module:type/mpi>} publickey_MPIs Public key multiprecision integers 
   * @param {String} data Data on where the signature was computed on.
   * @return {Boolean} true if signature (sig_data was equal to data over hash)
   */
  verify: function(algo, hash_algo, msg_MPIs, publickey_MPIs, data) {

    switch (algo) {
      case 1:
        // RSA (Encrypt or Sign) [HAC]  
      case 2:
        // RSA Encrypt-Only [HAC]
      case 3:
        // RSA Sign-Only [HAC]
        var rsa = new publicKey.rsa();
        var n = publickey_MPIs[0].toBigInteger();
        var k = publickey_MPIs[0].byteLength();
        var e = publickey_MPIs[1].toBigInteger();
        var m = msg_MPIs[0].toBigInteger();
        var EM = rsa.verify(m, e, n);
        var EM2 = pkcs1.emsa.encode(hash_algo, data, k);
        return EM.compareTo(EM2) === 0;
      case 16:
        // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
        throw new Error("signing with Elgamal is not defined in the OpenPGP standard.");
      case 17:
        // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
        var dsa = new publicKey.dsa();
        var s1 = msg_MPIs[0].toBigInteger();
        var s2 = msg_MPIs[1].toBigInteger();
        var p = publickey_MPIs[0].toBigInteger();
        var q = publickey_MPIs[1].toBigInteger();
        var g = publickey_MPIs[2].toBigInteger();
        var y = publickey_MPIs[3].toBigInteger();
        var m = data;
        var dopublic = dsa.verify(hash_algo, s1, s2, m, p, q, g, y);
        return dopublic.compareTo(s1) === 0;
      default:
        throw new Error('Invalid signature algorithm.');
    }
  },

  /**
   * Create a signature on data using the specified algorithm
   * @param {module:enums.hash} hash_algo hash Algorithm to use (See {@link http://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @param {module:enums.publicKey} algo Asymmetric cipher algorithm to use (See {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1})
   * @param {Array<module:type/mpi>} publicMPIs Public key multiprecision integers 
   * of the private key 
   * @param {Array<module:type/mpi>} secretMPIs Private key multiprecision 
   * integers which is used to sign the data
   * @param {String} data Data to be signed
   * @return {Array<module:type/mpi>}
   */
  sign: function(hash_algo, algo, keyIntegers, data) {

    var m;

    switch (algo) {
      case 1:
        // RSA (Encrypt or Sign) [HAC]  
      case 2:
        // RSA Encrypt-Only [HAC]
      case 3:
        // RSA Sign-Only [HAC]
        var rsa = new publicKey.rsa();
        var d = keyIntegers[2].toBigInteger();
        var n = keyIntegers[0].toBigInteger();
        m = pkcs1.emsa.encode(hash_algo,
          data, keyIntegers[0].byteLength());

        return rsa.sign(m, d, n).toMPI();

      case 17:
        // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
        var dsa = new publicKey.dsa();

        var p = keyIntegers[0].toBigInteger();
        var q = keyIntegers[1].toBigInteger();
        var g = keyIntegers[2].toBigInteger();
        var y = keyIntegers[3].toBigInteger();
        var x = keyIntegers[4].toBigInteger();
        m = data;
        var result = dsa.sign(hash_algo, m, g, p, q, x);

        return result[0].toString() + result[1].toString();
      case 16:
        // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
        throw new Error('Signing with Elgamal is not defined in the OpenPGP standard.');
      default:
        throw new Error('Invalid signature algorithm.');
    }
  }
};

},{"./hash":45,"./pkcs1.js":50,"./public_key":53}],58:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires encoding/base64
 * @requires enums
 * @requires config
 * @module encoding/armor
 */

var base64 = require('./base64.js'),
  enums = require('../enums.js'),
  config = require('../config');

/**
 * Finds out which Ascii Armoring type is used. Throws error if unknown type.
 * @private
 * @param {String} text [String] ascii armored text
 * @returns {Integer} 0 = MESSAGE PART n of m
 *         1 = MESSAGE PART n
 *         2 = SIGNED MESSAGE
 *         3 = PGP MESSAGE
 *         4 = PUBLIC KEY BLOCK
 *         5 = PRIVATE KEY BLOCK
 */
function getType(text) {
  var reHeader = /^-----BEGIN PGP (MESSAGE, PART \d+\/\d+|MESSAGE, PART \d+|SIGNED MESSAGE|MESSAGE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK|SIGNATURE)-----$\n/m;

  var header = text.match(reHeader);

  if (!header) {
    throw new Error('Unknown ASCII armor type');
  }

  // BEGIN PGP MESSAGE, PART X/Y
  // Used for multi-part messages, where the armor is split amongst Y
  // parts, and this is the Xth part out of Y.
  if (header[1].match(/MESSAGE, PART \d+\/\d+/)) {
    return enums.armor.multipart_section;
  } else
  // BEGIN PGP MESSAGE, PART X
  // Used for multi-part messages, where this is the Xth part of an
  // unspecified number of parts. Requires the MESSAGE-ID Armor
  // Header to be used.
  if (header[1].match(/MESSAGE, PART \d+/)) {
    return enums.armor.multipart_last;

  } else
  // BEGIN PGP SIGNATURE
  // Used for detached signatures, OpenPGP/MIME signatures, and
  // cleartext signatures. Note that PGP 2.x uses BEGIN PGP MESSAGE
  // for detached signatures.
  if (header[1].match(/SIGNED MESSAGE/)) {
    return enums.armor.signed;

  } else
  // BEGIN PGP MESSAGE
  // Used for signed, encrypted, or compressed files.
  if (header[1].match(/MESSAGE/)) {
    return enums.armor.message;

  } else
  // BEGIN PGP PUBLIC KEY BLOCK
  // Used for armoring public keys.
  if (header[1].match(/PUBLIC KEY BLOCK/)) {
    return enums.armor.public_key;

  } else
  // BEGIN PGP PRIVATE KEY BLOCK
  // Used for armoring private keys.
  if (header[1].match(/PRIVATE KEY BLOCK/)) {
    return enums.armor.private_key;
  }
}

/**
 * Add additional information to the armor version of an OpenPGP binary
 * packet block.
 * @author  Alex
 * @version 2011-12-16
 * @returns {String} The header information
 */
function addheader() {
  var result = "";
  if (config.show_version) {
    result += "Version: " + config.versionstring + '\r\n';
  }
  if (config.show_comment) {
    result += "Comment: " + config.commentstring + '\r\n';
  }
  result += '\r\n';
  return result;
}



/**
 * Calculates a checksum over the given data and returns it base64 encoded
 * @param {String} data Data to create a CRC-24 checksum for
 * @return {String} Base64 encoded checksum
 */
function getCheckSum(data) {
  var c = createcrc24(data);
  var str = "" + String.fromCharCode(c >> 16) +
    String.fromCharCode((c >> 8) & 0xFF) +
    String.fromCharCode(c & 0xFF);
  return base64.encode(str);
}

/**
 * Calculates the checksum over the given data and compares it with the
 * given base64 encoded checksum
 * @param {String} data Data to create a CRC-24 checksum for
 * @param {String} checksum Base64 encoded checksum
 * @return {Boolean} True if the given checksum is correct; otherwise false
 */
function verifyCheckSum(data, checksum) {
  var c = getCheckSum(data);
  var d = checksum;
  return c[0] == d[0] && c[1] == d[1] && c[2] == d[2] && c[3] == d[3];
}
/**
 * Internal function to calculate a CRC-24 checksum over a given string (data)
 * @param {String} data Data to create a CRC-24 checksum for
 * @return {Integer} The CRC-24 checksum as number
 */
var crc_table = [
    0x00000000, 0x00864cfb, 0x018ad50d, 0x010c99f6, 0x0393e6e1, 0x0315aa1a, 0x021933ec, 0x029f7f17, 0x07a18139,
    0x0727cdc2, 0x062b5434, 0x06ad18cf, 0x043267d8, 0x04b42b23, 0x05b8b2d5, 0x053efe2e, 0x0fc54e89, 0x0f430272,
    0x0e4f9b84, 0x0ec9d77f, 0x0c56a868, 0x0cd0e493, 0x0ddc7d65, 0x0d5a319e, 0x0864cfb0, 0x08e2834b, 0x09ee1abd,
    0x09685646, 0x0bf72951, 0x0b7165aa, 0x0a7dfc5c, 0x0afbb0a7, 0x1f0cd1e9, 0x1f8a9d12, 0x1e8604e4, 0x1e00481f,
    0x1c9f3708, 0x1c197bf3, 0x1d15e205, 0x1d93aefe, 0x18ad50d0, 0x182b1c2b, 0x192785dd, 0x19a1c926, 0x1b3eb631,
    0x1bb8faca, 0x1ab4633c, 0x1a322fc7, 0x10c99f60, 0x104fd39b, 0x11434a6d, 0x11c50696, 0x135a7981, 0x13dc357a,
    0x12d0ac8c, 0x1256e077, 0x17681e59, 0x17ee52a2, 0x16e2cb54, 0x166487af, 0x14fbf8b8, 0x147db443, 0x15712db5,
    0x15f7614e, 0x3e19a3d2, 0x3e9fef29, 0x3f9376df, 0x3f153a24, 0x3d8a4533, 0x3d0c09c8, 0x3c00903e, 0x3c86dcc5,
    0x39b822eb, 0x393e6e10, 0x3832f7e6, 0x38b4bb1d, 0x3a2bc40a, 0x3aad88f1, 0x3ba11107, 0x3b275dfc, 0x31dced5b,
    0x315aa1a0,
    0x30563856, 0x30d074ad, 0x324f0bba, 0x32c94741, 0x33c5deb7, 0x3343924c, 0x367d6c62, 0x36fb2099, 0x37f7b96f,
    0x3771f594, 0x35ee8a83, 0x3568c678, 0x34645f8e, 0x34e21375, 0x2115723b, 0x21933ec0, 0x209fa736, 0x2019ebcd,
    0x228694da, 0x2200d821, 0x230c41d7, 0x238a0d2c, 0x26b4f302, 0x2632bff9, 0x273e260f, 0x27b86af4, 0x252715e3,
    0x25a15918, 0x24adc0ee, 0x242b8c15, 0x2ed03cb2, 0x2e567049, 0x2f5ae9bf, 0x2fdca544, 0x2d43da53, 0x2dc596a8,
    0x2cc90f5e, 0x2c4f43a5, 0x2971bd8b, 0x29f7f170, 0x28fb6886, 0x287d247d, 0x2ae25b6a, 0x2a641791, 0x2b688e67,
    0x2beec29c, 0x7c3347a4, 0x7cb50b5f, 0x7db992a9, 0x7d3fde52, 0x7fa0a145, 0x7f26edbe, 0x7e2a7448, 0x7eac38b3,
    0x7b92c69d, 0x7b148a66, 0x7a181390, 0x7a9e5f6b, 0x7801207c, 0x78876c87, 0x798bf571, 0x790db98a, 0x73f6092d,
    0x737045d6, 0x727cdc20, 0x72fa90db, 0x7065efcc, 0x70e3a337, 0x71ef3ac1, 0x7169763a, 0x74578814, 0x74d1c4ef,
    0x75dd5d19, 0x755b11e2, 0x77c46ef5, 0x7742220e, 0x764ebbf8, 0x76c8f703, 0x633f964d, 0x63b9dab6, 0x62b54340,
    0x62330fbb,
    0x60ac70ac, 0x602a3c57, 0x6126a5a1, 0x61a0e95a, 0x649e1774, 0x64185b8f, 0x6514c279, 0x65928e82, 0x670df195,
    0x678bbd6e, 0x66872498, 0x66016863, 0x6cfad8c4, 0x6c7c943f, 0x6d700dc9, 0x6df64132, 0x6f693e25, 0x6fef72de,
    0x6ee3eb28, 0x6e65a7d3, 0x6b5b59fd, 0x6bdd1506, 0x6ad18cf0, 0x6a57c00b, 0x68c8bf1c, 0x684ef3e7, 0x69426a11,
    0x69c426ea, 0x422ae476, 0x42aca88d, 0x43a0317b, 0x43267d80, 0x41b90297, 0x413f4e6c, 0x4033d79a, 0x40b59b61,
    0x458b654f, 0x450d29b4, 0x4401b042, 0x4487fcb9, 0x461883ae, 0x469ecf55, 0x479256a3, 0x47141a58, 0x4defaaff,
    0x4d69e604, 0x4c657ff2, 0x4ce33309, 0x4e7c4c1e, 0x4efa00e5, 0x4ff69913, 0x4f70d5e8, 0x4a4e2bc6, 0x4ac8673d,
    0x4bc4fecb, 0x4b42b230, 0x49ddcd27, 0x495b81dc, 0x4857182a, 0x48d154d1, 0x5d26359f, 0x5da07964, 0x5cace092,
    0x5c2aac69, 0x5eb5d37e, 0x5e339f85, 0x5f3f0673, 0x5fb94a88, 0x5a87b4a6, 0x5a01f85d, 0x5b0d61ab, 0x5b8b2d50,
    0x59145247, 0x59921ebc, 0x589e874a, 0x5818cbb1, 0x52e37b16, 0x526537ed, 0x5369ae1b, 0x53efe2e0, 0x51709df7,
    0x51f6d10c,
    0x50fa48fa, 0x507c0401, 0x5542fa2f, 0x55c4b6d4, 0x54c82f22, 0x544e63d9, 0x56d11cce, 0x56575035, 0x575bc9c3,
    0x57dd8538
];

function createcrc24(input) {
  var crc = 0xB704CE;
  var index = 0;

  while ((input.length - index) > 16) {
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index)) & 0xff];
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index + 1)) & 0xff];
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index + 2)) & 0xff];
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index + 3)) & 0xff];
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index + 4)) & 0xff];
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index + 5)) & 0xff];
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index + 6)) & 0xff];
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index + 7)) & 0xff];
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index + 8)) & 0xff];
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index + 9)) & 0xff];
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index + 10)) & 0xff];
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index + 11)) & 0xff];
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index + 12)) & 0xff];
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index + 13)) & 0xff];
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index + 14)) & 0xff];
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index + 15)) & 0xff];
    index += 16;
  }

  for (var j = index; j < input.length; j++) {
    crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index++)) & 0xff];
  }
  return crc & 0xffffff;
}

/**
 * Splits a message into two parts, the headers and the body. This is an internal function
 * @param {String} text OpenPGP armored message part
 * @returns {(Boolean|Object)} Either false in case of an error
 * or an object with attribute "headers" containing the headers and
 * and an attribute "body" containing the body.
 */
function splitHeaders(text) {
  // empty line with whitespace characters
  var reEmptyLine = /^[ \f\r\t\u00a0\u2000-\u200a\u202f\u205f\u3000]*\n/m;
  var headers = '';
  var body = text;

  var matchResult = reEmptyLine.exec(text);

  if (matchResult !== null) {
    headers = text.slice(0, matchResult.index);
    body = text.slice(matchResult.index + matchResult[0].length);
  } else {
    throw new Error('Mandatory blank line missing between armor headers and armor data');
  }

  headers = headers.split('\n');
  // remove empty entry
  headers.pop();

  return { headers: headers, body: body };
}

/**
 * Verify armored headers. RFC4880, section 6.3: "OpenPGP should consider improperly formatted
 * Armor Headers to be corruption of the ASCII Armor."
 * @private
 * @param  {Array<String>} headers Armor headers
 */
function verifyHeaders(headers) {
  for (var i = 0; i < headers.length; i++) {
    if (!headers[i].match(/^(Version|Comment|MessageID|Hash|Charset): .+$/)) {
      throw new Error('Improperly formatted armor header: ' + headers[i]);;
    }
  }
}

/**
 * Splits a message into two parts, the body and the checksum. This is an internal function
 * @param {String} text OpenPGP armored message part
 * @returns {(Boolean|Object)} Either false in case of an error
 * or an object with attribute "body" containing the body
 * and an attribute "checksum" containing the checksum.
 */
function splitChecksum(text) {
  var reChecksumStart = /^=/m;
  var body = text;
  var checksum = "";

  var matchResult = reChecksumStart.exec(text);

  if (matchResult !== null) {
    body = text.slice(0, matchResult.index);
    checksum = text.slice(matchResult.index + 1);
  }

  return { body: body, checksum: checksum };
}

/**
 * DeArmor an OpenPGP armored message; verify the checksum and return
 * the encoded bytes
 * @param {String} text OpenPGP armored message
 * @returns {Object} An object with attribute "text" containing the message text,
 * an attribute "data" containing the bytes and "type" for the ASCII armor type
 * @static
 */
function dearmor(text) {
  var reSplit = /^-----[^-]+-----$\n/m;

  // remove trailing whitespace at end of line
  text = text.replace(/[\t\r ]+\n/g, '\n');

  var type = getType(text);

  var splittext = text.split(reSplit);

  // IE has a bug in split with a re. If the pattern matches the beginning of the
  // string it doesn't create an empty array element 0. So we need to detect this
  // so we know the index of the data we are interested in.
  var indexBase = 1;

  var result, checksum, msg;

  if (text.search(reSplit) != splittext[0].length) {
    indexBase = 0;
  }

  if (type != 2) {
    msg = splitHeaders(splittext[indexBase]);
    var msg_sum = splitChecksum(msg.body);

    result = {
      data: base64.decode(msg_sum.body),
      headers: msg.headers,
      type: type
    };

    checksum = msg_sum.checksum;
  } else {
    // Reverse dash-escaping for msg
    msg = splitHeaders(splittext[indexBase].replace(/^- /mg, ''));
    var sig = splitHeaders(splittext[indexBase + 1].replace(/^- /mg, ''));
    verifyHeaders(sig.headers);
    var sig_sum = splitChecksum(sig.body);

    result = {
      text:  msg.body.replace(/\n$/, '').replace(/\n/g, "\r\n"),
      data: base64.decode(sig_sum.body),
      headers: msg.headers,
      type: type
    };

    checksum = sig_sum.checksum;
  }

  checksum = checksum.substr(0, 4);

  if (!verifyCheckSum(result.data, checksum)) {
    throw new Error("Ascii armor integrity check on message failed: '" +
      checksum +
      "' should be '" +
      getCheckSum(result.data) + "'");
  }

  verifyHeaders(result.headers);

  return result;
}


/**
 * Armor an OpenPGP binary packet block
 * @param {Integer} messagetype type of the message
 * @param body
 * @param {Integer} partindex
 * @param {Integer} parttotal
 * @returns {String} Armored text
 * @static
 */
function armor(messagetype, body, partindex, parttotal) {
  var result = "";
  switch (messagetype) {
    case enums.armor.multipart_section:
      result += "-----BEGIN PGP MESSAGE, PART " + partindex + "/" + parttotal + "-----\r\n";
      result += addheader();
      result += base64.encode(body);
      result += "\r\n=" + getCheckSum(body) + "\r\n";
      result += "-----END PGP MESSAGE, PART " + partindex + "/" + parttotal + "-----\r\n";
      break;
    case enums.armor.multipart_last:
      result += "-----BEGIN PGP MESSAGE, PART " + partindex + "-----\r\n";
      result += addheader();
      result += base64.encode(body);
      result += "\r\n=" + getCheckSum(body) + "\r\n";
      result += "-----END PGP MESSAGE, PART " + partindex + "-----\r\n";
      break;
    case enums.armor.signed:
      result += "\r\n-----BEGIN PGP SIGNED MESSAGE-----\r\n";
      result += "Hash: " + body.hash + "\r\n\r\n";
      result += body.text.replace(/\n-/g, "\n- -");
      result += "\r\n-----BEGIN PGP SIGNATURE-----\r\n";
      result += addheader();
      result += base64.encode(body.data);
      result += "\r\n=" + getCheckSum(body.data) + "\r\n";
      result += "-----END PGP SIGNATURE-----\r\n";
      break;
    case enums.armor.message:
      result += "-----BEGIN PGP MESSAGE-----\r\n";
      result += addheader();
      result += base64.encode(body);
      result += "\r\n=" + getCheckSum(body) + "\r\n";
      result += "-----END PGP MESSAGE-----\r\n";
      break;
    case enums.armor.public_key:
      result += "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n";
      result += addheader();
      result += base64.encode(body);
      result += "\r\n=" + getCheckSum(body) + "\r\n";
      result += "-----END PGP PUBLIC KEY BLOCK-----\r\n\r\n";
      break;
    case enums.armor.private_key:
      result += "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n";
      result += addheader();
      result += base64.encode(body);
      result += "\r\n=" + getCheckSum(body) + "\r\n";
      result += "-----END PGP PRIVATE KEY BLOCK-----\r\n";
      break;
  }
  return result;
}

module.exports = {
  encode: armor,
  decode: dearmor
};

},{"../config":33,"../enums.js":60,"./base64.js":59}],59:[function(require,module,exports){
/* OpenPGP radix-64/base64 string encoding/decoding
 * Copyright 2005 Herbert Hanewinkel, www.haneWIN.de
 * version 1.0, check www.haneWIN.de for the latest version
 *
 * This software is provided as-is, without express or implied warranty.  
 * Permission to use, copy, modify, distribute or sell this software, with or
 * without fee, for any purpose and by any individual or organization, is hereby
 * granted, provided that the above copyright notice and this paragraph appear 
 * in all copies. Distribution as a part of an application or binary must
 * include the above copyright notice in the documentation and/or other materials
 * provided with the application or distribution.
 */

/**
 * @module encoding/base64
 */

var b64s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Convert binary string to radix-64
 * @param {String} t binary string to convert
 * @returns {string} radix-64 version of input string
 * @static
 */
function s2r(t) {
  var a, c, n;
  var r = '',
    l = 0,
    s = 0;
  var tl = t.length;

  for (n = 0; n < tl; n++) {
    c = t.charCodeAt(n);
    if (s === 0) {
      r += b64s.charAt((c >> 2) & 63);
      a = (c & 3) << 4;
    } else if (s == 1) {
      r += b64s.charAt((a | (c >> 4) & 15));
      a = (c & 15) << 2;
    } else if (s == 2) {
      r += b64s.charAt(a | ((c >> 6) & 3));
      l += 1;
      if ((l % 60) === 0)
        r += "\n";
      r += b64s.charAt(c & 63);
    }
    l += 1;
    if ((l % 60) === 0)
      r += "\n";

    s += 1;
    if (s == 3)
      s = 0;
  }
  if (s > 0) {
    r += b64s.charAt(a);
    l += 1;
    if ((l % 60) === 0)
      r += "\n";
    r += '=';
    l += 1;
  }
  if (s == 1) {
    if ((l % 60) === 0)
      r += "\n";
    r += '=';
  }

  return r;
}

/**
 * Convert radix-64 to binary string
 * @param {String} t radix-64 string to convert
 * @returns {string} binary version of input string
 * @static
 */
function r2s(t) {
  var c, n;
  var r = '',
    s = 0,
    a = 0;
  var tl = t.length;

  for (n = 0; n < tl; n++) {
    c = b64s.indexOf(t.charAt(n));
    if (c >= 0) {
      if (s)
        r += String.fromCharCode(a | (c >> (6 - s)) & 255);
      s = (s + 2) & 7;
      a = (c << s) & 255;
    }
  }
  return r;
}

module.exports = {
  encode: s2r,
  decode: r2s
};

},{}],60:[function(require,module,exports){
'use strict';

/**
 * @module enums
 */

module.exports = {

  /** A string to key specifier type
   * @enum {Integer}
   * @readonly
   */
  s2k: {
    simple: 0,
    salted: 1,
    iterated: 3,
    gnu: 101
  },

  /** {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC4880, section 9.1}
   * @enum {Integer}
   * @readonly
   */
  publicKey: {
    rsa_encrypt_sign: 1,
    rsa_encrypt: 2,
    rsa_sign: 3,
    elgamal: 16,
    dsa: 17
  },

  /** {@link http://tools.ietf.org/html/rfc4880#section-9.2|RFC4880, section 9.2}
   * @enum {Integer}
   * @readonly
   */
  symmetric: {
    plaintext: 0,
    /** Not implemented! */
    idea: 1,
    tripledes: 2,
    cast5: 3,
    blowfish: 4,
    aes128: 7,
    aes192: 8,
    aes256: 9,
    twofish: 10
  },

  /** {@link http://tools.ietf.org/html/rfc4880#section-9.3|RFC4880, section 9.3}
   * @enum {Integer}
   * @readonly
   */
  compression: {
    uncompressed: 0,
    /** RFC1951 */
    zip: 1,
    /** RFC1950 */
    zlib: 2,
    bzip2: 3
  },

  /** {@link http://tools.ietf.org/html/rfc4880#section-9.4|RFC4880, section 9.4}
   * @enum {Integer}
   * @readonly
   */
  hash: {
    md5: 1,
    sha1: 2,
    ripemd: 3,
    sha256: 8,
    sha384: 9,
    sha512: 10,
    sha224: 11
  },

  /** A list of packet types and numeric tags associated with them.
   * @enum {Integer}
   * @readonly
   */
  packet: {
    publicKeyEncryptedSessionKey: 1,
    signature: 2,
    symEncryptedSessionKey: 3,
    onePassSignature: 4,
    secretKey: 5,
    publicKey: 6,
    secretSubkey: 7,
    compressed: 8,
    symmetricallyEncrypted: 9,
    marker: 10,
    literal: 11,
    trust: 12,
    userid: 13,
    publicSubkey: 14,
    userAttribute: 17,
    symEncryptedIntegrityProtected: 18,
    modificationDetectionCode: 19
  },

  /** Data types in the literal packet
   * @enum {Integer}
   * @readonly
   */
  literal: {
    /** Binary data 'b' */
    binary: 'b'.charCodeAt(),
    /** Text data 't' */
    text: 't'.charCodeAt(),
    /** Utf8 data 'u' */
    utf8: 'u'.charCodeAt()
  },


  /** One pass signature packet type
   * @enum {Integer}
   * @readonly
   */
  signature: {
    /** 0x00: Signature of a binary document. */
    binary: 0,
    /** 0x01: Signature of a canonical text document.<br/>
     * Canonicalyzing the document by converting line endings. */
    text: 1,
    /** 0x02: Standalone signature.<br/>
     * This signature is a signature of only its own subpacket contents.
     * It is calculated identically to a signature over a zero-lengh
     * binary document.  Note that it doesn't make sense to have a V3
     * standalone signature. */
    standalone: 2,
    /** 0x10: Generic certification of a User ID and Public-Key packet.<br/>
     * The issuer of this certification does not make any particular
     * assertion as to how well the certifier has checked that the owner
     * of the key is in fact the person described by the User ID. */
    cert_generic: 16,
    /** 0x11: Persona certification of a User ID and Public-Key packet.<br/>
     * The issuer of this certification has not done any verification of
     * the claim that the owner of this key is the User ID specified. */
    cert_persona: 17,
    /** 0x12: Casual certification of a User ID and Public-Key packet.<br/>
     * The issuer of this certification has done some casual
     * verification of the claim of identity. */
    cert_casual: 18,
    /** 0x13: Positive certification of a User ID and Public-Key packet.<br/>
     * The issuer of this certification has done substantial
     * verification of the claim of identity.<br/>
     * <br/>
     * Most OpenPGP implementations make their "key signatures" as 0x10
     * certifications.  Some implementations can issue 0x11-0x13
     * certifications, but few differentiate between the types. */
    cert_positive: 19,
    /** 0x30: Certification revocation signature<br/>
     * This signature revokes an earlier User ID certification signature
     * (signature class 0x10 through 0x13) or direct-key signature
     * (0x1F).  It should be issued by the same key that issued the
     * revoked signature or an authorized revocation key.  The signature
     * is computed over the same data as the certificate that it
     * revokes, and should have a later creation date than that
     * certificate. */
    cert_revocation: 48,
    /** 0x18: Subkey Binding Signature<br/>
     * This signature is a statement by the top-level signing key that
     * indicates that it owns the subkey.  This signature is calculated
     * directly on the primary key and subkey, and not on any User ID or
     * other packets.  A signature that binds a signing subkey MUST have
     * an Embedded Signature subpacket in this binding signature that
     * contains a 0x19 signature made by the signing subkey on the
     * primary key and subkey. */
    subkey_binding: 24,
    /** 0x19: Primary Key Binding Signature<br/>
     * This signature is a statement by a signing subkey, indicating
     * that it is owned by the primary key and subkey.  This signature
     * is calculated the same way as a 0x18 signature: directly on the
     * primary key and subkey, and not on any User ID or other packets.<br/>
     * <br/>
     * When a signature is made over a key, the hash data starts with the
     * octet 0x99, followed by a two-octet length of the key, and then body
     * of the key packet.  (Note that this is an old-style packet header for
     * a key packet with two-octet length.)  A subkey binding signature
     * (type 0x18) or primary key binding signature (type 0x19) then hashes
     * the subkey using the same format as the main key (also using 0x99 as
     * the first octet). */
    key_binding: 25,
    /** 0x1F: Signature directly on a key<br/>
     * This signature is calculated directly on a key.  It binds the
     * information in the Signature subpackets to the key, and is
     * appropriate to be used for subpackets that provide information
     * about the key, such as the Revocation Key subpacket.  It is also
     * appropriate for statements that non-self certifiers want to make
     * about the key itself, rather than the binding between a key and a
     * name. */
    key: 31,
    /** 0x20: Key revocation signature<br/>
     * The signature is calculated directly on the key being revoked.  A
     * revoked key is not to be used.  Only revocation signatures by the
     * key being revoked, or by an authorized revocation key, should be
     * considered valid revocation signatures.a */
    key_revocation: 32,
    /** 0x28: Subkey revocation signature<br/>
     * The signature is calculated directly on the subkey being revoked.
     * A revoked subkey is not to be used.  Only revocation signatures
     * by the top-level signature key that is bound to this subkey, or
     * by an authorized revocation key, should be considered valid
     * revocation signatures.<br/>
     * <br/>
     * Key revocation signatures (types 0x20 and 0x28)
     * hash only the key being revoked. */
    subkey_revocation: 40,
    /** 0x40: Timestamp signature.<br/>
     * This signature is only meaningful for the timestamp contained in
     * it. */
    timestamp: 64,
    /** 0x50: Third-Party Confirmation signature.<br/>
     * This signature is a signature over some other OpenPGP Signature
     * packet(s).  It is analogous to a notary seal on the signed data.
     * A third-party signature SHOULD include Signature Target
     * subpacket(s) to give easy identification.  Note that we really do
     * mean SHOULD.  There are plausible uses for this (such as a blind
     * party that only sees the signature, not the key or source
     * document) that cannot include a target subpacket. */
    third_party: 80
  },

  /** Signature subpacket type
   * @enum {Integer}
   * @readonly
   */
  signatureSubpacket: {
    signature_creation_time: 2,
    signature_expiration_time: 3,
    exportable_certification: 4,
    trust_signature: 5,
    regular_expression: 6,
    revocable: 7,
    key_expiration_time: 9,
    placeholder_backwards_compatibility: 10,
    preferred_symmetric_algorithms: 11,
    revocation_key: 12,
    issuer: 16,
    notation_data: 20,
    preferred_hash_algorithms: 21,
    preferred_compression_algorithms: 22,
    key_server_preferences: 23,
    preferred_key_server: 24,
    primary_user_id: 25,
    policy_uri: 26,
    key_flags: 27,
    signers_user_id: 28,
    reason_for_revocation: 29,
    features: 30,
    signature_target: 31,
    embedded_signature: 32
  },

  /** Key flags
   * @enum {Integer}
   * @readonly
   */
  keyFlags: {
    /** 0x01 - This key may be used to certify other keys. */
    certify_keys: 1,
    /** 0x02 - This key may be used to sign data. */
    sign_data: 2,
    /** 0x04 - This key may be used to encrypt communications. */
    encrypt_communication: 4,
    /** 0x08 - This key may be used to encrypt storage. */
    encrypt_storage: 8,
    /** 0x10 - The private component of this key may have been split
     *        by a secret-sharing mechanism. */
    split_private_key: 16,
    /** 0x20 - This key may be used for authentication. */
    authentication: 32,
    /** 0x80 - The private component of this key may be in the
     *        possession of more than one person. */
    shared_private_key: 128
  },

  /** Key status
   * @enum {Integer}
   * @readonly
   */
  keyStatus: {
    invalid:      0,
    expired:      1,
    revoked:      2,
    valid:        3,
    no_self_cert: 4
  },

  /** Armor type
   * @enum {Integer}
   * @readonly
   */
  armor: {
    multipart_section: 0,
    multipart_last: 1,
    signed: 2,
    message: 3,
    public_key: 4,
    private_key: 5
  },

  /** Asserts validity and converts from string/integer to integer. */
  write: function(type, e) {
    if (typeof e == 'number') {
      e = this.read(type, e);
    }

    if (type[e] !== undefined) {
      return type[e];
    } else throw new Error('Invalid enum value.');
  },
  /** Converts from an integer to string. */
  read: function(type, e) {
    for (var i in type)
      if (type[i] == e) return i;

    throw new Error('Invalid enum value.');
  }
};

},{}],61:[function(require,module,exports){
'use strict';

module.exports = require('./openpgp.js');
/**
 * @see module:key
 * @name module:openpgp.key
 */
module.exports.key = require('./key.js');
/**
 * @see module:message
 * @name module:openpgp.message
 */
module.exports.message = require('./message.js');
/**
 * @see module:stream
 * @name module:openpgp.stream
 */
module.exports.stream = require('./stream');
/**
 * @see module:cleartext
 * @name module:openpgp.cleartext
 */
module.exports.cleartext = require('./cleartext.js');
/**
 * @see module:util
 * @name module:openpgp.util
 */
module.exports.util = require('./util.js');
/**
 * @see module:packet
 * @name module:openpgp.packet
 */
module.exports.packet = require('./packet');
/**
 * @see module:type/mpi
 * @name module:openpgp.MPI
 */
module.exports.MPI = require('./type/mpi.js');
/**
 * @see module:type/s2k
 * @name module:openpgp.S2K
 */
module.exports.S2K = require('./type/s2k.js');
/**
 * @see module:type/keyid
 * @name module:openpgp.Keyid
 */
module.exports.Keyid = require('./type/keyid.js');
/**
 * @see module:encoding/armor
 * @name module:openpgp.armor
 */
module.exports.armor = require('./encoding/armor.js');
/**
 * @see module:enums
 * @name module:openpgp.enums
 */
module.exports.enums = require('./enums.js');
/**
 * @see module:config/config
 * @name module:openpgp.config
 */
module.exports.config = require('./config/config.js');
/**
 * @see module:crypto
 * @name module:openpgp.crypto
 */
module.exports.crypto = require('./crypto');
/**
 * @see module:keyring
 * @name module:openpgp.Keyring
 */
module.exports.Keyring = require('./keyring');
/**
 * @see module:worker/async_proxy
 * @name module:openpgp.AsyncProxy
 */
module.exports.AsyncProxy = require('./worker/async_proxy.js');

},{"./cleartext.js":28,"./config/config.js":32,"./crypto":49,"./encoding/armor.js":58,"./enums.js":60,"./key.js":62,"./keyring":63,"./message.js":66,"./openpgp.js":67,"./packet":70,"./stream":89,"./type/keyid.js":92,"./type/mpi.js":93,"./type/s2k.js":94,"./util.js":95,"./worker/async_proxy.js":96}],62:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires config
 * @requires encoding/armor
 * @requires enums
 * @requires packet
 * @module key
 */

'use strict';

var packet = require('./packet'),
  enums = require('./enums.js'),
  armor = require('./encoding/armor.js'),
  config = require('./config'),
  util = require('./util');

/**
 * @class
 * @classdesc Class that represents an OpenPGP key. Must contain a primary key.
 * Can contain additional subkeys, signatures, user ids, user attributes.
 * @param  {module:packet/packetlist} packetlist The packets that form this key
 */

function Key(packetlist) {
  if (!(this instanceof Key)) {
    return new Key(packetlist);
  }
  // same data as in packetlist but in structured form
  this.primaryKey = null;
  this.revocationSignature = null;
  this.directSignatures = null;
  this.users = null;
  this.subKeys = null;
  this.packetlist2structure(packetlist);
  if (!this.primaryKey || !this.users) {
    throw new Error('Invalid key: need at least key and user ID packet');
  }
}

/**
 * Transforms packetlist to structured key data
 * @param  {module:packet/packetlist} packetlist The packets that form a key
 */
Key.prototype.packetlist2structure = function(packetlist) {
  var user, primaryKeyId, subKey;
  for (var i = 0; i < packetlist.length; i++) {
    switch (packetlist[i].tag) {
      case enums.packet.publicKey:
      case enums.packet.secretKey:
        this.primaryKey = packetlist[i];
        primaryKeyId = this.primaryKey.getKeyId();
        break;
      case enums.packet.userid:
      case enums.packet.userAttribute:
        user = new User(packetlist[i]);
        if (!this.users) this.users = [];
        this.users.push(user);
        break;
      case enums.packet.publicSubkey:
      case enums.packet.secretSubkey:
        user = null;
        if (!this.subKeys) this.subKeys = [];
        subKey = new SubKey(packetlist[i]);
        this.subKeys.push(subKey);
        break;
      case enums.packet.signature:
        switch (packetlist[i].signatureType) {
          case enums.signature.cert_generic:
          case enums.signature.cert_persona:
          case enums.signature.cert_casual:
          case enums.signature.cert_positive:
            if (!user) {
              util.print_debug('Dropping certification signatures without preceding user packet');
              continue;
            }
            if (packetlist[i].issuerKeyId.equals(primaryKeyId)) {
              if (!user.selfCertifications) user.selfCertifications = [];
              user.selfCertifications.push(packetlist[i]);
            } else {
              if (!user.otherCertifications) user.otherCertifications = [];
              user.otherCertifications.push(packetlist[i]);
            }
            break;
          case enums.signature.cert_revocation:
            if (user) {
              if (!user.revocationCertifications) user.revocationCertifications = [];
              user.revocationCertifications.push(packetlist[i]);
            } else {
              if (!this.directSignatures) this.directSignatures = [];
              this.directSignatures.push(packetlist[i]);
            }
            break;
          case enums.signature.key:
            if (!this.directSignatures) this.directSignatures = [];
            this.directSignatures.push(packetlist[i]);
            break;
          case enums.signature.subkey_binding:
            if (!subKey) {
              util.print_debug('Dropping subkey binding signature without preceding subkey packet');
              continue;
            }
            subKey.bindingSignature = packetlist[i];
            break;
          case enums.signature.key_revocation:
            this.revocationSignature = packetlist[i];
            break;
          case enums.signature.subkey_revocation:
            if (!subKey) {
              util.print_debug('Dropping subkey revocation signature without preceding subkey packet');
              continue;
            }
            subKey.revocationSignature = packetlist[i];
            break;
        }
        break;
    }
  }
};

/**
 * Transforms structured key data to packetlist
 * @return {module:packet/packetlist} The packets that form a key
 */
Key.prototype.toPacketlist = function() {
  var packetlist = new packet.List();
  packetlist.push(this.primaryKey);
  packetlist.push(this.revocationSignature);
  packetlist.concat(this.directSignatures);
  var i;
  for (i = 0; i < this.users.length; i++) {
    packetlist.concat(this.users[i].toPacketlist());
  }
  if (this.subKeys) {
    for (i = 0; i < this.subKeys.length; i++) {
      packetlist.concat(this.subKeys[i].toPacketlist());
    }
  }
  return packetlist;
};

/**
 * Returns all the private and public subkey packets
 * @returns {Array<(module:packet/public_subkey|module:packet/secret_subkey)>}
 */
Key.prototype.getSubkeyPackets = function() {
  var subKeys = [];
  if (this.subKeys) {
    for (var i = 0; i < this.subKeys.length; i++) {
      subKeys.push(this.subKeys[i].subKey);
    }
  }
  return subKeys;
};

/**
 * Returns all the private and public key and subkey packets
 * @returns {Array<(module:packet/public_subkey|module:packet/secret_subkey|module:packet/secret_key|module:packet/public_key)>}
 */
Key.prototype.getAllKeyPackets = function() {
  return [this.primaryKey].concat(this.getSubkeyPackets());
};

/**
 * Returns key IDs of all key packets
 * @returns {Array<module:type/keyid>}
 */
Key.prototype.getKeyIds = function() {
  var keyIds = [];
  var keys = this.getAllKeyPackets();
  for (var i = 0; i < keys.length; i++) {
    keyIds.push(keys[i].getKeyId());
  }
  return keyIds;
};

/**
 * Returns first key packet for given array of key IDs
 * @param  {Array<module:type/keyid>} keyIds
 * @return {(module:packet/public_subkey|module:packet/public_key|
 *           module:packet/secret_subkey|module:packet/secret_key|null)}
 */
Key.prototype.getKeyPacket = function(keyIds) {
  var keys = this.getAllKeyPackets();
  for (var i = 0; i < keys.length; i++) {
    var keyId = keys[i].getKeyId();
    for (var j = 0; j < keyIds.length; j++) {
      if (keyId.equals(keyIds[j])) {
        return keys[i];
      }
    }
  }
  return null;
};

/**
 * Returns userids
 * @return {Array<string>} array of userids
 */
Key.prototype.getUserIds = function() {
  var userids = [];
  for (var i = 0; i < this.users.length; i++) {
    if (this.users[i].userId) {
      userids.push(this.users[i].userId.write());
    }
  }
  return userids;
};

/**
 * Returns true if this is a public key
 * @return {Boolean}
 */
Key.prototype.isPublic = function() {
  return this.primaryKey.tag == enums.packet.publicKey;
};

/**
 * Returns true if this is a private key
 * @return {Boolean}
 */
Key.prototype.isPrivate = function() {
  return this.primaryKey.tag == enums.packet.secretKey;
};

/**
 * Returns key as public key (shallow copy)
 * @return {module:key~Key} new public Key
 */
Key.prototype.toPublic = function() {
  var packetlist = new packet.List();
  var keyPackets = this.toPacketlist();
  var bytes;
  for (var i = 0; i < keyPackets.length; i++) {
    switch (keyPackets[i].tag) {
      case enums.packet.secretKey:
        bytes = keyPackets[i].writePublicKey();
        var pubKeyPacket = new packet.PublicKey();
        pubKeyPacket.read(bytes);
        packetlist.push(pubKeyPacket);
        break;
      case enums.packet.secretSubkey:
        bytes = keyPackets[i].writePublicKey();
        var pubSubkeyPacket = new packet.PublicSubkey();
        pubSubkeyPacket.read(bytes);
        packetlist.push(pubSubkeyPacket);
        break;
      default:
        packetlist.push(keyPackets[i]);
    }
  }
  return new Key(packetlist);
};

/**
 * Returns ASCII armored text of key
 * @return {String} ASCII armor
 */
Key.prototype.armor = function() {
  var type = this.isPublic() ? enums.armor.public_key : enums.armor.private_key;
  return armor.encode(type, this.toPacketlist().write());
};

/**
 * Returns first key packet or key packet by given keyId that is available for signing or signature verification
 * @param  {module:type/keyid} keyId, optional
 * @return {(module:packet/secret_subkey|module:packet/secret_key|null)} key packet or null if no signing key has been found
 */
Key.prototype.getSigningKeyPacket = function(keyId) {
  var primaryUser = this.getPrimaryUser();
  if (primaryUser &&
      isValidSigningKeyPacket(this.primaryKey, primaryUser.selfCertificate) &&
      (!keyId || this.primaryKey.getKeyId().equals(keyId))) {
    return this.primaryKey;
  }
  if (this.subKeys) {
    for (var i = 0; i < this.subKeys.length; i++) {
      if (this.subKeys[i].isValidSigningKey(this.primaryKey) &&
          (!keyId || this.subKeys[i].subKey.getKeyId().equals(keyId))) {
        return this.subKeys[i].subKey;
      }
    }
  }
  return null;
};

/**
 * Returns preferred signature hash algorithm of this key
 * @return {String}
 */
Key.prototype.getPreferredHashAlgorithm = function() {
  var primaryUser = this.getPrimaryUser();
  if (primaryUser && primaryUser.selfCertificate.preferredHashAlgorithms) {
    return primaryUser.selfCertificate.preferredHashAlgorithms[0];
  }
  return config.prefer_hash_algorithm;
};

function isValidEncryptionKeyPacket(keyPacket, signature) {
  return keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.dsa) &&
         keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.rsa_sign) &&
         (!signature.keyFlags ||
          (signature.keyFlags[0] & enums.keyFlags.encrypt_communication) !== 0 ||
          (signature.keyFlags[0] & enums.keyFlags.encrypt_storage) !== 0);
}

function isValidSigningKeyPacket(keyPacket, signature) {
  return (keyPacket.algorithm == enums.read(enums.publicKey, enums.publicKey.dsa) ||
          keyPacket.algorithm == enums.read(enums.publicKey, enums.publicKey.rsa_sign) ||
          keyPacket.algorithm == enums.read(enums.publicKey, enums.publicKey.rsa_encrypt_sign)) &&
         (!signature.keyFlags ||
          (signature.keyFlags[0] & enums.keyFlags.sign_data) !== 0);
}

/**
 * Returns the first valid encryption key packet for this key
 * @returns {(module:packet/public_subkey|module:packet/secret_subkey|module:packet/secret_key|module:packet/public_key|null)} key packet or null if no encryption key has been found
 */
Key.prototype.getEncryptionKeyPacket = function() {
  // V4: by convention subkeys are prefered for encryption service
  // V3: keys MUST NOT have subkeys
  if (this.subKeys) {
    for (var i = 0; i < this.subKeys.length; i++) {
      if (this.subKeys[i].isValidEncryptionKey(this.primaryKey)) {
        return this.subKeys[i].subKey;
      }
    }
  }
  // if no valid subkey for encryption, evaluate primary key
  var primaryUser = this.getPrimaryUser();
  if (primaryUser &&
      isValidEncryptionKeyPacket(this.primaryKey, primaryUser.selfCertificate)) {
    return this.primaryKey;
  }
  return null;
};

/**
 * Decrypts all secret key and subkey packets
 * @param  {String} passphrase
 * @return {Boolean} true if all key and subkey packets decrypted successfully
 */
Key.prototype.decrypt = function(passphrase) {
  if (this.isPrivate()) {
    var keys = this.getAllKeyPackets();
    for (var i = 0; i < keys.length; i++) {
      var success = keys[i].decrypt(passphrase);
      if (!success) return false;
    }
  } else {
    throw new Error("Nothing to decrypt in a public key");
  }
  return true;
};

/**
 * Decrypts specific key packets by key ID
 * @param  {Array<module:type/keyid>} keyIds
 * @param  {String} passphrase
 * @return {Boolean} true if all key packets decrypted successfully
 */
Key.prototype.decryptKeyPacket = function(keyIds, passphrase) {
  if (this.isPrivate()) {
    var keys = this.getAllKeyPackets();
    for (var i = 0; i < keys.length; i++) {
      var keyId = keys[i].getKeyId();
      for (var j = 0; j < keyIds.length; j++) {
        if (keyId.equals(keyIds[j])) {
          var success = keys[i].decrypt(passphrase);
          if (!success) return false;
        }
      }
    }
  } else {
    throw new Error("Nothing to decrypt in a public key");
  }
  return true;
};

/**
 * Verify primary key. Checks for revocation signatures, expiration time
 * and valid self signature
 * @return {module:enums.keyStatus} The status of the primary key
 */
Key.prototype.verifyPrimaryKey = function() {
  // check revocation signature
  if (this.revocationSignature && !this.revocationSignature.isExpired() &&
     (this.revocationSignature.verified ||
      this.revocationSignature.verify(this.primaryKey, {key: this.primaryKey}))) {
    return enums.keyStatus.revoked;
  }
  // check V3 expiration time
  if (this.primaryKey.version == 3 && this.primaryKey.expirationTimeV3 !== 0 &&
    Date.now() > (this.primaryKey.created.getTime() + this.primaryKey.expirationTimeV3*24*3600*1000)) {
    return enums.keyStatus.expired;
  }
  // check for at least one self signature. Self signature of user ID not mandatory
  // See {@link http://tools.ietf.org/html/rfc4880#section-11.1}
  var selfSigned = false;
  for (var i = 0; i < this.users.length; i++) {
    if (this.users[i].userId && this.users[i].selfCertifications) {
      selfSigned = true;
    }
  }
  if (!selfSigned) {
    return enums.keyStatus.no_self_cert;
  }
  // check for valid self signature
  var primaryUser = this.getPrimaryUser();
  if (!primaryUser) {
    return enums.keyStatus.invalid;
  }
  // check V4 expiration time
  if (this.primaryKey.version == 4 && primaryUser.selfCertificate.keyNeverExpires === false &&
    Date.now() > (this.primaryKey.created.getTime() + primaryUser.selfCertificate.keyExpirationTime*1000)) {
    return enums.keyStatus.expired;
  }
  return enums.keyStatus.valid;
};

/**
 * Returns the expiration time of the primary key or null if key does not expire
 * @return {Date|null}
 */
Key.prototype.getExpirationTime = function() {
  if (this.primaryKey.version == 3) {
    return getExpirationTime(this.primaryKey);
  }
  if (this.primaryKey.version == 4) {
    var primaryUser = this.getPrimaryUser();
    if (!primaryUser) {
      return null;
    }
    return getExpirationTime(this.primaryKey, primaryUser.selfCertificate);
  }
};


function getExpirationTime(keyPacket, selfCertificate) {
  // check V3 expiration time
  if (keyPacket.version == 3 && keyPacket.expirationTimeV3 !== 0) {
    return new Date(keyPacket.created.getTime() + keyPacket.expirationTimeV3*24*3600*1000);
  }
  // check V4 expiration time
  if (keyPacket.version == 4 && selfCertificate.keyNeverExpires === false) {
    return new Date(keyPacket.created.getTime() + selfCertificate.keyExpirationTime*1000);
  }
  return null;
}

/**
 * Returns primary user and most significant (latest valid) self signature
 * - if multiple users are marked as primary users returns the one with the latest self signature
 * - if no primary user is found returns the user with the latest self signature
 * @return {{user: Array<module:packet/User>, selfCertificate: Array<module:packet/signature>}|null} The primary user and the self signature
 */
Key.prototype.getPrimaryUser = function() {
  var primUser = [];
  for (var i = 0; i < this.users.length; i++) {
    if (!this.users[i].userId || !this.users[i].selfCertifications) {
      continue;
    }
    for (var j = 0; j < this.users[i].selfCertifications.length; j++) {
      primUser.push({user: this.users[i], selfCertificate: this.users[i].selfCertifications[j]});
    }
  }
  // sort by primary user flag and signature creation time
  primUser = primUser.sort(function(a, b) {
    if (a.selfCertificate.isPrimaryUserID > b.selfCertificate.isPrimaryUserID) {
      return -1;
    } else if (a.selfCertificate.isPrimaryUserID < b.selfCertificate.isPrimaryUserID) {
      return 1;
    } else if (a.selfCertificate.created > b.selfCertificate.created) {
      return -1;
    } else if (a.selfCertificate.created < b.selfCertificate.created) {
      return 1;
    } else {
      return 0;
    }
  });
  // return first valid
  for (var i = 0; i < primUser.length; i++) {
    if (primUser[i].user.isValidSelfCertificate(this.primaryKey, primUser[i].selfCertificate)) {
      return primUser[i];
    }
  }
  return null;
};

/**
 * Update key with new components from specified key with same key ID:
 * users, subkeys, certificates are merged into the destination key,
 * duplicates are ignored.
 * If the specified key is a private key and the destination key is public,
 * the destination key is tranformed to a private key.
 * @param  {module:key~Key} key source key to merge
 */
Key.prototype.update = function(key) {
  var that = this;
  if (key.verifyPrimaryKey() === enums.keyStatus.invalid) {
    return;
  }
  if (this.primaryKey.getFingerprint() !== key.primaryKey.getFingerprint()) {
    throw new Error('Key update method: fingerprints of keys not equal');
  }
  if (this.isPublic() && key.isPrivate()) {
    // check for equal subkey packets
    var equal = ((this.subKeys && this.subKeys.length) === (key.subKeys && key.subKeys.length)) &&
                (!this.subKeys || this.subKeys.every(function(destSubKey) {
                  return key.subKeys.some(function(srcSubKey) {
                    return destSubKey.subKey.getFingerprint() === srcSubKey.subKey.getFingerprint();
                  });
                }));
    if (!equal) {
      throw new Error('Cannot update public key with private key if subkey mismatch');
    }
    this.primaryKey = key.primaryKey;
  }
  // revocation signature
  if (!this.revocationSignature && key.revocationSignature && !key.revocationSignature.isExpired() &&
     (key.revocationSignature.verified ||
      key.revocationSignature.verify(key.primaryKey, {key: key.primaryKey}))) {
    this.revocationSignature = key.revocationSignature;
  }
  // direct signatures
  mergeSignatures(key, this, 'directSignatures');
  // users
  key.users.forEach(function(srcUser) {
    var found = false;
    for (var i = 0; i < that.users.length; i++) {
      if (srcUser.userId && (srcUser.userId.userid === that.users[i].userId.userid) ||
          srcUser.userAttribute && (srcUser.userAttribute.equals(that.users[i].userAttribute))) {
        that.users[i].update(srcUser, that.primaryKey);
        found = true;
        break;
      }
    }
    if (!found) {
      that.users.push(srcUser);
    }
  });
  // subkeys
  if (key.subKeys) {
    key.subKeys.forEach(function(srcSubKey) {
      var found = false;
      for (var i = 0; i < that.subKeys.length; i++) {
        if (srcSubKey.subKey.getFingerprint() === that.subKeys[i].subKey.getFingerprint()) {
          that.subKeys[i].update(srcSubKey, that.primaryKey);
          found = true;
          break;
        }
      }
      if (!found) {
        that.subKeys.push(srcSubKey);
      }
    });
  }
};

/**
 * Merges signatures from source[attr] to dest[attr]
 * @private
 * @param  {Object} source
 * @param  {Object} dest
 * @param  {String} attr
 * @param  {Function} checkFn optional, signature only merged if true
 */
function mergeSignatures(source, dest, attr, checkFn) {
  source = source[attr];
  if (source) {
    if (!dest[attr]) {
      dest[attr] = source;
    } else {
      source.forEach(function(sourceSig) {
        if (!sourceSig.isExpired() && (!checkFn || checkFn(sourceSig)) &&
            !dest[attr].some(function(destSig) {
              return destSig.signature === sourceSig.signature;
            })) {
          dest[attr].push(sourceSig);
        }
      });
    }
  }
}

// TODO
Key.prototype.revoke = function() {

};

/**
 * @class
 * @classdesc Class that represents an user ID or attribute packet and the relevant signatures.
 */
function User(userPacket) {
  if (!(this instanceof User)) {
    return new User(userPacket);
  }
  this.userId = userPacket.tag == enums.packet.userid ? userPacket : null;
  this.userAttribute = userPacket.tag == enums.packet.userAttribute ? userPacket : null;
  this.selfCertifications = null;
  this.otherCertifications = null;
  this.revocationCertifications = null;
}

/**
 * Transforms structured user data to packetlist
 * @return {module:packet/packetlist}
 */
User.prototype.toPacketlist = function() {
  var packetlist = new packet.List();
  packetlist.push(this.userId || this.userAttribute);
  packetlist.concat(this.revocationCertifications);
  packetlist.concat(this.selfCertifications);
  packetlist.concat(this.otherCertifications);
  return packetlist;
};

/**
 * Checks if a self signature of the user is revoked
 * @param  {module:packet/signature}                    certificate
 * @param  {module:packet/secret_key|module:packet/public_key} primaryKey  The primary key packet
 * @return {Boolean}                                         True if the certificate is revoked
 */
User.prototype.isRevoked = function(certificate, primaryKey) {
  if (this.revocationCertifications) {
    var that = this;
    return this.revocationCertifications.some(function(revCert) {
             return revCert.issuerKeyId.equals(certificate.issuerKeyId) &&
                    !revCert.isExpired() &&
                    (revCert.verified ||
                     revCert.verify(primaryKey, {userid: that.userId || that.userAttribute, key: primaryKey}));
          });
  } else {
    return false;
  }
};

/**
 * Returns the most significant (latest valid) self signature of the user
 * @param  {module:packet/secret_key|module:packet/public_key} primaryKey The primary key packet
 * @return {module:packet/signature}                               The self signature
 */
User.prototype.getValidSelfCertificate = function(primaryKey) {
  if (!this.selfCertifications) {
    return null;
  }
  // most recent first
  var validCert = this.selfCertifications.sort(function(a, b) {
    a = a.created;
    b = b.created;
    return a>b ? -1 : a<b ? 1 : 0;
  });
  for (var i = 0; i < validCert.length; i++) {
    if (this.isValidSelfCertificate(primaryKey, validCert[i])) {
      return validCert[i];
    }
  }
  return null;
};

/**
 * Returns true if the self certificate is valid
 * @param  {module:packet/secret_key|module:packet/public_key}  primaryKey      The primary key packet
 * @param  {module:packet/signature}  selfCertificate A self certificate of this user
 * @return {Boolean}
 */
User.prototype.isValidSelfCertificate = function(primaryKey, selfCertificate) {
  if (this.isRevoked(selfCertificate, primaryKey)) {
    return false;
  }
  if (!selfCertificate.isExpired() &&
     (selfCertificate.verified ||
      selfCertificate.verify(primaryKey, {userid: this.userId || this.userAttribute, key: primaryKey}))) {
    return true;
  }
  return false;
};

/**
 * Verify User. Checks for existence of self signatures, revocation signatures
 * and validity of self signature
 * @param  {module:packet/secret_key|module:packet/public_key} primaryKey The primary key packet
 * @return {module:enums.keyStatus} status of user
 */
User.prototype.verify = function(primaryKey) {
  if (!this.selfCertifications) {
    return enums.keyStatus.no_self_cert;
  }
  var status;
  for (var i = 0; i < this.selfCertifications.length; i++) {
    if (this.isRevoked(this.selfCertifications[i], primaryKey)) {
      status = enums.keyStatus.revoked;
      continue;
    }
    if (!(this.selfCertifications[i].verified ||
        this.selfCertifications[i].verify(primaryKey, {userid: this.userId || this.userAttribute, key: primaryKey}))) {
      status = enums.keyStatus.invalid;
      continue;
    }
    if (this.selfCertifications[i].isExpired()) {
      status = enums.keyStatus.expired;
      continue;
    }
    status = enums.keyStatus.valid;
    break;
  }
  return status;
};

/**
 * Update user with new components from specified user
 * @param  {module:key~User} user source user to merge
 * @param  {module:packet/signature} primaryKey primary key used for validation
 */
User.prototype.update = function(user, primaryKey) {
  var that = this;
  // self signatures
  mergeSignatures(user, this, 'selfCertifications', function(srcSelfSig) {
    return srcSelfSig.verified ||
           srcSelfSig.verify(primaryKey, {userid: that.userId || that.userAttribute, key: primaryKey});
  });
  // other signatures
  mergeSignatures(user, this, 'otherCertifications');
  // revocation signatures
  mergeSignatures(user, this, 'revocationCertifications');
};

/**
 * @class
 * @classdesc Class that represents a subkey packet and the relevant signatures.
 */
function SubKey(subKeyPacket) {
  if (!(this instanceof SubKey)) {
    return new SubKey(subKeyPacket);
  }
  this.subKey = subKeyPacket;
  this.bindingSignature = null;
  this.revocationSignature = null;
}

/**
 * Transforms structured subkey data to packetlist
 * @return {module:packet/packetlist}
 */
SubKey.prototype.toPacketlist = function() {
  var packetlist = new packet.List();
  packetlist.push(this.subKey);
  packetlist.push(this.revocationSignature);
  packetlist.push(this.bindingSignature);
  return packetlist;
};

/**
 * Returns true if the subkey can be used for encryption
 * @param  {module:packet/secret_key|module:packet/public_key}  primaryKey The primary key packet
 * @return {Boolean}
 */
SubKey.prototype.isValidEncryptionKey = function(primaryKey) {
  return this.verify(primaryKey) == enums.keyStatus.valid &&
         isValidEncryptionKeyPacket(this.subKey, this.bindingSignature);
};

/**
 * Returns true if the subkey can be used for signing of data
 * @param  {module:packet/secret_key|module:packet/public_key}  primaryKey The primary key packet
 * @return {Boolean}
 */
SubKey.prototype.isValidSigningKey = function(primaryKey) {
  return this.verify(primaryKey) == enums.keyStatus.valid &&
         isValidSigningKeyPacket(this.subKey, this.bindingSignature);
};

/**
 * Verify subkey. Checks for revocation signatures, expiration time
 * and valid binding signature
 * @return {module:enums.keyStatus} The status of the subkey
 */
SubKey.prototype.verify = function(primaryKey) {
  // check subkey revocation signature
  if (this.revocationSignature && !this.revocationSignature.isExpired() &&
     (this.revocationSignature.verified ||
      this.revocationSignature.verify(primaryKey, {key:primaryKey, bind: this.subKey}))) {
    return enums.keyStatus.revoked;
  }
  // check V3 expiration time
  if (this.subKey.version == 3 && this.subKey.expirationTimeV3 !== 0 &&
      Date.now() > (this.subKey.created.getTime() + this.subKey.expirationTimeV3*24*3600*1000)) {
    return enums.keyStatus.expired;
  }
  // check subkey binding signature
  if (!this.bindingSignature) {
    return enums.keyStatus.invalid;
  }
  if (this.bindingSignature.isExpired()) {
    return enums.keyStatus.expired;
  }
  if (!(this.bindingSignature.verified ||
        this.bindingSignature.verify(primaryKey, {key: primaryKey, bind: this.subKey}))) {
    return enums.keyStatus.invalid;
  }
  // check V4 expiration time
  if (this.subKey.version == 4 &&
      this.bindingSignature.keyNeverExpires === false &&
      Date.now() > (this.subKey.created.getTime() + this.bindingSignature.keyExpirationTime*1000)) {
    return enums.keyStatus.expired;
  }
  return enums.keyStatus.valid;
};

/**
 * Returns the expiration time of the subkey or null if key does not expire
 * @return {Date|null}
 */
SubKey.prototype.getExpirationTime = function() {
  return getExpirationTime(this.subKey, this.bindingSignature);
};

/**
 * Update subkey with new components from specified subkey
 * @param  {module:key~SubKey} subKey source subkey to merge
 * @param  {module:packet/signature} primaryKey primary key used for validation
 */
SubKey.prototype.update = function(subKey, primaryKey) {
  if (subKey.verify(primaryKey) === enums.keyStatus.invalid) {
    return;
  }
  if (this.subKey.getFingerprint() !== subKey.subKey.getFingerprint()) {
    throw new Error('SubKey update method: fingerprints of subkeys not equal');
  }
  // key packet
  if (this.subKey.tag === enums.packet.publicSubkey &&
      subKey.subKey.tag === enums.packet.secretSubkey) {
    this.subKey = subKey.subKey;
  }
  // binding signature
  if (!this.bindingSignature && subKey.bindingSignature &&
     (subKey.bindingSignature.verified ||
      subKey.bindingSignature.verify(primaryKey, {key: primaryKey, bind: this.subKey}))) {
    this.bindingSignature = subKey.bindingSignature;
  }
  // revocation signature
  if (!this.revocationSignature && subKey.revocationSignature && !subKey.revocationSignature.isExpired() &&
     (subKey.revocationSignature.verified ||
      subKey.revocationSignature.verify(primaryKey, {key: primaryKey, bind: this.subKey}))) {
    this.revocationSignature = subKey.revocationSignature;
  }
};

/**
 * Reads an OpenPGP armored text and returns one or multiple key objects
 * @param {String} armoredText text to be parsed
 * @return {{keys: Array<module:key~Key>, err: (Array<Error>|null)}} result object with key and error arrays
 * @static
 */
function readArmored(armoredText) {
  var result = {};
  result.keys = [];
  try {
    var input = armor.decode(armoredText);
    if (!(input.type == enums.armor.public_key || input.type == enums.armor.private_key)) {
      throw new Error('Armored text not of type key');
    }
    var packetlist = new packet.List();
    packetlist.read(input.data);
    var keyIndex = packetlist.indexOfTag(enums.packet.publicKey, enums.packet.secretKey);
    if (keyIndex.length === 0) {
      throw new Error('No key packet found in armored text');
    }
    for (var i = 0; i < keyIndex.length; i++) {
      var oneKeyList = packetlist.slice(keyIndex[i], keyIndex[i + 1]);
      try {
        var newKey = new Key(oneKeyList);
        result.keys.push(newKey);
      } catch (e) {
        result.err = result.err || [];
        result.err.push(e);
      }
    }
  } catch (e) {
    result.err = result.err || [];
    result.err.push(e);
  }
  return result;
}

/**
 * Generates a new OpenPGP key. Currently only supports RSA keys.
 * Primary and subkey will be of same type.
 * @param {module:enums.publicKey} [options.keyType=module:enums.publicKey.rsa_encrypt_sign]    to indicate what type of key to make.
 *                             RSA is 1. See {@link http://tools.ietf.org/html/rfc4880#section-9.1}
 * @param {Integer} options.numBits    number of bits for the key creation.
 * @param {String}  options.userId     assumes already in form of "User Name <username@email.com>"
 * @param {String}  options.passphrase The passphrase used to encrypt the resulting private key
 * @param {Boolean} [options.unlocked=false]    The secret part of the generated key is unlocked
 * @return {module:key~Key}
 * @static
 */
function generate(options) {
  var packetlist, secretKeyPacket, userIdPacket, dataToSign, signaturePacket, secretSubkeyPacket, subkeySignaturePacket;

  options.keyType = options.keyType || enums.publicKey.rsa_encrypt_sign;
  // RSA Encrypt-Only and RSA Sign-Only are deprecated and SHOULD NOT be generated
  if (options.keyType !== enums.publicKey.rsa_encrypt_sign) {
    throw new Error('Only RSA Encrypt or Sign supported');
  }
  // Key without passphrase is unlocked by definition
  if (!options.passphrase) {
    options.unlocked = true;
  }

  // generate
  var genSecretKey = generateSecretKey();
  var genSecretSubkey = generateSecretSubkey();
  return Promise.all([genSecretKey, genSecretSubkey]).then(wrapKeyObject);

  function generateSecretKey() {
    secretKeyPacket = new packet.SecretKey();
    secretKeyPacket.algorithm = enums.read(enums.publicKey, options.keyType);
    if (options.created) {
      secretKeyPacket.created = options.created;
    }
    return secretKeyPacket.generate(options.numBits, options.prng);
  }

  function generateSecretSubkey() {
    secretSubkeyPacket = new packet.SecretSubkey();
    secretSubkeyPacket.algorithm = enums.read(enums.publicKey, options.keyType);
    if (options.created) {
      secretSubkeyPacket.created = options.created;
    }
    return secretSubkeyPacket.generate(options.numBits, options.prng);
  }

  function wrapKeyObject() {
    // set passphrase protection
    if (options.passphrase) {
      secretKeyPacket.encrypt(options.passphrase);
      secretSubkeyPacket.encrypt(options.passphrase);
    }

    packetlist = new packet.List();

    userIdPacket = new packet.Userid();
    userIdPacket.read(options.userId);

    dataToSign = {};
    dataToSign.userid = userIdPacket;
    dataToSign.key = secretKeyPacket;
    signaturePacket = new packet.Signature();
    signaturePacket.signatureType = enums.signature.cert_generic;
    signaturePacket.publicKeyAlgorithm = options.keyType;
    signaturePacket.hashAlgorithm = config.prefer_hash_algorithm;
    signaturePacket.keyFlags = [enums.keyFlags.certify_keys | enums.keyFlags.sign_data];
    signaturePacket.preferredSymmetricAlgorithms = [];
    signaturePacket.preferredSymmetricAlgorithms.push(enums.symmetric.aes256);
    signaturePacket.preferredSymmetricAlgorithms.push(enums.symmetric.aes192);
    signaturePacket.preferredSymmetricAlgorithms.push(enums.symmetric.aes128);
    signaturePacket.preferredSymmetricAlgorithms.push(enums.symmetric.cast5);
    signaturePacket.preferredSymmetricAlgorithms.push(enums.symmetric.tripledes);
    signaturePacket.preferredHashAlgorithms = [];
    signaturePacket.preferredHashAlgorithms.push(enums.hash.sha256);
    signaturePacket.preferredHashAlgorithms.push(enums.hash.sha1);
    signaturePacket.preferredHashAlgorithms.push(enums.hash.sha512);
    signaturePacket.preferredCompressionAlgorithms = [];
    signaturePacket.preferredCompressionAlgorithms.push(enums.compression.zlib);
    signaturePacket.preferredCompressionAlgorithms.push(enums.compression.zip);
    if (config.integrity_protect) {
      signaturePacket.features = [];
      signaturePacket.features.push(1); // Modification Detection
    }
    signaturePacket.sign(secretKeyPacket, dataToSign);

    dataToSign = {};
    dataToSign.key = secretKeyPacket;
    dataToSign.bind = secretSubkeyPacket;
    subkeySignaturePacket = new packet.Signature();
    subkeySignaturePacket.signatureType = enums.signature.subkey_binding;
    subkeySignaturePacket.publicKeyAlgorithm = options.keyType;
    subkeySignaturePacket.hashAlgorithm = config.prefer_hash_algorithm;
    subkeySignaturePacket.keyFlags = [enums.keyFlags.encrypt_communication | enums.keyFlags.encrypt_storage];
    subkeySignaturePacket.sign(secretKeyPacket, dataToSign);

    packetlist.push(secretKeyPacket);
    packetlist.push(userIdPacket);
    packetlist.push(signaturePacket);
    packetlist.push(secretSubkeyPacket);
    packetlist.push(subkeySignaturePacket);

    if (!options.unlocked) {
      secretKeyPacket.clearPrivateMPIs();
      secretSubkeyPacket.clearPrivateMPIs();
    }

    return new Key(packetlist);
  }
}

/**
 * Returns the preferred symmetric algorithm for a set of keys
 * @param  {Array<module:key~Key>} keys Set of keys
 * @return {enums.symmetric}   Preferred symmetric algorithm
 */
function getPreferredSymAlgo(keys) {
  var prioMap = {};
  for (var i = 0; i < keys.length; i++) {
    var primaryUser = keys[i].getPrimaryUser();
    if (!primaryUser || !primaryUser.selfCertificate.preferredSymmetricAlgorithms) {
      return config.encryption_cipher;
    }
    primaryUser.selfCertificate.preferredSymmetricAlgorithms.forEach(function(algo, index) {
      var entry = prioMap[algo] || (prioMap[algo] = {prio: 0, count: 0, algo: algo});
      entry.prio += 64 >> index;
      entry.count++;
    });
  }
  var prefAlgo = {prio: 0, algo: config.encryption_cipher};
  for (var algo in prioMap) {
    try {
      if (algo !== enums.symmetric.plaintext &&
          algo !== enums.symmetric.idea && // not implemented
          enums.read(enums.symmetric, algo) && // known algorithm
          prioMap[algo].count === keys.length && // available for all keys
          prioMap[algo].prio > prefAlgo.prio) {
        prefAlgo = prioMap[algo];
      }
    } catch (e) {}
  }
  return prefAlgo.algo;
}

exports.Key = Key;
exports.readArmored = readArmored;
exports.generate = generate;
exports.getPreferredSymAlgo = getPreferredSymAlgo;

},{"./config":33,"./encoding/armor.js":58,"./enums.js":60,"./packet":70,"./util":95}],63:[function(require,module,exports){
/**
 * @see module:keyring/keyring
 * @module keyring
 */
module.exports = require('./keyring.js');
module.exports.localstore = require('./localstore.js');

},{"./keyring.js":64,"./localstore.js":65}],64:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * The class that deals with storage of the keyring. Currently the only option is to use HTML5 local storage.
 * @requires enums
 * @requires key
 * @requires util
 * @module keyring/keyring
 */

var enums = require('../enums.js'),
  keyModule = require('../key.js'),
  util = require('../util.js');

module.exports = Keyring;

  /**
 * Initialization routine for the keyring. This method reads the
 * keyring from HTML5 local storage and initializes this instance.
 * @constructor
 * @param {class} [storeHandler] class implementing load() and store() methods
 */
function Keyring(storeHandler) {
  this.storeHandler = storeHandler || new (require('./localstore.js'))();
  this.publicKeys = new KeyArray(this.storeHandler.loadPublic());
  this.privateKeys = new KeyArray(this.storeHandler.loadPrivate());
}

/**
 * Calls the storeHandler to save the keys
 */
Keyring.prototype.store = function () {
  this.storeHandler.storePublic(this.publicKeys.keys);
  this.storeHandler.storePrivate(this.privateKeys.keys);
};

/**
 * Clear the keyring - erase all the keys
 */
Keyring.prototype.clear = function() {
  this.publicKeys.keys = [];
  this.privateKeys.keys = [];
};

/**
 * Searches the keyring for keys having the specified key id
 * @param {String} keyId provided as string of lowercase hex number
 * withouth 0x prefix (can be 16-character key ID or fingerprint)
 * @param  {Boolean} deep if true search also in subkeys
 * @return {Array<module:key~Key>|null} keys found or null
 */
Keyring.prototype.getKeysForId = function (keyId, deep) {
  var result = [];
  result = result.concat(this.publicKeys.getForId(keyId, deep) || []);
  result = result.concat(this.privateKeys.getForId(keyId, deep) || []);
  return result.length ? result : null;
};

/**
 * Removes keys having the specified key id from the keyring
 * @param {String} keyId provided as string of lowercase hex number
 * withouth 0x prefix (can be 16-character key ID or fingerprint)
 * @return {Array<module:key~Key>|null} keys found or null
 */
Keyring.prototype.removeKeysForId = function (keyId) {
  var result = [];
  result = result.concat(this.publicKeys.removeForId(keyId) || []);
  result = result.concat(this.privateKeys.removeForId(keyId) || []);
  return result.length ? result : null;
};

/**
 * Get all public and private keys
 * @return {Array<module:key~Key>} all keys
 */
Keyring.prototype.getAllKeys = function () {
  return this.publicKeys.keys.concat(this.privateKeys.keys);
};

/**
 * Array of keys
 * @param {Array<module:key~Key>} keys The keys to store in this array
 */
function KeyArray(keys) {
  this.keys = keys;
}

/**
 * Searches all keys in the KeyArray matching the address or address part of the user ids
 * @param {String} email email address to search for
 * @return {Array<module:key~Key>} The public keys associated with provided email address.
 */
KeyArray.prototype.getForAddress = function(email) {
  var results = [];
  for (var i = 0; i < this.keys.length; i++) {
    if (emailCheck(email, this.keys[i])) {
      results.push(this.keys[i]);
    }
  }
  return results;
};

/**
 * Checks a key to see if it matches the specified email address
 * @private
 * @param {String} email email address to search for
 * @param {module:key~Key} key The key to be checked.
 * @return {Boolean} True if the email address is defined in the specified key
 */
function emailCheck(email, key) {
  // escape email before using in regular expression
  email = email.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  var emailRegex = new RegExp('<' + email + '>');
  var keyEmails = key.getUserIds();
  for (var i = 0; i < keyEmails.length; i++) {
    if (emailRegex.test(keyEmails[i].toLowerCase())) {
      return true;
    }
  }
  return false;
}

/**
 * Checks a key to see if it matches the specified keyid
 * @private
 * @param {String} keyId provided as string of lowercase hex number
 * withouth 0x prefix (can be 16-character key ID or fingerprint)
 * @param {module:packet/secret_key|public_key|public_subkey|secret_subkey} keypacket The keypacket to be checked
 * @return {Boolean} True if keypacket has the specified keyid
 */
function keyIdCheck(keyId, keypacket) {
  if (keyId.length === 16) {
    return keyId === keypacket.getKeyId().toHex();
  } else {
    return keyId === keypacket.getFingerprint();
  }
}

/**
 * Searches the KeyArray for a key having the specified key id
 * @param {String} keyId provided as string of lowercase hex number
 * withouth 0x prefix (can be 16-character key ID or fingerprint)
 * @param  {Boolean} deep if true search also in subkeys
 * @return {module:key~Key|null} key found or null
 */
KeyArray.prototype.getForId = function (keyId, deep) {
  for (var i = 0; i < this.keys.length; i++) {
    if (keyIdCheck(keyId, this.keys[i].primaryKey)) {
      return this.keys[i];
    }
    if (deep && this.keys[i].subKeys) {
      for (var j = 0; j < this.keys[i].subKeys.length; j++) {
        if (keyIdCheck(keyId, this.keys[i].subKeys[j].subKey)) {
          return this.keys[i];
        }
      }
    }
  }
  return null;
};

/**
 * Imports a key from an ascii armored message
 * @param {String} armored message to read the keys/key from
 * @return {Array<Error>|null} array of error objects or null
 */
KeyArray.prototype.importKey = function (armored) {
  var imported = keyModule.readArmored(armored);
  var that = this;
  imported.keys.forEach(function(key) {
    // check if key already in key array
    var keyidHex = key.primaryKey.getKeyId().toHex();
    var keyFound = that.getForId(keyidHex);
    if (keyFound) {
      keyFound.update(key);
    } else {
      that.push(key);
    }
  });
  return imported.err ? imported.err : null;
};

/**
 * Add key to KeyArray
 * @param {module:key~Key} key The key that will be added to the keyring
 * @return {Number} The new length of the KeyArray
 */
KeyArray.prototype.push = function (key) {
  return this.keys.push(key);
};

/**
 * Removes a key with the specified keyid from the keyring
 * @param {String} keyId provided as string of lowercase hex number
 * withouth 0x prefix (can be 16-character key ID or fingerprint)
 * @return {module:key~Key|null} The key object which has been removed or null
 */
KeyArray.prototype.removeForId = function (keyId) {
  for (var i = 0; i < this.keys.length; i++) {
    if (keyIdCheck(keyId, this.keys[i].primaryKey)) {
      return this.keys.splice(i, 1)[0];
    }
  }
  return null;
};

},{"../enums.js":60,"../key.js":62,"../util.js":95,"./localstore.js":65}],65:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * The class that deals with storage of the keyring. Currently the only option is to use HTML5 local storage.
 * @requires config
 * @module keyring/localstore
 * @param {String} prefix prefix for itemnames in localstore
 */
module.exports = LocalStore;

var config = require('../config'),
  keyModule = require('../key.js'),
  util = require('../util.js');

function LocalStore(prefix) {
  prefix = prefix || 'openpgp-';
  this.publicKeysItem = prefix + this.publicKeysItem;
  this.privateKeysItem = prefix + this.privateKeysItem;
  if (typeof window != 'undefined' && window.localStorage) {
    this.storage = window.localStorage;
  } else {
    this.storage = new (require('node-localstorage').LocalStorage)(config.node_store);
  }
}

/*
 * Declare the localstore itemnames
 */
LocalStore.prototype.publicKeysItem = 'public-keys';
LocalStore.prototype.privateKeysItem = 'private-keys';

/**
 * Load the public keys from HTML5 local storage.
 * @return {Array<module:key~Key>} array of keys retrieved from localstore
 */
LocalStore.prototype.loadPublic = function () {
  return loadKeys(this.storage, this.publicKeysItem);
};

/**
 * Load the private keys from HTML5 local storage.
 * @return {Array<module:key~Key>} array of keys retrieved from localstore
 */
LocalStore.prototype.loadPrivate = function () {
  return loadKeys(this.storage, this.privateKeysItem);
};

function loadKeys(storage, itemname) {
  var armoredKeys = JSON.parse(storage.getItem(itemname));
  var keys = [];
  if (armoredKeys !== null && armoredKeys.length !== 0) {
    var key;
    for (var i = 0; i < armoredKeys.length; i++) {
      key = keyModule.readArmored(armoredKeys[i]);
      if (!key.err) {
        keys.push(key.keys[0]);
      } else {
        util.print_debug("Error reading armored key from keyring index: " + i);
      }
    }
  }
  return keys;
}

/**
 * Saves the current state of the public keys to HTML5 local storage.
 * The key array gets stringified using JSON
 * @param {Array<module:key~Key>} keys array of keys to save in localstore
 */
LocalStore.prototype.storePublic = function (keys) {
  storeKeys(this.storage, this.publicKeysItem, keys);
};

/**
 * Saves the current state of the private keys to HTML5 local storage.
 * The key array gets stringified using JSON
 * @param {Array<module:key~Key>} keys array of keys to save in localstore
 */
LocalStore.prototype.storePrivate = function (keys) {
  storeKeys(this.storage, this.privateKeysItem, keys);
};

function storeKeys(storage, itemname, keys) {
  var armoredKeys = [];
  for (var i = 0; i < keys.length; i++) {
    armoredKeys.push(keys[i].armor());
  }
  storage.setItem(itemname, JSON.stringify(armoredKeys));
}

},{"../config":33,"../key.js":62,"../util.js":95,"node-localstorage":false}],66:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires config
 * @requires crypto
 * @requires encoding/armor
 * @requires enums
 * @requires packet
 * @module message
 */

'use strict';

var packet = require('./packet'),
  enums = require('./enums.js'),
  armor = require('./encoding/armor.js'),
  config = require('./config'),
  crypto = require('./crypto'),
  keyModule = require('./key.js');

/**
 * @class
 * @classdesc Class that represents an OpenPGP message.
 * Can be an encrypted message, signed message, compressed message or literal message
 * @param  {module:packet/packetlist} packetlist The packets that form this message
 * See {@link http://tools.ietf.org/html/rfc4880#section-11.3}
 */

function Message(packetlist) {
  if (!(this instanceof Message)) {
    return new Message(packetlist);
  }
  this.packets = packetlist || new packet.List();
}

/**
 * Returns the key IDs of the keys to which the session key is encrypted
 * @return {Array<module:type/keyid>} array of keyid objects
 */
Message.prototype.getEncryptionKeyIds = function() {
  var keyIds = [];
  var pkESKeyPacketlist = this.packets.filterByTag(enums.packet.publicKeyEncryptedSessionKey);
  pkESKeyPacketlist.forEach(function(packet) {
    keyIds.push(packet.publicKeyId);
  });
  return keyIds;
};

/**
 * Returns the key IDs of the keys that signed the message
 * @return {Array<module:type/keyid>} array of keyid objects
 */
Message.prototype.getSigningKeyIds = function() {
  var keyIds = [];
  var msg = this.unwrapCompressed();
  // search for one pass signatures
  var onePassSigList = msg.packets.filterByTag(enums.packet.onePassSignature);
  onePassSigList.forEach(function(packet) {
    keyIds.push(packet.signingKeyId);
  });
  // if nothing found look for signature packets
  if (!keyIds.length) {
    var signatureList = msg.packets.filterByTag(enums.packet.signature);
    signatureList.forEach(function(packet) {
      keyIds.push(packet.issuerKeyId);
    });
  }
  return keyIds;
};

/**
 * Decrypt the message
 * @param {module:key~Key} privateKey private key with decrypted secret data
 * @return {Array<module:message~Message>} new message with decrypted content
 */
Message.prototype.decrypt = function(privateKey) {
  var encryptionKeyIds = this.getEncryptionKeyIds();
  if (!encryptionKeyIds.length) {
    // nothing to decrypt return unmodified message
    return this;
  }
  var privateKeyPacket = privateKey.getKeyPacket(encryptionKeyIds);
  if (!privateKeyPacket.isDecrypted) throw new Error('Private key is not decrypted.');
  var pkESKeyPacketlist = this.packets.filterByTag(enums.packet.publicKeyEncryptedSessionKey);
  var pkESKeyPacket;
  for (var i = 0; i < pkESKeyPacketlist.length; i++) {
    if (pkESKeyPacketlist[i].publicKeyId.equals(privateKeyPacket.getKeyId())) {
      pkESKeyPacket = pkESKeyPacketlist[i];
      pkESKeyPacket.decrypt(privateKeyPacket);
      break;
    }
  }
  if (pkESKeyPacket) {
    var symEncryptedPacketlist = this.packets.filterByTag(enums.packet.symmetricallyEncrypted, enums.packet.symEncryptedIntegrityProtected);
    if (symEncryptedPacketlist.length !== 0) {
      var symEncryptedPacket = symEncryptedPacketlist[0];
      symEncryptedPacket.decrypt(pkESKeyPacket.sessionKeyAlgorithm, pkESKeyPacket.sessionKey);
      var resultMsg = new Message(symEncryptedPacket.packets);
      // remove packets after decryption
      symEncryptedPacket.packets = new packet.List();
      return resultMsg;
    }
  }
};

/**
 * Get literal data that is the body of the message
 * @return {(String|null)} literal body of the message as string
 */
Message.prototype.getLiteralData = function() {
  var literal = this.packets.findPacket(enums.packet.literal);
  return literal && literal.data || null;
};

/**
 * Get literal data as text
 * @return {(String|null)} literal body of the message interpreted as text
 */
Message.prototype.getText = function() {
  var literal = this.packets.findPacket(enums.packet.literal);
  if (literal) {
    return literal.getText();
  } else {
    return null;
  }
};

/**
 * Encrypt the message
 * @param  {Array<module:key~Key>} keys array of keys, used to encrypt the message
 * @return {Array<module:message~Message>} new message with encrypted content
 */
Message.prototype.encrypt = function(keys) {
  var packetlist = new packet.List();
  var symAlgo = keyModule.getPreferredSymAlgo(keys);
  var sessionKey = crypto.generateSessionKey(enums.read(enums.symmetric, symAlgo));
  keys.forEach(function(key) {
    var encryptionKeyPacket = key.getEncryptionKeyPacket();
    if (encryptionKeyPacket) {
      var pkESKeyPacket = new packet.PublicKeyEncryptedSessionKey();
      pkESKeyPacket.publicKeyId = encryptionKeyPacket.getKeyId();
      pkESKeyPacket.publicKeyAlgorithm = encryptionKeyPacket.algorithm;
      pkESKeyPacket.sessionKey = sessionKey;
      pkESKeyPacket.sessionKeyAlgorithm = enums.read(enums.symmetric, symAlgo);
      pkESKeyPacket.encrypt(encryptionKeyPacket);
      packetlist.push(pkESKeyPacket);
    } else {
      throw new Error('Could not find valid key packet for encryption in key ' + key.primaryKey.getKeyId().toHex());
    }
  });
  var symEncryptedPacket;
  if (config.integrity_protect) {
    symEncryptedPacket = new packet.SymEncryptedIntegrityProtected();
  } else {
    symEncryptedPacket = new packet.SymmetricallyEncrypted();
  }
  symEncryptedPacket.packets = this.packets;
  symEncryptedPacket.encrypt(enums.read(enums.symmetric, symAlgo), sessionKey);
  packetlist.push(symEncryptedPacket);
  // remove packets after encryption
  symEncryptedPacket.packets = new packet.List();
  return new Message(packetlist);
};

/**
 * Sign the message (the literal data packet of the message)
 * @param  {Array<module:key~Key>} privateKey private keys with decrypted secret key data for signing
 * @return {module:message~Message}      new message with signed content
 */
Message.prototype.sign = function(privateKeys) {

  var packetlist = new packet.List();

  var literalDataPacket = this.packets.findPacket(enums.packet.literal);
  if (!literalDataPacket) throw new Error('No literal data packet to sign.');

  var literalFormat = enums.write(enums.literal, literalDataPacket.format);
  var signatureType = literalFormat == enums.literal.binary ?
                      enums.signature.binary : enums.signature.text;
  var i;
  for (i = 0; i < privateKeys.length; i++) {
    if (privateKeys[i].isPublic()) {
      throw new Error('Need private key for signing');
    }
    var onePassSig = new packet.OnePassSignature();
    onePassSig.type = signatureType;
    //TODO get preferred hashg algo from key signature
    onePassSig.hashAlgorithm = config.prefer_hash_algorithm;
    var signingKeyPacket = privateKeys[i].getSigningKeyPacket();
    if (!signingKeyPacket) {
      throw new Error('Could not find valid key packet for signing in key ' + privateKeys[i].primaryKey.getKeyId().toHex());
    }
    onePassSig.publicKeyAlgorithm = signingKeyPacket.algorithm;
    onePassSig.signingKeyId = signingKeyPacket.getKeyId();
    packetlist.push(onePassSig);
  }

  packetlist.push(literalDataPacket);

  for (i = privateKeys.length - 1; i >= 0; i--) {
    var signaturePacket = new packet.Signature();
    signaturePacket.signatureType = signatureType;
    signaturePacket.hashAlgorithm = config.prefer_hash_algorithm;
    signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
    if (!signingKeyPacket.isDecrypted) throw new Error('Private key is not decrypted.');
    signaturePacket.sign(signingKeyPacket, literalDataPacket);
    packetlist.push(signaturePacket);
  }

  return new Message(packetlist);
};

/**
 * Verify message signatures
 * @param {Array<module:key~Key>} keys array of keys to verify signatures
 * @return {Array<({keyid: module:type/keyid, valid: Boolean})>} list of signer's keyid and validity of signature
 */
Message.prototype.verify = function(keys) {
  var result = [];
  var msg = this.unwrapCompressed();
  var literalDataList = msg.packets.filterByTag(enums.packet.literal);
  if (literalDataList.length !== 1) throw new Error('Can only verify message with one literal data packet.');
  var signatureList = msg.packets.filterByTag(enums.packet.signature);
  for (var i = 0; i < signatureList.length; i++) {
    var keyPacket = null;
    for (var j = 0; j < keys.length; j++) {
      keyPacket = keys[j].getSigningKeyPacket(signatureList[i].issuerKeyId);
      if (keyPacket) {
        break;
      }
    }

    var verifiedSig = {};
    if (keyPacket) {
      verifiedSig.keyid = signatureList[i].issuerKeyId;
      verifiedSig.valid = signatureList[i].verify(keyPacket, literalDataList[0]);
    } else {
      verifiedSig.keyid = signatureList[i].issuerKeyId;
      verifiedSig.valid = null;
    }
    result.push(verifiedSig);
  }
  return result;
};

/**
 * Unwrap compressed message
 * @return {module:message~Message} message Content of compressed message
 */
Message.prototype.unwrapCompressed = function() {
  var compressed = this.packets.filterByTag(enums.packet.compressed);
  if (compressed.length) {
    return new Message(compressed[0].packets);
  } else {
    return this;
  }
};

/**
 * Returns ASCII armored text of message
 * @return {String} ASCII armor
 */
Message.prototype.armor = function() {
  return armor.encode(enums.armor.message, this.packets.write());
};

/**
 * reads an OpenPGP armored message and returns a message object
 * @param {String} armoredText text to be parsed
 * @return {module:message~Message} new message object
 * @static
 */
function readArmored(armoredText) {
  //TODO how do we want to handle bad text? Exception throwing
  //TODO don't accept non-message armored texts
  var input = armor.decode(armoredText).data;
  var packetlist = new packet.List();
  packetlist.read(input);
  var newMessage = new Message(packetlist);
  return newMessage;
}

/**
 * Create a message object from signed content and a detached armored signature.
 * @param {String} content An 8 bit ascii string containing e.g. a MIME subtree with text nodes or attachments
 * @param {String} detachedSignature The detached ascii armored PGP signarure
 */
function readSignedContent(content, detachedSignature) {
  var literalDataPacket = new packet.Literal();
  literalDataPacket.setBytes(content, enums.read(enums.literal, enums.literal.binary));
  var packetlist = new packet.List();
  packetlist.push(literalDataPacket);
  var input = armor.decode(detachedSignature).data;
  packetlist.read(input);
  var newMessage = new Message(packetlist);
  return newMessage;
}

/**
 * creates new message object from text
 * @param {String} text
 * @return {module:message~Message} new message object
 * @static
 */
function fromText(text) {
  var literalDataPacket = new packet.Literal();
  // text will be converted to UTF8
  literalDataPacket.setText(text);
  var literalDataPacketlist = new packet.List();
  literalDataPacketlist.push(literalDataPacket);
  var newMessage = new Message(literalDataPacketlist);
  return newMessage;
}

/**
 * creates new message object from binary data
 * @param {String} bytes
 * @return {module:message~Message} new message object
 * @static
 */
function fromBinary(bytes) {
  var literalDataPacket = new packet.Literal();
  literalDataPacket.setBytes(bytes, enums.read(enums.literal, enums.literal.binary));
  var literalDataPacketlist = new packet.List();
  literalDataPacketlist.push(literalDataPacket);
  var newMessage = new Message(literalDataPacketlist);
  return newMessage;
}

exports.Message = Message;
exports.readArmored = readArmored;
exports.readSignedContent = readSignedContent;
exports.fromText = fromText;
exports.fromBinary = fromBinary;

},{"./config":33,"./crypto":49,"./encoding/armor.js":58,"./enums.js":60,"./key.js":62,"./packet":70}],67:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @fileoverview The openpgp base module should provide all of the functionality
 * to consume the openpgp.js library. All additional classes are documented
 * for extending and developing on top of the base library.
 */

/**
 * @requires cleartext
 * @requires config
 * @requires encoding/armor
 * @requires enums
 * @requires message
 * @requires packet
 * @module openpgp
 */

'use strict';

var armor = require('./encoding/armor.js'),
  enums = require('./enums.js'),
  message = require('./message.js'),
  cleartext = require('./cleartext.js'),
  key = require('./key.js'),
  util = require('./util'),
  AsyncProxy = require('./worker/async_proxy.js');

if (typeof Promise === 'undefined') {
  // load ES6 Promises polyfill
  require('es6-promise').polyfill();
}

var asyncProxy = null; // instance of the asyncproxy

/**
 * Set the path for the web worker script and create an instance of the async proxy
 * @param {String} path relative path to the worker scripts, default: 'openpgp.worker.js'
 * @param {Object} [options.worker=Object] alternative to path parameter:
 *                                         web worker initialized with 'openpgp.worker.js'
 * @return {Boolean} true if worker created successfully
 */
function initWorker(path, options) {
  if (options && options.worker || typeof window !== 'undefined' && window.Worker) {
    options = options || {};
    options.config = this.config;
    asyncProxy = new AsyncProxy(path, options);
    return true;
  } else {
    return false;
  }
}

/**
 * Returns a reference to the async proxy if the worker was initialized with openpgp.initWorker()
 * @return {module:worker/async_proxy~AsyncProxy|null} the async proxy or null if not initialized
 */
function getWorker() {
  return asyncProxy;
}

/**
 * Encrypts message text with keys
 * @param  {(Array<module:key~Key>|module:key~Key)}  keys array of keys or single key, used to encrypt the message
 * @param  {String} text message as native JavaScript string
 * @return {Promise<String>}      encrypted ASCII armored message
 * @static
 */
function encryptMessage(keys, text) {
  if (!keys.length) {
    keys = [keys];
  }

  if (asyncProxy) {
    return asyncProxy.encryptMessage(keys, text);
  }

  return execute(function() {
    var msg, armored;
    msg = message.fromText(text);
    msg = msg.encrypt(keys);
    armored = armor.encode(enums.armor.message, msg.packets.write());
    return armored;

  }, 'Error encrypting message!');
}

/**
 * Signs message text and encrypts it
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key, used to encrypt the message
 * @param  {module:key~Key}    privateKey private key with decrypted secret key data for signing
 * @param  {String} text       message as native JavaScript string
 * @return {Promise<String>}   encrypted ASCII armored message
 * @static
 */
function signAndEncryptMessage(publicKeys, privateKey, text) {
  if (!publicKeys.length) {
    publicKeys = [publicKeys];
  }

  if (asyncProxy) {
    return asyncProxy.signAndEncryptMessage(publicKeys, privateKey, text);
  }

  return execute(function() {
    var msg, armored;
    msg = message.fromText(text);
    msg = msg.sign([privateKey]);
    msg = msg.encrypt(publicKeys);
    armored = armor.encode(enums.armor.message, msg.packets.write());
    return armored;

  }, 'Error signing and encrypting message!');
}

/**
 * Decrypts message
 * @param  {module:key~Key}                privateKey private key with decrypted secret key data
 * @param  {module:message~Message} msg    the message object with the encrypted data
 * @return {Promise<(String|null)>}        decrypted message as as native JavaScript string
 *                              or null if no literal data found
 * @static
 */
function decryptMessage(privateKey, msg) {
  if (asyncProxy) {
    return asyncProxy.decryptMessage(privateKey, msg);
  }

  return execute(function() {
    msg = msg.decrypt(privateKey);
    return msg.getText();

  }, 'Error decrypting message!');
}

/**
 * Decrypts message and verifies signatures
 * @param  {module:key~Key}     privateKey private key with decrypted secret key data
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key, to verify signatures
 * @param  {module:message~Message} msg    the message object with signed and encrypted data
 * @return {Promise<{text: String, signatures: Array<{keyid: module:type/keyid, valid: Boolean}>}>}
 *                              decrypted message as as native JavaScript string
 *                              with verified signatures or null if no literal data found
 * @static
 */
function decryptAndVerifyMessage(privateKey, publicKeys, msg) {
  if (!publicKeys.length) {
    publicKeys = [publicKeys];
  }

  if (asyncProxy) {
    return asyncProxy.decryptAndVerifyMessage(privateKey, publicKeys, msg);
  }

  return execute(function() {
    var result = {};
    msg = msg.decrypt(privateKey);
    result.text = msg.getText();
    if (result.text) {
      result.signatures = msg.verify(publicKeys);
      return result;
    }
    return null;

  }, 'Error decrypting and verifying message!');
}

/**
 * Signs a cleartext message
 * @param  {(Array<module:key~Key>|module:key~Key)}  privateKeys array of keys or single key with decrypted secret key data to sign cleartext
 * @param  {String} text        cleartext
 * @return {Promise<String>}    ASCII armored message
 * @static
 */
function signClearMessage(privateKeys, text) {
  if (!privateKeys.length) {
    privateKeys = [privateKeys];
  }

  if (asyncProxy) {
    return asyncProxy.signClearMessage(privateKeys, text);
  }

  return execute(function() {
    var cleartextMessage = new cleartext.CleartextMessage(text);
    cleartextMessage.sign(privateKeys);
    return cleartextMessage.armor();

  }, 'Error signing cleartext message!');
}

/**
 * Verifies signatures of cleartext signed message
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key, to verify signatures
 * @param  {module:cleartext~CleartextMessage} msg    cleartext message object with signatures
 * @return {Promise<{text: String, signatures: Array<{keyid: module:type/keyid, valid: Boolean}>}>}
 *                                       cleartext with status of verified signatures
 * @static
 */
function verifyClearSignedMessage(publicKeys, msg) {
  if (!publicKeys.length) {
    publicKeys = [publicKeys];
  }

  if (asyncProxy) {
    return asyncProxy.verifyClearSignedMessage(publicKeys, msg);
  }

  return execute(function() {
    var result = {};
    if (!(msg instanceof cleartext.CleartextMessage)) {
      throw new Error('Parameter [message] needs to be of type CleartextMessage.');
    }
    result.text = msg.getText();
    result.signatures = msg.verify(publicKeys);
    return result;

  }, 'Error verifying cleartext signed message!');
}

/**
 * Generates a new OpenPGP key pair. Currently only supports RSA keys.
 * Primary and subkey will be of same type.
 * @param {module:enums.publicKey} [options.keyType=module:enums.publicKey.rsa_encrypt_sign]    to indicate what type of key to make.
 *                             RSA is 1. See {@link http://tools.ietf.org/html/rfc4880#section-9.1}
 * @param {Integer} options.numBits    number of bits for the key creation. (should be 1024+, generally)
 * @param {String}  options.userId     assumes already in form of "User Name <username@email.com>"
 * @param {String}  options.passphrase The passphrase used to encrypt the resulting private key
 * @param {Boolean} [options.unlocked=false]    The secret part of the generated key is unlocked
 * @return {Promise<Object>} {key: module:key~Key, privateKeyArmored: String, publicKeyArmored: String}
 * @static
 */
function generateKeyPair(options) {
  // use web worker if web crypto apis are not supported
  if (!util.getWebCrypto() && asyncProxy) {
    return asyncProxy.generateKeyPair(options);
  }

  return key.generate(options).then(function(newKey) {
    var result = {};
    result.key = newKey;
    result.privateKeyArmored = newKey.armor();
    result.publicKeyArmored = newKey.toPublic().armor();
    return result;

  }).catch(function(err) {
    console.error(err);

    if (!util.getWebCrypto()) {
      // js fallback already tried
      throw new Error('Error generating keypair using js fallback!');
    }

    // fall back to js keygen in a worker
    console.log('Error generating keypair using native WebCrypto... falling back back to js!');
    return asyncProxy.generateKeyPair(options);

  }).catch(onError.bind(null, 'Error generating keypair!'));
}

//
// helper functions
//

/**
 * Command pattern that wraps synchronous code into a promise
 * @param  {function} cmd     The synchronous function with a return value
 *                            to be wrapped in a promise
 * @param  {String}   errMsg  A human readable error Message
 * @return {Promise}          The promise wrapped around cmd
 */
function execute(cmd, errMsg) {
  // wrap the sync cmd in a promise
  var promise = new Promise(function(resolve) {
    var result = cmd();
    resolve(result);
  });

  // handler error globally
  return promise.catch(onError.bind(null, errMsg));
}

/**
 * Global error handler that logs the stack trace and
 *   rethrows a high lvl error message
 * @param  {String} message   A human readable high level error Message
 * @param  {Error}  error     The internal error that caused the failure
 */
function onError(message, error) {
  // log the stack trace
  console.error(error.stack);
  // rethrow new high level error for api users
  throw new Error(message);
}

exports.initWorker = initWorker;
exports.getWorker = getWorker;
exports.encryptMessage = encryptMessage;
exports.signAndEncryptMessage = signAndEncryptMessage;
exports.decryptMessage = decryptMessage;
exports.decryptAndVerifyMessage = decryptAndVerifyMessage;
exports.signClearMessage = signClearMessage;
exports.verifyClearSignedMessage = verifyClearSignedMessage;
exports.generateKeyPair = generateKeyPair;
},{"./cleartext.js":28,"./encoding/armor.js":58,"./enums.js":60,"./key.js":62,"./message.js":66,"./util":95,"./worker/async_proxy.js":96,"es6-promise":18}],68:[function(require,module,exports){
/**
 * @requires enums
 * @module packet
 */
var enums = require('../enums.js');

// This is pretty ugly, but browserify needs to have the requires explicitly written.

module.exports = {
  packet: require('./packet.js'),
  /** @see module:packet/compressed */
  Compressed: require('./compressed.js'),
  /** @see module:packet/sym_encrypted_integrity_protected */
  SymEncryptedIntegrityProtected: require('./sym_encrypted_integrity_protected.js'),
  /** @see module:packet/public_key_encrypted_session_key */
  PublicKeyEncryptedSessionKey: require('./public_key_encrypted_session_key.js'),
  /** @see module:packet/sym_encrypted_session_key */
  SymEncryptedSessionKey: require('./sym_encrypted_session_key.js'),
  /** @see module:packet/literal */
  Literal: require('./literal.js'),
  /** @see module:packet/public_key */
  PublicKey: require('./public_key.js'),
  /** @see module:packet/symmetrically_encrypted */
  SymmetricallyEncrypted: require('./symmetrically_encrypted.js'),
  /** @see module:packet/marker */
  Marker: require('./marker.js'),
  /** @see module:packet/public_subkey */
  PublicSubkey: require('./public_subkey.js'),
  /** @see module:packet/user_attribute */
  UserAttribute: require('./user_attribute.js'),
  /** @see module:packet/one_pass_signature */
  OnePassSignature: require('./one_pass_signature.js'),
  /** @see module:packet/secret_key */
  SecretKey: require('./secret_key.js'),
  /** @see module:packet/userid */
  Userid: require('./userid.js'),
  /** @see module:packet/secret_subkey */
  SecretSubkey: require('./secret_subkey.js'),
  /** @see module:packet/signature */
  Signature: require('./signature.js'),
  /** @see module:packet/trust */
  Trust: require('./trust.js'),
  /**
   * Allocate a new packet
   * @param {String} tag property name from {@link module:enums.packet}
   * @returns {Object} new packet object with type based on tag
   */
  newPacketFromTag: function (tag) {
    return new this[packetClassFromTagName(tag)]();
  },
  /**
   * Allocate a new packet from structured packet clone
   * See {@link http://www.w3.org/html/wg/drafts/html/master/infrastructure.html#safe-passing-of-structured-data}
   * @param {Object} packetClone packet clone
   * @returns {Object} new packet object with data from packet clone
   */
  fromStructuredClone: function(packetClone) {
    var tagName = enums.read(enums.packet, packetClone.tag)
    var packet = this.newPacketFromTag(tagName);
    for (var attr in packetClone) {
        if (packetClone.hasOwnProperty(attr)) {
          packet[attr] = packetClone[attr];
        }
      }
    if (packet.postCloneTypeFix) {
      packet.postCloneTypeFix();
    }
    return packet;
  }
};

/**
 * Convert tag name to class name
 * @param {String} tag property name from {@link module:enums.packet}
 * @returns {String}
 */
function packetClassFromTagName(tag) {
  return tag.substr(0, 1).toUpperCase() + tag.substr(1);
}

},{"../enums.js":60,"./compressed.js":69,"./literal.js":71,"./marker.js":72,"./one_pass_signature.js":73,"./packet.js":74,"./public_key.js":76,"./public_key_encrypted_session_key.js":77,"./public_subkey.js":78,"./secret_key.js":79,"./secret_subkey.js":80,"./signature.js":81,"./sym_encrypted_integrity_protected.js":82,"./sym_encrypted_session_key.js":83,"./symmetrically_encrypted.js":84,"./trust.js":85,"./user_attribute.js":86,"./userid.js":87}],69:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the Compressed Data Packet (Tag 8)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.6|RFC4880 5.6}: The Compressed Data packet contains compressed data.  Typically,
 * this packet is found as the contents of an encrypted packet, or following
 * a Signature or One-Pass Signature packet, and contains a literal data packet.
 * @requires compression/zlib
 * @requires compression/rawinflate
 * @requires compression/rawdeflate
 * @requires enums
 * @requires util
 * @module packet/compressed
 */

module.exports = Compressed;

var enums = require('../enums.js'),
  util = require('../util.js'),
  Zlib = require('../compression/zlib.min.js'),
  RawInflate = require('../compression/rawinflate.min.js'),
  RawDeflate = require('../compression/rawdeflate.min.js');

/**
 * @constructor
 */
function Compressed() {
  /**
   * Packet type
   * @type {module:enums.packet}
   */
  this.tag = enums.packet.compressed;
  /**
   * List of packets
   * @type {module:packet/packetlist}
   */
  this.packets = null;
  /**
   * Compression algorithm
   * @type {compression}
   */
  this.algorithm = 'zip';

  /**
   * Compressed packet data
   * @type {String}
   */
  this.compressed = null;
}

/**
 * Parsing function for the packet.
 * @param {String} bytes Payload of a tag 8 packet
 */
Compressed.prototype.read = function (bytes) {
  // One octet that gives the algorithm used to compress the packet.
  this.algorithm = enums.read(enums.compression, bytes.charCodeAt(0));

  // Compressed data, which makes up the remainder of the packet.
  this.compressed = bytes.substr(1);

  this.decompress();
};



/**
 * Return the compressed packet.
 * @return {String} binary compressed packet
 */
Compressed.prototype.write = function () {
  if (this.compressed === null)
    this.compress();

  return String.fromCharCode(enums.write(enums.compression, this.algorithm)) + this.compressed;
};


/**
 * Decompression method for decompressing the compressed data
 * read by read_packet
 */
Compressed.prototype.decompress = function () {
  var decompressed;

  switch (this.algorithm) {
    case 'uncompressed':
      decompressed = this.compressed;
      break;

    case 'zip':
      var inflate = new RawInflate.Zlib.RawInflate(util.str2Uint8Array(this.compressed));
      decompressed = util.Uint8Array2str(inflate.decompress());
      break;

    case 'zlib':
      var inflate = new Zlib.Zlib.Inflate(util.str2Uint8Array(this.compressed));
      decompressed = util.Uint8Array2str(inflate.decompress());
      break;

    case 'bzip2':
      // TODO: need to implement this
      throw new Error('Compression algorithm BZip2 [BZ2] is not implemented.');

    default:
      throw new Error("Compression algorithm unknown :" + this.alogrithm);
  }

  this.packets.read(decompressed);
};

/**
 * Compress the packet data (member decompressedData)
 */
Compressed.prototype.compress = function () {
  var uncompressed, deflate;
  uncompressed = this.packets.write();

  switch (this.algorithm) {

    case 'uncompressed':
      // - Uncompressed
      this.compressed = uncompressed;
      break;

    case 'zip':
      // - ZIP [RFC1951]
      deflate = new RawDeflate.Zlib.RawDeflate(util.str2Uint8Array(uncompressed));
      this.compressed = util.Uint8Array2str(deflate.compress());
      break;

    case 'zlib':
      // - ZLIB [RFC1950]
      deflate = new Zlib.Zlib.Deflate(util.str2Uint8Array(uncompressed));
      this.compressed = util.Uint8Array2str(deflate.compress());
      break;

    case 'bzip2':
      //  - BZip2 [BZ2]
      // TODO: need to implement this
      throw new Error("Compression algorithm BZip2 [BZ2] is not implemented.");

    default:
      throw new Error("Compression algorithm unknown :" + this.type);
  }
};

},{"../compression/rawdeflate.min.js":29,"../compression/rawinflate.min.js":30,"../compression/zlib.min.js":31,"../enums.js":60,"../util.js":95}],70:[function(require,module,exports){
var enums = require('../enums.js');

module.exports = {
  /**
   * @name module:packet.List
   * @see module:packet/packetlist
   */
  List: require('./packetlist.js'),
  writeHeader: require('./packet.js').writeHeader
};

var packets = require('./all_packets.js');

for (var i in packets)
  module.exports[i] = packets[i];

},{"../enums.js":60,"./all_packets.js":68,"./packet.js":74,"./packetlist.js":75}],71:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the Literal Data Packet (Tag 11)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.9|RFC4880 5.9}: A Literal Data packet contains the body of a message; data that
 * is not to be further interpreted.
 * @requires enums
 * @requires util
 * @module packet/literal
 */

module.exports = Literal;

var util = require('../util.js'),
  enums = require('../enums.js');

/**
 * @constructor
 */
function Literal() {
  this.tag = enums.packet.literal;
  this.format = 'utf8'; // default format for literal data packets
  this.data = ''; // literal data representation as native JavaScript string or bytes
  this.date = new Date();
  this.filename = 'msg.txt';
}

/**
 * Set the packet data to a javascript native string, end of line
 * will be normalized to \r\n and by default text is converted to UTF8
 * @param {String} text Any native javascript string
 */
Literal.prototype.setText = function (text) {
  // normalize EOL to \r\n
  text = text.replace(/\r/g, '').replace(/\n/g, '\r\n');
  // encode UTF8
  this.data = this.format == 'utf8' ? util.encode_utf8(text) : text;
};

/**
 * Returns literal data packets as native JavaScript string
 * with normalized end of line to \n
 * @return {String} literal data as text
 */
Literal.prototype.getText = function () {
  // decode UTF8
  var text = util.decode_utf8(this.data);
  // normalize EOL to \n
  return text.replace(/\r\n/g, '\n');
};

/**
 * Set the packet data to value represented by the provided string of bytes.
 * @param {String} bytes The string of bytes
 * @param {utf8|binary|text} format The format of the string of bytes
 */
Literal.prototype.setBytes = function (bytes, format) {
  this.format = format;
  this.data = bytes;
};


/**
 * Get the byte sequence representing the literal packet data
 * @returns {String} A sequence of bytes
 */
Literal.prototype.getBytes = function () {
  return this.data;
};


/**
 * Sets the filename of the literal packet data
 * @param {String} filename Any native javascript string
 */
Literal.prototype.setFilename = function (filename) {
  this.filename = filename;
};


/**
 * Get the filename of the literal packet data
 * @returns {String} filename 
 */
Literal.prototype.getFilename = function() {
  return this.filename;
};


/**
 * Parsing function for a literal data packet (tag 11).
 *
 * @param {String} input Payload of a tag 11 packet
 * @param {Integer} position
 *            Position to start reading from the input string
 * @param {Integer} len
 *            Length of the packet or the remaining length of
 *            input at position
 * @return {module:packet/literal} object representation
 */
Literal.prototype.read = function (bytes) {
  // - A one-octet field that describes how the data is formatted.

  var format = enums.read(enums.literal, bytes.charCodeAt(0));

  var filename_len = bytes.charCodeAt(1);
  this.filename = util.decode_utf8(bytes.substr(2, filename_len));

  this.date = util.readDate(bytes.substr(2 + filename_len, 4));

  var data = bytes.substring(6 + filename_len);

  this.setBytes(data, format);
};

/**
 * Creates a string representation of the packet
 *
 * @param {String} data The data to be inserted as body
 * @return {String} string-representation of the packet
 */
Literal.prototype.write = function () {
  var filename = util.encode_utf8(this.filename);

  var data = this.getBytes();
  
  var result = '';
  result += String.fromCharCode(enums.write(enums.literal, this.format));
  result += String.fromCharCode(filename.length);
  result += filename;
  result += util.writeDate(this.date);
  result += data;
  return result;
};

},{"../enums.js":60,"../util.js":95}],72:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA


/**
 * Implementation of the strange "Marker packet" (Tag 10)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.8|RFC4880 5.8}: An experimental version of PGP used this packet as the Literal
 * packet, but no released version of PGP generated Literal packets with this
 * tag. With PGP 5.x, this packet has been reassigned and is reserved for use as
 * the Marker packet.<br/>
 * <br/>
 * Such a packet MUST be ignored when received.
 * @requires enums
 * @module packet/marker
 */

module.exports = Marker;

var enums = require('../enums.js');

/**
 * @constructor
 */
function Marker() {
  this.tag = enums.packet.marker;
}

/**
 * Parsing function for a literal data packet (tag 10).
 *
 * @param {String} input Payload of a tag 10 packet
 * @param {Integer} position
 *            Position to start reading from the input string
 * @param {Integer} len
 *            Length of the packet or the remaining length of
 *            input at position
 * @return {module:packet/marker} Object representation
 */
Marker.prototype.read = function (bytes) {
  if (bytes.charCodeAt(0) == 0x50 && // P
      bytes.charCodeAt(1) == 0x47 && // G
      bytes.charCodeAt(2) == 0x50) // P
    return true;
  // marker packet does not contain "PGP"
  return false;
};

},{"../enums.js":60}],73:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the One-Pass Signature Packets (Tag 4)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.4|RFC4880 5.4}: The One-Pass Signature packet precedes the signed data and contains
 * enough information to allow the receiver to begin calculating any
 * hashes needed to verify the signature.  It allows the Signature
 * packet to be placed at the end of the message, so that the signer
 * can compute the entire signed message in one pass.
 * @requires enums
 * @requires type/keyid
 * @module packet/one_pass_signature
*/

module.exports = OnePassSignature;

var enums = require('../enums.js'),
  type_keyid = require('../type/keyid.js');

/**
 * @constructor
 */
function OnePassSignature() {
  this.tag = enums.packet.onePassSignature; // The packet type
  this.version = null; // A one-octet version number.  The current version is 3.
  this.type = null; // A one-octet signature type.  Signature types are described in {@link http://tools.ietf.org/html/rfc4880#section-5.2.1|RFC4880 Section 5.2.1}.
  this.hashAlgorithm = null; // A one-octet number describing the hash algorithm used. (See {@link http://tools.ietf.org/html/rfc4880#section-9.4|RFC4880 9.4})
  this.publicKeyAlgorithm = null; // A one-octet number describing the public-key algorithm used. (See {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC4880 9.1})
  this.signingKeyId = null; // An eight-octet number holding the Key ID of the signing key.
  this.flags = null; //  A one-octet number holding a flag showing whether the signature is nested.  A zero value indicates that the next packet is another One-Pass Signature packet that describes another signature to be applied to the same message data.
}

/**
 * parsing function for a one-pass signature packet (tag 4).
 * @param {String} bytes payload of a tag 4 packet
 * @return {module:packet/one_pass_signature} object representation
 */
OnePassSignature.prototype.read = function (bytes) {
  var mypos = 0;
  // A one-octet version number.  The current version is 3.
  this.version = bytes.charCodeAt(mypos++);

  // A one-octet signature type.  Signature types are described in
  //   Section 5.2.1.
  this.type = enums.read(enums.signature, bytes.charCodeAt(mypos++));

  // A one-octet number describing the hash algorithm used.
  this.hashAlgorithm = enums.read(enums.hash, bytes.charCodeAt(mypos++));

  // A one-octet number describing the public-key algorithm used.
  this.publicKeyAlgorithm = enums.read(enums.publicKey, bytes.charCodeAt(mypos++));

  // An eight-octet number holding the Key ID of the signing key.
  this.signingKeyId = new type_keyid();
  this.signingKeyId.read(bytes.substr(mypos));
  mypos += 8;

  // A one-octet number holding a flag showing whether the signature
  //   is nested.  A zero value indicates that the next packet is
  //   another One-Pass Signature packet that describes another
  //   signature to be applied to the same message data.
  this.flags = bytes.charCodeAt(mypos++);
  return this;
};

/**
 * creates a string representation of a one-pass signature packet
 * @return {String} a string representation of a one-pass signature packet
 */
OnePassSignature.prototype.write = function () {
  var result = "";

  result += String.fromCharCode(3);
  result += String.fromCharCode(enums.write(enums.signature, this.type));
  result += String.fromCharCode(enums.write(enums.hash, this.hashAlgorithm));
  result += String.fromCharCode(enums.write(enums.publicKey, this.publicKeyAlgorithm));
  result += this.signingKeyId.write();
  result += String.fromCharCode(this.flags);

  return result;
};

/**
 * Fix custom types after cloning
 */
OnePassSignature.prototype.postCloneTypeFix = function() {
  this.signingKeyId = type_keyid.fromClone(this.signingKeyId);
};

},{"../enums.js":60,"../type/keyid.js":92}],74:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires enums
 * @requires util
 * @module packet/packet
 */

var enums = require('../enums.js'),
  util = require('../util.js');

module.exports = {
  readSimpleLength: function(bytes) {
    var len = 0,
      offset,
      type = bytes.charCodeAt(0);


    if (type < 192) {
      len = bytes.charCodeAt(0);
      offset = 1;
    } else if (type < 255) {
      len = ((bytes.charCodeAt(0) - 192) << 8) + (bytes.charCodeAt(1)) + 192;
      offset = 2;
    } else if (type == 255) {
      len = util.readNumber(bytes.substr(1, 4));
      offset = 5;
    }

    return {
      len: len,
      offset: offset
    };
  },

  /**
   * Encodes a given integer of length to the openpgp length specifier to a
   * string
   * 
   * @param {Integer} length The length to encode
   * @return {String} String with openpgp length representation
   */
  writeSimpleLength: function(length) {
    var result = "";
    if (length < 192) {
      result += String.fromCharCode(length);
    } else if (length > 191 && length < 8384) {
      /*
       * let a = (total data packet length) - 192 let bc = two octet
       * representation of a let d = b + 192
       */
      result += String.fromCharCode(((length - 192) >> 8) + 192);
      result += String.fromCharCode((length - 192) & 0xFF);
    } else {
      result += String.fromCharCode(255);
      result += util.writeNumber(length, 4);
    }
    return result;
  },

  /**
   * Writes a packet header version 4 with the given tag_type and length to a
   * string
   * 
   * @param {Integer} tag_type Tag type
   * @param {Integer} length Length of the payload
   * @return {String} String of the header
   */
  writeHeader: function(tag_type, length) {
    /* we're only generating v4 packet headers here */
    var result = "";
    result += String.fromCharCode(0xC0 | tag_type);
    result += this.writeSimpleLength(length);
    return result;
  },

  /**
   * Writes a packet header Version 3 with the given tag_type and length to a
   * string
   * 
   * @param {Integer} tag_type Tag type
   * @param {Integer} length Length of the payload
   * @return {String} String of the header
   */
  writeOldHeader: function(tag_type, length) {
    var result = "";
    if (length < 256) {
      result += String.fromCharCode(0x80 | (tag_type << 2));
      result += String.fromCharCode(length);
    } else if (length < 65536) {
      result += String.fromCharCode(0x80 | (tag_type << 2) | 1);
      result += util.writeNumber(length, 2);
    } else {
      result += String.fromCharCode(0x80 | (tag_type << 2) | 2);
      result += util.writeNumber(length, 4);
    }
    return result;
  },

  /**
   * Generic static Packet Parser function
   * 
   * @param {String} input Input stream as string
   * @param {integer} position Position to start parsing
   * @param {integer} len Length of the input from position on
   * @return {Object} Returns a parsed module:packet/packet
   */
  read: function(input, position, len) {
    // some sanity checks
    if (input === null || input.length <= position || input.substring(position).length < 2 || (input.charCodeAt(position) &
      0x80) === 0) {
      throw new Error("Error during parsing. This message / key is probably not containing a valid OpenPGP format.");
    }
    var mypos = position;
    var tag = -1;
    var format = -1;
    var packet_length;

    format = 0; // 0 = old format; 1 = new format
    if ((input.charCodeAt(mypos) & 0x40) !== 0) {
      format = 1;
    }

    var packet_length_type;
    if (format) {
      // new format header
      tag = input.charCodeAt(mypos) & 0x3F; // bit 5-0
    } else {
      // old format header
      tag = (input.charCodeAt(mypos) & 0x3F) >> 2; // bit 5-2
      packet_length_type = input.charCodeAt(mypos) & 0x03; // bit 1-0
    }

    // header octet parsing done
    mypos++;

    // parsed length from length field
    var bodydata = null;

    // used for partial body lengths
    var real_packet_length = -1;
    if (!format) {
      // 4.2.1. Old Format Packet Lengths
      switch (packet_length_type) {
        case 0:
          // The packet has a one-octet length. The header is 2 octets
          // long.
          packet_length = input.charCodeAt(mypos++);
          break;
        case 1:
          // The packet has a two-octet length. The header is 3 octets
          // long.
          packet_length = (input.charCodeAt(mypos++) << 8) | input.charCodeAt(mypos++);
          break;
        case 2:
          // The packet has a four-octet length. The header is 5
          // octets long.
          packet_length = (input.charCodeAt(mypos++) << 24) | (input.charCodeAt(mypos++) << 16) | (input.charCodeAt(mypos++) <<
            8) | input.charCodeAt(mypos++);
          break;
        default:
          // 3 - The packet is of indeterminate length. The header is 1
          // octet long, and the implementation must determine how long
          // the packet is. If the packet is in a file, this means that
          // the packet extends until the end of the file. In general, 
          // an implementation SHOULD NOT use indeterminate-length 
          // packets except where the end of the data will be clear 
          // from the context, and even then it is better to use a 
          // definite length, or a new format header. The new format 
          // headers described below have a mechanism for precisely
          // encoding data of indeterminate length.
          packet_length = len;
          break;
      }

    } else // 4.2.2. New Format Packet Lengths
    {

      // 4.2.2.1. One-Octet Lengths
      if (input.charCodeAt(mypos) < 192) {
        packet_length = input.charCodeAt(mypos++);
        util.print_debug("1 byte length:" + packet_length);
        // 4.2.2.2. Two-Octet Lengths
      } else if (input.charCodeAt(mypos) >= 192 && input.charCodeAt(mypos) < 224) {
        packet_length = ((input.charCodeAt(mypos++) - 192) << 8) + (input.charCodeAt(mypos++)) + 192;
        util.print_debug("2 byte length:" + packet_length);
        // 4.2.2.4. Partial Body Lengths
      } else if (input.charCodeAt(mypos) > 223 && input.charCodeAt(mypos) < 255) {
        packet_length = 1 << (input.charCodeAt(mypos++) & 0x1F);
        util.print_debug("4 byte length:" + packet_length);
        // EEEK, we're reading the full data here...
        var mypos2 = mypos + packet_length;
        bodydata = input.substring(mypos, mypos + packet_length);
        var tmplen;
        while (true) {
          if (input.charCodeAt(mypos2) < 192) {
            tmplen = input.charCodeAt(mypos2++);
            packet_length += tmplen;
            bodydata += input.substring(mypos2, mypos2 + tmplen);
            mypos2 += tmplen;
            break;
          } else if (input.charCodeAt(mypos2) >= 192 && input.charCodeAt(mypos2) < 224) {
            tmplen = ((input.charCodeAt(mypos2++) - 192) << 8) + (input.charCodeAt(mypos2++)) + 192;
            packet_length += tmplen;
            bodydata += input.substring(mypos2, mypos2 + tmplen);
            mypos2 += tmplen;
            break;
          } else if (input.charCodeAt(mypos2) > 223 && input.charCodeAt(mypos2) < 255) {
            tmplen = 1 << (input.charCodeAt(mypos2++) & 0x1F);
            packet_length += tmplen;
            bodydata += input.substring(mypos2, mypos2 + tmplen);
            mypos2 += tmplen;
          } else {
            mypos2++;
            tmplen = (input.charCodeAt(mypos2++) << 24) | (input.charCodeAt(mypos2++) << 16) | (input
              .charCodeAt(mypos2++) << 8) | input.charCodeAt(mypos2++);
            bodydata += input.substring(mypos2, mypos2 + tmplen);
            packet_length += tmplen;
            mypos2 += tmplen;
            break;
          }
        }
        real_packet_length = mypos2 - mypos;
        // 4.2.2.3. Five-Octet Lengths
      } else {
        mypos++;
        packet_length = (input.charCodeAt(mypos++) << 24) | (input.charCodeAt(mypos++) << 16) | (input.charCodeAt(mypos++) <<
          8) | input.charCodeAt(mypos++);
      }
    }

    // if there was'nt a partial body length: use the specified
    // packet_length
    if (real_packet_length == -1) {
      real_packet_length = packet_length;
    }

    if (bodydata === null) {
      bodydata = input.substring(mypos, mypos + real_packet_length);
    }

    return {
      tag: tag,
      packet: bodydata,
      offset: mypos + real_packet_length
    };
  }
};

},{"../enums.js":60,"../util.js":95}],75:[function(require,module,exports){
/**
 * This class represents a list of openpgp packets.
 * Take care when iterating over it - the packets themselves
 * are stored as numerical indices.
 * @requires enums
 * @requires packet
 * @requires packet/packet
 * @module packet/packetlist
 */

module.exports = Packetlist;

var packetParser = require('./packet.js'),
  packets = require('./all_packets.js'),
  enums = require('../enums.js'),
  util = require('../util.js');

/**
 * @constructor
 */
function Packetlist() {
  /** The number of packets contained within the list.
   * @readonly
   * @type {Integer} */
  this.length = 0;
}
/**
 * Reads a stream of binary data and interprents it as a list of packets.
 * @param {String} A binary string of bytes.
 */
Packetlist.prototype.read = function (bytes) {
  var i = 0;

  while (i < bytes.length) {
    var parsed = packetParser.read(bytes, i, bytes.length - i);
    i = parsed.offset;

    var tag = enums.read(enums.packet, parsed.tag);
    var packet = packets.newPacketFromTag(tag);

    this.push(packet);
    
    packet.read(parsed.packet);
  }
};

/**
 * Creates a binary representation of openpgp objects contained within the
 * class instance.
 * @returns {String} A binary string of bytes containing valid openpgp packets.
 */
Packetlist.prototype.write = function () {
  var bytes = '';

  for (var i = 0; i < this.length; i++) {
    var packetbytes = this[i].write();
    bytes += packetParser.writeHeader(this[i].tag, packetbytes.length);
    bytes += packetbytes;
  }

  return bytes;
};

/**
 * Adds a packet to the list. This is the only supported method of doing so;
 * writing to packetlist[i] directly will result in an error.
 */
Packetlist.prototype.push = function (packet) {
  if (!packet) return;

  packet.packets = packet.packets || new Packetlist();

  this[this.length] = packet;
  this.length++;
};

/**
* Creates a new PacketList with all packets that pass the test implemented by the provided function.
*/
Packetlist.prototype.filter = function (callback) {

  var filtered = new Packetlist();

  for (var i = 0; i < this.length; i++) {
    if (callback(this[i], i, this)) {
      filtered.push(this[i]);
    }
  }

  return filtered;
};

/**
* Creates a new PacketList with all packets from the given types
*/
Packetlist.prototype.filterByTag = function () {
  var args = Array.prototype.slice.call(arguments);
  var filtered = new Packetlist();
  var that = this;

  for (var i = 0; i < this.length; i++) {
    if (args.some(function(packetType) {return that[i].tag == packetType;})) {
      filtered.push(this[i]);
    }
  }

  return filtered;
};

/**
* Executes the provided callback once for each element
*/
Packetlist.prototype.forEach = function (callback) {
  for (var i = 0; i < this.length; i++) {
    callback(this[i]);
  }
};

/**
 * Traverses packet tree and returns first matching packet
 * @param  {module:enums.packet} type The packet type
 * @return {module:packet/packet|null}
 */
Packetlist.prototype.findPacket = function (type) {
  var packetlist = this.filterByTag(type);
  if (packetlist.length) {
    return packetlist[0];
  } else {
    var found = null;
    for (var i = 0; i < this.length; i++) {
      if (this[i].packets.length) {
        found = this[i].packets.findPacket(type);
        if (found) return found;
      }
    }
  }
  return null;
};

/**
 * Returns array of found indices by tag
 */
Packetlist.prototype.indexOfTag = function () {
  var args = Array.prototype.slice.call(arguments);
  var tagIndex = [];
  var that = this;
  for (var i = 0; i < this.length; i++) {
    if (args.some(function(packetType) {return that[i].tag == packetType;})) {
      tagIndex.push(i);
    }
  }
  return tagIndex;
};

/**
 * Returns slice of packetlist
 */
Packetlist.prototype.slice = function (begin, end) {
  if (!end) {
    end = this.length;
  }
  var part = new Packetlist();
  for (var i = begin; i < end; i++) {
    part.push(this[i]);
  }
  return part;
};

/**
 * Concatenates packetlist or array of packets
 */
Packetlist.prototype.concat = function (packetlist) {
  if (packetlist) {
    for (var i = 0; i < packetlist.length; i++) {
      this.push(packetlist[i]);
    }
  }
};

/**
 * Allocate a new packetlist from structured packetlist clone
 * See {@link http://www.w3.org/html/wg/drafts/html/master/infrastructure.html#safe-passing-of-structured-data}
 * @param {Object} packetClone packetlist clone
 * @returns {Object} new packetlist object with data from packetlist clone
 */
module.exports.fromStructuredClone = function(packetlistClone) {
  var packetlist = new Packetlist();
  for (var i = 0; i < packetlistClone.length; i++) {
    packetlist.push(packets.fromStructuredClone(packetlistClone[i]));
    if (packetlist[i].packets.length !== 0) {
      packetlist[i].packets = this.fromStructuredClone(packetlist[i].packets);
    } else {
      packetlist[i].packets = new Packetlist();
    }
  }
  return packetlist;
};

},{"../enums.js":60,"../util.js":95,"./all_packets.js":68,"./packet.js":74}],76:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the Key Material Packet (Tag 5,6,7,14)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.5|RFC4480 5.5}:
 * A key material packet contains all the information about a public or
 * private key.  There are four variants of this packet type, and two
 * major versions.  Consequently, this section is complex.
 * @requires crypto
 * @requires enums
 * @requires type/keyid
 * @requires type/mpi
 * @requires util
 * @module packet/public_key
 */

module.exports = PublicKey;

var util = require('../util.js'),
  type_mpi = require('../type/mpi.js'),
  type_keyid = require('../type/keyid.js'),
  enums = require('../enums.js'),
  crypto = require('../crypto');

/**
 * @constructor
 */
function PublicKey() {
  this.tag = enums.packet.publicKey;
  this.version = 4;
  /** Key creation date.
   * @type {Date} */
  this.created = new Date();
  /** A list of multiprecision integers
   * @type {module:type/mpi} */
  this.mpi = [];
  /** Public key algorithm
   * @type {module:enums.publicKey} */
  this.algorithm = 'rsa_sign';
  // time in days (V3 only)
  this.expirationTimeV3 = 0;
  /**
   * Fingerprint in lowercase hex
   * @type {String}
   */
  this.fingerprint = null;
  /**
   * Keyid
   * @type {module:type/keyid}
   */
  this.keyid = null;
}

/**
 * Internal Parser for public keys as specified in {@link http://tools.ietf.org/html/rfc4880#section-5.5.2|RFC 4880 section 5.5.2 Public-Key Packet Formats}
 * called by read_tag&lt;num&gt;
 * @param {String} input Input string to read the packet from
 * @return {Object} This object with attributes set by the parser
 */
PublicKey.prototype.read = function (bytes) {
  var pos = 0;
  // A one-octet version number (3 or 4).
  this.version = bytes.charCodeAt(pos++);

  if (this.version == 3 || this.version == 4) {
    // - A four-octet number denoting the time that the key was created.
    this.created = util.readDate(bytes.substr(pos, 4));
    pos += 4;

    if (this.version == 3) {
      // - A two-octet number denoting the time in days that this key is
      //   valid.  If this number is zero, then it does not expire.
      this.expirationTimeV3 = util.readNumber(bytes.substr(pos, 2));
      pos += 2;
    }

    // - A one-octet number denoting the public-key algorithm of this key.
    this.algorithm = enums.read(enums.publicKey, bytes.charCodeAt(pos++));

    var mpicount = crypto.getPublicMpiCount(this.algorithm);
    this.mpi = [];

    var bmpi = bytes.substr(pos);
    var p = 0;

    for (var i = 0; i < mpicount && p < bmpi.length; i++) {

      this.mpi[i] = new type_mpi();

      p += this.mpi[i].read(bmpi.substr(p));

      if (p > bmpi.length) {
        throw new Error('Error reading MPI @:' + p);
      }
    }

    return p + 6;
  } else {
    throw new Error('Version ' + this.version + ' of the key packet is unsupported.');
  }
};

/**
 * Alias of read()
 * @see module:packet/public_key~PublicKey#read
 */
PublicKey.prototype.readPublicKey = PublicKey.prototype.read;

/**
 * Same as write_private_key, but has less information because of
 * public key.
 * @return {Object} {body: [string]OpenPGP packet body contents,
 * header: [string] OpenPGP packet header, string: [string] header+body}
 */
PublicKey.prototype.write = function () {
  // Version
  var result = String.fromCharCode(this.version);
  result += util.writeDate(this.created);
  if (this.version == 3) {
    result += util.writeNumber(this.expirationTimeV3, 2);
  }
  result += String.fromCharCode(enums.write(enums.publicKey, this.algorithm));

  var mpicount = crypto.getPublicMpiCount(this.algorithm);

  for (var i = 0; i < mpicount; i++) {
    result += this.mpi[i].write();
  }

  return result;
};

/**
 * Alias of write()
 * @see module:packet/public_key~PublicKey#write
 */
PublicKey.prototype.writePublicKey = PublicKey.prototype.write;

/**
 * Write an old version packet - it's used by some of the internal routines.
 */
PublicKey.prototype.writeOld = function () {
  var bytes = this.writePublicKey();

  return String.fromCharCode(0x99) +
    util.writeNumber(bytes.length, 2) +
    bytes;
};

/**
 * Calculates the key id of the key
 * @return {String} A 8 byte key id
 */
PublicKey.prototype.getKeyId = function () {
  if (this.keyid) {
    return this.keyid;
  }
  this.keyid = new type_keyid();
  if (this.version == 4) {
    this.keyid.read(util.hex2bin(this.getFingerprint()).substr(12, 8));
  } else if (this.version == 3) {
    this.keyid.read(this.mpi[0].write().substr(-8));
  }
  return this.keyid;
};

/**
 * Calculates the fingerprint of the key
 * @return {String} A string containing the fingerprint in lowercase hex
 */
PublicKey.prototype.getFingerprint = function () {
  if (this.fingerprint) {
    return this.fingerprint;
  }
  var toHash = '';
  if (this.version == 4) {
    toHash = this.writeOld();
    this.fingerprint = crypto.hash.sha1(toHash);
  } else if (this.version == 3) {
    var mpicount = crypto.getPublicMpiCount(this.algorithm);
    for (var i = 0; i < mpicount; i++) {
      toHash += this.mpi[i].toBytes();
    }
    this.fingerprint = crypto.hash.md5(toHash);
  }
  this.fingerprint = util.hexstrdump(this.fingerprint);
  return this.fingerprint;
};

/**
 * Returns bit size of key
 * @return {int} Number of bits
 */
PublicKey.prototype.getBitSize = function () {
  return this.mpi[0].byteLength() * 8;
};

/**
 * Fix custom types after cloning
 */
PublicKey.prototype.postCloneTypeFix = function() {
  for (var i = 0; i < this.mpi.length; i++) {
    this.mpi[i] = type_mpi.fromClone(this.mpi[i]);
  }
  if (this.keyid) {
    this.keyid = type_keyid.fromClone(this.keyid);
  }
};

},{"../crypto":49,"../enums.js":60,"../type/keyid.js":92,"../type/mpi.js":93,"../util.js":95}],77:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Public-Key Encrypted Session Key Packets (Tag 1)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.1|RFC4880 5.1}: A Public-Key Encrypted Session Key packet holds the session key
 * used to encrypt a message. Zero or more Public-Key Encrypted Session Key
 * packets and/or Symmetric-Key Encrypted Session Key packets may precede a
 * Symmetrically Encrypted Data Packet, which holds an encrypted message. The
 * message is encrypted with the session key, and the session key is itself
 * encrypted and stored in the Encrypted Session Key packet(s). The
 * Symmetrically Encrypted Data Packet is preceded by one Public-Key Encrypted
 * Session Key packet for each OpenPGP key to which the message is encrypted.
 * The recipient of the message finds a session key that is encrypted to their
 * public key, decrypts the session key, and then uses the session key to
 * decrypt the message.
 * @requires crypto
 * @requires enums
 * @requires type/keyid
 * @requires type/mpi
 * @requires util
 * @module packet/public_key_encrypted_session_key
 */

module.exports = PublicKeyEncryptedSessionKey;

var type_keyid = require('../type/keyid.js'),
  util = require('../util.js'),
  type_mpi = require('../type/mpi.js'),
  enums = require('../enums.js'),
  crypto = require('../crypto');

/**
 * @constructor
 */
function PublicKeyEncryptedSessionKey() {
  this.tag = enums.packet.publicKeyEncryptedSessionKey;
  this.version = 3;

  this.publicKeyId = new type_keyid();
  this.publicKeyAlgorithm = 'rsa_encrypt';

  this.sessionKey = null;
  this.sessionKeyAlgorithm = 'aes256';

  /** @type {Array<module:type/mpi>} */
  this.encrypted = [];
}

/**
 * Parsing function for a publickey encrypted session key packet (tag 1).
 *
 * @param {String} input Payload of a tag 1 packet
 * @param {Integer} position Position to start reading from the input string
 * @param {Integer} len Length of the packet or the remaining length of
 *            input at position
 * @return {module:packet/public_key_encrypted_session_key} Object representation
 */
PublicKeyEncryptedSessionKey.prototype.read = function (bytes) {

  this.version = bytes.charCodeAt(0);
  this.publicKeyId.read(bytes.substr(1));
  this.publicKeyAlgorithm = enums.read(enums.publicKey, bytes.charCodeAt(9));

  var i = 10;

  var integerCount = (function(algo) {
    switch (algo) {
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
        return 1;

      case 'elgamal':
        return 2;

      default:
        throw new Error("Invalid algorithm.");
    }
  })(this.publicKeyAlgorithm);

  this.encrypted = [];

  for (var j = 0; j < integerCount; j++) {
    var mpi = new type_mpi();
    i += mpi.read(bytes.substr(i));
    this.encrypted.push(mpi);
  }
};

/**
 * Create a string representation of a tag 1 packet
 *
 * @param {String} publicKeyId
 *             The public key id corresponding to publicMPIs key as string
 * @param {Array<module:type/mpi>} publicMPIs
 *            Multiprecision integer objects describing the public key
 * @param {module:enums.publicKey} pubalgo
 *            The corresponding public key algorithm // See {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC4880 9.1}
 * @param {module:enums.symmetric} symmalgo
 *            The symmetric cipher algorithm used to encrypt the data
 *            within an encrypteddatapacket or encryptedintegrity-
 *            protecteddatapacket
 *            following this packet //See {@link http://tools.ietf.org/html/rfc4880#section-9.2|RFC4880 9.2}
 * @param {String} sessionkey
 *            A string of randombytes representing the session key
 * @return {String} The string representation
 */
PublicKeyEncryptedSessionKey.prototype.write = function () {

  var result = String.fromCharCode(this.version);
  result += this.publicKeyId.write();
  result += String.fromCharCode(
    enums.write(enums.publicKey, this.publicKeyAlgorithm));

  for (var i = 0; i < this.encrypted.length; i++) {
    result += this.encrypted[i].write();
  }

  return result;
};

PublicKeyEncryptedSessionKey.prototype.encrypt = function (key) {
  var data = String.fromCharCode(
    enums.write(enums.symmetric, this.sessionKeyAlgorithm));

  data += this.sessionKey;
  var checksum = util.calc_checksum(this.sessionKey);
  data += util.writeNumber(checksum, 2);

  var mpi = new type_mpi();
  mpi.fromBytes(crypto.pkcs1.eme.encode(
    data,
    key.mpi[0].byteLength()));

  this.encrypted = crypto.publicKeyEncrypt(
    this.publicKeyAlgorithm,
    key.mpi,
    mpi);
};

/**
 * Decrypts the session key (only for public key encrypted session key
 * packets (tag 1)
 *
 * @param {module:packet/secret_key} key
 *            Private key with secMPIs unlocked
 * @return {String} The unencrypted session key
 */
PublicKeyEncryptedSessionKey.prototype.decrypt = function (key) {
  var result = crypto.publicKeyDecrypt(
    this.publicKeyAlgorithm,
    key.mpi,
    this.encrypted).toBytes();

  var checksum = util.readNumber(result.substr(result.length - 2));

  var decoded = crypto.pkcs1.eme.decode(result);

  key = decoded.substring(1, decoded.length - 2);

  if (checksum != util.calc_checksum(key)) {
    throw new Error('Checksum mismatch');
  } else {
    this.sessionKey = key;
    this.sessionKeyAlgorithm =
      enums.read(enums.symmetric, decoded.charCodeAt(0));
  }
};

/**
 * Fix custom types after cloning
 */
PublicKeyEncryptedSessionKey.prototype.postCloneTypeFix = function() {
  this.publicKeyId = type_keyid.fromClone(this.publicKeyId);
  for (var i = 0; i < this.encrypted.length; i++) {
    this.encrypted[i] = type_mpi.fromClone(this.encrypted[i]);
  }
};

},{"../crypto":49,"../enums.js":60,"../type/keyid.js":92,"../type/mpi.js":93,"../util.js":95}],78:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires packet/public_key
 * @requires enums
 * @module packet/public_subkey
 */

module.exports = PublicSubkey;

var publicKey = require('./public_key.js'),
  enums = require('../enums.js');

/**
 * @constructor
 * @extends module:packet/public_key
 */
function PublicSubkey() {
  publicKey.call(this);
  this.tag = enums.packet.publicSubkey;
}

PublicSubkey.prototype = new publicKey();
PublicSubkey.prototype.constructor = PublicSubkey;

},{"../enums.js":60,"./public_key.js":76}],79:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the Key Material Packet (Tag 5,6,7,14)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.5|RFC4480 5.5}:
 * A key material packet contains all the information about a public or
 * private key.  There are four variants of this packet type, and two
 * major versions.  Consequently, this section is complex.
 * @requires crypto
 * @requires enums
 * @requires packet/public_key
 * @requires type/mpi
 * @requires type/s2k
 * @requires util
 * @module packet/secret_key
 */

module.exports = SecretKey;

var publicKey = require('./public_key.js'),
  enums = require('../enums.js'),
  util = require('../util.js'),
  crypto = require('../crypto'),
  type_mpi = require('../type/mpi.js'),
  type_s2k = require('../type/s2k.js');

/**
 * @constructor
 * @extends module:packet/public_key
 */
function SecretKey() {
  publicKey.call(this);
  this.tag = enums.packet.secretKey;
  // encrypted secret-key data
  this.encrypted = null;
  // indicator if secret-key data is available in decrypted form
  this.isDecrypted = false;
}

SecretKey.prototype = new publicKey();
SecretKey.prototype.constructor = SecretKey;

function get_hash_len(hash) {
  if (hash == 'sha1')
    return 20;
  else
    return 2;
}

function get_hash_fn(hash) {
  if (hash == 'sha1')
    return crypto.hash.sha1;
  else
    return function(c) {
      return util.writeNumber(util.calc_checksum(c), 2);
  };
}

// Helper function

function parse_cleartext_mpi(hash_algorithm, cleartext, algorithm) {
  var hashlen = get_hash_len(hash_algorithm),
    hashfn = get_hash_fn(hash_algorithm);

  var hashtext = cleartext.substr(cleartext.length - hashlen);
  cleartext = cleartext.substr(0, cleartext.length - hashlen);

  var hash = hashfn(cleartext);

  if (hash != hashtext)
    return new Error("Hash mismatch.");

  var mpis = crypto.getPrivateMpiCount(algorithm);

  var j = 0;
  var mpi = [];

  for (var i = 0; i < mpis && j < cleartext.length; i++) {
    mpi[i] = new type_mpi();
    j += mpi[i].read(cleartext.substr(j));
  }

  return mpi;
}

function write_cleartext_mpi(hash_algorithm, algorithm, mpi) {
  var bytes = '';
  var discard = crypto.getPublicMpiCount(algorithm);

  for (var i = discard; i < mpi.length; i++) {
    bytes += mpi[i].write();
  }


  bytes += get_hash_fn(hash_algorithm)(bytes);

  return bytes;
}


// 5.5.3.  Secret-Key Packet Formats

/**
 * Internal parser for private keys as specified in {@link http://tools.ietf.org/html/rfc4880#section-5.5.3|RFC 4880 section 5.5.3}
 * @param {String} bytes Input string to read the packet from
 */
SecretKey.prototype.read = function (bytes) {
  // - A Public-Key or Public-Subkey packet, as described above.
  var len = this.readPublicKey(bytes);

  bytes = bytes.substr(len);


  // - One octet indicating string-to-key usage conventions.  Zero
  //   indicates that the secret-key data is not encrypted.  255 or 254
  //   indicates that a string-to-key specifier is being given.  Any
  //   other value is a symmetric-key encryption algorithm identifier.
  var isEncrypted = bytes.charCodeAt(0);

  if (isEncrypted) {
    this.encrypted = bytes;
  } else {

    // - Plain or encrypted multiprecision integers comprising the secret
    //   key data.  These algorithm-specific fields are as described
    //   below.
    var parsedMPI = parse_cleartext_mpi('mod', bytes.substr(1), this.algorithm);
    if (parsedMPI instanceof Error)
      throw parsedMPI;
    this.mpi = this.mpi.concat(parsedMPI);
    this.isDecrypted = true;
  }

};

/** Creates an OpenPGP key packet for the given key.
  * @return {String} A string of bytes containing the secret key OpenPGP packet
  */
SecretKey.prototype.write = function () {
  var bytes = this.writePublicKey();

  if (!this.encrypted) {
    bytes += String.fromCharCode(0);

    bytes += write_cleartext_mpi('mod', this.algorithm, this.mpi);
  } else {
    bytes += this.encrypted;
  }

  return bytes;
};




/** Encrypt the payload. By default, we use aes256 and iterated, salted string
 * to key specifier. If the key is in a decrypted state (isDecrypted == true)
 * and the passphrase is empty or undefined, the key will be set as not encrypted.
 * This can be used to remove passphrase protection after calling decrypt().
 * @param {String} passphrase
 */
SecretKey.prototype.encrypt = function (passphrase) {
  if (this.isDecrypted && !passphrase) {
    this.encrypted = null;
    return;
  } else if (!passphrase) {
    throw new Error('The key must be decrypted before removing passphrase protection.');
  }

  var s2k = new type_s2k(),
    symmetric = 'aes256',
    cleartext = write_cleartext_mpi('sha1', this.algorithm, this.mpi),
    key = produceEncryptionKey(s2k, passphrase, symmetric),
    blockLen = crypto.cipher[symmetric].blockSize,
    iv = crypto.random.getRandomBytes(blockLen);

  this.encrypted = '';
  this.encrypted += String.fromCharCode(254);
  this.encrypted += String.fromCharCode(enums.write(enums.symmetric, symmetric));
  this.encrypted += s2k.write();
  this.encrypted += iv;

  this.encrypted += crypto.cfb.normalEncrypt(symmetric, key, cleartext, iv);
};

function produceEncryptionKey(s2k, passphrase, algorithm) {
  return s2k.produce_key(passphrase,
    crypto.cipher[algorithm].keySize);
}

/**
 * Decrypts the private key MPIs which are needed to use the key.
 * @link module:packet/secret_key.isDecrypted should be
 * false otherwise a call to this function is not needed
 *
 * @param {String} str_passphrase The passphrase for this private key
 * as string
 * @return {Boolean} True if the passphrase was correct or MPI already
 *                   decrypted; false if not
 */
SecretKey.prototype.decrypt = function (passphrase) {
  if (this.isDecrypted)
    return true;

  var i = 0,
    symmetric,
    key;

  var s2k_usage = this.encrypted.charCodeAt(i++);

  // - [Optional] If string-to-key usage octet was 255 or 254, a one-
  //   octet symmetric encryption algorithm.
  if (s2k_usage == 255 || s2k_usage == 254) {
    symmetric = this.encrypted.charCodeAt(i++);
    symmetric = enums.read(enums.symmetric, symmetric);

    // - [Optional] If string-to-key usage octet was 255 or 254, a
    //   string-to-key specifier.  The length of the string-to-key
    //   specifier is implied by its type, as described above.
    var s2k = new type_s2k();
    i += s2k.read(this.encrypted.substr(i));

    key = produceEncryptionKey(s2k, passphrase, symmetric);
  } else {
    symmetric = s2k_usage;
    symmetric = enums.read(enums.symmetric, symmetric);
    key = crypto.hash.md5(passphrase);
  }


  // - [Optional] If secret data is encrypted (string-to-key usage octet
  //   not zero), an Initial Vector (IV) of the same length as the
  //   cipher's block size.
  var iv = this.encrypted.substr(i,
    crypto.cipher[symmetric].blockSize);

  i += iv.length;

  var cleartext,
    ciphertext = this.encrypted.substr(i);

  cleartext = crypto.cfb.normalDecrypt(symmetric, key, ciphertext, iv);

  var hash = s2k_usage == 254 ?
    'sha1' :
    'mod';

  var parsedMPI = parse_cleartext_mpi(hash, cleartext, this.algorithm);
  if (parsedMPI instanceof Error) {
    return false;
  }
  this.mpi = this.mpi.concat(parsedMPI);
  this.isDecrypted = true;
  return true;
};

SecretKey.prototype.generate = function (bits, prng) {
  var self = this;
  return crypto.generateMpi(self.algorithm, bits, prng).then(function(mpi) {
    self.mpi = mpi;
    self.isDecrypted = true;
  });
};

/**
 * Clear private MPIs, return to initial state
 */
SecretKey.prototype.clearPrivateMPIs = function () {
  if (!this.encrypted) {
    throw new Error('If secret key is not encrypted, clearing private MPIs is irreversible.');
  }
  this.mpi = this.mpi.slice(0, crypto.getPublicMpiCount(this.algorithm));
  this.isDecrypted = false;
};

},{"../crypto":49,"../enums.js":60,"../type/mpi.js":93,"../type/s2k.js":94,"../util.js":95,"./public_key.js":76}],80:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires packet/secret_key
 * @requires enums
 * @module packet/secret_subkey
 */

module.exports = SecretSubkey;

var secretKey = require('./secret_key.js'),
  enums = require('../enums.js');

/**
 * @constructor
 * @extends module:packet/secret_key
 */
function SecretSubkey() {
  secretKey.call(this);
  this.tag = enums.packet.secretSubkey;
}

SecretSubkey.prototype = new secretKey();
SecretSubkey.prototype.constructor = SecretSubkey;

},{"../enums.js":60,"./secret_key.js":79}],81:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the Signature Packet (Tag 2)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.2|RFC4480 5.2}:
 * A Signature packet describes a binding between some public key and
 * some data.  The most common signatures are a signature of a file or a
 * block of text, and a signature that is a certification of a User ID.
 * @requires crypto
 * @requires enums
 * @requires packet/packet
 * @requires type/keyid
 * @requires type/mpi
 * @requires util
 * @module packet/signature
 */

module.exports = Signature;

var util = require('../util.js'),
  packet = require('./packet.js'),
  enums = require('../enums.js'),
  crypto = require('../crypto'),
  type_mpi = require('../type/mpi.js'),
  type_keyid = require('../type/keyid.js');

/**
 * @constructor
 */
function Signature() {
  this.tag = enums.packet.signature;
  this.version = 4;
  this.signatureType = null;
  this.hashAlgorithm = null;
  this.publicKeyAlgorithm = null;

  this.signatureData = null;
  this.unhashedSubpackets = null;
  this.signedHashValue = null;

  this.created = new Date();
  this.signatureExpirationTime = null;
  this.signatureNeverExpires = true;
  this.exportable = null;
  this.trustLevel = null;
  this.trustAmount = null;
  this.regularExpression = null;
  this.revocable = null;
  this.keyExpirationTime = null;
  this.keyNeverExpires = null;
  this.preferredSymmetricAlgorithms = null;
  this.revocationKeyClass = null;
  this.revocationKeyAlgorithm = null;
  this.revocationKeyFingerprint = null;
  this.issuerKeyId = new type_keyid();
  this.notation = null;
  this.preferredHashAlgorithms = null;
  this.preferredCompressionAlgorithms = null;
  this.keyServerPreferences = null;
  this.preferredKeyServer = null;
  this.isPrimaryUserID = null;
  this.policyURI = null;
  this.keyFlags = null;
  this.signersUserId = null;
  this.reasonForRevocationFlag = null;
  this.reasonForRevocationString = null;
  this.features = null;
  this.signatureTargetPublicKeyAlgorithm = null;
  this.signatureTargetHashAlgorithm = null;
  this.signatureTargetHash = null;
  this.embeddedSignature = null;

  this.verified = false;
}

/**
 * parsing function for a signature packet (tag 2).
 * @param {String} bytes payload of a tag 2 packet
 * @param {Integer} position position to start reading from the bytes string
 * @param {Integer} len length of the packet or the remaining length of bytes at position
 * @return {module:packet/signature} object representation
 */
Signature.prototype.read = function (bytes) {
  var i = 0;

  this.version = bytes.charCodeAt(i++);
  // switch on version (3 and 4)
  switch (this.version) {
    case 3:
      // One-octet length of following hashed material. MUST be 5.
      if (bytes.charCodeAt(i++) != 5)
        util.print_debug("packet/signature.js\n" +
          'invalid One-octet length of following hashed material.' +
          'MUST be 5. @:' + (i - 1));

      var sigpos = i;
      // One-octet signature type.
      this.signatureType = bytes.charCodeAt(i++);

      // Four-octet creation time.
      this.created = util.readDate(bytes.substr(i, 4));
      i += 4;

      // storing data appended to data which gets verified
      this.signatureData = bytes.substring(sigpos, i);

      // Eight-octet Key ID of signer.
      this.issuerKeyId.read(bytes.substring(i, i + 8));
      i += 8;

      // One-octet public-key algorithm.
      this.publicKeyAlgorithm = bytes.charCodeAt(i++);

      // One-octet hash algorithm.
      this.hashAlgorithm = bytes.charCodeAt(i++);
      break;
    case 4:
      this.signatureType = bytes.charCodeAt(i++);
      this.publicKeyAlgorithm = bytes.charCodeAt(i++);
      this.hashAlgorithm = bytes.charCodeAt(i++);

      function subpackets(bytes) {
        // Two-octet scalar octet count for following subpacket data.
        var subpacket_length = util.readNumber(
          bytes.substr(0, 2));

        var i = 2;

        // subpacket data set (zero or more subpackets)
        var subpacked_read = 0;
        while (i < 2 + subpacket_length) {

          var len = packet.readSimpleLength(bytes.substr(i));
          i += len.offset;

          this.read_sub_packet(bytes.substr(i, len.len));

          i += len.len;
        }

        return i;
      }

      // hashed subpackets
      i += subpackets.call(this, bytes.substr(i), true);

      // A V4 signature hashes the packet body
      // starting from its first field, the version number, through the end
      // of the hashed subpacket data.  Thus, the fields hashed are the
      // signature version, the signature type, the public-key algorithm, the
      // hash algorithm, the hashed subpacket length, and the hashed
      // subpacket body.
      this.signatureData = bytes.substr(0, i);
      var sigDataLength = i;

      // unhashed subpackets
      i += subpackets.call(this, bytes.substr(i), false);
      this.unhashedSubpackets = bytes.substr(sigDataLength, i - sigDataLength);

      break;
    default:
      throw new Error('Version ' + this.version + ' of the signature is unsupported.');
  }

  // Two-octet field holding left 16 bits of signed hash value.
  this.signedHashValue = bytes.substr(i, 2);
  i += 2;

  this.signature = bytes.substr(i);
};

Signature.prototype.write = function () {
  var result = '';
  switch (this.version) {
    case 3:
      result += String.fromCharCode(3); // version
      result += String.fromCharCode(5); // One-octet length of following hashed material.  MUST be 5
      result += this.signatureData;
      result += this.issuerKeyId.write();
      result += String.fromCharCode(this.publicKeyAlgorithm);
      result += String.fromCharCode(this.hashAlgorithm);
      break;
    case 4:
      result += this.signatureData;
      result += this.unhashedSubpackets ? this.unhashedSubpackets : util.writeNumber(0, 2);
      break;
  }
  result += this.signedHashValue + this.signature;
  return result;
};

/**
 * Signs provided data. This needs to be done prior to serialization.
 * @param {module:packet/secret_key} key private key used to sign the message.
 * @param {Object} data Contains packets to be signed.
 */
Signature.prototype.sign = function (key, data) {
  var signatureType = enums.write(enums.signature, this.signatureType),
    publicKeyAlgorithm = enums.write(enums.publicKey, this.publicKeyAlgorithm),
    hashAlgorithm = enums.write(enums.hash, this.hashAlgorithm);

  var result = String.fromCharCode(4);
  result += String.fromCharCode(signatureType);
  result += String.fromCharCode(publicKeyAlgorithm);
  result += String.fromCharCode(hashAlgorithm);

  this.issuerKeyId = key.getKeyId();

  // Add hashed subpackets
  result += this.write_all_sub_packets();

  this.signatureData = result;

  var trailer = this.calculateTrailer();

  var toHash = this.toSign(signatureType, data) +
    this.signatureData + trailer;

  var hash = crypto.hash.digest(hashAlgorithm, toHash);

  this.signedHashValue = hash.substr(0, 2);

  this.signature = crypto.signature.sign(hashAlgorithm,
    publicKeyAlgorithm, key.mpi, toHash);
};

/**
 * Creates string of bytes with all subpacket data
 * @return {String} a string-representation of a all subpacket data
 */
Signature.prototype.write_all_sub_packets = function () {
  var sub = enums.signatureSubpacket;
  var result = '';
  var bytes = '';
  if (this.created !== null) {
    result += write_sub_packet(sub.signature_creation_time, util.writeDate(this.created));
  }
  if (this.signatureExpirationTime !== null) {
    result += write_sub_packet(sub.signature_expiration_time, util.writeNumber(this.signatureExpirationTime, 4));
  }
  if (this.exportable !== null) {
    result += write_sub_packet(sub.exportable_certification, String.fromCharCode(this.exportable ? 1 : 0));
  }
  if (this.trustLevel !== null) {
    bytes = String.fromCharCode(this.trustLevel) + String.fromCharCode(this.trustAmount);
    result += write_sub_packet(sub.trust_signature, bytes);
  }
  if (this.regularExpression !== null) {
    result += write_sub_packet(sub.regular_expression, this.regularExpression);
  }
  if (this.revocable !== null) {
    result += write_sub_packet(sub.revocable, String.fromCharCode(this.revocable ? 1 : 0));
  }
  if (this.keyExpirationTime !== null) {
    result += write_sub_packet(sub.key_expiration_time, util.writeNumber(this.keyExpirationTime, 4));
  }
  if (this.preferredSymmetricAlgorithms !== null) {
    bytes = util.bin2str(this.preferredSymmetricAlgorithms);
    result += write_sub_packet(sub.preferred_symmetric_algorithms, bytes);
  }
  if (this.revocationKeyClass !== null) {
    bytes = String.fromCharCode(this.revocationKeyClass);
    bytes += String.fromCharCode(this.revocationKeyAlgorithm);
    bytes += this.revocationKeyFingerprint;
    result += write_sub_packet(sub.revocation_key, bytes);
  }
  if (!this.issuerKeyId.isNull()) {
    result += write_sub_packet(sub.issuer, this.issuerKeyId.write());
  }
  if (this.notation !== null) {
    for (var name in this.notation) {
      if (this.notation.hasOwnProperty(name)) {
        var value = this.notation[name];
        bytes = String.fromCharCode(0x80);
        bytes += String.fromCharCode(0);
        bytes += String.fromCharCode(0);
        bytes += String.fromCharCode(0);
        // 2 octets of name length
        bytes += util.writeNumber(name.length, 2);
        // 2 octets of value length
        bytes += util.writeNumber(value.length, 2);
        bytes += name + value;
        result += write_sub_packet(sub.notation_data, bytes);
      }
    }
  }
  if (this.preferredHashAlgorithms !== null) {
    bytes = util.bin2str(this.preferredHashAlgorithms);
    result += write_sub_packet(sub.preferred_hash_algorithms, bytes);
  }
  if (this.preferredCompressionAlgorithms !== null) {
    bytes = util.bin2str(this.preferredCompressionAlgorithms);
    result += write_sub_packet(sub.preferred_compression_algorithms, bytes);
  }
  if (this.keyServerPreferences !== null) {
    bytes = util.bin2str(this.keyServerPreferences);
    result += write_sub_packet(sub.key_server_preferences, bytes);
  }
  if (this.preferredKeyServer !== null) {
    result += write_sub_packet(sub.preferred_key_server, this.preferredKeyServer);
  }
  if (this.isPrimaryUserID !== null) {
    result += write_sub_packet(sub.primary_user_id, String.fromCharCode(this.isPrimaryUserID ? 1 : 0));
  }
  if (this.policyURI !== null) {
    result += write_sub_packet(sub.policy_uri, this.policyURI);
  }
  if (this.keyFlags !== null) {
    bytes = util.bin2str(this.keyFlags);
    result += write_sub_packet(sub.key_flags, bytes);
  }
  if (this.signersUserId !== null) {
    result += write_sub_packet(sub.signers_user_id, this.signersUserId);
  }
  if (this.reasonForRevocationFlag !== null) {
    bytes = String.fromCharCode(this.reasonForRevocationFlag);
    bytes += this.reasonForRevocationString;
    result += write_sub_packet(sub.reason_for_revocation, bytes);
  }
  if (this.features !== null) {
    bytes = util.bin2str(this.features);
    result += write_sub_packet(sub.features, bytes);
  }
  if (this.signatureTargetPublicKeyAlgorithm !== null) {
    bytes = String.fromCharCode(this.signatureTargetPublicKeyAlgorithm);
    bytes += String.fromCharCode(this.signatureTargetHashAlgorithm);
    bytes += this.signatureTargetHash;
    result += write_sub_packet(sub.signature_target, bytes);
  }
  if (this.embeddedSignature !== null) {
    result += write_sub_packet(sub.embedded_signature, this.embeddedSignature.write());
  }
  result = util.writeNumber(result.length, 2) + result;
  return result;
};

/**
 * creates a string representation of a sub signature packet (See {@link http://tools.ietf.org/html/rfc4880#section-5.2.3.1|RFC 4880 5.2.3.1})
 * @param {Integer} type subpacket signature type. Signature types as described
 * in {@link http://tools.ietf.org/html/rfc4880#section-5.2.3.2|RFC4880 Section 5.2.3.2}
 * @param {String} data data to be included
 * @return {String} a string-representation of a sub signature packet (See {@link http://tools.ietf.org/html/rfc4880#section-5.2.3.1|RFC 4880 5.2.3.1})
 */
function write_sub_packet(type, data) {
  var result = "";
  result += packet.writeSimpleLength(data.length + 1);
  result += String.fromCharCode(type);
  result += data;
  return result;
}

// V4 signature sub packets

Signature.prototype.read_sub_packet = function (bytes) {
  var mypos = 0;

  function read_array(prop, bytes) {
    this[prop] = [];

    for (var i = 0; i < bytes.length; i++) {
      this[prop].push(bytes.charCodeAt(i));
    }
  }

  // The leftwost bit denotes a "critical" packet, but we ignore it.
  var type = bytes.charCodeAt(mypos++) & 0x7F;
  var seconds;

  // subpacket type
  switch (type) {
    case 2:
      // Signature Creation Time
      this.created = util.readDate(bytes.substr(mypos));
      break;
    case 3:
      // Signature Expiration Time in seconds
      seconds = util.readNumber(bytes.substr(mypos));

      this.signatureNeverExpires = seconds === 0;
      this.signatureExpirationTime = seconds;

      break;
    case 4:
      // Exportable Certification
      this.exportable = bytes.charCodeAt(mypos++) == 1;
      break;
    case 5:
      // Trust Signature
      this.trustLevel = bytes.charCodeAt(mypos++);
      this.trustAmount = bytes.charCodeAt(mypos++);
      break;
    case 6:
      // Regular Expression
      this.regularExpression = bytes.substr(mypos);
      break;
    case 7:
      // Revocable
      this.revocable = bytes.charCodeAt(mypos++) == 1;
      break;
    case 9:
      // Key Expiration Time in seconds
      seconds = util.readNumber(bytes.substr(mypos));

      this.keyExpirationTime = seconds;
      this.keyNeverExpires = seconds === 0;

      break;
    case 11:
      // Preferred Symmetric Algorithms
      read_array.call(this, 'preferredSymmetricAlgorithms', bytes.substr(mypos));
      break;
    case 12:
      // Revocation Key
      // (1 octet of class, 1 octet of public-key algorithm ID, 20
      // octets of
      // fingerprint)
      this.revocationKeyClass = bytes.charCodeAt(mypos++);
      this.revocationKeyAlgorithm = bytes.charCodeAt(mypos++);
      this.revocationKeyFingerprint = bytes.substr(mypos, 20);
      break;

    case 16:
      // Issuer
      this.issuerKeyId.read(bytes.substr(mypos));
      break;

    case 20:
      // Notation Data
      // We don't know how to handle anything but a text flagged data.
      if (bytes.charCodeAt(mypos) == 0x80) {

        // We extract key/value tuple from the byte stream.
        mypos += 4;
        var m = util.readNumber(bytes.substr(mypos, 2));
        mypos += 2;
        var n = util.readNumber(bytes.substr(mypos, 2));
        mypos += 2;

        var name = bytes.substr(mypos, m),
          value = bytes.substr(mypos + m, n);

        this.notation = this.notation || {};
        this.notation[name] = value;
      } else {
    	  util.print_debug("Unsupported notation flag "+bytes.charCodeAt(mypos));
      	}
      break;
    case 21:
      // Preferred Hash Algorithms
      read_array.call(this, 'preferredHashAlgorithms', bytes.substr(mypos));
      break;
    case 22:
      // Preferred Compression Algorithms
      read_array.call(this, 'preferredCompressionAlgorithms', bytes.substr(mypos));
      break;
    case 23:
      // Key Server Preferences
      read_array.call(this, 'keyServerPreferencess', bytes.substr(mypos));
      break;
    case 24:
      // Preferred Key Server
      this.preferredKeyServer = bytes.substr(mypos);
      break;
    case 25:
      // Primary User ID
      this.isPrimaryUserID = bytes[mypos++] !== 0;
      break;
    case 26:
      // Policy URI
      this.policyURI = bytes.substr(mypos);
      break;
    case 27:
      // Key Flags
      read_array.call(this, 'keyFlags', bytes.substr(mypos));
      break;
    case 28:
      // Signer's User ID
      this.signersUserId += bytes.substr(mypos);
      break;
    case 29:
      // Reason for Revocation
      this.reasonForRevocationFlag = bytes.charCodeAt(mypos++);
      this.reasonForRevocationString = bytes.substr(mypos);
      break;
    case 30:
      // Features
      read_array.call(this, 'features', bytes.substr(mypos));
      break;
    case 31:
      // Signature Target
      // (1 octet public-key algorithm, 1 octet hash algorithm, N octets hash)
      this.signatureTargetPublicKeyAlgorithm = bytes.charCodeAt(mypos++);
      this.signatureTargetHashAlgorithm = bytes.charCodeAt(mypos++);

      var len = crypto.getHashByteLength(this.signatureTargetHashAlgorithm);

      this.signatureTargetHash = bytes.substr(mypos, len);
      break;
    case 32:
      // Embedded Signature
      this.embeddedSignature = new Signature();
      this.embeddedSignature.read(bytes.substr(mypos));
      break;
    default:
    	util.print_debug("Unknown signature subpacket type " + type + " @:" + mypos);
  }
};

// Produces data to produce signature on
Signature.prototype.toSign = function (type, data) {
  var t = enums.signature;

  switch (type) {
    case t.binary:
    case t.text:
      return data.getBytes();

    case t.standalone:
      return '';

    case t.cert_generic:
    case t.cert_persona:
    case t.cert_casual:
    case t.cert_positive:
    case t.cert_revocation:
      var packet, tag;

      if (data.userid !== undefined) {
        tag = 0xB4;
        packet = data.userid;
      } else if (data.userattribute !== undefined) {
        tag = 0xD1;
        packet = data.userattribute;
      } else throw new Error('Either a userid or userattribute packet needs to be ' +
          'supplied for certification.');

      var bytes = packet.write();

      if (this.version == 4) {
        return this.toSign(t.key, data) +
        String.fromCharCode(tag) +
        util.writeNumber(bytes.length, 4) +
        bytes;
      } else if (this.version == 3) {
        return this.toSign(t.key, data) +
        bytes;
      }
      break;

    case t.subkey_binding:
    case t.subkey_revocation:
    case t.key_binding:
      return this.toSign(t.key, data) + this.toSign(t.key, {
        key: data.bind
      });

    case t.key:
      if (data.key === undefined)
        throw new Error('Key packet is required for this signature.');

      return data.key.writeOld();

    case t.key_revocation:
      return this.toSign(t.key, data);
    case t.timestamp:
      return '';
    case t.third_party:
      throw new Error('Not implemented');
    default:
      throw new Error('Unknown signature type.');
  }
};


Signature.prototype.calculateTrailer = function () {
  // calculating the trailer
  var trailer = '';
  // V3 signatures don't have a trailer
  if (this.version == 3) return trailer;
  trailer += String.fromCharCode(4); // Version
  trailer += String.fromCharCode(0xFF);
  trailer += util.writeNumber(this.signatureData.length, 4);
  return trailer;
};


/**
 * verifys the signature packet. Note: not signature types are implemented
 * @param {String|Object} data data which on the signature applies
 * @param {module:packet/public_subkey|module:packet/public_key|
 *         module:packet/secret_subkey|module:packet/secret_key} key the public key to verify the signature
 * @return {boolean} True if message is verified, else false.
 */
Signature.prototype.verify = function (key, data) {
  var signatureType = enums.write(enums.signature, this.signatureType),
    publicKeyAlgorithm = enums.write(enums.publicKey, this.publicKeyAlgorithm),
    hashAlgorithm = enums.write(enums.hash, this.hashAlgorithm);

  var bytes = this.toSign(signatureType, data),
    trailer = this.calculateTrailer();


  var mpicount = 0;
  // Algorithm-Specific Fields for RSA signatures:
  //      - multiprecision number (MPI) of RSA signature value m**d mod n.
  if (publicKeyAlgorithm > 0 && publicKeyAlgorithm < 4)
    mpicount = 1;
  //    Algorithm-Specific Fields for DSA signatures:
  //      - MPI of DSA value r.
  //      - MPI of DSA value s.
  else if (publicKeyAlgorithm == 17)
    mpicount = 2;

  var mpi = [],
    i = 0;
  for (var j = 0; j < mpicount; j++) {
    mpi[j] = new type_mpi();
    i += mpi[j].read(this.signature.substr(i));
  }

  this.verified = crypto.signature.verify(publicKeyAlgorithm,
    hashAlgorithm, mpi, key.mpi,
    bytes + this.signatureData + trailer);

  return this.verified;
};

/**
 * Verifies signature expiration date
 * @return {Boolean} true if expired
 */
Signature.prototype.isExpired = function () {
  if (!this.signatureNeverExpires) {
    return Date.now() > (this.created.getTime() + this.signatureExpirationTime*1000);
  }
  return false;
};

/**
 * Fix custom types after cloning
 */
Signature.prototype.postCloneTypeFix = function() {
  this.issuerKeyId = type_keyid.fromClone(this.issuerKeyId);
};

},{"../crypto":49,"../enums.js":60,"../type/keyid.js":92,"../type/mpi.js":93,"../util.js":95,"./packet.js":74}],82:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the Sym. Encrypted Integrity Protected Data
 * Packet (Tag 18)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.13|RFC4880 5.13}:
 * The Symmetrically Encrypted Integrity Protected Data packet is
 * a variant of the Symmetrically Encrypted Data packet. It is a new feature
 * created for OpenPGP that addresses the problem of detecting a modification to
 * encrypted data. It is used in combination with a Modification Detection Code
 * packet.
 * @requires crypto
 * @requires util
 * @requires enums
 * @module packet/sym_encrypted_integrity_protected
 */

module.exports = SymEncryptedIntegrityProtected;

var util = require('../util.js'),
  crypto = require('../crypto'),
  enums = require('../enums.js');

/**
 * @constructor
 */
function SymEncryptedIntegrityProtected() {
  this.tag = enums.packet.symEncryptedIntegrityProtected;
  /** The encrypted payload. */
  this.encrypted = null; // string
  /**
   * If after decrypting the packet this is set to true,
   * a modification has been detected and thus the contents
   * should be discarded.
   * @type {Boolean}
   */
  this.modification = false;
  this.packets = null;
}

SymEncryptedIntegrityProtected.prototype.read = function (bytes) {
  // - A one-octet version number. The only currently defined value is 1.
  var version = bytes.charCodeAt(0);

  if (version != 1) {
    throw new Error('Invalid packet version.');
  }

  // - Encrypted data, the output of the selected symmetric-key cipher
  //   operating in Cipher Feedback mode with shift amount equal to the
  //   block size of the cipher (CFB-n where n is the block size).
  this.encrypted = bytes.substr(1);
};

SymEncryptedIntegrityProtected.prototype.write = function () {

  // 1 = Version
  return String.fromCharCode(1) + this.encrypted;
};

SymEncryptedIntegrityProtected.prototype.encrypt = function (sessionKeyAlgorithm, key) {
  var bytes = this.packets.write();

  var prefixrandom = crypto.getPrefixRandom(sessionKeyAlgorithm);
  var prefix = prefixrandom + prefixrandom.charAt(prefixrandom.length - 2) + prefixrandom.charAt(prefixrandom.length -
    1);

  var tohash = bytes;


  // Modification detection code packet.
  tohash += String.fromCharCode(0xD3);
  tohash += String.fromCharCode(0x14);


  tohash += crypto.hash.sha1(prefix + tohash);


  this.encrypted = crypto.cfb.encrypt(prefixrandom,
    sessionKeyAlgorithm, tohash, key, false).substring(0,
    prefix.length + tohash.length);
};

/**
 * Decrypts the encrypted data contained in this object read_packet must
 * have been called before
 *
 * @param {module:enums.symmetric} sessionKeyAlgorithm
 *            The selected symmetric encryption algorithm to be used
 * @param {String} key The key of cipher blocksize length to be used
 * @return {String} The decrypted data of this packet
 */
SymEncryptedIntegrityProtected.prototype.decrypt = function (sessionKeyAlgorithm, key) {
  var decrypted = crypto.cfb.decrypt(
    sessionKeyAlgorithm, key, this.encrypted, false);


  // there must be a modification detection code packet as the
  // last packet and everything gets hashed except the hash itself
  this.hash = crypto.hash.sha1(
    crypto.cfb.mdc(sessionKeyAlgorithm, key, this.encrypted) + decrypted.substring(0, decrypted.length - 20));


  var mdc = decrypted.substr(decrypted.length - 20, 20);

  if (this.hash != mdc) {
    throw new Error('Modification detected.');
  } else
    this.packets.read(decrypted.substr(0, decrypted.length - 22));
};

},{"../crypto":49,"../enums.js":60,"../util.js":95}],83:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Public-Key Encrypted Session Key Packets (Tag 1)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.1|RFC4880 5.1}: A Public-Key Encrypted Session Key packet holds the session key
 * used to encrypt a message. Zero or more Public-Key Encrypted Session Key
 * packets and/or Symmetric-Key Encrypted Session Key packets may precede a
 * Symmetrically Encrypted Data Packet, which holds an encrypted message. The
 * message is encrypted with the session key, and the session key is itself
 * encrypted and stored in the Encrypted Session Key packet(s). The
 * Symmetrically Encrypted Data Packet is preceded by one Public-Key Encrypted
 * Session Key packet for each OpenPGP key to which the message is encrypted.
 * The recipient of the message finds a session key that is encrypted to their
 * public key, decrypts the session key, and then uses the session key to
 * decrypt the message.
 * @requires crypto
 * @requires enums
 * @requires type/s2k
 * @module packet/sym_encrypted_session_key
 */

var type_s2k = require('../type/s2k.js'),
  enums = require('../enums.js'),
  crypto = require('../crypto');

module.exports = SymEncryptedSessionKey;

/**
 * @constructor
 */
function SymEncryptedSessionKey() {
  this.tag = enums.packet.symEncryptedSessionKey;
  this.version = 4;
  this.sessionKeyEncryptionAlgorithm = null;
  this.sessionKeyAlgorithm = 'aes256';
  this.encrypted = null;
  this.s2k = new type_s2k();
}

/**
 * Parsing function for a symmetric encrypted session key packet (tag 3).
 *
 * @param {String} input Payload of a tag 1 packet
 * @param {Integer} position Position to start reading from the input string
 * @param {Integer} len
 *            Length of the packet or the remaining length of
 *            input at position
 * @return {module:packet/sym_encrypted_session_key} Object representation
 */
SymEncryptedSessionKey.prototype.read = function(bytes) {
  // A one-octet version number. The only currently defined version is 4.
  this.version = bytes.charCodeAt(0);

  // A one-octet number describing the symmetric algorithm used.
  var algo = enums.read(enums.symmetric, bytes.charCodeAt(1));

  // A string-to-key (S2K) specifier, length as defined above.
  var s2klength = this.s2k.read(bytes.substr(2));

  // Optionally, the encrypted session key itself, which is decrypted
  // with the string-to-key object.
  var done = s2klength + 2;

  if (done < bytes.length) {
    this.encrypted = bytes.substr(done);
    this.sessionKeyEncryptionAlgorithm = algo;
  } else
    this.sessionKeyAlgorithm = algo;
};

SymEncryptedSessionKey.prototype.write = function() {
  var algo = this.encrypted === null ?
    this.sessionKeyAlgorithm :
    this.sessionKeyEncryptionAlgorithm;

  var bytes = String.fromCharCode(this.version) +
    String.fromCharCode(enums.write(enums.symmetric, algo)) +
    this.s2k.write();

  if (this.encrypted !== null)
    bytes += this.encrypted;
  return bytes;
};

/**
 * Decrypts the session key (only for public key encrypted session key
 * packets (tag 1)
 *
 * @return {String} The unencrypted session key
 */
SymEncryptedSessionKey.prototype.decrypt = function(passphrase) {
  var algo = this.sessionKeyEncryptionAlgorithm !== null ?
    this.sessionKeyEncryptionAlgorithm :
    this.sessionKeyAlgorithm;


  var length = crypto.cipher[algo].keySize;
  var key = this.s2k.produce_key(passphrase, length);

  if (this.encrypted === null) {
    this.sessionKey = key;

  } else {
    var decrypted = crypto.cfb.decrypt(
      this.sessionKeyEncryptionAlgorithm, key, this.encrypted, true);

    this.sessionKeyAlgorithm = enums.read(enums.symmetric,
      decrypted[0].keyCodeAt());

    this.sessionKey = decrypted.substr(1);
  }
};

SymEncryptedSessionKey.prototype.encrypt = function(passphrase) {
  var length = crypto.getKeyLength(this.sessionKeyEncryptionAlgorithm);
  var key = this.s2k.produce_key(passphrase, length);

  var private_key = String.fromCharCode(
    enums.write(enums.symmetric, this.sessionKeyAlgorithm)) +

  crypto.getRandomBytes(
    crypto.getKeyLength(this.sessionKeyAlgorithm));

  this.encrypted = crypto.cfb.encrypt(
    crypto.getPrefixRandom(this.sessionKeyEncryptionAlgorithm),
    this.sessionKeyEncryptionAlgorithm, key, private_key, true);
};

/**
 * Fix custom types after cloning
 */
SymEncryptedSessionKey.prototype.postCloneTypeFix = function() {
  this.s2k = type_s2k.fromClone(this.s2k);
};

},{"../crypto":49,"../enums.js":60,"../type/s2k.js":94}],84:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the Symmetrically Encrypted Data Packet (Tag 9)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.7|RFC4880 5.7}: The Symmetrically Encrypted Data packet contains data encrypted
 * with a symmetric-key algorithm. When it has been decrypted, it contains other
 * packets (usually a literal data packet or compressed data packet, but in
 * theory other Symmetrically Encrypted Data packets or sequences of packets
 * that form whole OpenPGP messages).
 * @requires crypto
 * @requires enums
 * @module packet/symmetrically_encrypted
 */

module.exports = SymmetricallyEncrypted;

var crypto = require('../crypto'),
  enums = require('../enums.js')
  util = require('../util.js');

/**
 * @constructor
 */
function SymmetricallyEncrypted() {
  this.tag = enums.packet.symmetricallyEncrypted;
  this.encrypted = null;
  /** Decrypted packets contained within. 
   * @type {module:packet/packetlist} */
  this.packets =  null;
}

SymmetricallyEncrypted.prototype.read = function (bytes) {
  this.encrypted = bytes;
};

SymmetricallyEncrypted.prototype.write = function () {
  return this.encrypted;
};

/**
 * Symmetrically decrypt the packet data
 *
 * @param {module:enums.symmetric} sessionKeyAlgorithm
 *             Symmetric key algorithm to use // See {@link http://tools.ietf.org/html/rfc4880#section-9.2|RFC4880 9.2}
 * @param {String} key
 *             Key as string with the corresponding length to the
 *            algorithm
 */
SymmetricallyEncrypted.prototype.decrypt = function (sessionKeyAlgorithm, key) {
  var decrypted = crypto.cfb.decrypt(
    sessionKeyAlgorithm, key, this.encrypted, true);

  this.packets.read(decrypted);
};

SymmetricallyEncrypted.prototype.encrypt = function (algo, key) {
  var data = this.packets.write();

  this.encrypted = crypto.cfb.encrypt(
    crypto.getPrefixRandom(algo), algo, data, key, true);
};

},{"../crypto":49,"../enums.js":60,"../util.js":95}],85:[function(require,module,exports){
/**
 * @requires enums
 * @module packet/trust
 */

module.exports = Trust;

var enums = require('../enums.js');

/**
 * @constructor
 */
function Trust() {
  this.tag = enums.packet.trust;
}

/**
 * Parsing function for a trust packet (tag 12).
 * Currently empty as we ignore trust packets
 * @param {String} byptes payload of a tag 12 packet
 */
Trust.prototype.read = function (bytes) {

};

},{"../enums.js":60}],86:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the User Attribute Packet (Tag 17)<br/>
 * <br/>
 * The User Attribute packet is a variation of the User ID packet.  It
 * is capable of storing more types of data than the User ID packet,
 * which is limited to text.  Like the User ID packet, a User Attribute
 * packet may be certified by the key owner ("self-signed") or any other
 * key owner who cares to certify it.  Except as noted, a User Attribute
 * packet may be used anywhere that a User ID packet may be used.
 * <br/>
 * While User Attribute packets are not a required part of the OpenPGP
 * standard, implementations SHOULD provide at least enough
 * compatibility to properly handle a certification signature on the
 * User Attribute packet.  A simple way to do this is by treating the
 * User Attribute packet as a User ID packet with opaque contents, but
 * an implementation may use any method desired.
 * module packet/user_attribute
 * @requires enums
 * @module packet/user_attribute
 */

var util = require('../util.js'),
  packet = require('./packet.js'),
  enums = require('../enums.js');

module.exports = UserAttribute;

/**
 * @constructor
 */
function UserAttribute() {
  this.tag = enums.packet.userAttribute;
  this.attributes = [];
}

/**
 * parsing function for a user attribute packet (tag 17).
 * @param {String} input payload of a tag 17 packet
 */
UserAttribute.prototype.read = function(bytes) {
  var i = 0;
  while (i < bytes.length) {
    var len = packet.readSimpleLength(bytes.substr(i));
    i += len.offset;

    this.attributes.push(bytes.substr(i, len.len));
    i += len.len;
  }
};

/**
 * Creates a string representation of the user attribute packet
 * @return {String} string representation
 */
UserAttribute.prototype.write = function() {
  var result = '';
  for (var i = 0; i < this.attributes.length; i++) {
    result += packet.writeSimpleLength(this.attributes[i].length);
    result += this.attributes[i];
  }
  return result;
};

/**
 * Compare for equality
 * @param  {module:user_attribute~UserAttribute} usrAttr
 * @return {Boolean}         true if equal
 */
UserAttribute.prototype.equals = function(usrAttr) {
  if (!usrAttr || !(usrAttr instanceof UserAttribute)) {
    return false;
  }
  return this.attributes.every(function(attr, index) {
    return attr === usrAttr.attributes[index];
  });
};

},{"../enums.js":60,"../util.js":95,"./packet.js":74}],87:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the User ID Packet (Tag 13)<br/>
 * <br/>
 * A User ID packet consists of UTF-8 text that is intended to represent
 * the name and email address of the key holder.  By convention, it
 * includes an RFC 2822 [RFC2822] mail name-addr, but there are no
 * restrictions on its content.  The packet length in the header
 * specifies the length of the User ID.
 * @requires util
 * @requires enums
 * @module packet/userid
 */

module.exports = Userid;

var util = require('../util.js'),
  enums = require('../enums.js');

/**
 * @constructor
 */
function Userid() {
  this.tag = enums.packet.userid;
  /** A string containing the user id. Usually in the form
   * John Doe <john@example.com>
   * @type {String} 
   */
  this.userid = '';
}

/**
 * Parsing function for a user id packet (tag 13).
 * @param {String} input payload of a tag 13 packet
 */
Userid.prototype.read = function (bytes) {
  this.userid = util.decode_utf8(bytes);
};

/**
 * Creates a string representation of the user id packet
 * @return {String} string representation
 */
Userid.prototype.write = function () {
  return util.encode_utf8(this.userid);
};

},{"../enums.js":60,"../util.js":95}],88:[function(require,module,exports){
var Buffer=require("__browserify_Buffer").Buffer;'use strict';

var util = require('../util'),
  stream = require('stream');

function CipherFeedback(opts) {
  stream.Transform.call(this, opts);
  this.prefixRandom = opts.prefixrandom;
  //crypto.getPrefixRandom(this.algo);
  this.cipher = new opts.cipherfn(opts.key);
  this.sessionKey = opts.key;
  if (opts.resync === undefined)
    opts.resync = true;
  this.resync = opts.resync;

  this.blockSize = this.cipher.blockSize;
  this.feedbackRegister = new Uint8Array(this.blockSize);
  this.feedbackRegisterEncrypted = new Uint8Array(this.blockSize);

  this._firstBlockEncrypted = false;
  this._eof = false;
  this._previousCiphertext = new Uint8Array();
  this._previousChunk = new Buffer([]);

  this._buffer = new Buffer(this.blockSize);
  this._offset = 0;
}
util.inherits(CipherFeedback, stream.Transform);

CipherFeedback.prototype._encryptFirstBlock = function(chunk) {
  var prefixrandom = this.prefixRandom;
  var resync = this.resync;
  var key = this.sessionKey;
  var block_size = this.blockSize;

  prefixrandom = prefixrandom + prefixrandom.charAt(block_size - 2) + prefixrandom.charAt(block_size - 1);
  var ciphertext = new Uint8Array(chunk.length + 2 + block_size * 2);
  var i, n, begin;
  var offset = resync ? 0 : 2;

  // 1.  The feedback register (FR) is set to the IV, which is all zeros.
  for (i = 0; i < block_size; i++) {
    this.feedbackRegister[i] = 0;
  }

  // 2.  FR is encrypted to produce FRE (FR Encrypted).  This is the
  //     encryption of an all-zero value.
  this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);
  // 3.  FRE is xored with the first BS octets of random data prefixed to
  //     the plaintext to produce C[1] through C[BS], the first BS octets
  //     of ciphertext.
  for (i = 0; i < block_size; i++) {
    ciphertext[i] = this.feedbackRegisterEncrypted[i] ^ prefixrandom.charCodeAt(i);
  }

  // 4.  FR is loaded with C[1] through C[BS].
  this.feedbackRegister.set(ciphertext.subarray(0, block_size));

  // 5.  FR is encrypted to produce FRE, the encryption of the first BS
  //     octets of ciphertext.
  this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);

  // 6.  The left two octets of FRE get xored with the next two octets of
  //     data that were prefixed to the plaintext.  This produces C[BS+1]
  //     and C[BS+2], the next two octets of ciphertext.
  ciphertext[block_size] = this.feedbackRegisterEncrypted[0] ^ prefixrandom.charCodeAt(block_size);
  ciphertext[block_size + 1] = this.feedbackRegisterEncrypted[1] ^ prefixrandom.charCodeAt(block_size + 1);

  if (resync) {
    // 7.  (The resync step) FR is loaded with C[3] through C[BS+2].
    this.feedbackRegister.set(ciphertext.subarray(2, block_size + 2));
  } else {
    this.feedbackRegister.set(ciphertext.subarray(0, block_size));
  }
  // 8.  FR is encrypted to produce FRE.
  this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);

  // 9.  FRE is xored with the first BS octets of the given plaintext, now
  //     that we have finished encrypting the BS+2 octets of prefixed
  //     data.  This produces C[BS+3] through C[BS+(BS+2)], the next BS
  //     octets of ciphertext.
  for (i = 0; i < block_size; i++) {
    ciphertext[block_size + 2 + i] = this.feedbackRegisterEncrypted[i + offset] ^ chunk[i];
  }
  this._previousCiphertext = ciphertext.subarray(block_size + 2 - offset, 2*block_size + 2 - offset);
  this._previousChunk = chunk;
  ciphertext = ciphertext.subarray(0, chunk.length + 2 + block_size - offset);
  return ciphertext;
}

CipherFeedback.prototype._encryptBlock = function(chunk) {
  var ciphertext = new Uint8Array(chunk.length + 2),
    block_size = this.blockSize,
    offset = this.resync ? 0 : 2,
    i, n, begin;
  for (n = 0; n < (chunk.length + offset); n += block_size) {
    begin = n;
    // 10. FR is loaded with C[BS+3] to C[BS + (BS+2)] (which is C11-C18 for
    // an 8-octet block).
    this.feedbackRegister.set(this._previousCiphertext);

    // 11. FR is encrypted to produce FRE.
    this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);

    // 12. FRE is xored with the next BS octets of plaintext, to produce
    // the next BS octets of ciphertext. These are loaded into FR, and
    // the process is repeated until the plaintext is used up.
    for (i = 0; i < block_size; i++) {
      var byte;
      if ((n + i - offset) < 0) {
        byte = this._previousChunk[block_size + (n + i - offset)];
      } else {
        byte = chunk[n + i - offset];
      }
      ciphertext[begin + i] = this.feedbackRegisterEncrypted[i] ^ byte;
    }
    this._previousCiphertext = ciphertext.subarray(0, chunk.length);
  }
  this._previousChunk = chunk;
  if (this._eof)
    ciphertext = ciphertext.subarray(0, chunk.length + offset);
  else
    ciphertext = ciphertext.subarray(0, chunk.length);
  return ciphertext;
}

CipherFeedback.prototype.encryptBlock = function(chunk) {
  var ciphertext;
  if (!this._firstBlockEncrypted) {
    ciphertext = this._encryptFirstBlock(chunk);
    this._firstBlockEncrypted = true;
  } else {
    ciphertext = this._encryptBlock(chunk);
  }
  var buffer = new Buffer(ciphertext.length, 'binary');
  for (var i = 0; i < ciphertext.length; i++) {
    buffer[i] = ciphertext[i];
  }
  return buffer;
};

CipherFeedback.prototype._transform = function(chunk, encoding, cb) {
  var availableIn = chunk && chunk.length || 0;
  if (availableIn + this._offset + 1 < this.blockSize) {
    chunk.copy(this._buffer, this._offset);
    this._offset += availableIn;
  } else {
    var block = this._buffer.slice(0, this._offset);
    var needed = this.blockSize - block.length;
    var chunkOffset = 0;
    if (needed === 0) {
      var encrypted = this.encryptBlock(block);
      this.push(encrypted);
    }
    while (availableIn > needed && needed > 0) {
      block = Buffer.concat([block, 
                            chunk.slice(chunkOffset, chunkOffset + needed)]);
      chunkOffset += needed;
      this.push(this.encryptBlock(block));
      availableIn -= needed;
      needed = this.blockSize;
      block = new Buffer([], 'binary');
    }
    this._offset = availableIn;
    chunk.slice(chunkOffset).copy(this._buffer);
  }
  this.emit('encrypted', chunk);
  cb();
}

CipherFeedback.prototype._flush = function(cb) {
  var block = this._buffer.slice(0, this._offset);
  this._eof = true;
  this.push(this.encryptBlock(block));
  this.emit('flushed', null);
  cb();
}

module.exports.CipherFeedback = CipherFeedback;

},{"../util":95,"__browserify_Buffer":16,"stream":9}],89:[function(require,module,exports){
'use strict';

var message = require('./message.js'),
  crypto = require('./crypto.js'),
  packet = require('./packet.js');

module.exports = {
  MessageStream: message.MessageStream,
  CipherFeedbackStream: crypto.CipherFeedback,
  HeaderPacketStream: packet.HeaderPacketStream
}

},{"./crypto.js":88,"./message.js":90,"./packet.js":91}],90:[function(require,module,exports){
var Buffer=require("__browserify_Buffer").Buffer;var util = require('../util.js'),
  packet_stream = require('./packet.js'),
  crypto_stream = require('./crypto.js'),
  packet = require('../packet'),
  enums = require('../enums.js'),
  armor = require('../encoding/armor.js'),
  config = require('../config'),
  crypto = require('../crypto'),
  keyModule = require('../key.js'),
  message = require('../message.js');

function MessageStream(keys, file_length, filename, opts) {
  var self = this;
  filename = filename || 'msg.txt';
  filename = util.encode_utf8(filename);
  opts = opts || {};
  packet_stream.HeaderPacketStream.call(this, opts);

  opts['algo'] = enums.read(enums.symmetric, keyModule.getPreferredSymAlgo(keys));
  opts['key'] = crypto.generateSessionKey(opts['algo']);
  opts['cipherfn'] = crypto.cipher[opts['algo']];
  opts['prefixrandom'] = crypto.getPrefixRandom(opts['algo']);
  if (config.integrity_protect) {
    var prefixrandom = opts['prefixrandom'];
    var prefix = prefixrandom + prefixrandom.charAt(prefixrandom.length - 2) + prefixrandom.charAt(prefixrandom.length - 1);
    opts['resync'] = false;
    this.hash = crypto.hash.forge_sha1.create();
    this.hash.update(prefix);
  }
  
  this.cipher = new crypto_stream.CipherFeedback(opts);
  this.fileLength = file_length;
  this.keys = keys;

  this.encrypted_packet_header = Buffer(
    String.fromCharCode(enums.write(enums.literal, 'utf8')) + 
    String.fromCharCode(filename.length) +
    filename +
    util.writeDate(new Date()),
    'binary'
  )
  this.encrypted_packet_header = Buffer.concat([
                  //new Buffer(String.fromCharCode(1)),
                  new Buffer(packet.packet.writeHeader(enums.packet.literal, 
                             this.encrypted_packet_header.length + this.fileLength), 'binary'),
                  this.encrypted_packet_header
  ]);

  this.cipher.on('data', function(data) {
    self.push(util.bin2str(data));
  });
}
util.inherits(MessageStream, packet_stream.HeaderPacketStream);

MessageStream.prototype.getHeader = function() {
  var that = this,
    packetList = new packet.List(),
    symAlgo = keyModule.getPreferredSymAlgo(this.keys);

  this.keys.forEach(function(key) {
    var encryptionKeyPacket = key.getEncryptionKeyPacket();
    if (encryptionKeyPacket) {
      var pkESKeyPacket = new packet.PublicKeyEncryptedSessionKey();
      pkESKeyPacket.publicKeyId = encryptionKeyPacket.getKeyId();
      pkESKeyPacket.publicKeyAlgorithm = encryptionKeyPacket.algorithm;
      pkESKeyPacket.sessionKey = that.cipher.sessionKey;
      pkESKeyPacket.sessionKeyAlgorithm = enums.read(enums.symmetric, symAlgo);
      pkESKeyPacket.encrypt(encryptionKeyPacket);
      packetList.push(pkESKeyPacket);
    } else {
      throw new Error('Could not find valid key packet for encryption in key ' + key.primaryKey.getKeyId().toHex());
    }
  });
  var packet_len = this.encrypted_packet_header.length + this.fileLength + this.cipher.blockSize + 2,
    header = packetList.write(),
    first_packet_header;

  if (config.integrity_protect) {
    packet_len += 2 + 20 + 1;
    first_packet_header = packet.packet.writeHeader(enums.packet.symEncryptedIntegrityProtected, packet_len) + String.fromCharCode(1);
  } else {
    first_packet_header = packet.packet.writeHeader(enums.packet.symmetricallyEncrypted, packet_len);
  }
  return header + first_packet_header;
}

MessageStream.prototype._transform = function(chunk, encoding, cb) {
  packet_stream.HeaderPacketStream.prototype._transform.call(this, chunk, encoding);
  chunk = new Buffer(chunk, 'binary');
  if (this.encrypted_packet_header) {
    chunk = Buffer.concat([this.encrypted_packet_header, chunk]);
    this.encrypted_packet_header = null;
  }
  this.cipher.once('encrypted', function(d) {
    cb();
  });
  if (config.integrity_protect) {
    this.hash.update(chunk.toString('binary'));
  }
  this.cipher.write(chunk);
}

MessageStream.prototype._flush = function(cb) {
  var self = this;
  this.cipher.once('flushed', function(d) {
    cb();
  });
  if (config.integrity_protect) {
    var mdc_header = String.fromCharCode(0xD3) + String.fromCharCode(0x14);
    this.hash.update(mdc_header);
    var hash_digest = this.hash.digest().getBytes();

    this.cipher.once('encrypted', function() {
      self.cipher.end();
    });
    this.cipher.write(
      new Buffer(mdc_header + hash_digest, 'binary')
    );
  } else {
    this.cipher.end();
  }
}
module.exports.MessageStream = MessageStream;

},{"../config":33,"../crypto":49,"../encoding/armor.js":58,"../enums.js":60,"../key.js":62,"../message.js":66,"../packet":70,"../util.js":95,"./crypto.js":88,"./packet.js":91,"__browserify_Buffer":16}],91:[function(require,module,exports){
var util = require('util'),
  stream = require('stream');

function HeaderPacketStream(opts) {
  stream.Transform.call(this, opts);
  this._headerWritten = false;
}
util.inherits(HeaderPacketStream, stream.Transform);

HeaderPacketStream.prototype.getHeader = function() {}
HeaderPacketStream.prototype._transform = function(chunk, encoding, cb) {
  if (!this._headerWritten) {
    this._headerWritten = true; 
    var header = this.getHeader();
    if (header) this.push(header);
  }
}

module.exports.HeaderPacketStream = HeaderPacketStream

},{"stream":9,"util":12}],92:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of type key id ({@link http://tools.ietf.org/html/rfc4880#section-3.3|RFC4880 3.3})<br/>
 * <br/>
 * A Key ID is an eight-octet scalar that identifies a key.
 * Implementations SHOULD NOT assume that Key IDs are unique.  The
 * section "Enhanced Key Formats" below describes how Key IDs are
 * formed.
 * @requires util
 * @module type/keyid
 */

module.exports = Keyid;

var util = require('../util.js');

/**
 * @constructor
 */
function Keyid() {

  this.bytes = '';
}

/**
 * Parsing method for a key id
 * @param {String} input Input to read the key id from
 */
Keyid.prototype.read = function(bytes) {
  this.bytes = bytes.substr(0, 8);
};

Keyid.prototype.write = function() {
  return this.bytes;
};

Keyid.prototype.toHex = function() {
  return util.hexstrdump(this.bytes);
};

Keyid.prototype.equals = function(keyid) {
  return this.bytes == keyid.bytes;
};

Keyid.prototype.isNull = function() {
  return this.bytes === '';
};

module.exports.mapToHex = function (keyId) {
  return keyId.toHex();
};

module.exports.fromClone = function (clone) {
  var keyid = new Keyid();
  keyid.bytes = clone.bytes;
  return keyid;
};

module.exports.fromId = function (hex) {
  var keyid = new Keyid();
  keyid.read(util.hex2bin(hex));
  return keyid;
};

},{"../util.js":95}],93:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

// Hint: We hold our MPIs as an array of octets in big endian format preceeding a two
// octet scalar: MPI: [a,b,c,d,e,f]
// - MPI size: (a << 8) | b 
// - MPI = c | d << 8 | e << ((MPI.length -2)*8) | f ((MPI.length -2)*8)

/**
 * Implementation of type MPI ({@link http://tools.ietf.org/html/rfc4880#section-3.2|RFC4880 3.2})<br/>
 * <br/>
 * Multiprecision integers (also called MPIs) are unsigned integers used
 * to hold large integers such as the ones used in cryptographic
 * calculations.
 * An MPI consists of two pieces: a two-octet scalar that is the length
 * of the MPI in bits followed by a string of octets that contain the
 * actual integer.
 * @requires crypto/public_key/jsbn
 * @requires util
 * @module type/mpi
 */

module.exports = MPI;

var BigInteger = require('../crypto/public_key/jsbn.js'),
  util = require('../util.js');

/**
 * @constructor
 */
function MPI() {
  /** An implementation dependent integer */
  this.data = null;
}

/**
 * Parsing function for a mpi ({@link http://tools.ietf.org/html/rfc4880#section3.2|RFC 4880 3.2}).
 * @param {String} input Payload of mpi data
 * @return {Integer} Length of data read
 */
MPI.prototype.read = function (bytes) {
  var bits = (bytes.charCodeAt(0) << 8) | bytes.charCodeAt(1);

  // Additional rules:
  //
  //    The size of an MPI is ((MPI.length + 7) / 8) + 2 octets.
  //
  //    The length field of an MPI describes the length starting from its
  //    most significant non-zero bit.  Thus, the MPI [00 02 01] is not
  //    formed correctly.  It should be [00 01 01].

  // TODO: Verification of this size method! This size calculation as
  //      specified above is not applicable in JavaScript
  var bytelen = Math.ceil(bits / 8);

  var raw = bytes.substr(2, bytelen);
  this.fromBytes(raw);

  return 2 + bytelen;
};

MPI.prototype.fromBytes = function (bytes) {
  this.data = new BigInteger(util.hexstrdump(bytes), 16);
};

MPI.prototype.toBytes = function () {
  return this.write().substr(2);
};

MPI.prototype.byteLength = function () {
  return this.toBytes().length;
};

/**
 * Converts the mpi object to a string as specified in {@link http://tools.ietf.org/html/rfc4880#section-3.2|RFC4880 3.2}
 * @return {String} mpi Byte representation
 */
MPI.prototype.write = function () {
  return this.data.toMPI();
};

MPI.prototype.toBigInteger = function () {
  return this.data.clone();
};

MPI.prototype.fromBigInteger = function (bn) {
  this.data = bn.clone();
};

module.exports.fromClone = function (clone) {
  clone.data.copyTo = BigInteger.prototype.copyTo;
  var bn = new BigInteger();
  clone.data.copyTo(bn);
  var mpi = new MPI();
  mpi.data = bn;
  return mpi;
};

},{"../crypto/public_key/jsbn.js":54,"../util.js":95}],94:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the String-to-key specifier ({@link http://tools.ietf.org/html/rfc4880#section-3.7|RFC4880 3.7})<br/>
 * <br/>
 * String-to-key (S2K) specifiers are used to convert passphrase strings
 * into symmetric-key encryption/decryption keys.  They are used in two
 * places, currently: to encrypt the secret part of private keys in the
 * private keyring, and to convert passphrases to encryption keys for
 * symmetrically encrypted messages.
 * @requires crypto
 * @requires enums
 * @requires util
 * @module type/s2k
 */

module.exports = S2K;

var enums = require('../enums.js'),
  util = require('../util.js'),
  crypto = require('../crypto');

/**
 * @constructor
 */
function S2K() {
  /** @type {module:enums.hash} */
  this.algorithm = 'sha256';
  /** @type {module:enums.s2k} */
  this.type = 'iterated';
  this.c = 96;
  /** Eight bytes of salt in a binary string.
   * @type {String}
   */
  this.salt = crypto.random.getRandomBytes(8);
}

S2K.prototype.get_count = function () {
  // Exponent bias, defined in RFC4880
  var expbias = 6;

  return (16 + (this.c & 15)) << ((this.c >> 4) + expbias);
};

/**
 * Parsing function for a string-to-key specifier ({@link http://tools.ietf.org/html/rfc4880#section-3.7|RFC 4880 3.7}).
 * @param {String} input Payload of string-to-key specifier
 * @return {Integer} Actual length of the object
 */
S2K.prototype.read = function (bytes) {
  var i = 0;
  this.type = enums.read(enums.s2k, bytes.charCodeAt(i++));
  this.algorithm = enums.read(enums.hash, bytes.charCodeAt(i++));

  switch (this.type) {
    case 'simple':
      break;

    case 'salted':
      this.salt = bytes.substr(i, 8);
      i += 8;
      break;

    case 'iterated':
      this.salt = bytes.substr(i, 8);
      i += 8;

      // Octet 10: count, a one-octet, coded value
      this.c = bytes.charCodeAt(i++);
      break;

    case 'gnu':
      if (bytes.substr(i, 3) == "GNU") {
        i += 3; // GNU
        var gnuExtType = 1000 + bytes.charCodeAt(i++);
        if (gnuExtType == 1001) {
          this.type = gnuExtType;
          // GnuPG extension mode 1001 -- don't write secret key at all
        } else {
          throw new Error("Unknown s2k gnu protection mode.");
        }
      } else {
        throw new Error("Unknown s2k type.");
      }
      break;

    default:
      throw new Error("Unknown s2k type.");
  }

  return i;
};


/**
 * writes an s2k hash based on the inputs.
 * @return {String} Produced key of hashAlgorithm hash length
 */
S2K.prototype.write = function () {
  var bytes = String.fromCharCode(enums.write(enums.s2k, this.type));
  bytes += String.fromCharCode(enums.write(enums.hash, this.algorithm));

  switch (this.type) {
    case 'simple':
      break;
    case 'salted':
      bytes += this.salt;
      break;
    case 'iterated':
      bytes += this.salt;
      bytes += String.fromCharCode(this.c);
      break;
  }

  return bytes;
};

/**
 * Produces a key using the specified passphrase and the defined
 * hashAlgorithm
 * @param {String} passphrase Passphrase containing user input
 * @return {String} Produced key with a length corresponding to
 * hashAlgorithm hash length
 */
S2K.prototype.produce_key = function (passphrase, numBytes) {
  passphrase = util.encode_utf8(passphrase);

  function round(prefix, s2k) {
    var algorithm = enums.write(enums.hash, s2k.algorithm);

    switch (s2k.type) {
      case 'simple':
        return crypto.hash.digest(algorithm, prefix + passphrase);

      case 'salted':
        return crypto.hash.digest(algorithm,
          prefix + s2k.salt + passphrase);

      case 'iterated':
        var isp = [],
          count = s2k.get_count();
        data = s2k.salt + passphrase;

        while (isp.length * data.length < count)
          isp.push(data);

        isp = isp.join('');

        if (isp.length > count)
          isp = isp.substr(0, count);

        return crypto.hash.digest(algorithm, prefix + isp);
    }
  }

  var result = '',
    prefix = '';

  while (result.length <= numBytes) {
    result += round(prefix, this);
    prefix += String.fromCharCode(0);
  }

  return result.substr(0, numBytes);
};

module.exports.fromClone = function (clone) {
  var s2k = new S2K();
  this.algorithm = clone.algorithm;
  this.type = clone.type;
  this.c = clone.c;
  this.salt = clone.salt;
  return s2k;
};

},{"../crypto":49,"../enums.js":60,"../util.js":95}],95:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * This object contains utility functions
 * @requires config
 * @module util
 */

'use strict';

var config = require('./config');

module.exports = {
  readNumber: function (bytes) {
    var n = 0;

    for (var i = 0; i < bytes.length; i++) {
      n <<= 8;
      n += bytes.charCodeAt(i);
    }

    return n;
  },

  writeNumber: function (n, bytes) {
    var b = '';
    for (var i = 0; i < bytes; i++) {
      b += String.fromCharCode((n >> (8 * (bytes - i - 1))) & 0xFF);
    }

    return b;
  },

  readDate: function (bytes) {
    var n = this.readNumber(bytes);
    var d = new Date();
    d.setTime(n * 1000);
    return d;
  },

  writeDate: function (time) {
    var numeric = Math.round(time.getTime() / 1000);

    return this.writeNumber(numeric, 4);
  },

  emailRegEx: /^[+a-zA-Z0-9_.-]+@([a-zA-Z0-9-]+\.)+[a-zA-Z0-9]{2,6}$/,

  hexdump: function (str) {
    var r = [];
    var e = str.length;
    var c = 0;
    var h;
    var i = 0;
    while (c < e) {
      h = str.charCodeAt(c++).toString(16);
      while (h.length < 2) h = "0" + h;
      r.push(" " + h);
      i++;
      if (i % 32 === 0)
        r.push("\n           ");
    }
    return r.join('');
  },

  /**
   * Create hexstring from a binary
   * @param {String} str String to convert
   * @return {String} String containing the hexadecimal values
   */
  hexstrdump: function (str) {
    if (str === null)
      return "";
    var r = [];
    var e = str.length;
    var c = 0;
    var h;
    while (c < e) {
      h = str.charCodeAt(c++).toString(16);
      while (h.length < 2) h = "0" + h;
      r.push("" + h);
    }
    return r.join('');
  },

  /**
   * Create binary string from a hex encoded string
   * @param {String} str Hex string to convert
   * @return {String} String containing the binary values
   */
  hex2bin: function (hex) {
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
      str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
  },

  /**
   * Creating a hex string from an binary array of integers (0..255)
   * @param {String} str Array of bytes to convert
   * @return {String} Hexadecimal representation of the array
   */
  hexidump: function (str) {
    var r = [];
    var e = str.length;
    var c = 0;
    var h;
    while (c < e) {
      h = str[c++].toString(16);
      while (h.length < 2) h = "0" + h;
      r.push("" + h);
    }
    return r.join('');
  },


  /**
   * Convert a native javascript string to a string of utf8 bytes
   * @param {String} str The string to convert
   * @return {String} A valid squence of utf8 bytes
   */
  encode_utf8: function (str) {
    return unescape(encodeURIComponent(str));
  },

  /**
   * Convert a string of utf8 bytes to a native javascript string
   * @param {String} utf8 A valid squence of utf8 bytes
   * @return {String} A native javascript string
   */
  decode_utf8: function (utf8) {
    if (typeof utf8 !== 'string') {
      throw new Error('Parameter "utf8" is not of type string');
    }
    try {
      return decodeURIComponent(escape(utf8));
    } catch (e) {
      return utf8;
    }
  },

  /**
   * Convert an array of integers(0.255) to a string
   * @param {Array<Integer>} bin An array of (binary) integers to convert
   * @return {String} The string representation of the array
   */
  bin2str: function (bin) {
    var result = [];
    for (var i = 0; i < bin.length; i++) {
      result[i] = String.fromCharCode(bin[i]);
    }
    return result.join('');
  },

  /**
   * Convert a string to an array of integers(0.255)
   * @param {String} str String to convert
   * @return {Array<Integer>} An array of (binary) integers
   */
  str2bin: function (str) {
    var result = [];
    for (var i = 0; i < str.length; i++) {
      result[i] = str.charCodeAt(i);
    }
    return result;
  },


  /**
   * Convert a string to a Uint8Array
   * @param {String} str String to convert
   * @return {Uint8Array} The array of (binary) integers
   */
  str2Uint8Array: function (str) {
    var result = new Uint8Array(str.length);
    for (var i = 0; i < str.length; i++) {
      result[i] = str.charCodeAt(i);
    }
    return result;
  },

  /**
   * Convert a Uint8Array to a string. This currently functions
   * the same as bin2str.
   * @function module:util.Uint8Array2str
   * @param {Uint8Array} bin An array of (binary) integers to convert
   * @return {String} String representation of the array
   */
  Uint8Array2str: function (bin) {
    var result = '';
    for (var i = 0; i < bin.length; i++) {
      result += String.fromCharCode(bin[i]);
    }
    return result;
  },

  /**
   * Calculates a 16bit sum of a string by adding each character
   * codes modulus 65535
   * @param {String} text String to create a sum of
   * @return {Integer} An integer containing the sum of all character
   * codes % 65535
   */
  calc_checksum: function (text) {
    var checksum = {
      s: 0,
      add: function (sadd) {
        this.s = (this.s + sadd) % 65536;
      }
    };
    for (var i = 0; i < text.length; i++) {
      checksum.add(text.charCodeAt(i));
    }
    return checksum.s;
  },

  /**
   * Helper function to print a debug message. Debug
   * messages are only printed if
   * @link module:config/config.debug is set to true.
   * @param {String} str String of the debug message
   */
  print_debug: function (str) {
    if (config.debug) {
      console.log(str);
    }
  },

  /**
   * Helper function to print a debug message. Debug
   * messages are only printed if
   * @link module:config/config.debug is set to true.
   * Different than print_debug because will call hexstrdump iff necessary.
   * @param {String} str String of the debug message
   */
  print_debug_hexstr_dump: function (str, strToHex) {
    if (config.debug) {
      str = str + this.hexstrdump(strToHex);
      console.log(str);
    }
  },

  getLeftNBits: function (string, bitcount) {
    var rest = bitcount % 8;
    if (rest === 0)
      return string.substring(0, bitcount / 8);
    var bytes = (bitcount - rest) / 8 + 1;
    var result = string.substring(0, bytes);
    return this.shiftRight(result, 8 - rest); // +String.fromCharCode(string.charCodeAt(bytes -1) << (8-rest) & 0xFF);
  },

  /**
   * Shifting a string to n bits right
   * @param {String} value The string to shift
   * @param {Integer} bitcount Amount of bits to shift (MUST be smaller
   * than 9)
   * @return {String} Resulting string.
   */
  shiftRight: function (value, bitcount) {
    var temp = util.str2bin(value);
    if (bitcount % 8 !== 0) {
      for (var i = temp.length - 1; i >= 0; i--) {
        temp[i] >>= bitcount % 8;
        if (i > 0)
          temp[i] |= (temp[i - 1] << (8 - (bitcount % 8))) & 0xFF;
      }
    } else {
      return value;
    }
    return util.bin2str(temp);
  },

  /**
   * Return the algorithm type as string
   * @return {String} String representing the message type
   */
  get_hashAlgorithmString: function (algo) {
    switch (algo) {
      case 1:
        return "MD5";
      case 2:
        return "SHA1";
      case 3:
        return "RIPEMD160";
      case 8:
        return "SHA256";
      case 9:
        return "SHA384";
      case 10:
        return "SHA512";
      case 11:
        return "SHA224";
    }
    return "unknown";
  },

  inherits: require('util').inherits,

  /**
   * Get native Web Cryptography api. The default configuration is to use
   * the api when available. But it can also be deactivated with config.useWebCrypto
   * @return {Object} The SubtleCrypto api or 'undefined'
   */
  getWebCrypto: function() {
    if (config.useWebCrypto === false) {
      // make web crypto optional
      return;
    }

    if (typeof window !== 'undefined' && window.crypto) {
      return window.crypto.subtle || window.crypto.webkitSubtle;
    }
  }
};

},{"./config":33,"util":12}],96:[function(require,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires crypto
 * @requires enums
 * @requires packet
 * @requires type_keyid
 * @requires key
 * @module async_proxy
 */

'use strict';

var crypto = require('../crypto'),
  packet = require('../packet'),
  key = require('../key.js'),
  type_keyid = require('../type/keyid.js');

var INITIAL_RANDOM_SEED = 50000, // random bytes seeded to worker
    RANDOM_SEED_REQUEST = 20000; // random bytes seeded after worker request

/**
 * Initializes a new proxy and loads the web worker
 * @constructor
 * @param {String} path The path to the worker or 'openpgp.worker.js' by default
 * @param {Object} [options.config=Object] config The worker configuration
 * @param {Object} [options.worker=Object] alternative to path parameter:
 *                                         web worker initialized with 'openpgp.worker.js'
 */
function AsyncProxy(path, options) {
  if (options && options.worker) {
    this.worker = options.worker;
  } else {
    this.worker = new Worker(path || 'openpgp.worker.js');
  }
  this.worker.onmessage = this.onMessage.bind(this);
  this.worker.onerror = function(e) {
    throw new Error('Unhandled error in openpgp worker: ' + e.message + ' (' + e.filename + ':' + e.lineno + ')');
  };
  this.seedRandom(INITIAL_RANDOM_SEED);
  // FIFO
  this.tasks = [];
  if (options && options.config) {
    this.worker.postMessage({event: 'configure', config: options.config});
  }
}

/**
 * Command pattern that wraps synchronous code into a promise
 * @param  {Object}   self    The current this
 * @param  {function} cmd     The synchronous function with a return value
 *                            to be wrapped in a promise
 * @return {Promise}          The promise wrapped around cmd
 */
AsyncProxy.prototype.execute = function(cmd) {
  var self = this;

  var promise = new Promise(function(resolve, reject) {
    cmd();
    self.tasks.push({ resolve:resolve, reject:reject });
  });

  return promise;
};

/**
 * Message handling
 */
AsyncProxy.prototype.onMessage = function(event) {
  var msg = event.data;
  switch (msg.event) {
    case 'method-return':
      if (msg.err) {
        // fail
        this.tasks.shift().reject(new Error(msg.err));
      } else {
        // success
        this.tasks.shift().resolve(msg.data);
      }
      break;
    case 'request-seed':
      this.seedRandom(RANDOM_SEED_REQUEST);
      break;
    default:
      throw new Error('Unknown Worker Event.');
  }
};

/**
 * Send message to worker with random data
 * @param  {Integer} size Number of bytes to send
 */
AsyncProxy.prototype.seedRandom = function(size) {
  var buf = this.getRandomBuffer(size);
  this.worker.postMessage({event: 'seed-random', buf: buf});
};

/**
 * Get Uint8Array with random numbers
 * @param  {Integer} size Length of buffer
 * @return {Uint8Array}
 */
AsyncProxy.prototype.getRandomBuffer = function(size) {
  if (!size) return null;
  var buf = new Uint8Array(size);
  crypto.random.getRandomValues(buf);
  return buf;
};

/**
 * Terminates the worker
 */
AsyncProxy.prototype.terminate = function() {
  this.worker.terminate();
};

/**
 * Encrypts message text with keys
 * @param  {(Array<module:key~Key>|module:key~Key)}  keys array of keys or single key, used to encrypt the message
 * @param  {String} text message as native JavaScript string
 */
AsyncProxy.prototype.encryptMessage = function(keys, text) {
  var self = this;

  return self.execute(function() {
    if (!keys.length) {
      keys = [keys];
    }
    keys = keys.map(function(key) {
      return key.toPacketlist();
    });
    self.worker.postMessage({
      event: 'encrypt-message',
      keys: keys,
      text: text
    });
  });
};

/**
 * Signs message text and encrypts it
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key, used to encrypt the message
 * @param  {module:key~Key}    privateKey private key with decrypted secret key data for signing
 * @param  {String} text       message as native JavaScript string
 */
AsyncProxy.prototype.signAndEncryptMessage = function(publicKeys, privateKey, text) {
  var self = this;

  return self.execute(function() {
    if (!publicKeys.length) {
      publicKeys = [publicKeys];
    }
    publicKeys = publicKeys.map(function(key) {
      return key.toPacketlist();
    });
    privateKey = privateKey.toPacketlist();
    self.worker.postMessage({
      event: 'sign-and-encrypt-message',
      publicKeys: publicKeys,
      privateKey: privateKey,
      text: text
    });
  });
};

/**
 * Decrypts message
 * @param  {module:key~Key}     privateKey private key with decrypted secret key data
 * @param  {module:message~Message} message    the message object with the encrypted data
 */
AsyncProxy.prototype.decryptMessage = function(privateKey, message) {
  var self = this;

  return self.execute(function() {
    privateKey = privateKey.toPacketlist();
    self.worker.postMessage({
      event: 'decrypt-message',
      privateKey: privateKey,
      message: message
    });
  });
};

/**
 * Decrypts message and verifies signatures
 * @param  {module:key~Key}     privateKey private key with decrypted secret key data
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key to verify signatures
 * @param  {module:message~Message} message    the message object with signed and encrypted data
 */
AsyncProxy.prototype.decryptAndVerifyMessage = function(privateKey, publicKeys, message) {
  var self = this;

  var promise = new Promise(function(resolve, reject) {
    privateKey = privateKey.toPacketlist();
    if (!publicKeys.length) {
      publicKeys = [publicKeys];
    }
    publicKeys = publicKeys.map(function(key) {
      return key.toPacketlist();
    });
    self.worker.postMessage({
      event: 'decrypt-and-verify-message',
      privateKey: privateKey,
      publicKeys: publicKeys,
      message: message
    });

    self.tasks.push({ resolve:function(data) {
      data.signatures = data.signatures.map(function(sig) {
        sig.keyid = type_keyid.fromClone(sig.keyid);
        return sig;
      });
      resolve(data);
    }, reject:reject });
  });

  return promise;
};

/**
 * Signs a cleartext message
 * @param  {(Array<module:key~Key>|module:key~Key)}  privateKeys array of keys or single key, with decrypted secret key data to sign cleartext
 * @param  {String} text        cleartext
 */
AsyncProxy.prototype.signClearMessage = function(privateKeys, text) {
  var self = this;

  return self.execute(function() {
    if (!privateKeys.length) {
      privateKeys = [privateKeys];
    }
    privateKeys = privateKeys.map(function(key) {
      return key.toPacketlist();
    });
    self.worker.postMessage({
      event: 'sign-clear-message',
      privateKeys: privateKeys,
      text: text
    });
  });
};

/**
 * Verifies signatures of cleartext signed message
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key, to verify signatures
 * @param  {module:cleartext~CleartextMessage} message    cleartext message object with signatures
 */
AsyncProxy.prototype.verifyClearSignedMessage = function(publicKeys, message) {
  var self = this;

  var promise = new Promise(function(resolve, reject) {
    if (!publicKeys.length) {
      publicKeys = [publicKeys];
    }
    publicKeys = publicKeys.map(function(key) {
      return key.toPacketlist();
    });
    self.worker.postMessage({
      event: 'verify-clear-signed-message',
      publicKeys: publicKeys,
      message: message
    });

    self.tasks.push({ resolve:function(data) {
      data.signatures = data.signatures.map(function(sig) {
        sig.keyid = type_keyid.fromClone(sig.keyid);
        return sig;
      });
      resolve(data);
    }, reject:reject });
  });

  return promise;
};

/**
 * Generates a new OpenPGP key pair. Currently only supports RSA keys.
 * Primary and subkey will be of same type.
 * @param {module:enums.publicKey} keyType    to indicate what type of key to make.
 *                             RSA is 1. See {@link http://tools.ietf.org/html/rfc4880#section-9.1}
 * @param {Integer} numBits    number of bits for the key creation. (should be 1024+, generally)
 * @param {String}  userId     assumes already in form of "User Name <username@email.com>"
 * @param {String}  passphrase The passphrase used to encrypt the resulting private key
 */
AsyncProxy.prototype.generateKeyPair = function(options) {
  var self = this;

  var promise = new Promise(function(resolve, reject) {
    self.worker.postMessage({
      event: 'generate-key-pair',
      options: options
    });

    self.tasks.push({ resolve:function(data) {
      var packetlist = packet.List.fromStructuredClone(data.key);
      data.key = new key.Key(packetlist);
      resolve(data);
    }, reject:reject });
  });

  return promise;
};

/**
 * Decrypts secret part of all secret key packets of key.
 * @param  {module:key~Key}     privateKey private key with encrypted secret key data
 * @param  {String} password    password to unlock the key
 */
AsyncProxy.prototype.decryptKey = function(privateKey, password) {
  var self = this;

  var promise = new Promise(function(resolve, reject) {
    privateKey = privateKey.toPacketlist();
    self.worker.postMessage({
      event: 'decrypt-key',
      privateKey: privateKey,
      password: password
    });

    self.tasks.push({ resolve:function(data) {
      var packetlist = packet.List.fromStructuredClone(data);
      data = new key.Key(packetlist);
      resolve(data);
    }, reject:reject });
  });

  return promise;
};

/**
 * Decrypts secret part of key packets matching array of keyids.
 * @param  {module:key~Key}     privateKey private key with encrypted secret key data
 * @param  {Array<module:type/keyid>} keyIds
 * @param  {String} password    password to unlock the key
 */
AsyncProxy.prototype.decryptKeyPacket = function(privateKey, keyIds, password) {
  var self = this;

  var promise = new Promise(function(resolve, reject) {
    privateKey = privateKey.toPacketlist();
    self.worker.postMessage({
      event: 'decrypt-key-packet',
      privateKey: privateKey,
      keyIds: keyIds,
      password: password
    });

    self.tasks.push({ resolve:function(data) {
      var packetlist = packet.List.fromStructuredClone(data);
      data = new key.Key(packetlist);
      resolve(data);
    }, reject:reject });
  });

  return promise;
};

module.exports = AsyncProxy;

},{"../crypto":49,"../key.js":62,"../packet":70,"../type/keyid.js":92}]},{},[61])
(61)
});
;