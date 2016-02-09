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

/* globals self: true */

self.window = {}; // to make UMD bundles work

// Mozilla bind polyfill because phantomjs is stupid
if (!Function.prototype.bind) {
  Function.prototype.bind = function(oThis) {
    if (typeof this !== "function") {
      // closest thing possible to the ECMAScript 5 internal IsCallable function
      throw new TypeError("Function.prototype.bind - what is trying to be bound is not callable");
    }

    var aArgs = Array.prototype.slice.call(arguments, 1),
        fToBind = this,
        FNOP = function() {},
        fBound = function() {
          return fToBind.apply(this instanceof FNOP && oThis ? this : oThis, aArgs.concat(Array.prototype.slice.call(arguments)));
        };

    FNOP.prototype = this.prototype;
    fBound.prototype = new FNOP();

    return fBound;
  };
}

importScripts('openpgp.js');
var openpgp = window.openpgp;

var MIN_SIZE_RANDOM_BUFFER = 40000;
var MAX_SIZE_RANDOM_BUFFER = 60000;

openpgp.crypto.random.randomBuffer.init(MAX_SIZE_RANDOM_BUFFER);

self.onmessage = function (event) {
  var msg = event.data,
      options = msg.options || {};

  switch (msg.event) {
    case 'configure':
      for (var i in msg.config) {
        openpgp.config[i] = msg.config[i];
      }
      break;

    case 'seed-random':
      if (!(msg.buf instanceof Uint8Array)) {
        msg.buf = new Uint8Array(msg.buf);
      }
      openpgp.crypto.random.randomBuffer.set(msg.buf);
      break;

    case 'generateKey':
    case 'decryptKey':
    case 'encrypt':
    case 'decrypt':
    case 'sign':
    case 'verify':
    case 'encryptSessionKey':
    case 'decryptSessionKey':
      // parse cloned packets
      openpgp[msg.event](openpgp.packet.clone.parseClonedPackets(options, msg.event)).then(function(data) {
        // clone packets (for web worker structured cloning algorithm)
        response({ event:'method-return', data:openpgp.packet.clone.clonePackets(data) });
      }).catch(function(e) {
        response({ event:'method-return', err:e.message });
      });
      break;

    default:
      throw new Error('Unknown Worker Event.');
  }
};

function response(event) {
  if (openpgp.crypto.random.randomBuffer.size < MIN_SIZE_RANDOM_BUFFER) {
    self.postMessage({event: 'request-seed'});
  }
  self.postMessage(event, openpgp.util.getTransferables.call(openpgp.util, event.data));
}