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

var MIN_SIZE_RANDOM_BUFFER = 40000;
var MAX_SIZE_RANDOM_BUFFER = 60000;

window.openpgp.crypto.random.randomBuffer.init(MAX_SIZE_RANDOM_BUFFER);

self.onmessage = function (event) {
  var data = null,
      err = null,
      msg = event.data,
      opt = msg.options || {},
      correct = false;

  switch (msg.event) {
    case 'configure':
      for (var i in msg.config) {
        window.openpgp.config[i] = msg.config[i];
      }
      break;

    case 'seed-random':
      if (!(msg.buf instanceof Uint8Array)) {
        msg.buf = new Uint8Array(msg.buf);
      }
      window.openpgp.crypto.random.randomBuffer.set(msg.buf);
      break;

    case 'decrypt-key':
      try {
        msg.privateKey = packetlistCloneToKey(msg.privateKey);
        correct = msg.privateKey.decrypt(msg.password);
        if (correct) {
          data = msg.privateKey.toPacketlist();
        } else {
          err = 'Wrong password';
        }
      } catch (e) {
        err = e.message;
      }
      response({event: 'method-return', data: data, err: err});
      break;

    case 'decrypt-key-packet':
      try {
        msg.privateKey = packetlistCloneToKey(msg.privateKey);
        msg.keyIds = msg.keyIds.map(window.openpgp.Keyid.fromClone);
        correct = msg.privateKey.decryptKeyPacket(msg.keyIds, msg.password);
        if (correct) {
          data = msg.privateKey.toPacketlist();
        } else {
          err = 'Wrong password';
        }
      } catch (e) {
        err = e.message;
      }
      response({event: 'method-return', data: data, err: err});
      break;

    case 'generateKey':
    case 'encrypt':
    case 'decrypt':
    case 'sign':
    case 'verify':
    case 'encryptSessionKey':
    case 'decryptSessionKey':
      // parse cloned packets
      window.openpgp[msg.event](parseClonedPackets(opt, msg.event)).then(function(data) {
        // clone packets (for web worker structured cloning algorithm)
        response({ event:'method-return', data:clonePackets(data) });
      }).catch(function(e) {
        response({ event:'method-return', err:e.message });
      });
      break;

    default:
      throw new Error('Unknown Worker Event.');
  }
};

function parseClonedPackets(options, method) {
  if(options.publicKeys) {
    options.publicKeys = options.publicKeys.map(packetlistCloneToKey);
  }
  if(options.privateKeys) {
    options.privateKeys = options.privateKeys.map(packetlistCloneToKey);
  }
  if(options.privateKey) {
    options.privateKey = packetlistCloneToKey(options.privateKey);
  }
  if (options.message && method === 'verify') { // verify supports only CleartextMessage
    options.message = packetlistCloneToCleartextMessage(options.message);
  } else if (options.message) {
    options.message = packetlistCloneToMessage(options.message);
  }
  return options;
}

function packetlistCloneToKey(clone) {
  var packetlist = window.openpgp.packet.List.fromStructuredClone(clone);
  return new window.openpgp.key.Key(packetlist);
}

function packetlistCloneToMessage(clone) {
  var packetlist = window.openpgp.packet.List.fromStructuredClone(clone.packets);
  return new window.openpgp.message.Message(packetlist);
}

function packetlistCloneToCleartextMessage(clone) {
  var packetlist = window.openpgp.packet.List.fromStructuredClone(clone.packets);
  return new window.openpgp.cleartext.CleartextMessage(clone.text, packetlist);
}

function clonePackets(data) {
  if (data.key) {
    data.key = data.key.toPacketlist();
  }
  return data;
}

function response(event) {
  if (window.openpgp.crypto.random.randomBuffer.size < MIN_SIZE_RANDOM_BUFFER) {
    postMessage({event: 'request-seed'});
  }
  postMessage(event);
}