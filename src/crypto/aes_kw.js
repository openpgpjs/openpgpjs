// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015-2016 Decentral
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

// Implementation of RFC 3394 AES Key Wrap & Key Unwrap funcions

import cipher from './cipher';

function wrap(key, data) {
  var aes = new cipher["aes" + (key.length*8)](key);
  var IV = new Uint32Array([0xA6A6A6A6, 0xA6A6A6A6]);
  var P = unpack(data);
  var A = IV;
  var R = P;
  var n = P.length/2;
  var t = new Uint32Array([0, 0]);
  var B = new Uint32Array(4);
  for (var j = 0; j <= 5; ++j) {
    for (var i = 0; i < n; ++i) {
      t[1] = n * j + (1 + i);
      // B = A
      B[0] = A[0];
      B[1] = A[1];
      // B = A || R[i]
      B[2] = R[2*i];
      B[3] = R[2*i+1];
      // B = AES(K, B)
      B = unpack(aes.encrypt(pack(B)));
      // A = MSB(64, B) ^ t
      A = B.subarray(0, 2);
      A[0] = A[0] ^ t[0];
      A[1] = A[1] ^ t[1];
      // R[i] = LSB(64, B)
      R[2*i] = B[2];
      R[2*i+1] = B[3];
    }
  }
  return pack(A, R);
}

function unwrap(key, data) {
  var aes = new cipher["aes" + (key.length*8)](key);
  var IV = new Uint32Array([0xA6A6A6A6, 0xA6A6A6A6]);
  var C = unpack(data);
  var A = C.subarray(0, 2);
  var R = C.subarray(2);
  var n = C.length/2-1;
  var t = new Uint32Array([0, 0]);
  var B = new Uint32Array(4);
  for (var j = 5; j >= 0; --j) {
    for (var i = n - 1; i >= 0; --i) {
      t[1] = n * j + (i + 1);
      // B = A ^ t
      B[0] = A[0] ^ t[0];
      B[1] = A[1] ^ t[1];
      // B = (A ^ t) || R[i]
      B[2] = R[2*i];
      B[3] = R[2*i+1];
      // B = AES-1(B)
      B = unpack(aes.decrypt(pack(B)));
      // A = MSB(64, B)
      A = B.subarray(0, 2);
      // R[i] = LSB(64, B)
      R[2*i] = B[2];
      R[2*i+1] = B[3];
    }
  }
  if (A[0] === IV[0] && A[1] === IV[1]) {
    return pack(R);
  }
  throw new Error("Key Data Integrity failed");
}

function createArrayBuffer(data) {
  if (typeof data === "string") {
    var length = data.length;
    var buffer = new ArrayBuffer(length);
    var view = new Uint8Array(buffer);
    for (var j = 0; j < length; ++j) {
      view[j] = data.charCodeAt(j);
    }
    return buffer;
  }
  return new Uint8Array(data).buffer;
}

function unpack(data) {
  var length = data.length;
  var buffer = createArrayBuffer(data);
  var view = new DataView(buffer);
  var arr = new Uint32Array(length/4);
  for (var i=0; i<length/4; ++i) {
    arr[i] = view.getUint32(4*i);
  }
  return arr;
}

function pack() {
  var length = 0;
  for (var k=0; k<arguments.length; ++k) {
    length += 4*arguments[k].length;
  }
  var buffer = new ArrayBuffer(length);
  var view = new DataView(buffer);
  var offset = 0;
  for (var i=0; i<arguments.length; ++i) {
    for (var j=0; j<arguments[i].length; ++j) {
      view.setUint32(offset+4*j, arguments[i][j]);
    }
    offset += 4*arguments[i].length;
  }
  return new Uint8Array(buffer);
}

module.exports = {
  wrap: wrap,
  unwrap: unwrap
};
