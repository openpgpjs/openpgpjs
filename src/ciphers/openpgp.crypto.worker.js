// OpenPGP.js WebWorker for multithreaded crypto in javascript
// Copyright (C) 2012 Tankred Hase
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

'use strict';

// import web worker dependencies
importScripts('../util/util.js');
importScripts('symmetric/aes.js');
importScripts('openpgp.cfb.js');
importScripts('openpgp.crypto.sym.js');

/**
 * Wrapper for the web worker crypto logic
 */
var CRYPTOWORKER = (function (symEncrypt, symDecrypt) {
	
	//
	// In the web worker thread context, 'this' and 'self' can be used as a global
	// variable namespace similar to the 'window' object in the main thread
	//
	
	self.addEventListener('message', function(e) {
		// define openpgp.config locally for openpgp.util.debug in the worker thread context
		self.openpgp = { config : {} };
		
		var args = e.data,
			output = null;
			
		if (args.type === 'encrypt' &&
			args.prefixrandom &&
			args.algo &&
			args.key &&
			args.data &&
			args.openpgp_cfb) {
			// start encryption
			output = symEncrypt(args.prefixrandom, args.algo, args.key, args.data, args.openpgp_cfb);
			
		} else if (args.type === 'decrypt' &&
			args.algo &&
			args.key &&
			args.data &&
			args.openpgp_cfb) {
			// start decryption
			output = symDecrypt(args.algo, args.key, args.data, args.openpgp_cfb);
			
		} else {
			throw 'Not all arguments for web worker crypto are defined!';
		}
		
		// pass output back to main thread
		self.postMessage(output);
	}, false);
	
}(openpgp_crypto_symmetricEncrypt, openpgp_crypto_symmetricDecrypt));