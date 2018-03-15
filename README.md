OpenPGP.js [![Build Status](https://travis-ci.org/openpgpjs/openpgpjs.svg?branch=master)](https://travis-ci.org/openpgpjs/openpgpjs)
==========

[OpenPGP.js](https://openpgpjs.org/) is a JavaScript implementation of the OpenPGP protocol. This is defined in [RFC 4880](https://tools.ietf.org/html/rfc4880).


[![Saucelabs Test Status](https://saucelabs.com/browser-matrix/openpgpjs.svg)](https://saucelabs.com/u/openpgpjs)
 
<!-- markdown-toc start - Don't edit this section. Run M-x markdown-toc-generate-toc again -->
**Table of Contents**

- [OpenPGP.js](#openpgpjs)
    - [Platform Support](#platform-support)
    - [Performance](#performance)
    - [Getting started](#getting-started)
        - [Npm](#npm)
        - [Bower](#bower)
    - [Examples](#examples)
        - [Set up](#set-up)
        - [Encrypt and decrypt *Uint8Array* data with a password](#encrypt-and-decrypt-uint8array-data-with-a-password)
        - [Encrypt and decrypt *String* data with PGP keys](#encrypt-and-decrypt-string-data-with-pgp-keys)
        - [Encrypt with compression](#encrypt-with-compression)
        - [Generate new key pair](#generate-new-key-pair)
        - [Lookup public key on HKP server](#lookup-public-key-on-hkp-server)
        - [Upload public key to HKP server](#upload-public-key-to-hkp-server)
        - [Sign and verify cleartext messages](#sign-and-verify-cleartext-messages)
        - [Create and verify *detached* signatures](#create-and-verify-detached-signatures)
    - [Documentation](#documentation)
    - [Security Audit](#security-audit)
    - [Security recommendations](#security-recommendations)
    - [Development](#development)
    - [How do I get involved?](#how-do-i-get-involved)
    - [License](#license)
    - [Resources](#resources)

<!-- markdown-toc end -->

### Platform Support

* OpenPGP.js v3.x is written in ES7 but is transpiled to ES5 using [Babel](https://babeljs.io/) to run in most environments. We support Node.js v8+ and browsers that implement [window.crypto.getRandomValues](https://caniuse.com/#feat=getrandomvalues).

* The API uses the Async/Await syntax introduced in ES7 to return Promise objects. Async functions are available in [most modern browsers](https://caniuse.com/#feat=async-functions). If you need to support older browsers, fear not! We use [core-js](https://github.com/zloirock/core-js) to polyfill new features so that no action is required on your part!

* For the OpenPGP HTTP Key Server (HKP) client the new [fetch API](https://caniuse.com/#feat=fetch) is used. The module is polyfilled for [browsers](https://github.com/github/fetch) and is included as a dependency for [Node.js](https://github.com/bitinn/node-fetch) runtimes.

### Performance

* Version 3.0.0 of the library introduces support for public-key cryptography using [elliptic curves](https://wiki.gnupg.org/ECC). We use native implementations on browsers and Node.js when available or [Elliptic](https://github.com/indutny/elliptic) otherwise. Elliptic curve cryptography provides stronger security per bits of key, which allows for much faster operations. Currently the following curves are supported (* = when available):


    | Curve           | Encryption | Signature | Elliptic | NodeCrypto | WebCrypto |
    |:--------------- |:----------:|:---------:|:--------:|:----------:|:---------:|
    | p256            | ECDH       | ECDSA     | Yes      | Yes*       | Yes*      |
    | p384            | ECDH       | ECDSA     | Yes      | Yes*       | Yes*      |
    | p521            | ECDH       | ECDSA     | Yes      | Yes*       | Yes*      |
    | secp256k1       | ECDH       | ECDSA     | Yes      | Yes*       | No        |
    | curve25519      | ECDH       | N/A       | Yes      | No (TODO)  | No        |
    | ed25519         | N/A        | EdDSA     | Yes      | No (TODO)  | No        |
    | brainpoolP256r1 | ECDH       | ECDSA     | Yes      | No (TODO)  | No        |
    | brainpoolP384r1 | ECDH       | ECDSA     | Yes      | No (TODO)  | No        |
    | brainpoolP512r1 | ECDH       | ECDSA     | Yes      | No (TODO)  | No        |

* Version 2.x of the library has been built from the ground up with Uint8Arrays. This allows for much better performance and memory usage than strings.

* If the user's browser supports [native WebCrypto](https://caniuse.com/#feat=cryptography) via the `window.crypto.subtle` API, this will be used. Under Node.js the native [crypto module](https://nodejs.org/API/crypto.html#crypto_crypto) is used. This can be deactivated by setting `openpgp.config.use_native = false`.

* The library implements the [IETF proposal](https://tools.ietf.org/html/draft-ford-openpgp-format-00) for authenticated encryption [using native AES-GCM](https://github.com/openpgpjs/openpgpjs/pull/430). This makes symmetric encryption about 30x faster on supported platforms. Since the specification has not been finalized and other OpenPGP implementations haven't adopted it yet, the feature is currently behind a flag. You can activate it by setting `openpgp.config.aead_protect = true`. **Note: activating this setting can break compatibility with other OpenPGP implementations, so be careful if that's one of your requirements.**

* For environments that don't provide native crypto, the library falls back to [asm.js](https://caniuse.com/#feat=asmjs) implementations of AES, SHA-1, and SHA-256. We use [Rusha](https://github.com/srijs/rusha) and [asmCrypto Lite](https://github.com/openpgpjs/asmcrypto-lite) (a minimal subset of asmCrypto.js built specifically for OpenPGP.js).


### Getting started

#### Npm

    npm install --save openpgp

#### Bower

    bower install --save openpgp

Or just fetch a minified build under [dist](https://github.com/openpgpjs/openpgpjs/tree/master/dist).


### Examples

Here are some examples of how to use the v2.x+ API. For more elaborate examples and working code, please check out the [public API unit tests](https://github.com/openpgpjs/openpgpjs/blob/master/test/general/openpgp.js). If you're upgrading from v1.x it might help to check out the [documentation](https://github.com/openpgpjs/openpgpjs#documentation).

#### Set up

```js
var openpgp = require('openpgp'); // use as CommonJS, AMD, ES6 module or via window.openpgp

openpgp.initWorker({ path:'openpgp.worker.js' }) // set the relative web worker path

openpgp.config.aead_protect = true // activate fast AES-GCM mode (not yet OpenPGP standard)
```

#### Encrypt and decrypt *Uint8Array* data with a password

```js
var options, encrypted;

options = {
    data: new Uint8Array([0x01, 0x01, 0x01]), // input as Uint8Array (or String)
    passwords: ['secret stuff'],              // multiple passwords possible
    armor: false                              // don't ASCII armor (for Uint8Array output)
};

openpgp.encrypt(options).then(function(ciphertext) {
    encrypted = ciphertext.message.packets.write(); // get raw encrypted packets as Uint8Array
});
```

```js
options = {
    message: openpgp.message.read(encrypted), // parse encrypted bytes
    passwords: ['secret stuff'],              // decrypt with password
    format: 'binary'                          // output as Uint8Array
};

openpgp.decrypt(options).then(function(plaintext) {
    return plaintext.data // Uint8Array([0x01, 0x01, 0x01])
});
```

#### Encrypt and decrypt *String* data with PGP keys

```js
var options, encrypted;

var pubkey = '-----BEGIN PGP PUBLIC KEY BLOCK ... END PGP PUBLIC KEY BLOCK-----';
var privkey = '-----BEGIN PGP PRIVATE KEY BLOCK ... END PGP PRIVATE KEY BLOCK-----'; //encrypted private key
var passphrase = 'secret passphrase'; //what the privKey is encrypted with

var privKeyObj = openpgp.key.readArmored(privkey).keys[0];
await privKeyObj.decrypt(passphrase);

options = {
    data: 'Hello, World!',                             // input as String (or Uint8Array)
    publicKeys: openpgp.key.readArmored(pubkey).keys,  // for encryption
    privateKeys: [privKeyObj]                          // for signing (optional)
};

openpgp.encrypt(options).then(function(ciphertext) {
    encrypted = ciphertext.data; // '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'
});
```

```js
options = {
    message: openpgp.message.readArmored(encrypted),     // parse armored message
    publicKeys: openpgp.key.readArmored(pubkey).keys,    // for verification (optional)
    privateKeys: [privKeyObj]                            // for decryption
};

openpgp.decrypt(options).then(function(plaintext) {
    return plaintext.data; // 'Hello, World!'
});
```

#### Encrypt with compression

By default, `encrypt` will not use any compression. It's possible to override that behavior in two ways:

Either set the `compression` parameter in the options object when calling `encrypt`.

```js
var options, encrypted;

options = {
    data: new Uint8Array([0x01, 0x02, 0x03]),    // input as Uint8Array (or String)
    passwords: ['secret stuff'],                 // multiple passwords possible
    compression: openpgp.enums.compression.zip   // compress the data with zip
};

ciphertext = await openpgp.encrypt(options);     // use ciphertext
```

Or, override the config to enable compression:

```js
openpgp.config.compression = openpgp.enums.compression.zip
```

Where the value can be any of:
 * `openpgp.enums.compression.zip`
 * `openpgp.enums.compression.zlib`
 * `openpgp.enums.compression.bzip2`


#### Generate new key pair

RSA keys:
```js
var options = {
    userIds: [{ name:'Jon Smith', email:'jon@example.com' }], // multiple user IDs
    numBits: 4096,                                            // RSA key size
    passphrase: 'super long and hard to guess secret'         // protects the private key
};
```

ECC keys:

Possible values for curve are: `curve25519`, `ed25519`, `p256`, `p384`, `p521`, `secp256k1`,
`brainpoolP256r1`, `brainpoolP384r1`, or `brainpoolP512r1`.
Note that options both `curve25519` and `ed25519` generate a primary key for signing using Ed25519
and a subkey for encryption using Curve25519.

```js
var options = {
    userIds: [{ name:'Jon Smith', email:'jon@example.com' }], // multiple user IDs
    curve: "ed25519",                                         // ECC curve name
    passphrase: 'super long and hard to guess secret'         // protects the private key
};
```

```js
openpgp.generateKey(options).then(function(key) {
    var privkey = key.privateKeyArmored; // '-----BEGIN PGP PRIVATE KEY BLOCK ... '
    var pubkey = key.publicKeyArmored;   // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
});
```

#### Lookup public key on HKP server

```js
var hkp = new openpgp.HKP('https://pgp.mit.edu');

var options = {
    query: 'alice@example.com'
};

hkp.lookup(options).then(function(key) {
    var pubkey = openpgp.key.readArmored(key);
});
```

#### Upload public key to HKP server

```js
var hkp = new openpgp.HKP('https://pgp.mit.edu');

var pubkey = '-----BEGIN PGP PUBLIC KEY BLOCK ... END PGP PUBLIC KEY BLOCK-----';

hkp.upload(pubkey).then(function() { ... });
```

#### Sign and verify cleartext messages

```js
var options, cleartext, validity;

var pubkey = '-----BEGIN PGP PUBLIC KEY BLOCK ... END PGP PUBLIC KEY BLOCK-----';
var privkey = '-----BEGIN PGP PRIVATE KEY BLOCK ... END PGP PRIVATE KEY BLOCK-----'; //encrypted private key
var passphrase = 'secret passphrase'; //what the privKey is encrypted with

var privKeyObj = openpgp.key.readArmored(privkey).keys[0];
await privKeyObj.decrypt(passphrase);
```

```js
options = {
    data: 'Hello, World!',                             // input as String (or Uint8Array)
    privateKeys: [privKeyObj]                          // for signing
};

openpgp.sign(options).then(function(signed) {
    cleartext = signed.data; // '-----BEGIN PGP SIGNED MESSAGE ... END PGP SIGNATURE-----'
});
```

```js
options = {
    message: openpgp.cleartext.readArmored(cleartext), // parse armored message
    publicKeys: openpgp.key.readArmored(pubkey).keys   // for verification
};

openpgp.verify(options).then(function(verified) {
	validity = verified.signatures[0].valid; // true
	if (validity) {
		console.log('signed by key id ' + verified.signatures[0].keyid.toHex());
	}
});
```

#### Create and verify *detached* signatures

```js
var options, detachedSig, validity;

var pubkey = '-----BEGIN PGP PUBLIC KEY BLOCK ... END PGP PUBLIC KEY BLOCK-----';
var privkey = '-----BEGIN PGP PRIVATE KEY BLOCK ... END PGP PRIVATE KEY BLOCK-----'; //encrypted private key
var passphrase = 'secret passphrase'; //what the privKey is encrypted with

var privKeyObj = openpgp.key.readArmored(privkey).keys[0];
await privKeyObj.decrypt(passphrase);
```

```js
options = {
    data: 'Hello, World!',                             // input as String (or Uint8Array)
    privateKeys: [privKeyObj],                         // for signing
    detached: true
};

openpgp.sign(options).then(function(signed) {
    detachedSig = signed.signature;
});
```


```js
options = {
    message: openpgp.message.fromText('Hello, World!'), // input as Message object
    signature: openpgp.signature.readArmored(detachedSig), // parse detached signature
    publicKeys: openpgp.key.readArmored(pubkey).keys   // for verification
};

openpgp.verify(options).then(function(verified) {
    validity = verified.signatures[0].valid; // true
    if (validity) {
        console.log('signed by key id ' + verified.signatures[0].keyid.toHex());
    }
});
```

### Documentation

A jsdoc build of our code comments is available at [doc/index.html](https://openpgpjs.org/openpgpjs/doc/index.html). Public calls should generally be made through the OpenPGP object [doc/openpgp.html](https://openpgpjs.org/openpgpjs/doc/module-openpgp.html).

### Security Audit

To date the OpenPGP.js code base has undergone two complete security audits from [Cure53](https://cure53.de). The first audit's report has been published [here](https://github.com/openpgpjs/openpgpjs/wiki/Cure53-security-audit).

### Security recommendations

It should be noted that js crypto apps deployed via regular web hosting (a.k.a. [**host-based security**](https://www.schneier.com/blog/archives/2012/08/cryptocat.html)) provide users with less security than installable apps with auditable static versions. Installable apps can be deployed as a [Firefox](https://developer.mozilla.org/en-US/Marketplace/Options/Packaged_apps) or [Chrome](https://developer.chrome.com/apps/about_apps.html) packaged app. These apps are basically signed zip files and their runtimes typically enforce a strict [Content Security Policy (CSP)](https://www.html5rocks.com/en/tutorials/security/content-security-policy/) to protect users against [XSS](https://en.wikipedia.org/wiki/Cross-site_scripting). This [blogpost](https://tankredhase.com/2014/04/13/heartbleed-and-javascript-crypto/) explains the trust model of the web quite well.

It is also recommended to set a strong passphrase that protects the user's private key on disk.

### Development

To create your own build of the library, just run the following command after cloning the git repo. This will download all dependencies, run the tests and create a minified bundle under `dist/openpgp.min.js` to use in your project:

    npm install && npm test

For debugging browser errors, you can open `test/unittests.html` in a browser or, after running the following command, open [`http://localhost:3000/test/unittests.html`](http://localhost:3000/test/unittests.html):

    grunt browsertest

### How do I get involved?

You want to help, great! Go ahead and fork our repo, make your changes and send us a pull request.

### License

GNU Lesser General Public License (3.0 or any later version). Please take a look at the [LICENSE](LICENSE) file for more information.

### Resources

Below is a collection of resources, many of these were projects that were in someway a precursor to the current OpenPGP.js project. If you'd like to add your link here, please do so in a pull request or email to the list.

* [https://www.hanewin.net/encrypt/](https://www.hanewin.net/encrypt/)
* [https://github.com/seancolyer/gmail-crypt](https://github.com/seancolyer/gmail-crypt)
* [https://github.com/mete0r/jspg](https://github.com/mete0r/jspg)
* [https://fitblip.pub/JSPGP-Stuffs/](https://fitblip.pub/JSPGP-Stuffs/)
* [http://qooxdoo.org/contrib/project/crypto](http://qooxdoo.org/contrib/project/crypto)
* [https://github.com/GPGTools/Mobile/wiki/Introduction](https://github.com/GPGTools/Mobile/wiki/Introduction)
* [http://gpg4browsers.recurity.com/](http://gpg4browsers.recurity.com/)
* [https://github.com/gmontalvoriv/mailock](https://github.com/gmontalvoriv/mailock)
