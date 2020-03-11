OpenPGP.js [![Build Status](https://travis-ci.org/openpgpjs/openpgpjs.svg?branch=master)](https://travis-ci.org/openpgpjs/openpgpjs) [![BrowserStack Status](https://automate.browserstack.com/badge.svg?badge_key=eEkxVVM1TytwOGJNWEdnTjk4Y0VNUUNyR3pXcEtJUGRXOVFBRjVNT1JpUT0tLTZYUlZaMWdtQWs4Z0ROS3grRXc2bFE9PQ==--4a9cac0d6ea009d81aff66de0dbb239edd1aef3c)](https://automate.browserstack.com/public-build/eEkxVVM1TytwOGJNWEdnTjk4Y0VNUUNyR3pXcEtJUGRXOVFBRjVNT1JpUT0tLTZYUlZaMWdtQWs4Z0ROS3grRXc2bFE9PQ==--4a9cac0d6ea009d81aff66de0dbb239edd1aef3c) [![Join the chat on Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/openpgpjs/openpgpjs?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
==========

[OpenPGP.js](https://openpgpjs.org/) is a JavaScript implementation of the OpenPGP protocol. This is defined in [RFC 4880](https://tools.ietf.org/html/rfc4880).

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
        - [Streaming encrypt *Uint8Array* data with a password](#streaming-encrypt-uint8array-data-with-a-password)
        - [Streaming encrypt and decrypt *String* data with PGP keys](#streaming-encrypt-and-decrypt-string-data-with-pgp-keys)
        - [Generate new key pair](#generate-new-key-pair)
        - [Revoke a key](#revoke-a-key)
        - [Lookup public key on HKP server](#lookup-public-key-on-hkp-server)
        - [Upload public key to HKP server](#upload-public-key-to-hkp-server)
        - [Sign and verify cleartext messages](#sign-and-verify-cleartext-messages)
        - [Create and verify *detached* signatures](#create-and-verify-detached-signatures)
        - [Streaming sign and verify *Uint8Array* data](#streaming-sign-and-verify-uint8array-data)
    - [Documentation](#documentation)
    - [Security Audit](#security-audit)
    - [Security recommendations](#security-recommendations)
    - [Development](#development)
    - [How do I get involved?](#how-do-i-get-involved)
    - [License](#license)
    - [Resources](#resources)

<!-- markdown-toc end -->

### Platform Support

* The `dist/openpgp.min.js` bundle works well with recent versions of Chrome, Firefox, Safari and Edge. It also works in Node.js 8+.

* The `dist/compat/openpgp.min.js` bundle also works with Internet Explorer 11 and old versions of Safari. Please note that this bundle overwrites the global `Promise` with a polyfill version even in some cases where it already exists, which may cause issues. It also adds some built-in prototype functions if they don't exist, such as `Array.prototype.includes`.

* If you wish, you could even load one or the other depending on which browser the user is using. However, if you're using the Web Worker, keep in mind that you also need to pass `{ path: 'compat/openpgp.worker.min.js' }` to `initWorker` whenever you load `compat/openpgp.min.js`.

* Currently, Chrome, Safari and Edge have partial implementations of the
[Streams specification](https://streams.spec.whatwg.org/), and Firefox
has a partial implementation behind feature flags. Chrome is the only
browser that implements `TransformStream`s, which we need, so we include
a [polyfill](https://github.com/MattiasBuelens/web-streams-polyfill) for
all other browsers. Please note that in those browsers, the global
`ReadableStream` property gets overwritten with the polyfill version if
it exists. In some edge cases, you might need to use the native
`ReadableStream` (for example when using it to create a `Response`
object), in which case you should store a reference to it before loading
OpenPGP.js. There is also the
[web-streams-adapter](https://github.com/MattiasBuelens/web-streams-adapter)
library to convert back and forth between them.

### Performance

* Version 3.0.0 of the library introduces support for public-key cryptography using [elliptic curves](https://wiki.gnupg.org/ECC). We use native implementations on browsers and Node.js when available or [Elliptic](https://github.com/indutny/elliptic) otherwise. Elliptic curve cryptography provides stronger security per bits of key, which allows for much faster operations. Currently the following curves are supported (* = when available):


    | Curve           | Encryption | Signature | Elliptic | NodeCrypto | WebCrypto |
    |:--------------- |:----------:|:---------:|:--------:|:----------:|:---------:|
    | p256            | ECDH       | ECDSA     | Yes      | Yes*       | Yes*      |
    | p384            | ECDH       | ECDSA     | Yes      | Yes*       | Yes*      |
    | p521            | ECDH       | ECDSA     | Yes      | Yes*       | Yes*      |
    | secp256k1       | ECDH       | ECDSA     | Yes      | Yes*       | No        |
    | brainpoolP256r1 | ECDH       | ECDSA     | Yes      | Yes*       | No        |
    | brainpoolP384r1 | ECDH       | ECDSA     | Yes      | Yes*       | No        |
    | brainpoolP512r1 | ECDH       | ECDSA     | Yes      | Yes*       | No        |
    | curve25519      | ECDH       | N/A       | Yes      | No         | No        |
    | ed25519         | N/A        | EdDSA     | Yes      | No         | No        |

* Version 2.x of the library has been built from the ground up with Uint8Arrays. This allows for much better performance and memory usage than strings.

* If the user's browser supports [native WebCrypto](https://caniuse.com/#feat=cryptography) via the `window.crypto.subtle` API, this will be used. Under Node.js the native [crypto module](https://nodejs.org/api/crypto.html#crypto_crypto) is used. This can be deactivated by setting `openpgp.config.use_native = false`.

* The library implements the [IETF proposal](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-07) for authenticated encryption using native AES-EAX, OCB, or GCM. This makes symmetric encryption up to 30x faster on supported platforms. Since the specification has not been finalized and other OpenPGP implementations haven't adopted it yet, the feature is currently behind a flag. **Note: activating this setting can break compatibility with other OpenPGP implementations, and also with future versions of OpenPGP.js. Don't use it with messages you want to store on disk or in a database.** You can enable it by setting `openpgp.config.aead_protect = true`.

  You can change the AEAD mode by setting one of the following options:

  ```
  openpgp.config.aead_mode = openpgp.enums.aead.eax // Default, native
  openpgp.config.aead_mode = openpgp.enums.aead.ocb // Non-native
  openpgp.config.aead_mode = openpgp.enums.aead.experimental_gcm // **Non-standard**, fastest
  ```

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

##### Node.js

```js
const openpgp = require('openpgp');
```

##### Browser

Copy `dist/openpgp.min.js` or `dist/compat/openpgp.min.js` (depending on the browser support you need, see [Platform Support](#platform-support)) to your project folder, and load it in a script tag:

```html
<script src="openpgp.min.js"></script>
```

If you want to use the built-in Web Worker, to offload cryptographic operations off the main thread:

```js
await openpgp.initWorker({ path: 'openpgp.worker.js' }); // set the relative web worker path
```

On logout, be sure to destroy the worker again, to clear private keys from memory:

```js
await openpgp.destroyWorker();
```

Alternatively, you can also implement a Web Worker in your application and load OpenPGP.js from there. This can be more performant if you store or fetch keys and messages directly inside the Worker, so that they don't have to be `postMessage`d there.

If you want to use the lightweight build (which is smaller, and lazily loads non-default curves on demand), copy `dist/lightweight/openpgp.min.js` and `dist/lightweight/elliptic.min.js`, load the former in a script tag, and point `openpgp.config.indutny_elliptic_path` to the latter:

```html
<script src="lightweight/openpgp.min.js"></script>
<script>
openpgp.config.indutny_elliptic_path = 'lightweight/elliptic.min.js';
</script>
```

To test whether the lazy loading works, try:

```js
await openpgp.generateKey({ curve: 'brainpoolP512r1',  userIds: [{ name: 'Test', email: 'test@test.com' }] });
```

For more examples of how to generate a key, see [Generate new key pair](#generate-new-key-pair). It is recommended to use `curve25519` instead of `brainpoolP512r1` by default.

#### Encrypt and decrypt *Uint8Array* data with a password

Encryption will use the algorithm specified in config.encryption_cipher (defaults to aes256), and decryption will use the algorithm used for encryption.

```js
(async () => {
    const { message } = await openpgp.encrypt({
        message: openpgp.message.fromBinary(new Uint8Array([0x01, 0x01, 0x01])), // input as Message object
        passwords: ['secret stuff'],                                             // multiple passwords possible
        armor: false                                                             // don't ASCII armor (for Uint8Array output)
    });
    const encrypted = message.packets.write(); // get raw encrypted packets as Uint8Array

    const { data: decrypted } = await openpgp.decrypt({
        message: await openpgp.message.read(encrypted), // parse encrypted bytes
        passwords: ['secret stuff'],                    // decrypt with password
        format: 'binary'                                // output as Uint8Array
    });
    console.log(decrypted); // Uint8Array([0x01, 0x01, 0x01])
})();
```

#### Encrypt and decrypt *String* data with PGP keys

Encryption will use the algorithm preferred by the public key (defaults to aes256 for keys generated in OpenPGP.js), and decryption will use the algorithm used for encryption.

```js
const openpgp = require('openpgp'); // use as CommonJS, AMD, ES6 module or via window.openpgp

(async () => {
    await openpgp.initWorker({ path: 'openpgp.worker.js' }); // set the relative web worker path

    // put keys in backtick (``) to avoid errors caused by spaces or tabs
    const publicKeyArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`;
    const privateKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----`; // encrypted private key
    const passphrase = `yourPassphrase`; // what the private key is encrypted with

    const { keys: [privateKey] } = await openpgp.key.readArmored(privateKeyArmored);
    await privateKey.decrypt(passphrase);

    const { data: encrypted } = await openpgp.encrypt({
        message: openpgp.message.fromText('Hello, World!'),                 // input as Message object
        publicKeys: (await openpgp.key.readArmored(publicKeyArmored)).keys, // for encryption
        privateKeys: [privateKey]                                           // for signing (optional)
    });
    console.log(encrypted); // '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'
    const { data: decrypted } = await openpgp.decrypt({
        message: await openpgp.message.readArmored(encrypted),              // parse armored message
        publicKeys: (await openpgp.key.readArmored(publicKeyArmored)).keys, // for verification (optional)
        privateKeys: [privateKey]                                           // for decryption
    });
    console.log(decrypted); // 'Hello, World!'
})();
```

Encrypt with multiple public keys:

```js
(async () => {
    const publicKeysArmored = [
        `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`,
        `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`
    ];
    const privateKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----`;    // encrypted private key
    const passphrase = `yourPassphrase`; // what the private key is encrypted with
    const message = 'Hello, World!';

    const { keys: [privateKey] } = await openpgp.key.readArmored(privateKeyArmored);
    await privateKey.decrypt(passphrase)

    const publicKeys = await Promise.all(publicKeysArmored.map(async (key) => {
        return (await openpgp.key.readArmored(key)).keys[0];
    }));

    const { data: encrypted } = await openpgp.encrypt({
        message: openpgp.message.fromText(message),   // input as Message object
        publicKeys,                                   // for encryption
        privateKeys: [privateKey]                     // for signing (optional)
    });
    console.log(encrypted); // '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'
})();
```

#### Encrypt with compression

By default, `encrypt` will not use any compression. It's possible to override that behavior in two ways:

Either set the `compression` parameter in the options object when calling `encrypt`.

```js
(async () => {
    const encrypted = await openpgp.encrypt({
        message: openpgp.message.fromBinary(new Uint8Array([0x01, 0x02, 0x03])), // or .fromText('string')
        passwords: ['secret stuff'],                                             // multiple passwords possible
        compression: openpgp.enums.compression.zip                               // compress the data with zip
    });
})();
```

Or, override the config to enable compression:

```js
openpgp.config.compression = openpgp.enums.compression.zlib;
```

Where the value can be any of:
 * `openpgp.enums.compression.zip`
 * `openpgp.enums.compression.zlib`


#### Streaming encrypt *Uint8Array* data with a password

```js
(async () => {
    const readableStream = new ReadableStream({
        start(controller) {
            controller.enqueue(new Uint8Array([0x01, 0x02, 0x03]));
            controller.close();
        }
    });

    const { message } = await openpgp.encrypt({
        message: openpgp.message.fromBinary(readableStream), // input as Message object
        passwords: ['secret stuff'],                         // multiple passwords possible
        armor: false                                         // don't ASCII armor (for Uint8Array output)
    });
    const encrypted = message.packets.write(); // get raw encrypted packets as ReadableStream<Uint8Array>

    // Either pipe the above stream somewhere, pass it to another function,
    // or read it manually as follows:
    const reader = openpgp.stream.getReader(encrypted);
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        console.log('new chunk:', value); // Uint8Array
    }

    // Or, in Node.js, you can pipe the above stream as follows:
    const nodeStream = openpgp.stream.webToNode(encrypted);
    nodeStream.pipe(nodeWritableStream);
})();
```

For more information on creating ReadableStreams, see [the MDN Documentation on `new
ReadableStream()`](https://developer.mozilla.org/docs/Web/API/ReadableStream/ReadableStream).
For more information on reading streams using `openpgp.stream`, see the documentation of
[the web-stream-tools dependency](https://openpgpjs.org/web-stream-tools/), particularly
its [Reader class](https://openpgpjs.org/web-stream-tools/Reader.html).


#### Streaming encrypt and decrypt *String* data with PGP keys

```js
(async () => {
    const publicKeyArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`; // Public key
    const [privateKeyArmored] = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----`; // Encrypted private key
    const passphrase = `yourPassphrase`; // Password that private key is encrypted with

    const privateKey = (await openpgp.key.readArmored([privateKeyArmored])).keys[0];
    await privateKey.decrypt(passphrase);

    const readableStream = new ReadableStream({
        start(controller) {
            controller.enqueue('Hello, world!');
            controller.close();
        }
    });

    const encrypted = await openpgp.encrypt({
        message: openpgp.message.fromText(readableStream),                  // input as Message object
        publicKeys: (await openpgp.key.readArmored(publicKeyArmored)).keys, // for encryption
        privateKeys: [privateKey]                                           // for signing (optional)
    });
    const ciphertext = encrypted.data; // ReadableStream containing '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'

    const decrypted = await openpgp.decrypt({
        message: await openpgp.message.readArmored(ciphertext),             // parse armored message
        publicKeys: (await openpgp.key.readArmored(publicKeyArmored)).keys, // for verification (optional)
        privateKeys: [privateKey]                                           // for decryption
    });
    const plaintext = await openpgp.stream.readToEnd(decrypted.data); // 'Hello, World!'
})();
```


#### Generate new key pair

ECC keys:

Possible values for `curve` are: `curve25519`, `ed25519`, `p256`, `p384`, `p521`, `secp256k1`,
`brainpoolP256r1`, `brainpoolP384r1`, or `brainpoolP512r1`.
Note that both the `curve25519` and `ed25519` options generate a primary key for signing using Ed25519
and a subkey for encryption using Curve25519.

```js
(async () => {
    const { privateKeyArmored, publicKeyArmored, revocationCertificate } = await openpgp.generateKey({
        userIds: [{ name: 'Jon Smith', email: 'jon@example.com' }], // you can pass multiple user IDs
        curve: 'ed25519',                                           // ECC curve name
        passphrase: 'super long and hard to guess secret'           // protects the private key
    });

    console.log(privateKeyArmored);     // '-----BEGIN PGP PRIVATE KEY BLOCK ... '
    console.log(publicKeyArmored);      // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
    console.log(revocationCertificate); // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
})();
```

RSA keys:

```js
(async () => {
    const key = await openpgp.generateKey({
        userIds: [{ name: 'Jon Smith', email: 'jon@example.com' }], // you can pass multiple user IDs
        rsaBits: 4096,                                              // RSA key size
        passphrase: 'super long and hard to guess secret'           // protects the private key
    });
})();
```

#### Revoke a key

Using a revocation certificate:
```js
(async () => {
    const { publicKeyArmored: revokedKeyArmored } = await openpgp.revokeKey({
        key: (await openpgp.key.readArmored(publicKeyArmored)).keys[0],
        revocationCertificate
    });
    console.log(revokedKeyArmored); // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
})();
```

Using the private key:
```js
(async () => {
    const { publicKeyArmored, publicKey } = await openpgp.revokeKey({
        key: (await openpgp.key.readArmored(privateKeyArmored)).keys[0]
    });
})();
```

#### Lookup public key on HKP server

```js
(async () => {
    var hkp = new openpgp.HKP(); // Defaults to https://keyserver.ubuntu.com, or pass another keyserver URL as a string

    let publicKeyArmored = await hkp.lookup({
        query: 'alice@example.com'
    });
    var { keys: [publicKey] } = await openpgp.key.readArmored(publicKeyArmored);
})();
```

#### Upload public key to HKP server

```js
(async () => {
    var hkp = new openpgp.HKP('https://pgp.mit.edu');

    var publicKeyArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`;

    await hkp.upload(publicKeyArmored);
})();
```

#### Sign and verify cleartext messages

```js
(async () => {
    const publicKeyArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`;
    const privateKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----`; // encrypted private key
    const passphrase = `yourPassphrase`; // what the private key is encrypted with

    const { keys: [privateKey] } = await openpgp.key.readArmored(privateKeyArmored);
    await privateKey.decrypt(passphrase);

    const { data: cleartext } = await openpgp.sign({
        message: openpgp.cleartext.fromText('Hello, World!'), // CleartextMessage or Message object
        privateKeys: [privateKey]                             // for signing
    });
    console.log(cleartext); // '-----BEGIN PGP SIGNED MESSAGE ... END PGP SIGNATURE-----'

    const verified = await openpgp.verify({
        message: await openpgp.cleartext.readArmored(cleartext),           // parse armored message
        publicKeys: (await openpgp.key.readArmored(publicKeyArmored)).keys // for verification
    });
    const { valid } = verified.signatures[0];
    if (valid) {
        console.log('signed by key id ' + verified.signatures[0].keyid.toHex());
    } else {
        throw new Error('signature could not be verified');
    }
})();
```

#### Create and verify *detached* signatures

```js
(async () => {
    const publicKeyArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`;
    const privateKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----`; // encrypted private key
    const passphrase = `yourPassphrase`; // what the private key is encrypted with

    const { keys: [privateKey] } = await openpgp.key.readArmored(privateKeyArmored);
    await privateKey.decrypt(passphrase);

    const { signature: detachedSignature } = await openpgp.sign({
        message: openpgp.cleartext.fromText('Hello, World!'), // CleartextMessage or Message object
        privateKeys: [privateKey],                            // for signing
        detached: true
    });
    console.log(detachedSignature);

    const verified = await openpgp.verify({
        message: openpgp.cleartext.fromText('Hello, World!'),              // CleartextMessage or Message object
        signature: await openpgp.signature.readArmored(detachedSignature), // parse detached signature
        publicKeys: (await openpgp.key.readArmored(publicKeyArmored)).keys // for verification
    });
    const { valid } = verified.signatures[0];
    if (valid) {
        console.log('signed by key id ' + verified.signatures[0].keyid.toHex());
    } else {
        throw new Error('signature could not be verified');
    }
})();
```

#### Streaming sign and verify *Uint8Array* data

```js
(async () => {
    var readableStream = new ReadableStream({
        start(controller) {
            controller.enqueue(new Uint8Array([0x01, 0x02, 0x03]));
            controller.close();
        }
    });

    const publicKeyArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`;
    const privateKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----`; // encrypted private key
    const passphrase = `yourPassphrase`; // what the private key is encrypted with

    const { keys: [privateKey] } = await openpgp.key.readArmored(privateKeyArmored);
    await privateKey.decrypt(passphrase);

    const { data: signatureArmored } = await openpgp.sign({
        message: openpgp.message.fromBinary(readableStream),  // or .fromText(readableStream: ReadableStream<String>)
        privateKeys: [privateKey]                             // for signing
    });
    console.log(signatureArmored); // ReadableStream containing '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'

    const verified = await openpgp.verify({
        message: await openpgp.message.readArmored(signatureArmored),       // parse armored signature
        publicKeys: (await openpgp.key.readArmored(publicKeyArmored)).keys  // for verification
    });

    await openpgp.stream.readToEnd(verified.data);
    // Note: you *have* to read `verified.data` in some way or other,
    // even if you don't need it, as that is what triggers the
    // verification of the data.

    const { valid } = verified.signatures[0];
    if (valid) {
        console.log('signed by key id ' + verified.signatures[0].keyid.toHex());
    } else {
        throw new Error('signature could not be verified');
    }
})();
```

### Documentation

A jsdoc build of our code comments is available at [doc/index.html](https://openpgpjs.org/openpgpjs/doc/index.html). Public calls should generally be made through the OpenPGP object [doc/openpgp.html](https://openpgpjs.org/openpgpjs/doc/module-openpgp.html).

For the documentation of `openpgp.stream`, see the documentation of [the web-stream-tools dependency](https://openpgpjs.org/web-stream-tools/).

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

You want to help, great! It's probably best to send us a message on [Gitter](https://gitter.im/openpgpjs/openpgpjs) before you start your undertaking, to make sure nobody else is working on it, and so we can discuss the best course of action. Other than that, just go ahead and fork our repo, make your changes and send us a pull request! :)

### License

[GNU Lesser General Public License](https://www.gnu.org/licenses/lgpl-3.0.en.html) (3.0 or any later version). Please take a look at the [LICENSE](LICENSE) file for more information.

### Resources

Below is a collection of resources, many of these were projects that were in someway a precursor to the current OpenPGP.js project. If you'd like to add your link here, please do so in a pull request or email to the list.

* [https://www.hanewin.net/encrypt/](https://www.hanewin.net/encrypt/)
* [https://github.com/seancolyer/gmail-crypt](https://github.com/seancolyer/gmail-crypt)
* [https://github.com/mete0r/jspg](https://github.com/mete0r/jspg)
* [https://github.com/GPGTools/Mobile/wiki/Introduction](https://github.com/GPGTools/Mobile/wiki/Introduction)
* [https://github.com/gmontalvoriv/mailock](https://github.com/gmontalvoriv/mailock)
