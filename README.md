OpenPGP.js [![BrowserStack Status](https://automate.browserstack.com/badge.svg?badge_key=eEkxVVM1TytwOGJNWEdnTjk4Y0VNUUNyR3pXcEtJUGRXOVFBRjVNT1JpUT0tLTZYUlZaMWdtQWs4Z0ROS3grRXc2bFE9PQ==--4a9cac0d6ea009d81aff66de0dbb239edd1aef3c)](https://automate.browserstack.com/public-build/eEkxVVM1TytwOGJNWEdnTjk4Y0VNUUNyR3pXcEtJUGRXOVFBRjVNT1JpUT0tLTZYUlZaMWdtQWs4Z0ROS3grRXc2bFE9PQ==--4a9cac0d6ea009d81aff66de0dbb239edd1aef3c) [![Join the chat on Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/openpgpjs/openpgpjs?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
==========

[OpenPGP.js](https://openpgpjs.org/) is a JavaScript implementation of the OpenPGP protocol. It implements [RFC4880](https://tools.ietf.org/html/rfc4880) and parts of [RFC4880bis](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-10).

**Table of Contents**

- [OpenPGP.js](#openpgpjs)
    - [Platform Support](#platform-support)
    - [Performance](#performance)
    - [Getting started](#getting-started)
        - [Node.js](#nodejs)
        - [Browser (webpack)](#browser-webpack)
        - [Browser (plain files)](#browser-plain-files)
    - [Examples](#examples)
        - [Encrypt and decrypt *Uint8Array* data with a password](#encrypt-and-decrypt-uint8array-data-with-a-password)
        - [Encrypt and decrypt *String* data with PGP keys](#encrypt-and-decrypt-string-data-with-pgp-keys)
        - [Encrypt with compression](#encrypt-with-compression)
        - [Streaming encrypt *Uint8Array* data with a password](#streaming-encrypt-uint8array-data-with-a-password)
        - [Streaming encrypt and decrypt *String* data with PGP keys](#streaming-encrypt-and-decrypt-string-data-with-pgp-keys)
        - [Generate new key pair](#generate-new-key-pair)
        - [Revoke a key](#revoke-a-key)
        - [Sign and verify cleartext messages](#sign-and-verify-cleartext-messages)
        - [Create and verify *detached* signatures](#create-and-verify-detached-signatures)
        - [Streaming sign and verify *Uint8Array* data](#streaming-sign-and-verify-uint8array-data)
    - [Documentation](#documentation)
    - [Security Audit](#security-audit)
    - [Security recommendations](#security-recommendations)
    - [Development](#development)
    - [How do I get involved?](#how-do-i-get-involved)
    - [License](#license)

### Platform Support

* The `dist/openpgp.min.js` bundle works well with recent versions of Chrome, Firefox, Safari and Edge.

* The `dist/node/openpgp.min.js` bundle works well in Node.js. It is used by default when you `require('openpgp')` in Node.js.

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

* Version 3.0.0 of the library introduces support for public-key cryptography using [elliptic curves](https://wiki.gnupg.org/ECC). We use native implementations on browsers and Node.js when available. Elliptic curve cryptography provides stronger security per bits of key, which allows for much faster operations. Currently the following curves are supported:

    | Curve           | Encryption | Signature | NodeCrypto | WebCrypto | Constant-Time     |
    |:---------------:|:----------:|:---------:|:----------:|:---------:|:-----------------:|
    | curve25519      | ECDH       | N/A       | No         | No        | Algorithmically** |
    | ed25519         | N/A        | EdDSA     | No         | No        | Algorithmically** |
    | p256            | ECDH       | ECDSA     | Yes*       | Yes*      | If native***      |
    | p384            | ECDH       | ECDSA     | Yes*       | Yes*      | If native***      |
    | p521            | ECDH       | ECDSA     | Yes*       | Yes*      | If native***      |
    | brainpoolP256r1 | ECDH       | ECDSA     | Yes*       | No        | If native***      |
    | brainpoolP384r1 | ECDH       | ECDSA     | Yes*       | No        | If native***      |
    | brainpoolP512r1 | ECDH       | ECDSA     | Yes*       | No        | If native***      |
    | secp256k1       | ECDH       | ECDSA     | Yes*       | No        | If native***      |

   \* when available  
   \** the curve25519 and ed25519 implementations are algorithmically constant-time, but may not be constant-time after optimizations of the JavaScript compiler  
   \*** these curves are only constant-time if the underlying native implementation is available and constant-time

* Version 2.x of the library has been built from the ground up with Uint8Arrays. This allows for much better performance and memory usage than strings.

* If the user's browser supports [native WebCrypto](https://caniuse.com/#feat=cryptography) via the `window.crypto.subtle` API, this will be used. Under Node.js the native [crypto module](https://nodejs.org/api/crypto.html#crypto_crypto) is used.

* The library implements the [IETF proposal](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-10) for authenticated encryption using native AES-EAX, OCB, or GCM. This makes symmetric encryption up to 30x faster on supported platforms. Since the specification has not been finalized and other OpenPGP implementations haven't adopted it yet, the feature is currently behind a flag. **Note: activating this setting can break compatibility with other OpenPGP implementations, and also with future versions of OpenPGP.js. Don't use it with messages you want to store on disk or in a database.** You can enable it by setting `openpgp.config.aeadProtect = true`.

  You can change the AEAD mode by setting one of the following options:

  ```
  openpgp.config.aeadMode = openpgp.enums.aead.eax // Default, native
  openpgp.config.aeadMode = openpgp.enums.aead.ocb // Non-native
  openpgp.config.aeadMode = openpgp.enums.aead.experimentalGcm // **Non-standard**, fastest
  ```

* For environments that don't provide native crypto, the library falls back to [asm.js](https://caniuse.com/#feat=asmjs) implementations of AES, SHA-1, and SHA-256.


### Getting started

#### Node.js

Install OpenPGP.js using npm and save it in your dependencies:

```sh
npm install --save openpgp
```

And import it as a CommonJS module:

```js
const openpgp = require('openpgp');
```

Or as an ES6 module, from an .mjs file:

```js
import * as openpgp from 'openpgp';
```

#### Browser (webpack)

Install OpenPGP.js using npm and save it in your devDependencies:

```sh
npm install --save-dev openpgp
```

And import it as an ES6 module:

```js
import * as openpgp from 'openpgp';
```

You can also only import the functions you need, as follows:

```js
import { readMessage, decrypt } from 'openpgp';
```

Or, if you want to use the lightweight build (which is smaller, and lazily loads non-default curves on demand):

```js
import * as openpgp from 'openpgp/lightweight';
```

To test whether the lazy loading works, try to generate a key with a non-standard curve:

```js
import { generateKey } from 'openpgp/lightweight';
await generateKey({ curve: 'brainpoolP512r1',  userIds: [{ name: 'Test', email: 'test@test.com' }] });
```

For more examples of how to generate a key, see [Generate new key pair](#generate-new-key-pair). It is recommended to use `curve25519` instead of `brainpoolP512r1` by default.


#### Browser (plain files)

Grab `openpgp.min.js` from [unpkg.com/openpgp/dist](https://unpkg.com/openpgp/dist/), and load it in a script tag:

```html
<script src="openpgp.min.js"></script>
```

Or, to load OpenPGP.js as an ES6 module, grab `openpgp.min.mjs` from [unpkg.com/openpgp/dist](https://unpkg.com/openpgp/dist/), and import it as follows:

```html
<script type="module">
import * as openpgp from './openpgp.min.mjs';
</script>
```

To offload cryptographic operations off the main thread, you can implement a Web Worker in your application and load OpenPGP.js from there. For an example Worker implementation, see `test/worker/worker_example.js`.

### Examples

Here are some examples of how to use OpenPGP.js v5. For more elaborate examples and working code, please check out the [public API unit tests](https://github.com/openpgpjs/openpgpjs/blob/master/test/general/openpgp.js). If you're upgrading from v4 it might help to check out the [changelog](https://github.com/openpgpjs/openpgpjs/wiki/V5-Changelog) and [documentation](https://github.com/openpgpjs/openpgpjs#documentation).

#### Encrypt and decrypt *Uint8Array* data with a password

Encryption will use the algorithm specified in config.encryptionCipher (defaults to aes256), and decryption will use the algorithm used for encryption.

```js
(async () => {
    const message = openpgp.Message.fromBinary(new Uint8Array([0x01, 0x01, 0x01]));
    const encrypted = await openpgp.encrypt({
        message, // input as Message object
        passwords: ['secret stuff'], // multiple passwords possible
        armor: false // don't ASCII armor (for Uint8Array output)
    });
    console.log(encrypted); // Uint8Array

    const encryptedMessage = await openpgp.readMessage({
        binaryMessage: encrypted // parse encrypted bytes
    });
    const { data: decrypted } = await openpgp.decrypt({
        message: encryptedMessage,
        passwords: ['secret stuff'], // decrypt with password
        format: 'binary' // output as Uint8Array
    });
    console.log(decrypted); // Uint8Array([0x01, 0x01, 0x01])
})();
```

#### Encrypt and decrypt *String* data with PGP keys

Encryption will use the algorithm preferred by the public key (defaults to aes256 for keys generated in OpenPGP.js), and decryption will use the algorithm used for encryption.

```js
const openpgp = require('openpgp'); // use as CommonJS, AMD, ES6 module or via window.openpgp

(async () => {
    // put keys in backtick (``) to avoid errors caused by spaces or tabs
    const publicKeyArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`;
    const privateKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----`; // encrypted private key
    const passphrase = `yourPassphrase`; // what the private key is encrypted with

    const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });

    const privateKey = await openpgp.readKey({ armoredKey: privateKeyArmored });
    await privateKey.decrypt(passphrase);

    const encrypted = await openpgp.encrypt({
        message: openpgp.Message.fromText('Hello, World!'), // input as Message object
        publicKeys: publicKey, // for encryption
        privateKeys: privateKey // for signing (optional)
    });
    console.log(encrypted); // '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'

    const message = await openpgp.readMessage({
        armoredMessage: encrypted // parse armored message
    });
    const { data: decrypted } = await openpgp.decrypt({
        message,
        publicKeys: publicKey, // for verification (optional)
        privateKeys: privateKey // for decryption
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

    const publicKeys = await Promise.all(publicKeysArmored.map(armoredKey => openpgp.readKey({ armoredKey })));

    const privateKey = await openpgp.readKey({ armoredKey: privateKeyArmored });
    await privateKey.decrypt(passphrase)

    const message = openpgp.Message.fromText(message);
    const encrypted = await openpgp.encrypt({
        message:, // input as Message object
        publicKeys, // for encryption
        privateKeys: privateKey // for signing (optional)
    });
    console.log(encrypted); // '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'
})();
```

#### Encrypt with compression

By default, `encrypt` will not use any compression. It's possible to override that behavior in two ways:

Either set the `compression` parameter in the options object when calling `encrypt`.

```js
(async () => {
    const message = openpgp.Message.fromBinary(new Uint8Array([0x01, 0x02, 0x03])); // or .fromText('string')
    const encrypted = await openpgp.encrypt({
        message,
        passwords: ['secret stuff'], // multiple passwords possible
        compression: openpgp.enums.compression.zip // compress the data with zip
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
    const readableStream = new openpgp.stream.ReadableStream({
        start(controller) {
            controller.enqueue(new Uint8Array([0x01, 0x02, 0x03]));
            controller.close();
        }
    });

    const message = openpgp.Message.fromBinary(readableStream);
    const encrypted = await openpgp.encrypt({
        message, // input as Message object
        passwords: ['secret stuff'], // multiple passwords possible
        armor: false // don't ASCII armor (for Uint8Array output)
    });
    console.log(encrypted); // raw encrypted packets as ReadableStream<Uint8Array>

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

    const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });

    const privateKey = await openpgp.readKey({ armoredKey: privateKeyArmored });
    await privateKey.decrypt(passphrase);

    const readableStream = new openpgp.stream.ReadableStream({
        start(controller) {
            controller.enqueue('Hello, world!');
            controller.close();
        }
    });

    const encrypted = await openpgp.encrypt({
        message: openpgp.Message.fromText(readableStream), // input as Message object
        publicKeys: publicKey, // for encryption
        privateKeys: privateKey // for signing (optional)
    });
    console.log(encrypted); // ReadableStream containing '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'

    const message = await openpgp.readMessage({
        armoredMessage: encrypted // parse armored message
    });
    const decrypted = await openpgp.decrypt({
        message,
        publicKeys: publicKey, // for verification (optional)
        privateKeys: privateKey // for decryption
    });
    const plaintext = await openpgp.stream.readToEnd(decrypted.data);
    console.log(plaintext); // 'Hello, World!'
})();
```


#### Generate new key pair

ECC keys (smaller and faster to generate):

Possible values for `curve` are: `curve25519`, `ed25519`, `p256`, `p384`, `p521`,
`brainpoolP256r1`, `brainpoolP384r1`, `brainpoolP512r1`, and `secp256k1`.
Note that both the `curve25519` and `ed25519` options generate a primary key for signing using Ed25519
and a subkey for encryption using Curve25519.

```js
(async () => {
    const { privateKeyArmored, publicKeyArmored, revocationCertificate } = await openpgp.generateKey({
        type: 'ecc', // Type of the key, defaults to ECC
        curve: 'curve25519', // ECC curve name, defaults to curve25519
        userIds: [{ name: 'Jon Smith', email: 'jon@example.com' }], // you can pass multiple user IDs
        passphrase: 'super long and hard to guess secret' // protects the private key
    });

    console.log(privateKeyArmored);     // '-----BEGIN PGP PRIVATE KEY BLOCK ... '
    console.log(publicKeyArmored);      // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
    console.log(revocationCertificate); // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
})();
```

RSA keys (increased compatibility):

```js
(async () => {
    const key = await openpgp.generateKey({
        type: 'rsa', // Type of the key
        rsaBits: 4096, // RSA key size (defaults to 4096 bits)
        userIds: [{ name: 'Jon Smith', email: 'jon@example.com' }], // you can pass multiple user IDs
        passphrase: 'super long and hard to guess secret' // protects the private key
    });
})();
```

#### Revoke a key

Using a revocation certificate:
```js
(async () => {
    const { publicKeyArmored: revokedKeyArmored } = await openpgp.revokeKey({
        key: await openpgp.readKey({ armoredKey: publicKeyArmored }),
        revocationCertificate
    });
    console.log(revokedKeyArmored); // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
})();
```

Using the private key:
```js
(async () => {
    const { publicKeyArmored, publicKey } = await openpgp.revokeKey({
        key: await openpgp.readKey({ armoredKey: privateKeyArmored })
    });
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

    const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });

    const privateKey = await openpgp.readKey({ armoredKey: privateKeyArmored });
    await privateKey.decrypt(passphrase);

    const unsignedMessage = openpgp.CleartextMessage.fromText('Hello, World!');
    const cleartextMessage = await openpgp.sign({
        message: unsignedMessage, // CleartextMessage or Message object
        privateKeys: privateKey // for signing
    });
    console.log(cleartextMessage); // '-----BEGIN PGP SIGNED MESSAGE ... END PGP SIGNATURE-----'

    const signedMessage = await openpgp.readCleartextMessage({
        cleartextMessage // parse armored message
    });
    const verified = await openpgp.verify({
        message: signedMessage,
        publicKeys: publicKey // for verification
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

    const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });

    const privateKey = await openpgp.readKey({ armoredKey: privateKeyArmored });
    await privateKey.decrypt(passphrase);

    const cleartextMessage = openpgp.CleartextMessage.fromText('Hello, World!');
    const detachedSignature = await openpgp.sign({
        message: cleartextMessage, // CleartextMessage or Message object
        privateKeys: privateKey, // for signing
        detached: true
    });
    console.log(detachedSignature);

    const signature = await openpgp.readSignature({
        armoredSignature: detachedSignature // parse detached signature
    });
    const verified = await openpgp.verify({
        message: cleartextMessage, // CleartextMessage or Message object
        signature,
        publicKeys: publicKey // for verification
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
    var readableStream = new openpgp.stream.ReadableStream({
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

    const privateKey = await openpgp.readKey({ armoredKey: privateKeyArmored });
    await privateKey.decrypt(passphrase);

    const message = openpgp.Message.fromBinary(readableStream); // or .fromText(readableStream: ReadableStream<String>)
    const signatureArmored = await openpgp.sign({
        message,
        privateKeys: privateKey // for signing
    });
    console.log(signatureArmored); // ReadableStream containing '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'

    const verified = await openpgp.verify({
        message: await openpgp.readMessage({ armoredMessage: signatureArmored }), // parse armored signature
        publicKeys: await openpgp.readKey({ armoredKey: publicKeyArmored })   // for verification
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

The full documentation is available at [openpgpjs.org](https://openpgpjs.org/openpgpjs/).

### Security Audit

To date the OpenPGP.js code base has undergone two complete security audits from [Cure53](https://cure53.de). The first audit's report has been published [here](https://github.com/openpgpjs/openpgpjs/wiki/Cure53-security-audit).

### Security recommendations

It should be noted that js crypto apps deployed via regular web hosting (a.k.a. [**host-based security**](https://www.schneier.com/blog/archives/2012/08/cryptocat.html)) provide users with less security than installable apps with auditable static versions. Installable apps can be deployed as a [Firefox](https://developer.mozilla.org/en-US/Marketplace/Options/Packaged_apps) or [Chrome](https://developer.chrome.com/apps/about_apps.html) packaged app. These apps are basically signed zip files and their runtimes typically enforce a strict [Content Security Policy (CSP)](https://www.html5rocks.com/en/tutorials/security/content-security-policy/) to protect users against [XSS](https://en.wikipedia.org/wiki/Cross-site_scripting). This [blogpost](https://tankredhase.com/2014/04/13/heartbleed-and-javascript-crypto/) explains the trust model of the web quite well.

It is also recommended to set a strong passphrase that protects the user's private key on disk.

### Development

To create your own build of the library, just run the following command after cloning the git repo. This will download all dependencies, run the tests and create a minified bundle under `dist/openpgp.min.js` to use in your project:

    npm install && npm test

For debugging browser errors, you can run `npm start` and open [`http://localhost:8080/test/unittests.html`](http://localhost:8080/test/unittests.html) in a browser, or run the following command:

    npm run browsertest

### How do I get involved?

You want to help, great! It's probably best to send us a message on [Gitter](https://gitter.im/openpgpjs/openpgpjs) before you start your undertaking, to make sure nobody else is working on it, and so we can discuss the best course of action. Other than that, just go ahead and fork our repo, make your changes and send us a pull request! :)

### License

[GNU Lesser General Public License](https://www.gnu.org/licenses/lgpl-3.0.en.html) (3.0 or any later version). Please take a look at the [LICENSE](LICENSE) file for more information.
