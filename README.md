OpenPGP.js [![BrowserStack Status](https://automate.browserstack.com/badge.svg?badge_key=N1l2eHFOanVBMU9wYWxJM3ZnWERnc1lidkt5UkRqa3BralV3SWVhOGpGTT0tLVljSjE4Z3dzVmdiQjl6RWgxb2c3T2c9PQ==--5864052cd523f751b6b907d547ac9c4c5f88c8a3)](https://automate.browserstack.com/public-build/N1l2eHFOanVBMU9wYWxJM3ZnWERnc1lidkt5UkRqa3BralV3SWVhOGpGTT0tLVljSjE4Z3dzVmdiQjl6RWgxb2c3T2c9PQ==--5864052cd523f751b6b907d547ac9c4c5f88c8a3) [![Join the chat on Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/openpgpjs/openpgpjs?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
==========

[OpenPGP.js](https://openpgpjs.org/) is a JavaScript implementation of the OpenPGP protocol. It implements [RFC4880](https://tools.ietf.org/html/rfc4880) and parts of [RFC4880bis](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-10).

**Table of Contents**

- [OpenPGP.js](#openpgpjs)
    - [Platform Support](#platform-support)
    - [Performance](#performance)
    - [Getting started](#getting-started)
        - [Node.js](#nodejs)
        - [Deno (experimental)](#deno-experimental)
        - [Browser (webpack)](#browser-webpack)
        - [Browser (plain files)](#browser-plain-files)
    - [Examples](#examples)
        - [Encrypt and decrypt *Uint8Array* data with a password](#encrypt-and-decrypt-uint8array-data-with-a-password)
        - [Encrypt and decrypt *String* data with PGP keys](#encrypt-and-decrypt-string-data-with-pgp-keys)
        - [Encrypt symmetrically with compression](#encrypt-symmetrically-with-compression)
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

* The library implements the [RFC4880bis proposal](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-10) for authenticated encryption using native AES-EAX, OCB, or GCM. This makes symmetric encryption up to 30x faster on supported platforms. Since the specification has not been finalized and other OpenPGP implementations haven't adopted it yet, the feature is currently behind a flag. **Note: activating this setting can break compatibility with other OpenPGP implementations, and also with future versions of OpenPGP.js. Don't use it with messages you want to store on disk or in a database.** You can enable it by setting `openpgp.config.aeadProtect = true`.

  You can change the AEAD mode by setting one of the following options:

  ```
  openpgp.config.preferredAEADAlgorithm = openpgp.enums.aead.eax // Default, native
  openpgp.config.preferredAEADAlgorithm = openpgp.enums.aead.ocb // Non-native
  openpgp.config.preferredAEADAlgorithm = openpgp.enums.aead.experimentalGCM // **Non-standard**, fastest
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

#### Deno (experimental)

Import as an ES6 module, using /dist/openpgp.mjs.

```js
import * as openpgp from './openpgpjs/dist/openpgp.mjs';
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
await generateKey({ curve: 'brainpoolP512r1',  userIDs: [{ name: 'Test', email: 'test@test.com' }] });
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

#### TypeScript

Since TS is not fully integrated in the library, TS-only dependencies are currently listed as `devDependencies`, so to compile the project you’ll need to add `@openpgp/web-stream-tools` manually (NB: only versions below v0.12 are compatible with OpenPGP.js v5):

```sh
npm install --save-dev @openpgp/web-stream-tools@0.0.11-patch-0
```

If you notice missing or incorrect type definitions, feel free to open a PR.

### Examples

Here are some examples of how to use OpenPGP.js v5. For more elaborate examples and working code, please check out the [public API unit tests](https://github.com/openpgpjs/openpgpjs/blob/main/test/general/openpgp.js). If you're upgrading from v4 it might help to check out the [changelog](https://github.com/openpgpjs/openpgpjs/wiki/V5-Changelog) and [documentation](https://github.com/openpgpjs/openpgpjs#documentation).

#### Encrypt and decrypt *Uint8Array* data with a password

Encryption will use the algorithm specified in config.preferredSymmetricAlgorithm (defaults to aes256), and decryption will use the algorithm used for encryption.

```js
(async () => {
    const message = await openpgp.createMessage({ binary: new Uint8Array([0x01, 0x01, 0x01]) });
    const encrypted = await openpgp.encrypt({
        message, // input as Message object
        passwords: ['secret stuff'], // multiple passwords possible
        format: 'binary' // don't ASCII armor (for Uint8Array output)
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

Encryption will use the algorithm preferred by the public (encryption) key (defaults to aes256 for keys generated in OpenPGP.js), and decryption will use the algorithm used for encryption.

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

    const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
        passphrase
    });

    const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: 'Hello, World!' }), // input as Message object
        encryptionKeys: publicKey,
        signingKeys: privateKey // optional
    });
    console.log(encrypted); // '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'

    const message = await openpgp.readMessage({
        armoredMessage: encrypted // parse armored message
    });
    const { data: decrypted, signatures } = await openpgp.decrypt({
        message,
        verificationKeys: publicKey, // optional
        decryptionKeys: privateKey
    });
    console.log(decrypted); // 'Hello, World!'
    // check signature validity (signed messages only)
    try {
        await signatures[0].verified; // throws on invalid signature
        console.log('Signature is valid');
    } catch (e) {
        throw new Error('Signature could not be verified: ' + e.message);
    }
})();
```

Encrypt to multiple public keys:

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
    const plaintext = 'Hello, World!';

    const publicKeys = await Promise.all(publicKeysArmored.map(armoredKey => openpgp.readKey({ armoredKey })));

    const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: privateKeyArmored }),
        passphrase
    });

    const message = await openpgp.createMessage({ text: plaintext });
    const encrypted = await openpgp.encrypt({
        message, // input as Message object
        encryptionKeys: publicKeys,
        signingKeys: privateKey // optional
    });
    console.log(encrypted); // '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'
})();
```

If you expect an encrypted message to be signed with one of the public keys you have, and do not want to trust the decrypted data otherwise, you can pass the decryption option `expectSigned = true`, so that the decryption operation will fail if no valid signature is found:
```js
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

    const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
        passphrase
    });

    const encryptedAndSignedMessage = `-----BEGIN PGP MESSAGE-----
...
-----END PGP MESSAGE-----`;

    const message = await openpgp.readMessage({
        armoredMessage: encryptedAndSignedMessage // parse armored message
    });
    // decryption will fail if all signatures are invalid or missing
    const { data: decrypted, signatures } = await openpgp.decrypt({
        message,
        decryptionKeys: privateKey,
        expectSigned: true,
        verificationKeys: publicKey, // mandatory with expectSigned=true
    });
    console.log(decrypted); // 'Hello, World!'
})();
```

#### Encrypt symmetrically with compression

By default, `encrypt` will not use any compression when encrypting symmetrically only (i.e. when no `encryptionKeys` are given).
It's possible to change that behaviour by enabling compression through the config, either for the single encryption:

```js
(async () => {
    const message = await openpgp.createMessage({ binary: new Uint8Array([0x01, 0x02, 0x03]) }); // or createMessage({ text: 'string' })
    const encrypted = await openpgp.encrypt({
        message,
        passwords: ['secret stuff'], // multiple passwords possible
        config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib } // compress the data with zlib
    });
})();
```

or by changing the default global configuration:
```js
openpgp.config.preferredCompressionAlgorithm = openpgp.enums.compression.zlib
```

Where the value can be any of:
 * `openpgp.enums.compression.zip`
 * `openpgp.enums.compression.zlib`
 * `openpgp.enums.compression.uncompressed` (default)



#### Streaming encrypt *Uint8Array* data with a password

```js
(async () => {
    const readableStream = new ReadableStream({
        start(controller) {
            controller.enqueue(new Uint8Array([0x01, 0x02, 0x03]));
            controller.close();
        }
    });

    const message = await openpgp.createMessage({ binary: readableStream });
    const encrypted = await openpgp.encrypt({
        message, // input as Message object
        passwords: ['secret stuff'], // multiple passwords possible
        format: 'binary' // don't ASCII armor (for Uint8Array output)
    });
    console.log(encrypted); // raw encrypted packets as ReadableStream<Uint8Array>

    // Either pipe the above stream somewhere, pass it to another function,
    // or read it manually as follows:
    for await (const chunk of encrypted) {
        console.log('new chunk:', chunk); // Uint8Array
    }
})();
```

For more information on using ReadableStreams, see [the MDN Documentation on the
Streams API](https://developer.mozilla.org/en-US/docs/Web/API/Streams_API).

You can also pass a [Node.js `Readable`
stream](https://nodejs.org/api/stream.html#stream_class_stream_readable), in
which case OpenPGP.js will return a Node.js `Readable` stream as well, which you
can `.pipe()` to a `Writable` stream, for example.


#### Streaming encrypt and decrypt *String* data with PGP keys

```js
(async () => {
    const publicKeyArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`; // Public key
    const privateKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----`; // Encrypted private key
    const passphrase = `yourPassphrase`; // Password that private key is encrypted with

    const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });

    const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
        passphrase
    });

    const readableStream = new ReadableStream({
        start(controller) {
            controller.enqueue('Hello, world!');
            controller.close();
        }
    });

    const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: readableStream }), // input as Message object
        encryptionKeys: publicKey,
        signingKeys: privateKey // optional
    });
    console.log(encrypted); // ReadableStream containing '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'

    const message = await openpgp.readMessage({
        armoredMessage: encrypted // parse armored message
    });
    const decrypted = await openpgp.decrypt({
        message,
        verificationKeys: publicKey, // optional
        decryptionKeys: privateKey
    });
    const chunks = [];
    for await (const chunk of decrypted.data) {
        chunks.push(chunk);
    }
    const plaintext = chunks.join('');
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
    const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
        type: 'ecc', // Type of the key, defaults to ECC
        curve: 'curve25519', // ECC curve name, defaults to curve25519
        userIDs: [{ name: 'Jon Smith', email: 'jon@example.com' }], // you can pass multiple user IDs
        passphrase: 'super long and hard to guess secret', // protects the private key
        format: 'armored' // output key format, defaults to 'armored' (other options: 'binary' or 'object')
    });

    console.log(privateKey);     // '-----BEGIN PGP PRIVATE KEY BLOCK ... '
    console.log(publicKey);      // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
    console.log(revocationCertificate); // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
})();
```

RSA keys (increased compatibility):

```js
(async () => {
    const { privateKey, publicKey } = await openpgp.generateKey({
        type: 'rsa', // Type of the key
        rsaBits: 4096, // RSA key size (defaults to 4096 bits)
        userIDs: [{ name: 'Jon Smith', email: 'jon@example.com' }], // you can pass multiple user IDs
        passphrase: 'super long and hard to guess secret' // protects the private key
    });
})();
```

#### Revoke a key

Using a revocation certificate:
```js
(async () => {
    const { publicKey: revokedKeyArmored } = await openpgp.revokeKey({
        key: await openpgp.readKey({ armoredKey: publicKeyArmored }),
        revocationCertificate,
        format: 'armored' // output armored keys
    });
    console.log(revokedKeyArmored); // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
})();
```

Using the private key:
```js
(async () => {
    const { publicKey: revokedKeyArmored } = await openpgp.revokeKey({
        key: await openpgp.readKey({ armoredKey: privateKeyArmored }),
        format: 'armored' // output armored keys
    });
    console.log(revokedKeyArmored); // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
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

    const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
        passphrase
    });

    const unsignedMessage = await openpgp.createCleartextMessage({ text: 'Hello, World!' });
    const cleartextMessage = await openpgp.sign({
        message: unsignedMessage, // CleartextMessage or Message object
        signingKeys: privateKey
    });
    console.log(cleartextMessage); // '-----BEGIN PGP SIGNED MESSAGE ... END PGP SIGNATURE-----'

    const signedMessage = await openpgp.readCleartextMessage({
        cleartextMessage // parse armored message
    });
    const verificationResult = await openpgp.verify({
        message: signedMessage,
        verificationKeys: publicKey
    });
    const { verified, keyID } = verificationResult.signatures[0];
    try {
        await verified; // throws on invalid signature
        console.log('Signed by key id ' + keyID.toHex());
    } catch (e) {
        throw new Error('Signature could not be verified: ' + e.message);
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

    const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
        passphrase
    });

    const message = await openpgp.createMessage({ text: 'Hello, World!' });
    const detachedSignature = await openpgp.sign({
        message, // Message object
        signingKeys: privateKey,
        detached: true
    });
    console.log(detachedSignature);

    const signature = await openpgp.readSignature({
        armoredSignature: detachedSignature // parse detached signature
    });
    const verificationResult = await openpgp.verify({
        message, // Message object
        signature,
        verificationKeys: publicKey
    });
    const { verified, keyID } = verificationResult.signatures[0];
    try {
        await verified; // throws on invalid signature
        console.log('Signed by key id ' + keyID.toHex());
    } catch (e) {
        throw new Error('Signature could not be verified: ' + e.message);
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

    const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
        passphrase
    });

    const message = await openpgp.createMessage({ binary: readableStream }); // or createMessage({ text: ReadableStream<String> })
    const signatureArmored = await openpgp.sign({
        message,
        signingKeys: privateKey
    });
    console.log(signatureArmored); // ReadableStream containing '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'

    const verificationResult = await openpgp.verify({
        message: await openpgp.readMessage({ armoredMessage: signatureArmored }), // parse armored signature
        verificationKeys: await openpgp.readKey({ armoredKey: publicKeyArmored })
    });

    for await (const chunk of verificationResult.data) {}
    // Note: you *have* to read `verificationResult.data` in some way or other,
    // even if you don't need it, as that is what triggers the
    // verification of the data.

    try {
        await verificationResult.signatures[0].verified; // throws on invalid signature
        console.log('Signed by key id ' + verificationResult.signatures[0].keyID.toHex());
     } catch (e) {
        throw new Error('Signature could not be verified: ' + e.message);
    }
})();
```

### Documentation

The full documentation is available at [openpgpjs.org](https://docs.openpgpjs.org/).

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
