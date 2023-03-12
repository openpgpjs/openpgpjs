OpenPGP.js for Postman
==========

Forked of [OpenPGP.js](https://openpgpjs.org/) a JavaScript implementation of the OpenPGP protocol. This version modified to support usage inside Postman Runtime.

### Getting started

#### Installation

To install on postman, create GET request with URL:

```js
https://raw.githubusercontent.com/maasdi/openpgpjs/postman/lib/openpgp.min.js
```

and then add to Test script

```js
pm.test("status code should be 200", function () {
    pm.response.to.have.status(200)
    pm.globals.set("openpgp", responseBody)
});
```

Next.. when you want to use it: 

```js
eval(pm.globals.get("openpgp"));
```

### Examples

Here are some examples of how to use OpenPGP.js v5. For more elaborate examples and working code, please check out the [public API unit tests](https://github.com/openpgpjs/openpgpjs/blob/main/test/general/openpgp.js). If you're upgrading from v4 it might help to check out the [changelog](https://github.com/openpgpjs/openpgpjs/wiki/V5-Changelog) and [documentation](https://github.com/openpgpjs/openpgpjs#documentation).

#### Encrypt and decrypt *Uint8Array* data with a password

Encryption will use the algorithm specified in config.preferredSymmetricAlgorithm (defaults to aes256), and decryption will use the algorithm used for encryption.

```js
eval(pm.globals.get("openpgp"));
(async () => {
    try {
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
    } catch (e) {
        console.log(e);
    }
})();
```

#### Encrypt and decrypt *String* data with PGP keys

Encryption will use the algorithm preferred by the public (encryption) key (defaults to aes256 for keys generated in OpenPGP.js), and decryption will use the algorithm used for encryption.

```js
eval(pm.globals.get("openpgp"));

(async () => {
    // put keys in backtick (``) to avoid errors caused by spaces or tabs
    const publicKeyArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`;
    const privateKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----`; // encrypted private key
    const passphrase = `yourPassphrase`; // what the private key is encrypted with

    try {
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

        await signatures[0].verified; // throws on invalid signature
        console.log('Signature is valid');
    } catch (e) {
        throw new Error('Signature could not be verified: ' + e.message);
    }
})();
```

Encrypt to multiple public keys:

```js
eval(pm.globals.get("openpgp"));

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

    try {
        const publicKeys = [];
        for (let armoredKey of publicKeysArmored) {
            publicKeys.push(await openpgp.readKey({ armoredKey }));
        }

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
    } catch (e) {
        console.log(e);
    }
})();
```

#### Encrypt symmetrically with compression

By default, `encrypt` will not use any compression when encrypting symmetrically only (i.e. when no `encryptionKeys` are given).
It's possible to change that behaviour by enabling compression through the config, either for the single encryption:

```js
eval(pm.globals.get("openpgp"));

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

#### Sign and verify cleartext messages

```js
eval(pm.globals.get("openpgp"));

(async () => {
    const publicKeyArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`;
    const privateKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----`; // encrypted private key
    const passphrase = `yourPassphrase`; // what the private key is encrypted with

    try {
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
        
        await verified; // throws on invalid signature
        console.log('Signed by key id ' + keyID.toHex());
    } catch (e) {
        throw new Error('Signature could not be verified: ' + e.message);
    }
})();
```

#### Create and verify *detached* signatures

```js
eval(pm.globals.get("openpgp"));

(async () => {
    const publicKeyArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`;
    const privateKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----`; // encrypted private key
    const passphrase = `yourPassphrase`; // what the private key is encrypted with

    try {
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
        
        await verified; // throws on invalid signature
        console.log('Signed by key id ' + keyID.toHex());
    } catch (e) {
        throw new Error('Signature could not be verified: ' + e.message);
    }
})();
```

### Documentation

The full documentation is available at [openpgpjs.org](https://docs.openpgpjs.org/).

### License

[GNU Lesser General Public License](https://www.gnu.org/licenses/lgpl-3.0.en.html) (3.0 or any later version). Please take a look at the [LICENSE](LICENSE) file for more information.
