/**
 * High level crypto api that handles all calls to OpenPGP.js
 */
define(function(require) {
    'use strict';

    var openpgp = require('openpgp').openpgp,
        util = require('openpgp').util;

    var PGP = function() {
        openpgp.init();
    };

    /**
     * Generate a key pair for the user
     */
    PGP.prototype.generateKeys = function(options, callback) {
        var keys, userId;

        if (!util.emailRegEx.test(options.emailAddress) || !options.keySize || typeof options.passphrase !== 'string') {
            callback({
                errMsg: 'Crypto init failed. Not all options set!'
            });
            return;
        }

        // generate keypair (keytype 1=RSA)
        try {
            userId = 'Whiteout User <' + options.emailAddress + '>';
            keys = openpgp.generate_key_pair(1, options.keySize, userId, options.passphrase);
        } catch (e) {
            callback({
                errMsg: 'Keygeneration failed!',
                err: e
            });
            return;
        }

        callback(null, {
            keyId: util.hexstrdump(keys.privateKey.getKeyId()).toUpperCase(),
            privateKeyArmored: keys.privateKeyArmored,
            publicKeyArmored: keys.publicKeyArmored
        });
    };

    /**
     * Import the user's key pair
     */
    PGP.prototype.importKeys = function(options, callback) {
        var publicKey, privateKey;

        // check passphrase
        if (typeof options.passphrase !== 'string' || !options.privateKeyArmored || !options.publicKeyArmored) {
            callback({
                errMsg: 'Importing keys failed. Not all options set!'
            });
            return;
        }

        // clear any keypair already in the keychain
        openpgp.keyring.init();
        // unlock and import private key 
        if (!openpgp.keyring.importPrivateKey(options.privateKeyArmored, options.passphrase)) {
            openpgp.keyring.init();
            callback({
                errMsg: 'Incorrect passphrase!'
            });
            return;
        }
        // import public key
        openpgp.keyring.importPublicKey(options.publicKeyArmored);

        // check if keys have the same id
        privateKey = openpgp.keyring.exportPrivateKey(0);
        publicKey = openpgp.keyring.getPublicKeysForKeyId(privateKey.keyId)[0];
        if (!privateKey || !privateKey.armored || !publicKey || !publicKey.armored || privateKey.keyId !== publicKey.keyId) {
            // reset keyring
            openpgp.keyring.init();
            callback({
                errMsg: 'Key IDs dont match!'
            });
            return;
        }

        callback();
    };

    /**
     * Export the user's key pair
     */
    PGP.prototype.exportKeys = function(callback) {
        var publicKey, privateKey;

        privateKey = openpgp.keyring.exportPrivateKey(0);
        if (privateKey && privateKey.keyId) {
            publicKey = openpgp.keyring.getPublicKeysForKeyId(privateKey.keyId)[0];
        }

        if (!privateKey || !privateKey.keyId || !privateKey.armored || !publicKey || !publicKey.armored) {
            callback({
                errMsg: 'Could not export keys!'
            });
            return;
        }

        callback(null, {
            keyId: util.hexstrdump(privateKey.keyId).toUpperCase(),
            privateKeyArmored: privateKey.armored,
            publicKeyArmored: publicKey.armored
        });
    };

    /**
     * Encrypt and sign a pgp message for a list of receivers
     */
    PGP.prototype.encrypt = function(plaintext, receiverKeys, callback) {
        var ct, i,
            privateKey = openpgp.keyring.exportPrivateKey(0).obj;

        for (i = 0; i < receiverKeys.length; i++) {
            receiverKeys[i] = openpgp.read_publicKey(receiverKeys[i])[0];
        }

        ct = openpgp.write_signed_and_encrypted_message(privateKey, receiverKeys, plaintext);

        callback(null, ct);
    };

    /**
     * Decrypt and verify a pgp message for a single sender
     */
    PGP.prototype.decrypt = function(ciphertext, senderKey, callback) {
        var privateKey = openpgp.keyring.exportPrivateKey(0).obj;
        senderKey = openpgp.read_publicKey(senderKey)[0];

        var msg = openpgp.read_message(ciphertext)[0];
        var keymat = null;
        var sesskey = null;

        // Find the private (sub)key for the session key of the message
        for (var i = 0; i < msg.sessionKeys.length; i++) {
            if (privateKey.privateKeyPacket.publicKey.getKeyId() === msg.sessionKeys[i].keyId.bytes) {
                keymat = {
                    key: privateKey,
                    keymaterial: privateKey.privateKeyPacket
                };
                sesskey = msg.sessionKeys[i];
                break;
            }
            for (var j = 0; j < privateKey.subKeys.length; j++) {
                if (privateKey.subKeys[j].publicKey.getKeyId() === msg.sessionKeys[i].keyId.bytes) {
                    keymat = {
                        key: privateKey,
                        keymaterial: privateKey.subKeys[j]
                    };
                    sesskey = msg.sessionKeys[i];
                    break;
                }
            }
        }
        if (keymat !== null) {
            var decrypted = msg.decryptAndVerifySignature(keymat, sesskey, senderKey);
            callback(null, decrypted.text);

        } else {
            callback({
                errMsg: 'No private key found!'
            });
        }
    };

    return PGP;
});