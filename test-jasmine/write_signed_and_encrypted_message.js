describe("write_signed_and_encrypted_message", function () {

    openpgp.init();


    function test(passphrase, userid, message) {

        // generate keys
        var key = openpgp.generate_key_pair(1, 512, userid, passphrase),
            priv_key = key.privateKey,
            pub_key = openpgp.read_publicKey(key.publicKeyArmored);

        // check if password can decrypt private key
        var s = priv_key.decryptSecretMPIs(passphrase);
        expect(s).toBeTruthy(s); // Generating a decryptable private key failed

        // execute method under test
        var encrypted = openpgp.write_signed_and_encrypted_message(priv_key, pub_key, message);

        // read back encrypted message
        var msg = openpgp.read_message(encrypted);
        var keymat = null;
        var sesskey = null;

        // Find the private (sub)key for the session key of the message
        for (var i = 0; i < msg[0].sessionKeys.length; i++) {
            if (priv_key.privateKeyPacket.publicKey.getKeyId() === msg[0].sessionKeys[i].keyId.bytes) {
                keymat = { key: priv_key, keymaterial: priv_key.privateKeyPacket };
                sesskey = msg[0].sessionKeys[i];
                break;
            }
            for (var j = 0; j < priv_key.subKeys.length; j++) {
                if (priv_key.subKeys[j].publicKey.getKeyId() === msg[0].sessionKeys[i].keyId.bytes) {
                    keymat = { key: priv_key, keymaterial: priv_key.subKeys[j] };
                    sesskey = msg[0].sessionKeys[i];
                    break;
                }
            }
        }

        expect(keymat).not.toBeNull(); // no private key found

        var decrypted = "";

        // decrypt private key with passphrase
        var d = keymat.keymaterial.decryptSecretMPIs(passphrase);
        expect(d).toBeTruthy(); // Password for secret key was incorrect!

        // decrypt encrypted message
        decrypted = msg[0].decrypt(keymat, sesskey);

        // test for equality
        expect(decrypted).toBe(message);
    }


    it("encrypts and signs a simple 'hello world' message", function () {
        test('password', 'Test McTestington <test@example.com>', 'hello world');
    });


    it("encrypts and signs an empty message", function () {
        test('password', 'Test McTestington <test@example.com>', '');
    });

    it("encrypts and signs a long message", function () {
        test('password', 'Test McTestington <test@example.com>', 'this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message this is a long message ');
    });

    it("encrypts and signs special characters", function () {
        test('●●●●', '♔♔♔♔ <test@example.com>', 'łäóć');
    });

    it("encrypts and signs a message with carriage returns and newlines", function () {
        test('password', 'Test McTestington <test@example.com>', 'another test\r\nwith newlines\r\n');
    });


});