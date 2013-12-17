var openpgp = require('openpgp'),
    keyring = require('keyring');

'use strict';

var expect = chai.expect;

describe('Openpgp integration tests', function() {
    var user = 'test@t-online.de',
        passphrase = 'asdf',
        keySize = 512,
        keyId = 'F6F60E9B42CDFF4C',
        pubkey = '-----BEGIN PGP PUBLIC KEY BLOCK-----\n' +
            'Version: OpenPGP.js v.1.20131011\n' +
            'Comment: http://openpgpjs.org\n' +
            '\n' +
            'xk0EUlhMvAEB/2MZtCUOAYvyLFjDp3OBMGn3Ev8FwjzyPbIF0JUw+L7y2XR5\n' +
            'RVGvbK88unV3cU/1tOYdNsXI6pSp/Ztjyv7vbBUAEQEAAc0pV2hpdGVvdXQg\n' +
            'VXNlciA8d2hpdGVvdXQudGVzdEB0LW9ubGluZS5kZT7CXAQQAQgAEAUCUlhM\n' +
            'vQkQ9vYOm0LN/0wAAAW4Af9C+kYW1AvNWmivdtr0M0iYCUjM9DNOQH1fcvXq\n' +
            'IiN602mWrkd8jcEzLsW5IUNzVPLhrFIuKyBDTpLnC07Loce1\n' +
            '=6XMW\n' +
            '-----END PGP PUBLIC KEY BLOCK-----',
        privkey = '-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
            'Version: OpenPGP.js v.1.20131011\n' +
            'Comment: http://openpgpjs.org\n' +
            '\n' +
            'xcBeBFJYTLwBAf9jGbQlDgGL8ixYw6dzgTBp9xL/BcI88j2yBdCVMPi+8tl0\n' +
            'eUVRr2yvPLp1d3FP9bTmHTbFyOqUqf2bY8r+72wVABEBAAH+AwMIhNB4ivtv\n' +
            'Y2xg6VeMcjjHxZayESHACV+nQx5Tx6ev6xzIF1Qh72fNPDppLhFSFOuTTMsU\n' +
            'kTN4c+BVYt29spH+cA1jcDAxQ2ULrNAXo+hheOqhpedTs8aCbcLFkJAS16hk\n' +
            'YSk4OnJgp/z24rVju1SHRSFbgundPzmNgXeX9e8IkviGhhQ11Wc5YwVkx03t\n' +
            'Z3MdDMF0jyhopbPIoBdyJB0dhvBh98w3JmwpYh9wjUA9MBHD1tvHpRmSZ3BM\n' +
            'UCmATn2ZLWBRWiYqFbgDnL1GM80pV2hpdGVvdXQgVXNlciA8d2hpdGVvdXQu\n' +
            'dGVzdEB0LW9ubGluZS5kZT7CXAQQAQgAEAUCUlhMvQkQ9vYOm0LN/0wAAAW4\n' +
            'Af9C+kYW1AvNWmivdtr0M0iYCUjM9DNOQH1fcvXqIiN602mWrkd8jcEzLsW5\n' +
            'IUNzVPLhrFIuKyBDTpLnC07Loce1\n' +
            '=ULta\n' +
            '-----END PGP PRIVATE KEY BLOCK-----';

    describe('Generate key pair', function() {
        it('should work', function(done) {
            // generate keypair (keytype 1=RSA)
            var errMsg, err;
            var keys = null;

            try {
                var userId = 'Whiteout User <' + user + '>';
                var keys = openpgp.generateKeyPair(1, keySize, userId, passphrase);
                var keyId = openpgp.util.hexstrdump(keys.key.getKeyPacket().getKeyId()).toUpperCase();
                expect(keyId).to.exist;
                expect(keys.privateKeyArmored).to.exist;
                expect(keys.publicKeyArmored).to.exist;
            } catch (e) {
                errMsg = 'Keygeneration failed!';
                err = e;
            }

            expect(err).to.not.exist;
            done();
        });
    });

    describe('Keyring', function() {
        describe('Import key pair', function() {
            it('should work', function(done) {
                // clear any keypair already in the keychain
                keyring.init();
                keyring.importKey(privkey);
                keyring.importKey(pubkey);
                done();
            });
        });
        describe('Retrieve keys', function() {
            it('getPublicKeyForAddress() - unknown address', function(done) {
                var key = keyring.getPublicKeyForAddress('nobody@example.com');
                expect(key).to.be.empty;
                done();
            });
            it('getPublicKeyForAddress() - valid address', function(done) {
                var key = keyring.getPublicKeyForAddress(user);
                expect(key).to.exist;
                done();
            });
            it('getPrivateKeyForAddress() - unknown address', function(done) {
                var key = keyring.getPrivateKeyForAddress('nobody@example.com');
                expect(key).to.be.empty;
                done();
            });
            it('getPrivateKeyForAddress() - valid address', function(done) {
                var key = keyring.getPrivateKeyForAddress(user);
                expect(key).to.exist;
                done();
            });
            it('getKeysForKeyId() - unknown id', function(done) {
                var keys = keyring.getKeysForKeyId('000102030405060708');
                expect(keys).to.be.empty;
                done();
            });
            it('getKeysForKeyId() - valid id', function(done) {
                var keys = keyring.getKeysForKeyId(keyId.toLowerCase());
                expect(keys).to.exist.and.have.length(1);
                done();
            });
        });
    });

    describe('Encryption', function() {
        var message = 'asdfs\n\nThursday, Nov 21, 2013 7:38 PM asdf@example.com wrote:\n' +
                            '> asdf\n' +
                            '> \n' +
                            '> Thursday, Nov 21, 2013 7:32 PM asdf@example.com wrote:\n' +
                            '> > secret 3',
            ciphertext;

        describe('Encrypt and Sign', function() {
            it('should work', function(done) {
                var signkey = openpgp.key.readArmored(privkey).keys[0];
                expect(signkey).to.exist;
                var encryptkey = openpgp.key.readArmored(pubkey).keys[0];
                expect(encryptkey).to.exist;
                expect(signkey.decrypt(passphrase)).to.be.true;
                ciphertext = openpgp.signAndEncryptMessage([encryptkey], signkey, message);
                expect(ciphertext).to.exist;
                done();
            });
        });

        describe('Decrypt and Verify', function() {
            it('should work', function(done) {
                var decryptkey = openpgp.key.readArmored(privkey).keys[0];
                expect(decryptkey, 'decryptkey').to.exist;
                var verifykey = openpgp.key.readArmored(pubkey).keys[0];
                expect(verifykey, 'verifykey').to.exist;
                var pgpmsg = openpgp.message.readArmored(ciphertext);
                expect(pgpmsg, 'pgpmsg').to.exist;
                var keyids = pgpmsg.getEncryptionKeyIds();
                expect(keyids, 'keyids').to.exist;
                expect(decryptkey.decryptKeyPacket(keyids, passphrase), 'decryptKeyPacket()').to.be.true;
                var result = openpgp.decryptAndVerifyMessage(decryptkey, [verifykey], pgpmsg);
                expect(result, 'decryptAndVerifyMessage() result').to.exist;
                expect(result.text, 'decryptAndVerifyMessage() result.text').to.exist.and.equal(message);
                expect(result.signatures, 'decryptAndVerifyMessage() result.signatures').to.exist.and.not.be.empty;
                expect(result.signatures[0].valid, 'decryptAndVerifyMessage() result.signatures[0].valid').to.be.true;
                done();
            });
        });
    });

    describe('Verify clearsign from gpg', function() {
        describe('Verify V3 signature', function() {
            var v3_clearsign_msg = '-----BEGIN PGP SIGNED MESSAGE-----\r\n' +
                'Hash: SHA1\r\n' +
                '\r\n' +
                'This is a test message.\r\n' +
                '\r\n' +
                'This paragraph is separated form the next by a line of dashes.\r\n' +
                '\r\n' +
                '- --------------------------------------------------------------------------\r\n' +
                '\r\n' +
                'The next paragraph has a number of blank lines between this one and it.\r\n' +
                '\r\n' +
                '\r\n' +
                '\r\n' +
                '\r\n' +
                '\r\n' +
                '\r\n' +
                'This is the last paragraph.\r\n' +
                '\r\n' +
                '- --\r\n' +
                '\r\n' +
                'Joe Test\r\n' +
                '-----BEGIN PGP SIGNATURE-----\r\n' +
                'Version: GnuPG v1.4.15 (GNU/Linux)\r\n' +
                '\r\n' +
                'iQBVAwUBUp/7GPb2DptCzf9MAQKviQH6A6Pqa63kxWI+atMiaSXz5uifgsBoiOof\r\n' +
                'E3/oVTIGyGTgB7KnwZiFkDMFrUNREJVSQGt6+4nxje8gARcuYpMnWw==\r\n' +
                '=lOCC\r\n' +
                '-----END PGP SIGNATURE-----\r\n';
            it('should work', function(done) {
                var cleartext = openpgp.cleartext.readArmored(v3_clearsign_msg);
                expect(cleartext).to.exist;
                var verifykey = openpgp.key.readArmored(pubkey).keys[0];
                expect(verifykey, 'verifykey').to.exist;
                var result = cleartext.verify([verifykey])
                expect(result, 'verify() result').to.exist.and.not.be.empty;
                expect(result[0].keyid, 'verify() result[0].keyid').to.exist;
                expect(result[0].valid, 'verify() result[0].valid').to.be.true;
                done();
            });
        });

        describe('Verify V4 signature', function() {
            var v4_clearsign_msg = '-----BEGIN PGP SIGNED MESSAGE-----\r\n' +
                'Hash: SHA1\r\n' +
                '\r\n' +
                'This is a test message.\r\n' +
                '\r\n' +
                'This paragraph is separated form the next by a line of dashes.\r\n' +
                '\r\n' +
                '- --------------------------------------------------------------------------\r\n' +
                '\r\n' +
                'The next paragraph has a number of blank lines between this one and it.\r\n' +
                '\r\n' +
                '\r\n' +
                '\r\n' +
                '\r\n' +
                '\r\n' +
                '\r\n' +
                'This is the last paragraph.\r\n' +
                '\r\n' +
                '- --\r\n' +
                '\r\n' +
                'Joe Test\r\n' +
                '-----BEGIN PGP SIGNATURE-----\r\n' +
                'Version: GnuPG v1.4.15 (GNU/Linux)\r\n' +
                '\r\n' +
                'iFwEAQECAAYFAlKf5LcACgkQ9vYOm0LN/0ybVwH8CItdDh4kWKVcyUx3Q3hWZnWd\r\n' +
                'zP9CUbIa9uToIPABjV3GOTDM3ZgiP0/SE6Al5vG8hlx+/u2piVojoLovk/4LnA==\r\n' +
                '=i6ew\r\n' +
                '-----END PGP SIGNATURE-----\r\n';

            it('should work', function(done) {
                var cleartext = openpgp.cleartext.readArmored(v4_clearsign_msg);
                expect(cleartext).to.exist;
                var verifykey = openpgp.key.readArmored(pubkey).keys[0];
                expect(verifykey, 'verifykey').to.exist;
                var result = cleartext.verify([verifykey])
                expect(result, 'verify() result').to.exist.and.not.be.empty;
                expect(result[0].keyid, 'verify() result[0].keyid').to.exist;
                expect(result[0].valid, 'verify() result[0].valid').to.be.true;
                done();
            });
        });
    });
});
