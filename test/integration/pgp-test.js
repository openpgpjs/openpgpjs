define(function(require) {
    'use strict';

    var PGP = require('pgp'),
        expect = chai.expect;

    describe('PGP Crypto Api unit tests', function() {
        var pgp,
            user = 'test@t-online.de',
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

			beforeEach(function() {
			    pgp = new PGP();
			});

			afterEach(function() {});

			describe('Generate key pair', function() {
			    it('should fail', function(done) {
				pgp.generateKeys({
				    emailAddress: 'test@t-onlinede',
				    keySize: keySize,
				    passphrase: passphrase
				}, function(err, keys) {
				    expect(err).to.exist;
				    expect(keys).to.not.exist;
				    done();
				});
			    });
			    it('should fail', function(done) {
				pgp.generateKeys({
				    emailAddress: 'testt-online.de',
				    keySize: keySize,
				    passphrase: passphrase
				}, function(err, keys) {
				    expect(err).to.exist;
				    expect(keys).to.not.exist;
				    done();
				});
			    });
			    it('should work', function(done) {
				pgp.generateKeys({
				    emailAddress: user,
				    keySize: keySize,
				    passphrase: passphrase
				}, function(err, keys) {
				    expect(err).to.not.exist;
				    expect(keys.keyId).to.exist;
				    expect(keys.privateKeyArmored).to.exist;
				    expect(keys.publicKeyArmored).to.exist;
				    done();
				});
			    });
			});

			describe('Import/Export key pair', function() {
			    it('should fail', function(done) {
				pgp.importKeys({
				    passphrase: 'asd',
				    privateKeyArmored: privkey,
				    publicKeyArmored: pubkey
				}, function(err) {
				    expect(err).to.exist;

				    pgp.exportKeys(function(err, keys) {
					expect(err).to.exist;
					expect(keys).to.not.exist;
					done();
				    });
				});
			    });
			    it('should work', function(done) {
				pgp.importKeys({
				    passphrase: passphrase,
				    privateKeyArmored: privkey,
				    publicKeyArmored: pubkey
				}, function(err) {
				    expect(err).to.not.exist;

				    pgp.exportKeys(function(err, keys) {
					expect(err).to.not.exist;
					expect(keys.keyId).to.equal(keyId);
					expect(keys.privateKeyArmored).to.equal(privkey);
					expect(keys.publicKeyArmored).to.equal(pubkey);
					done();
				    });
				});
			    });
			});

			describe('Encryption', function() {
			    var message = 'Hello, World!',
				ciphertext;

			    beforeEach(function(done) {
				pgp.importKeys({
				    passphrase: passphrase,
				    privateKeyArmored: privkey,
				    publicKeyArmored: pubkey
				}, function(err) {
				    expect(err).to.not.exist;
				    done();
				});
			    });

			    describe('Encrypt and Sign', function() {
				it('should work', function(done) {
				    pgp.encrypt(message, [pubkey], function(err, ct) {
					expect(err).to.not.exist;
					expect(ct).to.exist;
					ciphertext = ct;
					done();
				    });
				});
			    });

			    describe('Decrypt and Verify', function() {
				it('should work', function(done) {
				    pgp.decrypt(ciphertext, pubkey, function(err, pt) {
					expect(err).to.not.exist;
					expect(pt.text).to.equal(message);
					expect(pt.validSignatures[0]).to.be.true;
					done();
				    });
				});
			    });

			});

			describe('Verify clearsign from gpg', function() {
                var clearsign_msg = '-----BEGIN PGP SIGNED MESSAGE-----\r\n' +
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

			    beforeEach(function(done) {
				pgp.importKeys({
				    passphrase: passphrase,
				    privateKeyArmored: privkey,
				    publicKeyArmored: pubkey
				}, function(err) {
				    expect(err).to.not.exist;
				    done();
				});
			    });

			    describe('Verify', function() {
				it('should work', function(done) {
				    pgp.verify(clearsign_msg, pubkey, function(err, pt) {
					expect(err).to.not.exist;
					expect(pt).to.be.true;
					done();
				    });
				});
			    });

			});

		    });
		});
