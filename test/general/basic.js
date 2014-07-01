'use strict';

var openpgp = typeof window != 'undefined' && window.openpgp ? window.openpgp : require('openpgp');

var chai = require('chai'),
  expect = chai.expect;

describe('Basic', function() {

  describe("Key generation/encryption/decryption", function() {
    var testHelper = function(passphrase, userid, message) {
      var key = openpgp.generateKeyPair({numBits: 512, userId: userid, passphrase: passphrase});
      expect(key).to.exist;
      expect(key.key).to.exist;
      expect(key.privateKeyArmored).to.exist;
      expect(key.publicKeyArmored).to.exist;

      var info = '\npassphrase: ' + passphrase + '\n' + 'userid: ' + userid + '\n' + 'message: ' + message;

      var privKeys = openpgp.key.readArmored(key.privateKeyArmored);
      var publicKeys = openpgp.key.readArmored(key.publicKeyArmored);

      expect(privKeys).to.exist;
      expect(privKeys.err).to.not.exist;
      expect(privKeys.keys).to.have.length(1);

      var privKey = privKeys.keys[0];
      var pubKey = publicKeys.keys[0];

      expect(privKey).to.exist;
      expect(pubKey).to.exist;

      var success = privKey.decrypt(passphrase);

      expect(success).to.be.true;

      var encrypted = openpgp.signAndEncryptMessage([pubKey], privKey, message);

      expect(encrypted).to.exist;

      var msg = openpgp.message.readArmored(encrypted);

      expect(msg).to.exist;

      var keyids = msg.getEncryptionKeyIds();

      expect(keyids).to.exist;

      var decrypted = openpgp.decryptAndVerifyMessage(privKey, [pubKey], msg);
      expect(decrypted).to.exist;
      expect(decrypted.signatures[0].valid).to.be.true;
      expect(decrypted.text).to.equal(message);
    };

    it('ASCII Text', function (done) {
      testHelper('password', 'Test McTestington <test@example.com>', 'hello world');
      done();
    });
    it('Unicode Text', function (done) {
      testHelper('●●●●', '♔♔♔♔ <test@example.com>', 'łäóć');
      done();
    });

    it('should fail to verify signature for wrong public key', function (done) {
      var userid = 'Test McTestington <test@example.com>';
      var passphrase = 'password';
      var message = 'hello world';

      var key = openpgp.generateKeyPair({numBits: 512, userId: userid, passphrase: passphrase});

      var privKeys = openpgp.key.readArmored(key.privateKeyArmored);
      var publicKeys = openpgp.key.readArmored(key.publicKeyArmored);

      var privKey = privKeys.keys[0];
      var pubKey = publicKeys.keys[0];

      var success = privKey.decrypt(passphrase);

      var encrypted = openpgp.signAndEncryptMessage([pubKey], privKey, message);

      var msg = openpgp.message.readArmored(encrypted);
      expect(msg).to.exist;

      var anotherKey = openpgp.generateKeyPair({numBits: 512, userId: userid, passphrase: passphrase});
      var anotherPubKey = openpgp.key.readArmored(anotherKey.publicKeyArmored).keys[0];

      var decrypted = openpgp.decryptAndVerifyMessage(privKey, [anotherPubKey], msg);
      expect(decrypted).to.exist;
      expect(decrypted.signatures[0].valid).to.be.null;
      expect(decrypted.text).to.equal(message);
      done();
    });

    it('Performance test', function (done) {
      // init test data
      function randomString(length, chars) {
        var result = '';
        for (var i = length; i > 0; --i) result += chars[Math.round(Math.random() * (chars.length - 1))];
        return result;
      }
      var message = randomString(1024*1024*3, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ');

      var userid = 'Test McTestington <test@example.com>';
      var passphrase = 'password';

      var key = openpgp.generateKeyPair({numBits: 512, userId: userid, passphrase: passphrase});

      var info = '\npassphrase: ' + passphrase + '\n' + 'userid: ' + userid + '\n' + 'message: ' + message;

      var privKeys = openpgp.key.readArmored(key.privateKeyArmored);
      var publicKeys = openpgp.key.readArmored(key.publicKeyArmored);

      var privKey = privKeys.keys[0];
      var pubKey = publicKeys.keys[0];

      var success = privKey.decrypt(passphrase);

      if (console.profile) {
        console.profile("encrypt/sign/verify/decrypt");
      }

      // sign and encrypt
      var msg, encrypted;
      msg = openpgp.message.fromBinary(message);
      msg = msg.sign([privKey]);
      msg = msg.encrypt([pubKey]);
      encrypted = openpgp.armor.encode(openpgp.enums.armor.message, msg.packets.write());

      if (console.profileEnd) {
        console.profileEnd();
      }

      msg = openpgp.message.readArmored(encrypted);

      var keyids = msg.getEncryptionKeyIds();

      expect(keyids).to.exist;

      var decrypted = openpgp.decryptAndVerifyMessage(privKey, [pubKey], msg);

      expect(decrypted).to.exist;
      expect(decrypted.signatures[0].valid).to.be.true;
      expect(decrypted.text).to.equal(message);

      done();
    });
  });

  describe("Message encryption/decryption", function() {
    var pub_key =
       ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
        'Version: GnuPG v2.0.19 (GNU/Linux)',
        '',
        'mI0EUmEvTgEEANyWtQQMOybQ9JltDqmaX0WnNPJeLILIM36sw6zL0nfTQ5zXSS3+',
        'fIF6P29lJFxpblWk02PSID5zX/DYU9/zjM2xPO8Oa4xo0cVTOTLj++Ri5mtr//f5',
        'GLsIXxFrBJhD/ghFsL3Op0GXOeLJ9A5bsOn8th7x6JucNKuaRB6bQbSPABEBAAG0',
        'JFRlc3QgTWNUZXN0aW5ndG9uIDx0ZXN0QGV4YW1wbGUuY29tPoi5BBMBAgAjBQJS',
        'YS9OAhsvBwsJCAcDAgEGFQgCCQoLBBYCAwECHgECF4AACgkQSmNhOk1uQJQwDAP6',
        'AgrTyqkRlJVqz2pb46TfbDM2TDF7o9CBnBzIGoxBhlRwpqALz7z2kxBDmwpQa+ki',
        'Bq3jZN/UosY9y8bhwMAlnrDY9jP1gdCo+H0sD48CdXybblNwaYpwqC8VSpDdTndf',
        '9j2wE/weihGp/DAdy/2kyBCaiOY1sjhUfJ1GogF49rC4jQRSYS9OAQQA6R/PtBFa',
        'JaT4jq10yqASk4sqwVMsc6HcifM5lSdxzExFP74naUMMyEsKHP53QxTF0Grqusag',
        'Qg/ZtgT0CN1HUM152y7ACOdp1giKjpMzOTQClqCoclyvWOFB+L/SwGEIJf7LSCEr',
        'woBuJifJc8xAVr0XX0JthoW+uP91eTQ3XpsAEQEAAYkBPQQYAQIACQUCUmEvTgIb',
        'LgCoCRBKY2E6TW5AlJ0gBBkBAgAGBQJSYS9OAAoJEOCE90RsICyXuqIEANmmiRCA',
        'SF7YK7PvFkieJNwzeK0V3F2lGX+uu6Y3Q/Zxdtwc4xR+me/CSBmsURyXTO29OWhP',
        'GLszPH9zSJU9BdDi6v0yNprmFPX/1Ng0Abn/sCkwetvjxC1YIvTLFwtUL/7v6NS2',
        'bZpsUxRTg9+cSrMWWSNjiY9qUKajm1tuzPDZXAUEAMNmAN3xXN/Kjyvj2OK2ck0X',
        'W748sl/tc3qiKPMJ+0AkMF7Pjhmh9nxqE9+QCEl7qinFqqBLjuzgUhBU4QlwX1GD',
        'AtNTq6ihLMD5v1d82ZC7tNatdlDMGWnIdvEMCv2GZcuIqDQ9rXWs49e7tq1NncLY',
        'hz3tYjKhoFTKEIq3y3Pp',
        '=h/aX',
        '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

    var priv_key =
        ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'Version: GnuPG v2.0.19 (GNU/Linux)',
        '',
        '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',
        '=lw5e',
        '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

    var plaintext = 'short message\nnext line\n한국어/조선말';

    var privKey, message, keyids;

    it('Test initialization', function (done) {
      var pubKeys = openpgp.key.readArmored(pub_key);

      expect(pubKeys).to.exist;
      expect(pubKeys.err).to.not.exist;
      expect(pubKeys.keys).to.have.length(1);

      var pubKey = pubKeys.keys[0];

      expect(pubKey).to.exist;

      var encrypted = openpgp.encryptMessage([pubKey], plaintext);

      expect(encrypted).to.exist;

      message = openpgp.message.readArmored(encrypted);

      expect(message).to.exist;

      var privKeys = openpgp.key.readArmored(priv_key);

      expect(privKeys).to.exist;
      expect(privKeys.err).to.not.exist;
      expect(privKeys.keys).to.have.length(1);

      privKey = privKeys.keys[0];

      expect(privKey).to.exist;

      // get key IDs the message is encrypted for
      keyids = message.getEncryptionKeyIds();

      expect(keyids).to.exist;
      expect(keyids).to.have.length(1);
      done();
    });

    it('Decrypting key packet with wrong password returns false', function (done) {
      // decrypt only required key packets
      var success = privKey.decryptKeyPacket(keyids, 'hello what?');

      expect(success).to.be.false;
      done();
    });

    var decrypted, error;

    it('Calling decryptMessage with not decrypted key packet leads to exception', function (done) {
      function exceptionTest() {
        decrypted = openpgp.decryptMessage(privKey, message);
      }

      expect(exceptionTest).to.throw(Error);
      done();
    });

    it('Decrypting key packet with correct password returns true', function (done) {
      var success = privKey.decryptKeyPacket(keyids, 'hello world');

      expect(success).to.be.true;
      done();
    });

    it('Encrypt plain text and afterwards decrypt leads to same result', function (done) {
      decrypted = openpgp.decryptMessage(privKey, message);
      expect(decrypted).to.exist;
      expect(decrypted).to.equal(plaintext);
      done();
    });

    it('Decrypt message 2x', function() {
      decrypted = openpgp.decryptMessage(privKey, message);
      var decrypted2 = openpgp.decryptMessage(privKey, message);
      expect(decrypted).to.equal(decrypted2);
    });

  });

  describe("Message 3DES decryption", function() {
    var pgp_msg =
        ['-----BEGIN PGP MESSAGE-----',
        'Version: GnuPG/MacGPG2 v2.0.19 (Darwin)',
        'Comment: GPGTools - http://gpgtools.org',
        '',
        'hIwDBU4Dycfvp2EBA/9tuhQgOrcATcm2PRmIOcs6q947YhlsBTZZdVJDfVjkKlyM',
        'M0yE+lnNplWb041Cpfkkl6IvorKQd2iPbAkOL0IXwmVN41l+PvVgMcuFvvzetehG',
        'Ca0/VEYOaTZRNqyr9FIzcnVy1I/PaWT3iqVAYa+G8TEA5Dh9RLfsx8ZA9UNIaNI+',
        'ASm9aZ3H6FerNhm8RezDY5vRn6xw3o/wH5YEBvV2BEmmFKZ2BlqFQxqChr8UNwd1',
        'Ieebnq0HtBPE8YU/L0U=',
        '=JyIa',
        '-----END PGP MESSAGE-----'].join('\n');

    var priv_key =
        ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'Version: GnuPG/MacGPG2 v2.0.19 (Darwin)',
        'Comment: GPGTools - http://gpgtools.org',
        '',
        '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',
        '22q10ausyQXoOxXfDWVwKA==',
        '=IkKW',
        '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

    it('Decrypt message', function (done) {
      var privKey, message, decrypted;

      privKey = openpgp.key.readArmored(priv_key).keys[0];
      privKey.decrypt('1234');
      message = openpgp.message.readArmored(pgp_msg);
      decrypted = openpgp.decryptMessage(privKey, message);

      expect(decrypted).to.equal('hello 3des\n');
      done();
    });
  });

  describe("Misc.", function() {

    it('util.decode_utf8 throws error if invalid parameter type', function () {
      var test = openpgp.util.decode_utf8.bind(null, {chameleon: true});
      expect(test).to.throw(Error, /Parameter "utf8" is not of type string/);
    });

  });

});
