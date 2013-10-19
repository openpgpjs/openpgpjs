var unit = require('../unit.js');

unit.register("Encryption/decryption", function() {
  var openpgp = require('../../');
  var keyring = require('../../src/openpgp.keyring.js');
  var result = [];
  var testHelper = function(passphrase, userid, message) {
    var key = openpgp.generateKeyPair(openpgp.enums.publicKey.rsa_encrypt_sign, 512, 
                                      userid, message, passphrase);

    var info = '\npassphrase: ' + passphrase + '\n'
        + 'userid: ' + userid + '\n'
        + 'message: ' + message;

    var keyPacketlist = openpgp.readArmoredPackets(key);
    if(!priv_key.decryptSecretMPIs(passphrase)) {
      return new test_result('Generating a decryptable private key failed'
        + info,
        false);
    }

    var encrypted = openpgp.write_signed_and_encrypted_message(priv_key,
      pub_key, message);

    openpgp.keyring.importPublicKey(key.publicKeyArmored);


    var msg = openpgp.read_message(encrypted);
    var keymat = null;
    var sesskey = null;

    // Find the private (sub)key for the session key of the message
    for (var i = 0; i< msg[0].sessionKeys.length; i++) {
      if (priv_key.privateKeyPacket.publicKey.getKeyId().write() == msg[0].sessionKeys[i].keyId.bytes) {
        keymat = { key: priv_key, keymaterial: priv_key.privateKeyPacket};
        sesskey = msg[0].sessionKeys[i];
        break;
      }
      for (var j = 0; j < priv_key.subKeys.length; j++) {
        if (priv_key.subKeys[j].publicKey.getKeyId().write() == msg[0].sessionKeys[i].keyId.bytes) {
          keymat = { key: priv_key, keymaterial: priv_key.subKeys[j]};
          sesskey = msg[0].sessionKeys[i];
          break;
        }
      }
    }

    var decrypted = '';
    if (keymat !== null) {
      if (!keymat.keymaterial.decryptSecretMPIs(passphrase)) {
        return new test_result("Password for secrect key was incorrect!", 
          + info, false);
      }

      decrypted = msg[0].decrypt(keymat, sesskey);
    } else {
      return new test_result("No private key found!" + info, false);
    }
    return new test_result(message + ' == ' + decrypted + info, message == decrypted);
  };

  result.push(testHelper('password', 'Test McTestington <test@example.com>', 'hello world'));
  result.push(testHelper('●●●●', '♔♔♔♔ <test@example.com>', 'łäóć'));

  return result;
});

