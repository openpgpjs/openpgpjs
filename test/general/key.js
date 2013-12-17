var unit = require('../unit.js');

unit.register("Key testing", function() {
  var openpgp = require('openpgp');

      var twoKeys =
       ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
        'Version: GnuPG v2.0.19 (GNU/Linux)',
        '',
        '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',
        'PepQmgsu',
        '=w6wd',
        '-----END PGP PUBLIC KEY BLOCK-----'].join("\n");


  var tests = [function() {
    var pubKey = openpgp.key.readArmored(twoKeys);
    var verified = !pubKey.err && pubKey.keys.length == 2 &&
                   pubKey.keys[0].getKeyPacket().getKeyId().toHex() == '4a63613a4d6e4094' &&
                   pubKey.keys[1].getKeyPacket().getKeyId().toHex() == 'dbf223e870534df4';
    return new unit.result("Parsing armored text with two keys", verified);

  }];

  var results = [];

  for(var i in tests) {
    results.push(tests[i]());
  }  
  
  return results;

});

