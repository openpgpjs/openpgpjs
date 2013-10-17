unittests.register("Testing of binary signature checking", function() {
  var result = new Array();
  var priv_key = openpgp.read_privateKey([
        '-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'Version: GnuPG v1.4.11 (GNU/Linux)',
        '',
        'lQHhBFERnrMRBADmM0hIfkI3yosjgbWo9v0Lnr3CCE+8KsMszgVS+hBu0XfGraKm',
        'ivcA2aaJimHqVYOP7gEnwFAxHBBpeTJcu5wzCFyJwEYqVeS3nnaIhBPplSF14Duf',
        'i6bB9RV7KxVAg6aunmM2tAutqC+a0y2rDaf7jkJoZ9gWJe2zI+vraD6fiwCgxvHo',
        '3IgULB9RqIqpLoMgXfcjC+cD/1jeJlKRm+n71ryYwT/ECKsspFz7S36z6q3XyS8Q',
        'QfrsUz2p1fbFicvJwIOJ8B20J/N2/nit4P0gBUTUxv3QEa7XCM/56/xrGkyBzscW',
        'AzBoy/AK9K7GN6z13RozuAS60F1xO7MQc6Yi2VU3eASDQEKiyL/Ubf/s/rkZ+sGj',
        'yJizBACtwCbQzA+z9XBZNUat5NPgcZz5Qeh1nwF9Nxnr6pyBv7tkrLh/3gxRGHqG',
        '063dMbUk8pmUcJzBUyRsNiIPDoEUsLjY5zmZZmp/waAhpREsnK29WLCbqLdpUors',
        'c1JJBsObkA1IM8TZY8YUmvsMEvBLCCanuKpclZZXqeRAeOHJ0v4DAwK8WfuTe5B+',
        'M2BOOeZbN8BpfiA1l//fMMHLRS3UvbLBv4P1+4SyvhyYTR7M76Q0xPc03MFOWHL+',
        'S9VumbQWVGVzdDIgPHRlc3QyQHRlc3QuY29tPohiBBMRAgAiBQJREZ6zAhsDBgsJ',
        'CAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRARJ5QDyxae+MXNAKCzWSDR3tMrTrDb',
        'TAri73N1Xb3j1ACfSl9y+SAah2q7GvmiR1+6+/ekqJGdAVgEURGesxAEANlpMZjW',
        '33jMxlKHDdyRFXtKOq8RreXhq00plorHbgz9zFEWm4VF53+E/KGnmHGyY5Cy8TKy',
        'ZjaueZZ9XuG0huZg5If68irFfNZtxdA26jv8//PdZ0Uj+X6J3RVa2peMLDDswTYL',
        'OL1ZO1fxdtDD40fdAiIZ1QyjwEG0APtz41EfAAMFBAC5/dtgBBPtHe8UjDBaUe4n',
        'NzHuUBBp6XE+H7eqHNFCuZAJ7yqJLGVHNIaQR419cNy08/OO/+YUQ7rg78LxjFiv',
        'CH7IzhfU+6yvELSbgRMicY6EnAP2GT+b1+MtFNa3lBGtBHcJla52c2rTAHthYZWk',
        'fT5R5DnJuQ2cJHBMS9HWyP4DAwK8WfuTe5B+M2C7a/YJSUv6SexdGCaiaTcAm6g/',
        'PvA6hw/FLzIEP67QcQSSTmhftQIwnddt4S4MyJJH3U4fJaFfYQ1zCniYJohJBBgR',
        'AgAJBQJREZ6zAhsMAAoJEBEnlAPLFp74QbMAn3V4857xwnO9/+vzIVnL93W3k0/8',
        'AKC8omYPPomN1E/UJFfXdLDIMi5LoA==',
        '=LSrW',
        '-----END PGP PRIVATE KEY BLOCK-----'
      ].join("\n"));
  var pub_key = openpgp.read_publicKey(
      [ '-----BEGIN PGP PUBLIC KEY BLOCK-----',
        'Version: GnuPG v1.4.11 (GNU/Linux)',
        '',
        'mQGiBFERlw4RBAD6Bmcf2w1dtUmtCLkdxeqZLArk3vYoQAjdibxA3gXVyur7fsWb',
        'ro0jVbBHqOCtC6jDxE2l52NP9+tTlWeVMaqqNvUE47LSaPq2DGI8Wx1Rj6bF3mTs',
        'obYEwhGbGh/MhJnME9AHODarvk8AZbzo0+k1EwrBWF6dTUBPfqO7rGU2ewCg80WV',
        'x5pt3evj8rRK3jQ8SMKTNRsD/1PhTdxdZTdXARAFzcW1VaaruWW0Rr1+XHKKwDCz',
        'i7HE76SO9qjnQfZCZG75CdQxI0h8GFeN3zsDqmhob2iSz2aJ1krtjM+iZ1FBFd57',
        'OqCV6wmk5IT0RBN12ZzMS19YvzN/ONXHrmTZlKExd9Mh9RKLeVNw+bf6JsKQEzcY',
        'JzFkBACX9X+hDYchO/2hiTwx4iOO9Fhsuh7eIWumB3gt+aUpm1jrSbas/QLTymmk',
        'uZuQVXI4NtnlvzlNgWv4L5s5RU5WqNGG7WSaKNdcrvJZRC2dgbUJt04J5CKrWp6R',
        'aIYal/81Ut1778lU01PEt563TcQnUBlnjU5OR25KhfSeN5CZY7QUVGVzdCA8dGVz',
        'dEB0ZXN0LmNvbT6IYgQTEQIAIgUCURGXDgIbAwYLCQgHAwIGFQgCCQoLBBYCAwEC',
        'HgECF4AACgkQikDlZK/UvLSspgCfcNaOpTg1W2ucR1JwBbBGvaERfuMAnRgt3/rs',
        'EplqEakMckCtikEnpxYe',
        '=b2Ln',
        '-----END PGP PUBLIC KEY BLOCK-----'
      ].join("\n"));
  var msg = openpgp.read_message([
        '-----BEGIN PGP MESSAGE-----',
        'Version: GnuPG v1.4.11 (GNU/Linux)',
        '',
        'hQEOA1N4OCSSjECBEAP/diDJCQn4e88193PgqhbfAkohk9RQ0v0MPnXpJbCRTHKO',
        '8r9nxiAr/TQv4ZOingXdAp2JZEoE9pXxZ3r1UWew04czxmgJ8FP1ztZYWVFAWFVi',
        'Tj930TBD7L1fY/MD4fK6xjEG7z5GT8k4tn4mLm/PpWMbarIglfMopTy1M/py2cID',
        '/2Sj7Ikh3UFiG+zm4sViYc5roNbMy8ixeoKixxi99Mx8INa2cxNfqbabjblFyc0Z',
        'BwmbIc+ZiY2meRNI5y/tk0gRD7hT84IXGGl6/mH00bsX/kkWdKGeTvz8s5G8RDHa',
        'Za4HgLbXItkX/QarvRS9kvkD01ujHfj+1ZvgmOBttNfP0p8BQLIICqvg1eYD9aPB',
        '+GtOZ2F3+k5VyBL5yIn/s65SBjNO8Fqs3aL0x+p7s1cfUzx8J8a8nWpqq/qIQIqg',
        'ZJH6MZRKuQwscwH6NWgsSVwcnVCAXnYOpbHxFQ+j7RbF/+uiuqU+DFH/Rd5pik8b',
        '0Dqnp0yfefrkjQ0nuvubgB6Rv89mHpnvuJfFJRInpg4lrHwLvRwdpN2HDozFHcKK',
        'aOU=',
        '=4iGt',
        '-----END PGP MESSAGE-----'
      ].join("\n"));
  priv_key[0].subKeys[0].decryptSecretMPIs("abcd");
  var ret = msg[0].decryptAndVerifySignature(
      { key: priv_key[0], keymaterial: priv_key[0].subKeys[0]},
      msg[0].sessionKeys[0],
      [{obj:pub_key[0], keyId: pub_key[0].getKeyId()}]);
  result[0] = new test_result("Testing signature checking on CAST5-enciphered message",
          ret[0].signatureValid == true);

  // exercises the GnuPG s2k type 1001 extension:
  // the secrets on the primary key have been stripped.
  var priv_key_gnupg_ext = openpgp.read_privateKey([
        '-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'Version: GnuPG v1.4.11 (GNU/Linux)',
        '',
        'lQGqBFERnrMRBADmM0hIfkI3yosjgbWo9v0Lnr3CCE+8KsMszgVS+hBu0XfGraKm',
        'ivcA2aaJimHqVYOP7gEnwFAxHBBpeTJcu5wzCFyJwEYqVeS3nnaIhBPplSF14Duf',
        'i6bB9RV7KxVAg6aunmM2tAutqC+a0y2rDaf7jkJoZ9gWJe2zI+vraD6fiwCgxvHo',
        '3IgULB9RqIqpLoMgXfcjC+cD/1jeJlKRm+n71ryYwT/ECKsspFz7S36z6q3XyS8Q',
        'QfrsUz2p1fbFicvJwIOJ8B20J/N2/nit4P0gBUTUxv3QEa7XCM/56/xrGkyBzscW',
        'AzBoy/AK9K7GN6z13RozuAS60F1xO7MQc6Yi2VU3eASDQEKiyL/Ubf/s/rkZ+sGj',
        'yJizBACtwCbQzA+z9XBZNUat5NPgcZz5Qeh1nwF9Nxnr6pyBv7tkrLh/3gxRGHqG',
        '063dMbUk8pmUcJzBUyRsNiIPDoEUsLjY5zmZZmp/waAhpREsnK29WLCbqLdpUors',
        'c1JJBsObkA1IM8TZY8YUmvsMEvBLCCanuKpclZZXqeRAeOHJ0v4DZQJHTlUBtBZU',
        'ZXN0MiA8dGVzdDJAdGVzdC5jb20+iGIEExECACIFAlERnrMCGwMGCwkIBwMCBhUI',
        'AgkKCwQWAgMBAh4BAheAAAoJEBEnlAPLFp74xc0AoLNZINHe0ytOsNtMCuLvc3Vd',
        'vePUAJ9KX3L5IBqHarsa+aJHX7r796SokZ0BWARREZ6zEAQA2WkxmNbfeMzGUocN',
        '3JEVe0o6rxGt5eGrTSmWisduDP3MURabhUXnf4T8oaeYcbJjkLLxMrJmNq55ln1e',
        '4bSG5mDkh/ryKsV81m3F0DbqO/z/891nRSP5fondFVral4wsMOzBNgs4vVk7V/F2',
        '0MPjR90CIhnVDKPAQbQA+3PjUR8AAwUEALn922AEE+0d7xSMMFpR7ic3Me5QEGnp',
        'cT4ft6oc0UK5kAnvKoksZUc0hpBHjX1w3LTz847/5hRDuuDvwvGMWK8IfsjOF9T7',
        'rK8QtJuBEyJxjoScA/YZP5vX4y0U1reUEa0EdwmVrnZzatMAe2FhlaR9PlHkOcm5',
        'DZwkcExL0dbI/gMDArxZ+5N7kH4zYLtr9glJS/pJ7F0YJqJpNwCbqD8+8DqHD8Uv',
        'MgQ/rtBxBJJOaF+1AjCd123hLgzIkkfdTh8loV9hDXMKeJgmiEkEGBECAAkFAlER',
        'nrMCGwwACgkQESeUA8sWnvhBswCfdXjznvHCc73/6/MhWcv3dbeTT/wAoLyiZg8+',
        'iY3UT9QkV9d0sMgyLkug',
        '=GQsY',
        '-----END PGP PRIVATE KEY BLOCK-----',
      ].join("\n"));
  priv_key_gnupg_ext[0].subKeys[0].decryptSecretMPIs("abcd");
  var ret2 = msg[0].decryptAndVerifySignature(
      { key: priv_key_gnupg_ext[0], keymaterial: priv_key_gnupg_ext[0].subKeys[0]},
      msg[0].sessionKeys[0],
      [{obj:pub_key[0], keyId: pub_key[0].getKeyId()}]);
  result[1] = new test_result("Testing GnuPG stripped-key extensions",
          priv_key_gnupg_ext[0].privateKeyPacket.s2k.type == 1001 &&
          ret[0].signatureValid == true);

  // Exercises the ability of openpgp_keyring.getPublicKeysForKeyId to return subkeys
  var test_keyring = new openpgp_keyring();
  test_keyring.init();
  test_keyring.importPublicKey([
        '-----BEGIN PGP PUBLIC KEY BLOCK-----',
        'Version: GnuPG v1.4.11 (GNU/Linux)',
        '',
        'mQGiBFERvI4RBAD0M/HGglCtVNXPF72ehT8riAXrl0rSec4RJC61Bh+UAOhxn5+U',
        'fDgos5p1SpIzYmn+M87JoSSVLAjfakFk0gHgR9I3bu7SIwq3Bikk1Vw3gO+yDSO6',
        'TKpLUFGYDiBSSE1MGdxBadWLE1hlRf5B2x62gnGmjSpSVbly33PFkoDmrwCg9rAp',
        'RmncnF9GhWjOLFkEoQw9Yx8EAOsxvq8Ig5Z1gk+ZKfDZeftpHRe3FdrRtbnhxvYY',
        '7z+w9uz1EpoZUwDR5G4X3hTwJQ7lXmIOskg/+eRMLEAqEY7b/7tW6RaUJ2d6Ehsi',
        'dOS89fIxElwjAOnVOM5S24f0FDQTTto7QBOoxcNTfkEJCHXSlpoOUmGAP85fXh3l',
        'yPTGBACJfKc76Un3UWC1sWIRDxYiyh3ZpZyNEskoV6ESW8jEI1RnMnv5TrfGJH5K',
        'E8jWX7TTnoFyPJtBTjlucAtkQaS4Bb7dg1LLja17zAqKNGOJK2b9fb2Z+lnTjPiY',
        'i7DPH1XHnfaEexjlh/U7mYa5RrwIphRxNi8gCuxv874ZMmhEn7QWVGVzdDMgPHRl',
        'c3QzQHRlc3QuY29tPohiBBMRAgAiBQJREbyOAhsDBgsJCAcDAgYVCAIJCgsEFgID',
        'AQIeAQIXgAAKCRC0u8O0Moa2JYxyAJ9Oi2UlcUT0VJNgwjyl/VF9Xcjf9gCeJPvy',
        'g/fp4EAU8MJIaN2yMI8pLFS5AaIEURG8nhEEAKVgeNDuYDPufLuJ0GrJV/CbXEjj',
        'aEPA0iTUqV0nTCPdAfQ/nmE3gh5UlNMr/zSHJ+c4FQhYdLrzRGDOSzV+mfPHH3t+',
        'YVx+wat0BYwABpHAtsIuLIVo2RQqYZYH85tatwBkm71HHT3jmlEAvr6NFH38+v3s',
        '3w4Wl0/sdHyaeiSXAKCxJ4X1eOdN7L1rrbJozQ/gDCFuVQP/dcV6Ksss8Aw443jG',
        'AYBLHWh6o4GhAY6/h1kijF0xD+uc+tNmTQnQi1tEOoTeIZMXnSRwtk8XEuJkkbAP',
        '+uyvMgyV3wrk9zkaTAin7nrjAERxezFOdBEOtnB1CovJxtMn+RRxaMEGpC4GnETy',
        'N5+6FkLuLcNXiCQP75ajzOAN1aID/juNjUNpBbNpfqBV7j1K+Kn0n9HYTyQl9ghy',
        '026+/4c8ag2HV+bg3BD7c2VTVu9xBODHsfu0q8Ql/QB9W8tmYugU6DeXMHaeWPUH',
        'ph98guM9kF2yHIiRBvAd5i7wOjwn+I/Ir6nBR2yxJ3p31CDUnUlbjTPYg7mtQvHW',
        'EY2Cp4SWiJEEGBECAAkFAlERvJ4CGwIAUgkQtLvDtDKGtiVHIAQZEQIABgUCURG8',
        'ngAKCRAMiMeR296Y2SjyAJ9V3wRJJ2Szazqal4khWGfLu5R6/wCfQQIRD24yVdz8',
        '2a+2eCrwyALT2GAihACfS0nWM3a0gtITqngpJsRws+Ep+eIAn15qD2itutxNb8NI',
        'bR2gBB5QmVJ3',
        '=pGA6',
        '-----END PGP PUBLIC KEY BLOCK-----'
        ].join("\n"));

  var msg2 = openpgp.read_message([
        '-----BEGIN PGP MESSAGE-----',
        'Version: GnuPG v1.4.11 (GNU/Linux)',
        '',
        'kA0DAAIRDIjHkdvemNkBrB1iB2Zvby50eHRREbz3VEVTVCBEQVRBIDEyMzQ1NohG',
        'BAARAgAGBQJREbz3AAoJEAyIx5Hb3pjZ2TcAn32LpDEuHe9QrSRlyvSuREKNOFwz',
        'AJ9zh4zsK4GIPuEu81YPNmHsju7DYg==',
        '=WaSx',
        '-----END PGP MESSAGE-----'
        ].join("\n"));
  var pubKey = test_keyring.getPublicKeysForKeyId(msg2[1].signature.issuerKeyId);
  result[2] = new test_result("Testing keyring public subkey support",
          pubKey != null && 
          pubKey.length == 1 && 
          msg2[1].signature.verify(msg2[0].data, pubKey[0]));
  return result;
})

