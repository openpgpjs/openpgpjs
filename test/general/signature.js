const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;

describe("Signature", function() {
  const priv_key_arm1 =
    ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
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
      '-----END PGP PRIVATE KEY BLOCK-----'].join("\n");

  const pub_key_arm1 =
    ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
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
      '-----END PGP PUBLIC KEY BLOCK-----'].join("\n");

  const msg_arm1 =
    ['-----BEGIN PGP MESSAGE-----',
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
      '-----END PGP MESSAGE-----'].join("\n");

  const priv_key_arm2 =
    ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
      'Version: GnuPG v2.0.19 (GNU/Linux)',
      '',
      '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',
      '=lw5e',
      '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

  const pub_key_arm2 =
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

  const pub_key_arm3 =
    ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
      'Version: GnuPG v2.0.19 (GNU/Linux)',
      '',
      'mQENBFKV0FUBCACtZliApy01KBGbGNB36YGH4lpr+5KoqF1I8A5IT0YeNjyGisOk',
      'WsDsUzOqaNvgzQ82I3MY/jQV5rLBhH/6LiRmCA16WkKcqBrHfNGIxJ+Q+ofVBHUb',
      'aS9ClXYI88j747QgWzirnLuEA0GfilRZcewII1pDA/G7+m1HwV4qHsPataYLeboq',
      'hPA3h1EVVQFMAcwlqjOuS8+weHQRfNVRGQdRMm6H7166PseDVRUHdkJpVaKFhptg',
      'rDoNI0lO+UujdqeF1o5tVZ0j/s7RbyBvdLTXNuBbcpq93ceSWuJPZmi1XztQXKYe',
      'y0f+ltgVtZDEc7TGV5WDX9erRECCcA3+s7J3ABEBAAG0G0pTIENyeXB0byA8ZGlm',
      'ZmllQGhvbWUub3JnPokBPwQTAQIAKQUCUpXQVQIbAwUJCWYBgAcLCQgHAwIBBhUI',
      'AgkKCwQWAgMBAh4BAheAAAoJENvyI+hwU030yRAIAKX/mGEgi/miqasbbQoyK/CS',
      'a7sRxgZwOWQLdi2xxpE5V4W4HJIDNLJs5vGpRN4mmcNK2fmJAh74w0PskmVgJEhP',
      'dFJ14UC3fFPq5nbqkBl7hU0tDP5jZxo9ruQZfDOWpHKxOCz5guYJ0CW97bz4fChZ',
      'NFDyfU7VsJQwRIoViVcMCipP0fVZQkIhhwpzQpmVmN8E0a6jWezTZv1YpMdlzbEf',
      'H79l3StaOh9/Un9CkIyqEWdYiKvIYms9nENyehN7r/OKYN3SW+qlt5GaL+ws+N1w',
      '6kEZjPFwnsr+Y4A3oHcAwXq7nfOz71USojSmmo8pgdN8je16CP98vw3/k6TncLS5',
      'AQ0EUpXQVQEIAMEjHMeqg7B04FliUFWr/8C6sJDb492MlGAWgghIbnuJfXAnUGdN',
      'oAzn0S+n93Y/qHbW6YcjHD4/G+kK3MuxthAFqcVjdHZQXK0rkhXO/u1co7v1cdtk',
      'OTEcyOpyLXolM/1S2UYImhrml7YulTHMnWVja7xu6QIRso+7HBFT/u9D47L/xXrX',
      'MzXFVZfBtVY+yoeTrOY3OX9cBMOAu0kuN9eT18Yv2yi6XMzP3iONVHtl6HfFrAA7',
      'kAtx4ne0jgAPWZ+a8hMy59on2ZFs/AvSpJtSc1kw/vMTWkyVP1Ky20vAPHQ6Ej5q',
      '1NGJ/JbcFgolvEeI/3uDueLjj4SdSIbLOXMAEQEAAYkBJQQYAQIADwUCUpXQVQIb',
      'DAUJCWYBgAAKCRDb8iPocFNN9NLkB/wO4iRxia0zf4Kw2RLVZG8qcuo3Bw9UTXYY',
      'lI0AutoLNnSURMLLCq6rcJ0BCXGj/2iZ0NBxZq3t5vbRh6uUv+hpiSxK1nF7AheN',
      '4aAAzhbWx0UDTF04ebG/neE4uDklRIJLhif6+Bwu+EUeTlGbDj7fqGSsNe8g92w7',
      '1e41rF/9CMoOswrKgIjXAou3aexogWcHvKY2D+1q9exORe1rIa1+sUGl5PG2wsEs',
      'znN6qtN5gMlGY1ofWDY+I02gO4qzaZ/FxRZfittCw7v5dmQYKot9qRi2Kx3Fvw+h',
      'ivFBpC4TWgppFBnJJnAsFXZJQcejMW4nEmOViRQXY8N8PepQmgsu',
      '=ummy',
      '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  const pub_revoked =
    ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
      'Version: GnuPG v2.0.19 (GNU/Linux)',
      '',
      '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',
      'pMiJM+NJAQ==',
      '=ok+o',
      '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  const pub_expired =
    ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
      'Comment: GPGTools - https://gpgtools.org',
      '',
      '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',
      '2g==',
      '=X7/F',
      '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

    const msg_sig_expired =
    ['-----BEGIN PGP MESSAGE-----',
      'Comment: GPGTools - https://gpgtools.org',
      '',
      'owEBWwKk/ZANAwAKAeyAexA3gWZ0AawUYgloZWxsby50eHRaX2WpaGVsbG+JAjME',
      'AAEKAB0WIQTxcIn7ZRrhwd51IZbsgHsQN4FmdAUCWl9lqQAKCRDsgHsQN4FmdCln',
      'D/44x1bcrOXg+DbRStSrC75wFa+cvPEmaTZyqN6d7qlQCMxOcPlq6lbZ74QWfEq7',
      'i1ZYHp4AU8jALw0QqBQQE5FvABleQKpVfY22s83Bqy+P0DB9ntpD+t+oZrxGCLmL',
      'MbZJNFnGro48gHt+/OQKLuftiVwE2opHfgogVKNL74FmYA0hMItdzpn4OPNFkP8t',
      'Iq/m0hkXlTAKqBPITVLv1FN16v+Sm1iC317eP/HOTYqVZdJN3svVF8ZBfg29a8p6',
      '6nl67fZhXgrt0OB6KSNIZEwMTWjFAqi365mtTssqAA0un94+cQ/WvAC5QcMM8g5S',
      'i3G7vny9AsXor+GDU1z7UDWs3wBV4mVRdj7bBIS6PK+6oe012aNpRObcI2bU2BT/',
      'H/7uHZWfwEmpfvH9RVZgoeETA3vSx7MDrNyDt3gwv2hxOHEd7nnVQ3EKG33173o1',
      '/5/oEmn2USujKGhHJ2Zo3aWNRuUWZlvBaYw+PwB2R0UiuJbi0KofNYPssNdpw4sg',
      'Qs7Nb2/Ilo1zn5bDh+WDrUrn6zHKAfBytBPpwPFWPZ8W10HUlC5vMZSKH5/UZhj5',
      'kLlUC1zKjFPpRhO27ImTJuImil4lR2/CFjB1duG3JGJQaYIq8RFJOjvTVY29wl0i',
      'pFy6y1Ofv2lLHB9K7N7dvvee2nvpUMkLEL52oFQ6Jc7sdg==',
      '=Q4tk',
      '-----END PGP MESSAGE-----'].join('\n');

  it('Testing signature checking on CAST5-enciphered message', async function() {
    const priv_key = (await openpgp.key.readArmored(priv_key_arm1)).keys[0];
    const pub_key = (await openpgp.key.readArmored(pub_key_arm1)).keys[0];
    const msg = await openpgp.message.readArmored(msg_arm1);
    await priv_key.decrypt("abcd");
    return openpgp.decrypt({ privateKeys: priv_key, publicKeys:[pub_key], message:msg }).then(function(decrypted) {
      expect(decrypted.data).to.exist;
      expect(decrypted.signatures[0].valid).to.be.true;
      expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
    });
  });

  it('Testing GnuPG stripped-key extensions', async function() {
    // exercises the GnuPG s2k type 1001 extension:
    // the secrets on the primary key have been stripped.
    const priv_key_gnupg_ext = (await openpgp.key.readArmored(
      ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
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
        '-----END PGP PRIVATE KEY BLOCK-----'].join("\n"))).keys[0];
    const pub_key = (await openpgp.key.readArmored(pub_key_arm1)).keys[0];
    const msg = await openpgp.message.readArmored(msg_arm1);

    await priv_key_gnupg_ext.subKeys[0].keyPacket.decrypt("abcd");
    return msg.decrypt([priv_key_gnupg_ext]).then(function(msg) {
      return msg.verify([pub_key]).then(async verified => {
        openpgp.stream.pipe(msg.getLiteralData(), new WritableStream());
        expect(verified).to.exist;
        expect(verified).to.have.length(1);
        expect(await verified[0].verified).to.be.true;
        expect((await verified[0].signature).packets.length).to.equal(1);
      });
    });
  });

  it('Verify V4 signature. Hash: SHA1. PK: RSA. Signature Type: 0x00 (binary document)', async function() {
    const signedArmor =
      ['-----BEGIN PGP MESSAGE-----',
        'Version: GnuPG v2.0.19 (GNU/Linux)',
        '',
        'owGbwMvMwMT4oOW7S46CznTGNeZJLCWpFSVBU3ZGF2fkF5Uo5KYWFyemp3LlAUUV',
        'cjLzUrneTp3zauvaN9O26L9ZuOFNy4LXyydwcXXMYWFgZGJgY2UCaWXg4hSAmblK',
        'nPmfsXYxd58Ka9eVrEnSpzilr520fXBrJsf2P/oTqzTj3hzyLG0o3TTzxFfrtOXf',
        'cw6U57n3/Z4X0pEZ68C5/o/6NpPICD7fuEOz3936raZ6wXGzueY8pfPnVjY0ajAc',
        'PtJzvvqj+ubYaT1sK9wWhd9lL3/V+9Zuua9QjOWC22buchsCroh8fLoZAA==',
        '=VH8F',
        '-----END PGP MESSAGE-----'].join('\n');

    const sMsg = await openpgp.message.readArmored(signedArmor);
    const pub_key = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];
    return sMsg.verify([pub_key]).then(async verified => {
      openpgp.stream.pipe(sMsg.getLiteralData(), new WritableStream());
      expect(verified).to.exist;
      expect(verified).to.have.length(1);
      expect(await verified[0].verified).to.be.true;
      expect((await verified[0].signature).packets.length).to.equal(1);
    });
  });

  it('Verify signature of signed and encrypted message from GPG2 with openpgp.decrypt', async function() {
    const msg_armor =
      ['-----BEGIN PGP MESSAGE-----',
        'Version: GnuPG v2.0.19 (GNU/Linux)',
        '',
        'hIwD4IT3RGwgLJcBBADEBdm+GEW7IV1K/Bykg0nB0WYO08ai7/8/+Y/O9xu6RiU0',
        'q7/jWuKms7kSjw9gxMCjf2dGnAuT4Cg505Kj5WfeBuHh618ovO8qo4h0qHyp1/y3',
        'o1P0IXPAb+LGJOeO7DyM9Xp2AOBiIKOVWzFTg+MBZOc+XZEVx3FioHfm9SSDudLA',
        'WAEkDakCG6MRFj/7SmOiV8mQKH+YPMKT69eDZW7hjINabrpM2pdRU7c9lC7CMUBx',
        'Vj7wZsQBMASSC8f2rhpGA2iKvYMsmW3g9R1xkvj1MXWftSPUS4jeNTAgEwvvF6Af',
        'cP+OYSXKlTbwfEr73ES2O3/IFE9sHRjPqWaxWuv4DDQ5YfIxE54C1aE8Aq5/QaIH',
        'v38TUSia0yEMCc/tJd58DikkT07AF162tcx9Ro0ZjhudyuvUyXIfPfxA+XWR2pdz',
        'ifxyV4zia9RvaCUY8vXGM+gQJ3NNXx2LkZA3kWUEyxFVL1Vl/XUQY0M6U+uccSk4',
        'eMXm6eyEWDcj0lBRckqKoKo1w/uan11jPuHsnRz6jO9DsuKEz79UDgI=',
        '=cFi7',
        '-----END PGP MESSAGE-----'].join('\n');

    const plaintext = 'short message\nnext line\n한국어/조선말';
    const esMsg = await openpgp.message.readArmored(msg_armor);
    const pubKey = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];
    const privKey = (await openpgp.key.readArmored(priv_key_arm2)).keys[0];

    await Promise.all(esMsg.getEncryptionKeyIds().map(keyId => privKey.decrypt('hello world', keyId)));

    return openpgp.decrypt({ privateKeys: privKey, publicKeys:[pubKey], message:esMsg }).then(function(decrypted) {
      expect(decrypted.data).to.exist;
      expect(decrypted.data).to.equal(plaintext);
      expect(decrypted.signatures).to.have.length(1);
      expect(decrypted.signatures[0].valid).to.be.true;
      expect(decrypted.signatures[0].signature.packets.length).to.equal(1);
    });
  });

  it('Verify signed message with two one pass signatures', async function() {
    const msg_armor =
      ['-----BEGIN PGP MESSAGE-----',
        'Version: GnuPG v2.0.19 (GNU/Linux)',
        '',
        'owGbwMvMwMF4+5Pyi4Jg3y8ME8DcBy3fXXIUdKYzrjFNYilJrSgJmsXDXJyRX1Si',
        'kJtaXJyYnsqVBxRVyMnMS+V6O3XOq61r30zbov9m4YY3LQteL5/QMYeFgZGDgY2V',
        'CaSRgYtTAGZiYxYLwySbQk07ptZel6gmjrKyBWsyWdkOG3oscLBdIpXXfDdb6fNv',
        '8ULN5L1ed+xNo79P2dBotWud6vn7e9dtLJ7o12PunnvEz8gyyvP4/As/los0xsnZ',
        'H+8ublrhvGtLxJUZuUKZO6QdHq2Nepuw8OrfiMXPBDQXXpV2q11Ze+rD3lndgv/C',
        'bJQNOhll0J0H839jFvt/16m20h/ZmDoWqJywapnypjdIjcXr+7rJFess40yenV7Q',
        '2LSu/EX6Aq29x+dv+GPUMfuhTNE3viWWUR4PD6T7XfmdViUwmSf8fkRNUn/t3a2n',
        'cq46Xr36seCor/OLp0atSZwHrjx2SU5zPLheZn+zw/0d1/YZnD7AEeP9s/Cuycyv',
        'CZ5HZNKufvB8fsh+dfdSXW0GfqkPfxk36Vw8ufpjaoZDyt2nxxg/6D4KS3UvZzv3',
        'axdLZ9yd0OJNZv4P501If24W4vTGz6nI7Ser8Yd2PiOvE5MWMT0wLZQ+zPX1sv0/',
        's8PvkyWmVM0O0fB/ZSHovHNNPffDg/rWhzOmXQ9/7vTn477F+aWm5sYzJ75/BQA=',
        '=+L0S',
        '-----END PGP MESSAGE-----'].join('\n');

    const plaintext = 'short message\nnext line\n한국어/조선말';
    const sMsg = await openpgp.message.readArmored(msg_armor);
    const pubKey2 = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];
    const pubKey3 = (await openpgp.key.readArmored(pub_key_arm3)).keys[0];

    const keyids = sMsg.getSigningKeyIds();

    expect(pubKey2.getKeys(keyids[1])).to.not.be.empty;
    expect(pubKey3.getKeys(keyids[0])).to.not.be.empty;

    return sMsg.verify([pubKey2, pubKey3]).then(async verifiedSig => {
      expect(await openpgp.stream.readToEnd(sMsg.getText())).to.equal(plaintext);
      expect(verifiedSig).to.exist;
      expect(verifiedSig).to.have.length(2);
      expect(await verifiedSig[0].verified).to.be.true;
      expect(await verifiedSig[1].verified).to.be.true;
      expect((await verifiedSig[0].signature).packets.length).to.equal(1);
      expect((await verifiedSig[1].signature).packets.length).to.equal(1);
    });
  });

  it('Verify cleartext signed message with two signatures with openpgp.verify', async function() {
    const msg_armor =
      ['-----BEGIN PGP SIGNED MESSAGE-----',
        'Hash: SHA256',
        '',
        'short message',
        'next line',
        '한국어/조선말',
        '-----BEGIN PGP SIGNATURE-----',
        'Version: GnuPG v2.0.19 (GNU/Linux)',
        '',
        'iJwEAQEIAAYFAlKcju8ACgkQ4IT3RGwgLJci6gP/dCmIraUa6AGpJxzGfK+jYpjl',
        'G0KunFyGmyPxeJVnPi2bBp3EPIbiayQ71CcDe9DKpF046tora07AA9eo+/YbvJ9P',
        'PWeScw3oj/ejsmKQoDBGzyDMFUphevnhgc5lENjovJqmiu6FKjNmADTxcZ/qFTOq',
        '44EWTgdW3IqXFkNpKjeJARwEAQEIAAYFAlKcju8ACgkQ2/Ij6HBTTfQi6gf9HxhE',
        'ycLDhQ8iyC090TaYwsDytScU2vOMiI5rJCy2tfDV0pfn+UekYGMnKxZTpwtmno1j',
        'mVOlieENszz5IcehS5TYwk4lmRFjoba+Z8qwPEYhYxP29GMbmRIsH811sQHFTigo',
        'LI2t4pSSSUpAiXd9y6KtvkWcGGn8IfkNHCEHPh1ov28QvH0+ByIiKYK5N6ZB8hEo',
        '0uMYhKQPVJdPCvMkAxQCRPw84EvmxuJ0HMCeSB9tHQXpz5un2m8D9yiGpBQPnqlW',
        'vCCq7fgaUz8ksxvQ9bSwv0iIIbbBdTP7Z8y2c1Oof6NDl7irH+QCeNT7IIGs8Smn',
        'BEzv/FqkQAhjy3Krxg==',
        '=3Pkl',
        '-----END PGP SIGNATURE-----'].join('\n');

    const plaintext = 'short message\nnext line\n한국어/조선말';
    const csMsg = await openpgp.cleartext.readArmored(msg_armor);
    const pubKey2 = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];
    const pubKey3 = (await openpgp.key.readArmored(pub_key_arm3)).keys[0];

    const keyids = csMsg.getSigningKeyIds();

    expect(pubKey2.getKeys(keyids[0])).to.not.be.empty;
    expect(pubKey3.getKeys(keyids[1])).to.not.be.empty;

    return openpgp.verify({ publicKeys:[pubKey2, pubKey3], message:csMsg }).then(function(cleartextSig) {
      expect(cleartextSig).to.exist;
      expect(cleartextSig.data).to.equal(plaintext);
      expect(cleartextSig.signatures).to.have.length(2);
      expect(cleartextSig.signatures[0].valid).to.be.true;
      expect(cleartextSig.signatures[1].valid).to.be.true;
      expect(cleartextSig.signatures[0].signature.packets.length).to.equal(1);
      expect(cleartextSig.signatures[1].signature.packets.length).to.equal(1);
    });
  });

  it('Verify cleartext signed message with trailing spaces from GPG', async function() {
    const msg_armor =
      `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

space: 
space and tab: \t
no trailing space
  
tab:\t
tab and space:\t 
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1

iJwEAQECAAYFAlrZzCQACgkQ4IT3RGwgLJeWggP+Pb33ubbELIzg9/imM+zlR063
g0FbG4B+RGZNFSbaDArUgh9fdVqBy8M9vvbbDMBalSiQxY09Lrasfb+tsomrygbN
NisuPRa5phPhn1bB4hZDb2ed/iK41CNyU7QHuv4AAvLC0mMamRnEg0FW2M2jZLGh
zmuVOdNuWQqxT9Sqa84=
=bqAR
-----END PGP SIGNATURE-----`;

    const plaintext = 'space: \nspace and tab: \t\nno trailing space\n  \ntab:\t\ntab and space:\t ';
    const csMsg = await openpgp.cleartext.readArmored(msg_armor);
    const pubKey = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];

    const keyids = csMsg.getSigningKeyIds();

    expect(pubKey.getKeys(keyids[0])).to.not.be.empty;

    return openpgp.verify({ publicKeys:[pubKey], message:csMsg }).then(function(cleartextSig) {
      expect(cleartextSig).to.exist;
      expect(cleartextSig.data).to.equal(openpgp.util.removeTrailingSpaces(plaintext));
      expect(cleartextSig.signatures).to.have.length(1);
      expect(cleartextSig.signatures[0].valid).to.be.true;
      expect(cleartextSig.signatures[0].signature.packets.length).to.equal(1);
    });
  });

  it('Verify signed message with trailing spaces from GPG', async function() {
    const msg_armor =
      `-----BEGIN PGP MESSAGE-----
Version: GnuPG v1

owGbwMvMyMT4oOW7S46CznTG01El3MUFicmpxbolqcUlUTev14K5Vgq8XGCGQmJe
ikJJYpKVAicvV16+QklRYmZOZl66AliWl0sBqBAkzQmmwKohBnAqdMxhYWRkYmBj
ZQIZy8DFKQCztusM8z+Vt/svG80IS/etn90utv/T16jquk69zPvp6t9F16ryrwpb
kfVlS5Xl38KnVYxWvIor0nao6WUczA4vvZX9TXPWnnW3tt1vbZoiqWUjYjjjhuKG
4DtmMTuL3TW6/zNzVfWp/Q11+71O8RGnXMsBvWM6mSqX75uLiPo6HRaUDHnvrfCP
yYDnCgA=
=15ki
-----END PGP MESSAGE-----`;

    const plaintext = 'space: \nspace and tab: \t\nno trailing space\n  \ntab:\t\ntab and space:\t ';
    const sMsg = await openpgp.message.readArmored(msg_armor);
    const pubKey = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];

    const keyids = sMsg.getSigningKeyIds();

    expect(pubKey.getKeys(keyids[0])).to.not.be.empty;

    return openpgp.verify({ publicKeys:[pubKey], message:sMsg }).then(function(cleartextSig) {
      expect(cleartextSig).to.exist;
      expect(openpgp.util.nativeEOL(openpgp.util.Uint8Array_to_str(cleartextSig.data))).to.equal(plaintext);
      expect(cleartextSig.signatures).to.have.length(1);
      expect(cleartextSig.signatures[0].valid).to.be.true;
      expect(cleartextSig.signatures[0].signature.packets.length).to.equal(1);
    });
  });

  it('Streaming verify signed message with trailing spaces from GPG', async function() {
    const msg_armor =
      `-----BEGIN PGP MESSAGE-----
Version: GnuPG v1

owGbwMvMyMT4oOW7S46CznTG01El3MUFicmpxbolqcUlUTev14K5Vgq8XGCGQmJe
ikJJYpKVAicvV16+QklRYmZOZl66AliWl0sBqBAkzQmmwKohBnAqdMxhYWRkYmBj
ZQIZy8DFKQCztusM8z+Vt/svG80IS/etn90utv/T16jquk69zPvp6t9F16ryrwpb
kfVlS5Xl38KnVYxWvIor0nao6WUczA4vvZX9TXPWnnW3tt1vbZoiqWUjYjjjhuKG
4DtmMTuL3TW6/zNzVfWp/Q11+71O8RGnXMsBvWM6mSqX75uLiPo6HRaUDHnvrfCP
yYDnCgA=
=15ki
-----END PGP MESSAGE-----`.split('');

    const plaintext = 'space: \nspace and tab: \t\nno trailing space\n  \ntab:\t\ntab and space:\t ';
    const sMsg = await openpgp.message.readArmored(new ReadableStream({
      async pull(controller) {
        await new Promise(setTimeout);
        controller.enqueue(msg_armor.shift());
        if (!msg_armor.length) controller.close();
      }
    }));
    const pubKey = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];

    const keyids = sMsg.getSigningKeyIds();

    expect(pubKey.getKeys(keyids[0])).to.not.be.empty;

    return openpgp.verify({ publicKeys:[pubKey], message:sMsg }).then(async function(cleartextSig) {
      expect(cleartextSig).to.exist;
      expect(openpgp.util.nativeEOL(openpgp.util.Uint8Array_to_str(await openpgp.stream.readToEnd(cleartextSig.data)))).to.equal(plaintext);
      expect(cleartextSig.signatures).to.have.length(1);
      expect(await cleartextSig.signatures[0].verified).to.be.true;
      expect((await cleartextSig.signatures[0].signature).packets.length).to.equal(1);
    });
  });

  it('Sign text with openpgp.sign and verify with openpgp.verify leads to same string cleartext and valid signatures', async function() {
    const plaintext = 'short message\nnext line \n한국어/조선말';
    const pubKey = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];
    const privKey = (await openpgp.key.readArmored(priv_key_arm2)).keys[0];
    await privKey.decrypt('hello world');

    return openpgp.sign({ privateKeys:[privKey], message: openpgp.cleartext.fromText(plaintext) }).then(async function(signed) {

      const csMsg = await openpgp.cleartext.readArmored(signed.data);
      return openpgp.verify({ publicKeys:[pubKey], message:csMsg });

    }).then(function(cleartextSig) {
      expect(cleartextSig).to.exist;
      expect(cleartextSig.data).to.equal(openpgp.util.removeTrailingSpaces(plaintext.replace(/\r/g,'')));
      expect(cleartextSig.signatures).to.have.length(1);
      expect(cleartextSig.signatures[0].valid).to.be.true;
      expect(cleartextSig.signatures[0].signature.packets.length).to.equal(1);
    });
  });

  it('Sign text with openpgp.sign and verify with openpgp.verify leads to same string cleartext and valid signatures -- escape armored message', async function() {
    const plaintext = pub_key_arm2;
    const pubKey = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];
    const privKey = (await openpgp.key.readArmored(priv_key_arm2)).keys[0];
    await privKey.decrypt('hello world');

    return openpgp.sign({ privateKeys:[privKey], message: openpgp.cleartext.fromText(plaintext) }).then(async function(signed) {

      const csMsg = await openpgp.cleartext.readArmored(signed.data);
      return openpgp.verify({ publicKeys:[pubKey], message:csMsg });

    }).then(function(cleartextSig) {
      expect(cleartextSig).to.exist;
      expect(cleartextSig.data).to.equal(plaintext);
      expect(cleartextSig.signatures).to.have.length(1);
      expect(cleartextSig.signatures[0].valid).to.be.true;
      expect(cleartextSig.signatures[0].signature.packets.length).to.equal(1);
    });
  });

  it('Sign text with openpgp.sign and verify with openpgp.verify leads to same string cleartext and valid signatures -- trailing spaces', async function() {
    const plaintext = 'space: \nspace and tab: \t\nno trailing space\n  \ntab:\t\ntab and space:\t ';
    const pubKey = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];
    const privKey = (await openpgp.key.readArmored(priv_key_arm2)).keys[0];
    await privKey.decrypt('hello world');

    return openpgp.sign({ privateKeys:[privKey], message: openpgp.cleartext.fromText(plaintext) }).then(async function(signed) {

      const csMsg = await openpgp.cleartext.readArmored(signed.data);
      return openpgp.verify({ publicKeys:[pubKey], message:csMsg });

    }).then(function(cleartextSig) {
      expect(cleartextSig).to.exist;
      expect(cleartextSig.data).to.equal(openpgp.util.removeTrailingSpaces(plaintext));
      expect(cleartextSig.signatures).to.have.length(1);
      expect(cleartextSig.signatures[0].valid).to.be.true;
      expect(cleartextSig.signatures[0].signature.packets.length).to.equal(1);
    });
  });

  it('Sign text with openpgp.sign and verify with openpgp.verify leads to same bytes cleartext and valid signatures - armored', async function() {
    const plaintext = openpgp.util.str_to_Uint8Array('short message\nnext line \n한국어/조선말');
    const pubKey = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];
    const privKey = (await openpgp.key.readArmored(priv_key_arm2)).keys[0];
    await privKey.decrypt('hello world');

    return openpgp.sign({ privateKeys:[privKey], message: openpgp.message.fromBinary(plaintext) }).then(async function(signed) {

      const csMsg = await openpgp.message.readArmored(signed.data);
      return openpgp.verify({ publicKeys:[pubKey], message:csMsg });

    }).then(async function(cleartextSig) {
      expect(cleartextSig).to.exist;
      expect(cleartextSig.data).to.deep.equal(plaintext);
      expect(cleartextSig.signatures).to.have.length(1);
      expect(cleartextSig.signatures[0].valid).to.be.true;
      expect(cleartextSig.signatures[0].signature.packets.length).to.equal(1);
    });
  });

  it('Sign text with openpgp.sign and verify with openpgp.verify leads to same bytes cleartext and valid signatures - not armored', async function() {
    const plaintext = openpgp.util.str_to_Uint8Array('short message\nnext line \n한국어/조선말');
    const pubKey = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];
    const privKey = (await openpgp.key.readArmored(priv_key_arm2)).keys[0];
    await privKey.decrypt('hello world');

    return openpgp.sign({ privateKeys:[privKey], message: openpgp.message.fromBinary(plaintext), armor:false }).then(function(signed) {

      const csMsg = signed.message;
      return openpgp.verify({ publicKeys:[pubKey], message:csMsg });

    }).then(function(cleartextSig) {
      expect(cleartextSig).to.exist;
      expect(cleartextSig.data).to.deep.equal(plaintext);
      expect(cleartextSig.signatures).to.have.length(1);
      expect(cleartextSig.signatures[0].valid).to.be.true;
      expect(cleartextSig.signatures[0].signature.packets.length).to.equal(1);
    });
  });

  it('Should verify cleartext message correctly when using a detached cleartext signature and binary literal data', async function () {
    const plaintext = 'short message\nnext line \n한국어/조선말';
    const pubKey = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];
    const privKey = (await openpgp.key.readArmored(priv_key_arm2)).keys[0];
    await privKey.decrypt('hello world');
    return openpgp.sign({ privateKeys:[privKey], message: openpgp.message.fromText(plaintext), detached: true}).then(async function(signed) {
      const signature = await openpgp.signature.readArmored(signed.signature);
      return openpgp.verify({ publicKeys:[pubKey], message: openpgp.message.fromBinary(openpgp.util.encode_utf8(plaintext)), signature: signature });
    }).then(function(cleartextSig) {
      expect(cleartextSig).to.exist;
      expect(cleartextSig.signatures).to.have.length(1);
      expect(cleartextSig.signatures[0].valid).to.be.true;
      expect(cleartextSig.signatures[0].signature.packets.length).to.equal(1);
    });
  });

  it('Should verify cleartext message correctly when using a detached binary signature and text literal data', async function () {
    const plaintext = 'short message\nnext line \n한국어/조선말';
    const plaintextArray = openpgp.util.str_to_Uint8Array(plaintext);
    const pubKey = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];
    const privKey = (await openpgp.key.readArmored(priv_key_arm2)).keys[0];
    await privKey.decrypt('hello world');
    return openpgp.sign({ privateKeys:[privKey], message:openpgp.message.fromBinary(plaintextArray), detached: true}).then(async function(signed) {
      const signature = await openpgp.signature.readArmored(signed.signature);
      return openpgp.verify({ publicKeys:[pubKey], message: openpgp.message.fromText(plaintext), signature: signature });
    }).then(function(cleartextSig) {
      expect(cleartextSig).to.exist;
      expect(cleartextSig.signatures).to.have.length(1);
      expect(cleartextSig.signatures[0].valid).to.be.true;
      expect(cleartextSig.signatures[0].signature.packets.length).to.equal(1);
    });
  });

  it('Should verify encrypted cleartext message correctly when encrypting binary literal data with a canonical text signature', async function () {
    const plaintext = 'short message\nnext line \n한국어/조선말';
    const pubKey = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];
    const privKey = (await openpgp.key.readArmored(priv_key_arm2)).keys[0];
    await Promise.all([privKey.primaryKey.decrypt('hello world'), privKey.subKeys[0].keyPacket.decrypt('hello world')]);
    return openpgp.sign({ privateKeys:[privKey], message: openpgp.message.fromText(plaintext), detached: true}).then(async function(signed) {
      const signature = await openpgp.signature.readArmored(signed.signature);
      return openpgp.encrypt({ message: openpgp.message.fromBinary(openpgp.util.encode_utf8(plaintext)), publicKeys: [pubKey], signature })
    }).then(async ({ data }) => {
      const csMsg = await openpgp.message.readArmored(data);
      return openpgp.decrypt({ message: csMsg, privateKeys: [ privKey ], publicKeys: [ pubKey ] });
    }).then(function(cleartextSig) {
      expect(cleartextSig).to.exist;
      expect(cleartextSig.signatures).to.have.length(1);
      expect(cleartextSig.signatures[0].valid).to.be.true;
      expect(cleartextSig.signatures[0].signature.packets.length).to.equal(1);
    });
  });

  it('Verify test with expired verification public key', async function() {
    const pubKey = (await openpgp.key.readArmored(pub_expired)).keys[0];
    const message = await openpgp.message.readArmored(msg_sig_expired);
    return openpgp.verify({ publicKeys:[pubKey], message:message }).then(function(verified) {
      expect(verified).to.exist;
      expect(verified.signatures).to.have.length(1);
      expect(verified.signatures[0].valid).to.not.be.true;
      expect(verified.signatures[0].signature.packets.length).to.equal(1);
    });

  });

  it('Verify test with expired verification public key and disable expiration checks using null date', async function() {
    const pubKey = (await openpgp.key.readArmored(pub_expired)).keys[0];
    const message = await openpgp.message.readArmored(msg_sig_expired);
    return openpgp.verify({ publicKeys:[pubKey], message:message, date: null }).then(function(verified) {
      expect(verified).to.exist;
      expect(verified.signatures).to.have.length(1);
      expect(verified.signatures[0].valid).to.be.true;
      expect(verified.signatures[0].signature.packets.length).to.equal(1);
    });

  });

  it('Verify test with expired verification public key', async function() {
    const pubKey = (await openpgp.key.readArmored(pub_expired)).keys[0];
    const message = await openpgp.message.readArmored(msg_sig_expired);
    return openpgp.verify({ publicKeys:[pubKey], message:message }).then(function(verified) {
      expect(verified).to.exist;
      expect(verified.signatures).to.have.length(1);
      expect(verified.signatures[0].valid).to.not.be.true;
      expect(verified.signatures[0].signature.packets.length).to.equal(1);
    });

  });

  it('Verify test with expired verification public key and disable expiration checks using null date', async function() {
    const pubKey = (await openpgp.key.readArmored(pub_expired)).keys[0];
    const message = await openpgp.message.readArmored(msg_sig_expired);
    return openpgp.verify({ publicKeys:[pubKey], message:message, date: null }).then(function(verified) {
      expect(verified).to.exist;
      expect(verified.signatures).to.have.length(1);
      expect(verified.signatures[0].valid).to.be.true;
      expect(verified.signatures[0].signature.packets.length).to.equal(1);
    });

  });

  // TODO add test with multiple revocation signatures
  it('Verify primary key revocation signatures', async function() {
    const pubKey = (await openpgp.key.readArmored(pub_revoked)).keys[0];
    await expect(pubKey.revocationSignatures[0].verify(
      pubKey.primaryKey, {key: pubKey.primaryKey}
    )).to.eventually.be.true;
  });

  // TODO add test with multiple revocation signatures
  it('Verify subkey revocation signatures', async function() {
    const pubKey = (await openpgp.key.readArmored(pub_revoked)).keys[0];
    await expect(pubKey.subKeys[0].revocationSignatures[0].verify(
      pubKey.primaryKey, {key: pubKey.primaryKey, bind: pubKey.subKeys[0].keyPacket}
    )).to.eventually.be.true;
  });

  it('Verify key expiration date', async function() {
    const pubKey = (await openpgp.key.readArmored(pub_revoked)).keys[0];

    expect(pubKey).to.exist;
    expect(pubKey.users[0].selfCertifications[0].keyNeverExpires).to.be.false;
    expect(pubKey.users[0].selfCertifications[0].keyExpirationTime).to.equal(5*365*24*60*60);
  });

  it('Write unhashed subpackets', async function() {
    let pubKey = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];
    expect(pubKey.users[0].selfCertifications).to.exist;
    pubKey = (await openpgp.key.readArmored(pubKey.armor())).keys[0];
    expect(pubKey.users[0].selfCertifications).to.exist;
  });

  it('Write V4 signatures', async function() {
    const pubKey = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];
    const pubKey2 = (await openpgp.key.readArmored(pubKey.armor())).keys[0];
    expect(pubKey2).to.exist;
    expect(pubKey.users[0].selfCertifications).to.eql(pubKey2.users[0].selfCertifications);
  });

  it('Verify a detached signature using appendSignature', async function() {
    const detachedSig = ['-----BEGIN PGP SIGNATURE-----',
      'Version: GnuPG v1.4.13 (Darwin)',
      'Comment: GPGTools - https://gpgtools.org',
      'Comment: Using GnuPG with Thunderbird - https://www.enigmail.net/',
      '',
      'iQEcBAEBCgAGBQJTqH5OAAoJENf7k/zfv8I8oFoH/R6EFTw2CYUQoOKSAQstWIHp',
      'fVVseLOkFbByUV5eLuGVBNI3DM4GQ6C7dGntKAn34a1iTGcAIZH+fIhaZ2WtNdtA',
      'R+Ijn8xDjbF/BWvcTBOaRvgw9b8viPxhkVYa3PioHYz6krt/LmFqFdp/phWZcqR4',
      'jzWMX55h4FOw3YBNGiz2NuIg+iGrFRWPYgd8NVUmJKReZHs8C/6HGz7F4/A24k6Y',
      '7xms9D6Er+MhspSl+1dlRdHjtXiRqC5Ld1hi2KBKc6YzgOLpVw5l9sffbnH+aRG4',
      'dH+2J5U3elqBDK1i3GyG8ixLSB0FGW9+lhYNosZne2xy8SbQKdgsnTBnWSGevP0=',
      '=xiih',
      '-----END PGP SIGNATURE-----'].join('\r\n');

    const content = ['Content-Type: multipart/mixed;',
      ' boundary="------------070307080002050009010403"',
      '',
      'This is a multi-part message in MIME format.',
      '--------------070307080002050009010403',
      'Content-Type: text/plain; charset=ISO-8859-1',
      'Content-Transfer-Encoding: quoted-printable',
      '',
      'test11',
      '',
      '--------------070307080002050009010403',
      'Content-Type: application/macbinary;',
      ' name="test.bin"',
      'Content-Transfer-Encoding: base64',
      'Content-Disposition: attachment;',
      ' filename="test.bin"',
      '',
      'dGVzdGF0dGFjaG1lbnQ=',
      '--------------070307080002050009010403--',
      ''].join('\r\n');

    const publicKeyArmored = '-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nVersion: OpenPGP.js v.1.20131116\r\nComment: Whiteout Mail - https://whiteout.io\r\n\r\nxsBNBFKODs4BB/9iOF4THsjQMY+WEpT7ShgKxj4bHzRRaQkqczS4nZvP0U3g\r\nqeqCnbpagyeKXA+bhWFQW4GmXtgAoeD5PXs6AZYrw3tWNxLKu2Oe6Tp9K/XI\r\nxTMQ2wl4qZKDXHvuPsJ7cmgaWqpPyXtxA4zHHS3WrkI/6VzHAcI/y6x4szSB\r\nKgSuhI3hjh3s7TybUC1U6AfoQGx/S7e3WwlCOrK8GTClirN/2mCPRC5wuIft\r\nnkoMfA6jK8d2OPrJ63shy5cgwHOjQg/xuk46dNS7tkvGmbaa+X0PgqSKB+Hf\r\nYPPNS/ylg911DH9qa8BqYU2QpNh9jUKXSF+HbaOM+plWkCSAL7czV+R3ABEB\r\nAAHNLVdoaXRlb3V0IFVzZXIgPHNhZmV3aXRobWUudGVzdHVzZXJAZ21haWwu\r\nY29tPsLAXAQQAQgAEAUCUo4O2gkQ1/uT/N+/wjwAAN2cB/9gFRmAfvEQ2qz+\r\nWubmT2EsSSnjPMxzG4uyykFoa+TaZCWo2Xa2tQghmU103kEkQb1OEjRjpgwJ\r\nYX9Kghnl8DByM686L5AXnRyHP78qRJCLXSXl0AGicboUDp5sovaa4rswQceH\r\nvcdWgZ/mgHTRoiQeJddy9k+H6MPFiyFaVcFwegVsmpc+dCcC8yT+qh8ZIbyG\r\nRJU60PmKKN7LUusP+8DbSv39zCGJCBlVVKyA4MzdF5uM+sqTdXbKzOrT5DGd\r\nCZaox4s+w16Sq1rHzZKFWfQPfKLDB9pyA0ufCVRA3AF6BUi7G3ZqhZiHNhMP\r\nNvE45V/hS1PbZcfPVoUjE2qc1Ix1\r\n=7Wpe\r\n-----END PGP PUBLIC KEY BLOCK-----';
    const publicKeys = (await openpgp.key.readArmored(publicKeyArmored)).keys;

    // Text
    const msg = openpgp.message.fromText(content);
    await msg.appendSignature(detachedSig);
    return msg.verify(publicKeys).then(async result => {
      openpgp.stream.pipe(msg.getLiteralData(), new WritableStream());
      expect(await result[0].verified).to.be.true;
    });
  });

  it('Detached signature signing and verification', async function() {
    const msg = openpgp.message.fromText('hello');
    const pubKey2 = (await openpgp.key.readArmored(pub_key_arm2)).keys[0];
    const privKey2 = (await openpgp.key.readArmored(priv_key_arm2)).keys[0];
    await privKey2.decrypt('hello world');

    const opt = {numBits: 512, userIds: { name:'test', email:'a@b.com' }, passphrase: null};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    return openpgp.generateKey(opt).then(function(gen) {
      const generatedKey = gen.key;
      return msg.signDetached([generatedKey, privKey2]).then(detachedSig => {
        return msg.verifyDetached(detachedSig, [generatedKey.toPublic(), pubKey2]).then(async result => {
          expect(await result[0].verified).to.be.true;
          expect(await result[1].verified).to.be.true;
        });
      });
    });
  });

  it('Sign message with key without password', function() {
    const opt = {numBits: 512, userIds: { name:'test', email:'a@b.com' }, passphrase: null};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    return openpgp.generateKey(opt).then(function(gen) {
      const key = gen.key;
      let message = openpgp.message.fromText('hello world');
      message = message.sign([key]);
      expect(message).to.exist;
    });
  });

  it('Verify signed key', async function() {
    const signedArmor = [
      '-----BEGIN PGP PUBLIC KEY BLOCK-----',
      'Version: GnuPG v1',
      '',
      'mI0EUmEvTgEEANyWtQQMOybQ9JltDqmaX0WnNPJeLILIM36sw6zL0nfTQ5zXSS3+',
      'fIF6P29lJFxpblWk02PSID5zX/DYU9/zjM2xPO8Oa4xo0cVTOTLj++Ri5mtr//f5',
      'GLsIXxFrBJhD/ghFsL3Op0GXOeLJ9A5bsOn8th7x6JucNKuaRB6bQbSPABEBAAG0',
      'JFRlc3QgTWNUZXN0aW5ndG9uIDx0ZXN0QGV4YW1wbGUuY29tPoi5BBMBAgAjBQJS',
      'YS9OAhsvBwsJCAcDAgEGFQgCCQoLBBYCAwECHgECF4AACgkQSmNhOk1uQJQwDAP6',
      'AgrTyqkRlJVqz2pb46TfbDM2TDF7o9CBnBzIGoxBhlRwpqALz7z2kxBDmwpQa+ki',
      'Bq3jZN/UosY9y8bhwMAlnrDY9jP1gdCo+H0sD48CdXybblNwaYpwqC8VSpDdTndf',
      '9j2wE/weihGp/DAdy/2kyBCaiOY1sjhUfJ1GogF49rCIRgQQEQIABgUCVuXBfQAK',
      'CRARJ5QDyxae+O0fAJ9hUQPejXvZv6VW1Q3/Pm3+x2wfJACgwFg9NlrPPfejoC1w',
      'P+z+vE5NFA24jQRSYS9OAQQA6R/PtBFaJaT4jq10yqASk4sqwVMsc6HcifM5lSdx',
      'zExFP74naUMMyEsKHP53QxTF0GrqusagQg/ZtgT0CN1HUM152y7ACOdp1giKjpMz',
      'OTQClqCoclyvWOFB+L/SwGEIJf7LSCErwoBuJifJc8xAVr0XX0JthoW+uP91eTQ3',
      'XpsAEQEAAYkBPQQYAQIACQUCUmEvTgIbLgCoCRBKY2E6TW5AlJ0gBBkBAgAGBQJS',
      'YS9OAAoJEOCE90RsICyXuqIEANmmiRCASF7YK7PvFkieJNwzeK0V3F2lGX+uu6Y3',
      'Q/Zxdtwc4xR+me/CSBmsURyXTO29OWhPGLszPH9zSJU9BdDi6v0yNprmFPX/1Ng0',
      'Abn/sCkwetvjxC1YIvTLFwtUL/7v6NS2bZpsUxRTg9+cSrMWWSNjiY9qUKajm1tu',
      'zPDZXAUEAMNmAN3xXN/Kjyvj2OK2ck0XW748sl/tc3qiKPMJ+0AkMF7Pjhmh9nxq',
      'E9+QCEl7qinFqqBLjuzgUhBU4QlwX1GDAtNTq6ihLMD5v1d82ZC7tNatdlDMGWnI',
      'dvEMCv2GZcuIqDQ9rXWs49e7tq1NncLYhz3tYjKhoFTKEIq3y3Pp',
      '=fvK7',
      '-----END PGP PUBLIC KEY BLOCK-----'
    ].join('\n');

    const signedKey = (await openpgp.key.readArmored(signedArmor)).keys[0];
    const signerKey = (await openpgp.key.readArmored(priv_key_arm1)).keys[0];
    return signedKey.verifyPrimaryUser([signerKey]).then(signatures => {
      expect(signatures[0].valid).to.be.null;
      expect(signatures[0].keyid.toHex()).to.equal(signedKey.getKeyId().toHex());
      expect(signatures[1].valid).to.be.true;
      expect(signatures[1].keyid.toHex()).to.equal(signerKey.getKeyId().toHex());
    });
  });

  it('Verify signed UserIDs and User Attributes', async function() {
    const armoredKeyWithPhoto = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EW1CJGAEEAM+BzuFzcYk9HttmDbjGexQ8dfme074Q5PuHas3PBISPm0AwmnDM
tzjlcrrg2VGuLqHvNF600w2ZgOo2gElNYCOas1q/fVFuIgJ4SUduNOEe/JnIW4uP
iEGU9l6zOVVgTc/nGVpZdvHgvOL8nl9BKHtWEnMD3Du7UYAm+Avshu9jABEBAAG0
AViI1AQTAQoAPhYhBKcH118Rrg0wLBrTk5IyMikCym+4BQJbUIkYAhsDBQkDwmcA
BQsJCAcDBRUKCQgLBRYDAgEAAh4BAheAAAoJEJIyMikCym+4K8oEAJc7YFiNau6V
HTVK4cTvWU5MuYiejejFZai4ELUJy+WF6cZYrLuF/z/kRt8B7hpumXChPCUlT0q7
FWypQtA3leu83DGMXqhfS80h2S1+VLmDVVWKQXOwgOb44jT9F08bDU5QK08SkjF8
/EirIy8ANzdwCA4rHytIS2yx6tLlthvX0cBwwG4BEAABAQAAAAAAAAAAAAAAAP/Y
/+AAEEpGSUYAAQEAAAEAAQAA/9sAQwABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB
AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB/9sAQwEBAQEB
AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB
AQEBAQEBAQEBAQEB/8AAEQgAAQABAwEiAAIRAQMRAf/EABUAAQEAAAAAAAAAAAAA
AAAAAAAK/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/EABQBAQAAAAAAAAAAAAAAAAAA
AAD/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwC/gAH/2YjUBBMB
CgA+FiEEpwfXXxGuDTAsGtOTkjIyKQLKb7gFAltQimUCGwMFCQPCZwAFCwkIBwMF
FQoJCAsFFgMCAQACHgECF4AACgkQkjIyKQLKb7gm/wQAiyZF89qr8hf3XQNJ6Ir/
QtaniPcesjrYCIE47ZfeDYpBTPeiMm295o2dZXVJS4ItllYsplASw5DJiIMnQKlJ
mbXakYFzzclTa/JrKzFYCy/DPT95xK+633omgrIUgJodizoKJE7XeB2U6aRUJJ4O
iTuGu4fEU1UligAXSrZmCdE=
=VK6I
-----END PGP PUBLIC KEY BLOCK-----`;

    const key = (await openpgp.key.readArmored(armoredKeyWithPhoto)).keys[0];
    for (const user of key.users) {
      expect(await user.verify(key.primaryKey)).to.equal(openpgp.enums.keyStatus.valid);
    }
  });

});
