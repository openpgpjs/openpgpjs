'use strict';

var openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');
var elliptic = openpgp.crypto.publicKey.elliptic;

var chai = require('chai');
chai.use(require('chai-as-promised'));
var expect = chai.expect;

describe('X25519 Cryptography', function () {
  var data = {
    light: {
      id: '1ecdf026c0245830',
      pass: 'sun',
      pub: [
        '-----BEGIN PGP PUBLIC KEY BLOCK-----',
        '',
        'mDMEWkN+5BYJKwYBBAHaRw8BAQdAIGqj23Kp273IPkgjwA7ue5MDIRAfWLYRqnFy',
        'c2AFMcC0EUxpZ2h0IDxsaWdodEBzdW4+iJAEExYIADgWIQSGS0GuVELT3Rs0woce',
        'zfAmwCRYMAUCWkN+5AIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRAezfAm',
        'wCRYMLteAQCFZcl8kBxCH86wmqpc2+KtEA8l/hsfh7jd+JWuyFuuRAD7BOix8Vo1',
        'P/hv8qUYwSn3IRXPeGXucoWVoKGgxRd+zAO4OARaQ37kEgorBgEEAZdVAQUBAQdA',
        'L1KkHCFxtK1CgvZlInT/y6OQeCfXiYzd/i452t2ZR2ADAQgHiHgEGBYIACAWIQSG',
        'S0GuVELT3Rs0wocezfAmwCRYMAUCWkN+5AIbDAAKCRAezfAmwCRYMJ71AQDmoQTg',
        '36pfjrl82srS6XPRJxl3r/6lpWGaNij0VptB2wEA2V10ifOhnwILCw1qBle6On7a',
        'Ba257lrFM+cOSMaEsgo=',
        '=D8HS',
        '-----END PGP PUBLIC KEY BLOCK-----'].join('\n'),
      priv: [
        '-----BEGIN PGP PRIVATE KEY BLOCK-----',
        '',
        'lIYEWkN+5BYJKwYBBAHaRw8BAQdAIGqj23Kp273IPkgjwA7ue5MDIRAfWLYRqnFy',
        'c2AFMcD+BwMCeaL+cNXzgI7uJQ7HBv53TAXO3y5uyJQMonkFtQtldL8YDbNP3pbd',
        '3zzo9fxU12bWAJyFwBlBWJqkrxZN+0jt0ElsG3kp+V67MESJkrRhKrQRTGlnaHQg',
        'PGxpZ2h0QHN1bj6IkAQTFggAOBYhBIZLQa5UQtPdGzTChx7N8CbAJFgwBQJaQ37k',
        'AhsDBQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEB7N8CbAJFgwu14BAIVlyXyQ',
        'HEIfzrCaqlzb4q0QDyX+Gx+HuN34la7IW65EAPsE6LHxWjU/+G/ypRjBKfchFc94',
        'Ze5yhZWgoaDFF37MA5yLBFpDfuQSCisGAQQBl1UBBQEBB0AvUqQcIXG0rUKC9mUi',
        'dP/Lo5B4J9eJjN3+Ljna3ZlHYAMBCAf+BwMCvyW2D5Yx6dbujE3yHi1XQ9MbhOY5',
        'XRFFgYIUYzzi1qmaL+8Gr9zODsUdeO60XHnMXOmqVa6/sdx32TWo5s3sgS19kRUM',
        'D+pbxS/aZnxvrYh4BBgWCAAgFiEEhktBrlRC090bNMKHHs3wJsAkWDAFAlpDfuQC',
        'GwwACgkQHs3wJsAkWDCe9QEA5qEE4N+qX465fNrK0ulz0ScZd6/+paVhmjYo9Fab',
        'QdsBANlddInzoZ8CCwsNagZXujp+2gWtue5axTPnDkjGhLIK',
        '=wo91',
        '-----END PGP PRIVATE KEY BLOCK-----'].join('\n'),
      message: 'Hi, Light wrote this!',
      message_signed: [
        '-----BEGIN PGP SIGNED MESSAGE-----',
        'Hash: SHA256',
        '',
        'Hi, Light wrote this!',
        '-----BEGIN PGP SIGNATURE-----',
        '',
        'iIAEARYIACgWIQSGS0GuVELT3Rs0wocezfAmwCRYMAUCWkyVkAocbGlnaHRAc3Vu',
        'AAoJEB7N8CbAJFgwdqAA/RwTsy9Nt5HEJLnokUNgHVX8wNr7Ef9wfAG1RaMgMMWs',
        'AP9KEEohpHqaj8smb1oLjYU9DgOugE40LrkujvnWNbOZBQ==',
        '=T9p+',
        '-----END PGP SIGNATURE-----'].join('\n')
    },
    night: {
      id: 'f25e5f24bb372cfa',
      pass: 'moon',
      pub: [
        '-----BEGIN PGP PUBLIC KEY BLOCK-----',
        '',
        'mDMEWkN/RRYJKwYBBAHaRw8BAQdAM359sYg+LtcQo9G+mzMwxiu6wgY7UTVyip+V',
        'y8CWMhy0Ek5pZ2h0IDxuaWdodEBtb29uPoiQBBMWCAA4FiEEdracm9388E/nI0Df',
        '8l5fJLs3LPoFAlpDf0UCGwMFCwkIBwIGFQgJCgsCBBYCAwECHgECF4AACgkQ8l5f',
        'JLs3LPqoFAD+IkES10NVLoInYf6rMcxKY2/Nn+Dg4aYtdvphY8hY0b0A/jl34YEe',
        'cZAQvGWueGa5X2sCJvR1WZEMUWjW9cfR0TIHuDgEWkN/RRIKKwYBBAGXVQEFAQEH',
        'QCeuETdjFsEorruYHXmASKo7VNVgm29EZeA4bgbX1gsVAwEIB4h4BBgWCAAgFiEE',
        'dracm9388E/nI0Df8l5fJLs3LPoFAlpDf0UCGwwACgkQ8l5fJLs3LPojTgEApyg3',
        'Gd7R77zhC8mkSDIssegrFCoLqDgNYOSISgixUdgA/j7tIDGF45C9JC4LQsjfKY9W',
        'Td0I97hWRfub9tYo0P8K',
        '=nbhM',
        '-----END PGP PUBLIC KEY BLOCK-----'].join('\n'),
      priv: [
        '-----BEGIN PGP PRIVATE KEY BLOCK-----',
        '',
        'lIYEWkN/RRYJKwYBBAHaRw8BAQdAM359sYg+LtcQo9G+mzMwxiu6wgY7UTVyip+V',
        'y8CWMhz+BwMCxwCG2X+GJp7uQHSoj4fmvArR8d9hzyKBKDX84QsC1nCqMNRARz1v',
        'aSqXfCt4gLzR3sZh4yS0cDUB0UdDfFhh3XiG2j8zRJ3cKkXdV3GcSbQSTmlnaHQg',
        'PG5pZ2h0QG1vb24+iJAEExYIADgWIQR2tpyb3fzwT+cjQN/yXl8kuzcs+gUCWkN/',
        'RQIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRDyXl8kuzcs+qgUAP4iQRLX',
        'Q1Uugidh/qsxzEpjb82f4ODhpi12+mFjyFjRvQD+OXfhgR5xkBC8Za54ZrlfawIm',
        '9HVZkQxRaNb1x9HRMgeciwRaQ39FEgorBgEEAZdVAQUBAQdAJ64RN2MWwSiuu5gd',
        'eYBIqjtU1WCbb0Rl4DhuBtfWCxUDAQgH/gcDAoeG6mA2BitC7sbt5erYFzAndJx3',
        'fOBDIo9MF2xo/JX1OrL5Z9Fro1UP+A3P+YyZQ3W/PMMVFArfnyiEoJAmQOkashgd',
        'CocKYaKUNrgbYl2IeAQYFggAIBYhBHa2nJvd/PBP5yNA3/JeXyS7Nyz6BQJaQ39F',
        'AhsMAAoJEPJeXyS7Nyz6I04BAKcoNxne0e+84QvJpEgyLLHoKxQqC6g4DWDkiEoI',
        'sVHYAP4+7SAxheOQvSQuC0LI3ymPVk3dCPe4VkX7m/bWKND/Cg==',
        '=NDSU',
        '-----END PGP PRIVATE KEY BLOCK-----'].join('\n'),
      message: 'Oh hi, this is a private message from Light to Night!',
      message_encrypted: [
        '-----BEGIN PGP MESSAGE-----',
        '',
        'hF4DzfwiGcVT05ISAQdAetSWotgG0+MTEfyKvagrHAeGw0Denjph+Mu2KcpAajIw',
        'kE398hrqnc6qYFdf3p761kzvgjX0auua8L2WFlhAzGh1ULodxHVLmvxwiId4JwHq',
        '0sAzAaM+Vn5hfDM5799p2DpPK8635LN0UvtlOqGIdaNfu5DgfoherMSb3zlBa4YF',
        'WJG1Fa9glfWTOlMNKKoFl4LUh1BUF4TbqUv3a0BR6GcDy6zSp4KRl3NIq22fUD/F',
        'BZWuhPRhnsvDAoBTbvlgjyuActYhtXU5srMAEh4UeVvKyU8xImDfLgJReU4500JU',
        'VjZkMXTileVhAprvE5KCCDWi6YWzV+SSpn+VhtnShAfoF870GI+DOnvFwEnhQlol',
        'JRZdfjq5haoEjWTuqSIS+O40AgmQYPIjnO5ALehFuWTHKLDFVv4EDqx7MatXZidz',
        'drpAMWGi',
        '=erKa',
        '-----END PGP MESSAGE-----'].join('\n')
    }
  };
  function load_pub_key(name) {
    if (data[name].pub_key) {
      return data[name].pub_key;
    }
    var pub = openpgp.key.readArmored(data[name].pub);
    expect(pub).to.exist;
    expect(pub.err).to.not.exist;
    expect(pub.keys).to.have.length(1);
    expect(pub.keys[0].primaryKey.getKeyId().toHex()).to.equal(data[name].id);
    data[name].pub_key = pub.keys[0];
    return data[name].pub_key;
  }
  function load_priv_key(name) {
    if (data[name].priv_key) {
      return data[name].priv_key;
    }
    var pk = openpgp.key.readArmored(data[name].priv);
    expect(pk).to.exist;
    expect(pk.err).to.not.exist;
    expect(pk.keys).to.have.length(1);
    expect(pk.keys[0].primaryKey.getKeyId().toHex()).to.equal(data[name].id);
    expect(pk.keys[0].decrypt(data[name].pass)).to.be.true;
    data[name].priv_key = pk.keys[0];
    return data[name].priv_key;
  }
  it('Load public key', function (done) {
    load_pub_key('light');
    load_pub_key('night');
    done();
  });
  it('Load private key', function (done) {
    load_priv_key('light');
    load_priv_key('night');
    done();
  }).timeout(10000);
  it('Verify clear signed message', function () {
    var name = 'light';
    var pub = load_pub_key(name);
    var msg = openpgp.cleartext.readArmored(data[name].message_signed);
    return openpgp.verify({publicKeys: [pub], message: msg}).then(function(result) {
      expect(result).to.exist;
      expect(result.data.trim()).to.equal(data[name].message);
      expect(result.signatures).to.have.length(1);
      expect(result.signatures[0].valid).to.be.true;
    });
  });
  // FIXME is this pattern correct?
  it('Sign message', function () {
    var name = 'light'
    var priv = load_priv_key(name);
    return openpgp.sign({privateKeys: [priv], data: data[name].message + "\n"}).then(function (signed) {
      var pub = load_pub_key(name);
      var msg = openpgp.cleartext.readArmored(signed.data);
      return openpgp.verify({publicKeys: [pub], message: msg}).then(function (result) {
        expect(result).to.exist;
        expect(result.data.trim()).to.equal(data[name].message);
        expect(result.signatures).to.have.length(1);
        expect(result.signatures[0].valid).to.be.true;
      });
    });
  });
  it('Decrypt and verify message', function () {
    var light = load_pub_key('light');
    var night = load_priv_key('night');
    expect(night.decrypt(data['night'].pass)).to.be.true;
    var msg = openpgp.message.readArmored(data['night'].message_encrypted);
    return openpgp.decrypt(
      {privateKey: night, publicKeys: [light], message: msg}
    ).then(function (result) {
      expect(result).to.exist;
      // trim required because https://github.com/openpgpjs/openpgpjs/issues/311
      expect(result.data.trim()).to.equal(data['night'].message);
      expect(result.signatures).to.have.length(1);
      expect(result.signatures[0].valid).to.be.true;
    });
  });
  it('Encrypt and sign message', function () {
    var night = load_pub_key('night');
    var light = load_priv_key('light');
    expect(light.decrypt(data['light'].pass)).to.be.true;
    openpgp.encrypt(
      {publicKeys: [night], privateKeys: [light], data: data['light'].message + "\n"}
    ).then(function (encrypted) {
      var message = openpgp.message.readArmored(encrypted.data);
      var light = load_pub_key('light');
      var night = load_priv_key('night');
      return openpgp.decrypt(
        {privateKey: night, publicKeys: [light], message: message}
      ).then(function (result) {
        expect(result).to.exist;
        expect(result.data.trim()).to.equal(data['light'].message);
        expect(result.signatures).to.have.length(1);
        expect(result.signatures[0].valid).to.be.true;
      });
    });
  });

  // TODO generate, export, then reimport key and validate
  it('Omnibus Ed25519/Curve25519 Test', function () {
    var options = {
      userIds: {name: "Hi", email: "hi@hel.lo"},
      curve: "ed25519"
    };
    return openpgp.generateKey(options).then(function (firstKey) {
      expect(firstKey).to.exist;
      expect(firstKey.privateKeyArmored).to.exist;
      expect(firstKey.publicKeyArmored).to.exist;
      expect(firstKey.key).to.exist;
      expect(firstKey.key.primaryKey).to.exist;
      expect(firstKey.key.subKeys).to.have.length(1);
      expect(firstKey.key.subKeys[0].subKey).to.exist;

      var hi = firstKey.key;
      var primaryKey = hi.primaryKey;
      var subKey = hi.subKeys[0].subKey;
      expect(primaryKey.params[0].oid).to.equal(elliptic.get('ed25519').oid);
      expect(primaryKey.algorithm).to.equal('eddsa');
      expect(subKey.params[0].oid).to.equal(elliptic.get('curve25519').oid);
      expect(subKey.algorithm).to.equal('ecdh');

      // Self Certificate is valid
      var user = hi.users[0]
      expect(user.selfCertifications[0].verify(
        primaryKey, {userid: user.userId, key: primaryKey}
      )).to.eventually.be.true;
      expect(user.verifyCertificate(
        primaryKey, user.selfCertifications[0], [hi.toPublic()]
      )).to.eventually.equal(openpgp.enums.keyStatus.valid);

      var options = {
        userIds: {name: "Bye", email: "bye@good.bye"},
        curve: "curve25519"
      };
      return openpgp.generateKey(options).then(function (secondKey) {
        var bye = secondKey.key;
        expect(bye.primaryKey.params[0].oid).to.equal(elliptic.get('ed25519').oid);
        expect(bye.primaryKey.algorithm).to.equal('eddsa');
        expect(bye.subKeys[0].subKey.params[0].oid).to.equal(elliptic.get('curve25519').oid);
        expect(bye.subKeys[0].subKey.algorithm).to.equal('ecdh');

        // Self Certificate is valid
        var user = bye.users[0]
        expect(user.selfCertifications[0].verify(
          bye.primaryKey, {userid: user.userId, key: bye.primaryKey}
        )).to.eventually.be.true;
        expect(user.verifyCertificate(
          bye.primaryKey, user.selfCertifications[0], [bye.toPublic()]
        )).to.eventually.equal(openpgp.enums.keyStatus.valid);

        return Promise.all([
          // Hi trusts Bye!
          bye.toPublic().signPrimaryUser([ hi ]).then(trustedBye => {
            expect(trustedBye.users[0].otherCertifications[0].verify(
              primaryKey, { userid: user.userId, key: bye.toPublic().primaryKey }
            )).to.eventually.be.true;
          }),
          // Signing message
          openpgp.sign(
            { data: 'Hi, this is me, Hi!', privateKeys: hi }
          ).then(signed => {
            var msg = openpgp.cleartext.readArmored(signed.data);
            // Verifying signed message
            return Promise.all([
              openpgp.verify(
                { message: msg, publicKeys: hi.toPublic() }
              ).then(output => expect(output.signatures[0].valid).to.be.true),
              // Verifying detached signature
              openpgp.verify(
                { message: openpgp.message.fromText('Hi, this is me, Hi!'),
                  publicKeys: hi.toPublic(),
                  signature: openpgp.signature.readArmored(signed.data) }
              ).then(output => expect(output.signatures[0].valid).to.be.true)
            ]);
          }),
          // Encrypting and signing
          openpgp.encrypt(
            { data: 'Hi, Hi wrote this but only Bye can read it!',
              publicKeys: [ bye.toPublic() ],
              privateKeys: [ hi ] }
          ).then(encrypted => {
            var msg = openpgp.message.readArmored(encrypted.data)
            // Decrypting and verifying
            return openpgp.decrypt(
              { message: msg,
                privateKey: bye,
                publicKeys: [ hi.toPublic() ] }
            ).then(output => {
              expect(output.data).to.equal('Hi, Hi wrote this but only Bye can read it!');
              expect(output.signatures[0].valid).to.be.true;
            });
          })
        ]);
      });
    });
  });
});
