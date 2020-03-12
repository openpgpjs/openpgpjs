const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const elliptic = openpgp.crypto.publicKey.elliptic;

const chai = require('chai');
chai.use(require('chai-as-promised'));

const { expect } = chai;
const input = require('./testInputs');

(openpgp.config.ci ? describe.skip : describe)('X25519 Cryptography', function () {
  const data = {
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
        '-----END PGP PUBLIC KEY BLOCK-----'
      ].join('\n'),
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
        '-----END PGP PRIVATE KEY BLOCK-----'
      ].join('\n'),
      message: 'Hi, Light wrote this!\n',
      message_signed: [
        '-----BEGIN PGP SIGNED MESSAGE-----',
        'Hash: SHA512',
        '',
        'Hi, Light wrote this!',
        '',
        '-----BEGIN PGP SIGNATURE-----',
        'Version: OpenPGP.js v3.1.0',
        'Comment: https://openpgpjs.org',
        '',
        'wl4EARYKABAFAltbFNAJEB7N8CbAJFgwAAAhcAEA5b2MIQNxQYj8TAMyuhZJ',
        'UvxEgPS8DU59Kxw5F9+oldQBAN4mA+SOJyTxEx4oyyLh+8RD27dqyeDpmXju',
        'xqMRN8oE',
        '=siSU',
        '-----END PGP SIGNATURE-----'
      ].join('\n')
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
        '-----END PGP PUBLIC KEY BLOCK-----'
      ].join('\n'),
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
        '-----END PGP PRIVATE KEY BLOCK-----'
      ].join('\n'),
      message: 'Oh hi, this is a private message from Light to Night!\n',
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
        '-----END PGP MESSAGE-----'
      ].join('\n')
    }
  };

  async function load_pub_key(name) {
    if (data[name].pub_key) {
      return data[name].pub_key;
    }
    const pub = await openpgp.key.readArmored(data[name].pub);
    expect(pub).to.exist;
    expect(pub.err).to.not.exist;
    expect(pub.keys).to.have.length(1);
    expect(pub.keys[0].getKeyId().toHex()).to.equal(data[name].id);
    data[name].pub_key = pub.keys[0];
    return data[name].pub_key;
  }

  async function load_priv_key(name) {
    if (data[name].priv_key) {
      return data[name].priv_key;
    }
    const pk = await openpgp.key.readArmored(data[name].priv);
    expect(pk).to.exist;
    expect(pk.err).to.not.exist;
    expect(pk.keys).to.have.length(1);
    expect(pk.keys[0].getKeyId().toHex()).to.equal(data[name].id);
    expect(await pk.keys[0].decrypt(data[name].pass)).to.be.true;
    data[name].priv_key = pk.keys[0];
    return data[name].priv_key;
  }

  it('Load public key', async function () {
    await load_pub_key('light');
    await load_pub_key('night');
  });

  // This test is slow because the keys are generated by GPG2, which
  // by default chooses a larger number for S2K iterations than we do.
  it('Load private key', async function () {
    await load_priv_key('light');
    await load_priv_key('night');
    return true;
  });

  it('Verify clear signed message', async function () {
    const name = 'light';
    const pub = await load_pub_key(name);
    const msg = await openpgp.cleartext.readArmored(data[name].message_signed);
    return openpgp.verify({ publicKeys: [pub], message: msg }).then(function(result) {
      expect(result).to.exist;
      expect(result.data).to.equal(data[name].message);
      expect(result.signatures).to.have.length(1);
      expect(result.signatures[0].valid).to.be.true;
    });
  });

  it('Sign message', async function () {
    const name = 'light';
    const randomData = input.createSomeMessage();
    const priv = await load_priv_key(name);
    const signed = await openpgp.sign({ privateKeys: [priv], message: openpgp.cleartext.fromText(randomData)});
    const pub = await load_pub_key(name);
    const msg = await openpgp.cleartext.readArmored(signed.data);
    const result = await openpgp.verify({ publicKeys: [pub], message: msg});

    expect(result).to.exist;
    expect(result.data).to.equal(randomData.replace(/[ \t]+$/mg, ''));
    expect(result.signatures).to.have.length(1);
    expect(result.signatures[0].valid).to.be.true;
  });

  it('Decrypt and verify message', async function () {
    const light = await load_pub_key('light');
    const night = await load_priv_key('night');
    const msg = await openpgp.message.readArmored(data.night.message_encrypted);
    const result = await openpgp.decrypt({ privateKeys: night, publicKeys: [light], message: msg });

    expect(result).to.exist;
    expect(result.data).to.equal(data.night.message);
    expect(result.signatures).to.have.length(1);
    expect(result.signatures[0].valid).to.be.true;
  });

  it('Encrypt and sign message', async function () {
    const nightPublic = await load_pub_key('night');
    const lightPrivate = await load_priv_key('light');
    const randomData = input.createSomeMessage();
    const encrypted = await openpgp.encrypt({ publicKeys: [nightPublic], privateKeys: [lightPrivate], message: openpgp.message.fromText(randomData) });

    const message = await openpgp.message.readArmored(encrypted.data);
    const lightPublic = await load_pub_key('light');
    const nightPrivate = await load_priv_key('night');
    const result = await openpgp.decrypt({ privateKeys: nightPrivate, publicKeys: [lightPublic], message: message });

    expect(result).to.exist;
    expect(result.data).to.equal(randomData);
    expect(result.signatures).to.have.length(1);
    expect(result.signatures[0].valid).to.be.true;
  });

  describe('Ed25519 Test Vectors from RFC8032', function () {
    // https://tools.ietf.org/html/rfc8032#section-7.1
    const signature = openpgp.crypto.signature;
    const util = openpgp.util;
    function testVector(vector) {
      const curve = new elliptic.Curve('ed25519');
      const { publicKey } = openpgp.crypto.publicKey.nacl.sign.keyPair.fromSeed(openpgp.util.hex_to_Uint8Array(vector.SECRET_KEY));
      expect(publicKey).to.deep.equal(openpgp.util.hex_to_Uint8Array(vector.PUBLIC_KEY));
      const data = util.str_to_Uint8Array(vector.MESSAGE);
      const keyIntegers = [
        openpgp.OID.fromClone(curve),
        new openpgp.MPI(util.hex_to_str('40'+vector.PUBLIC_KEY)),
        new openpgp.MPI(util.hex_to_str(vector.SECRET_KEY))
      ];
      const msg_MPIs = [
        new openpgp.MPI(util.Uint8Array_to_str(util.hex_to_Uint8Array(vector.SIGNATURE.R).reverse())),
        new openpgp.MPI(util.Uint8Array_to_str(util.hex_to_Uint8Array(vector.SIGNATURE.S).reverse()))
      ];
      return Promise.all([
        signature.sign(22, undefined, keyIntegers, undefined, data).then(signed => {
          const len = ((signed[0] << 8| signed[1]) + 7) / 8;
          expect(util.hex_to_Uint8Array(vector.SIGNATURE.R)).to.deep.eq(signed.slice(2, 2 + len));
          expect(util.hex_to_Uint8Array(vector.SIGNATURE.S)).to.deep.eq(signed.slice(4 + len));
        }),
        signature.verify(22, undefined, msg_MPIs, keyIntegers, undefined, data).then(result => {
          expect(result).to.be.true;
        })
      ]);
    }

    it('Signature of empty string', function () {
      return testVector({
        SECRET_KEY:
        ['9d61b19deffd5a60ba844af492ec2cc4',
         '4449c5697b326919703bac031cae7f60'].join(''),
        PUBLIC_KEY:
        ['d75a980182b10ab7d54bfed3c964073a',
         '0ee172f3daa62325af021a68f707511a'].join(''),
        MESSAGE: '',
        SIGNATURE:
        { R: ['e5564300c360ac729086e2cc806e828a',
              '84877f1eb8e5d974d873e06522490155'].join(''),
          S: ['5fb8821590a33bacc61e39701cf9b46b',
              'd25bf5f0595bbe24655141438e7a100b'].join('') }
      });
    });

    it('Signature of single byte', function () {
      return testVector({
        SECRET_KEY:
        ['4ccd089b28ff96da9db6c346ec114e0f',
         '5b8a319f35aba624da8cf6ed4fb8a6fb'].join(''),
        PUBLIC_KEY:
        ['3d4017c3e843895a92b70aa74d1b7ebc',
         '9c982ccf2ec4968cc0cd55f12af4660c'].join(''),
        MESSAGE: util.hex_to_str('72'),
        SIGNATURE:
        { R: ['92a009a9f0d4cab8720e820b5f642540',
              'a2b27b5416503f8fb3762223ebdb69da'].join(''),
          S: ['085ac1e43e15996e458f3613d0f11d8c',
              '387b2eaeb4302aeeb00d291612bb0c00'].join('') }
      });
    });

    it('Signature of two bytes', function () {
      return testVector({
        SECRET_KEY:
        ['c5aa8df43f9f837bedb7442f31dcb7b1',
         '66d38535076f094b85ce3a2e0b4458f7'].join(''),
        PUBLIC_KEY:
        ['fc51cd8e6218a1a38da47ed00230f058',
         '0816ed13ba3303ac5deb911548908025'].join(''),
        MESSAGE: util.hex_to_str('af82'),
        SIGNATURE:
        { R: ['6291d657deec24024827e69c3abe01a3',
              '0ce548a284743a445e3680d7db5ac3ac'].join(''),
          S: ['18ff9b538d16f290ae67f760984dc659',
              '4a7c15e9716ed28dc027beceea1ec40a'].join('') }
      });
    });

    it('Signature of 1023 bytes', function () {
      return testVector({
        SECRET_KEY:
        ['f5e5767cf153319517630f226876b86c',
         '8160cc583bc013744c6bf255f5cc0ee5'].join(''),
        PUBLIC_KEY:
        ['278117fc144c72340f67d0f2316e8386',
         'ceffbf2b2428c9c51fef7c597f1d426e'].join(''),
        MESSAGE: util.hex_to_str([
          '08b8b2b733424243760fe426a4b54908',
          '632110a66c2f6591eabd3345e3e4eb98',
          'fa6e264bf09efe12ee50f8f54e9f77b1',
          'e355f6c50544e23fb1433ddf73be84d8',
          '79de7c0046dc4996d9e773f4bc9efe57',
          '38829adb26c81b37c93a1b270b20329d',
          '658675fc6ea534e0810a4432826bf58c',
          '941efb65d57a338bbd2e26640f89ffbc',
          '1a858efcb8550ee3a5e1998bd177e93a',
          '7363c344fe6b199ee5d02e82d522c4fe',
          'ba15452f80288a821a579116ec6dad2b',
          '3b310da903401aa62100ab5d1a36553e',
          '06203b33890cc9b832f79ef80560ccb9',
          'a39ce767967ed628c6ad573cb116dbef',
          'efd75499da96bd68a8a97b928a8bbc10',
          '3b6621fcde2beca1231d206be6cd9ec7',
          'aff6f6c94fcd7204ed3455c68c83f4a4',
          '1da4af2b74ef5c53f1d8ac70bdcb7ed1',
          '85ce81bd84359d44254d95629e9855a9',
          '4a7c1958d1f8ada5d0532ed8a5aa3fb2',
          'd17ba70eb6248e594e1a2297acbbb39d',
          '502f1a8c6eb6f1ce22b3de1a1f40cc24',
          '554119a831a9aad6079cad88425de6bd',
          'e1a9187ebb6092cf67bf2b13fd65f270',
          '88d78b7e883c8759d2c4f5c65adb7553',
          '878ad575f9fad878e80a0c9ba63bcbcc',
          '2732e69485bbc9c90bfbd62481d9089b',
          'eccf80cfe2df16a2cf65bd92dd597b07',
          '07e0917af48bbb75fed413d238f5555a',
          '7a569d80c3414a8d0859dc65a46128ba',
          'b27af87a71314f318c782b23ebfe808b',
          '82b0ce26401d2e22f04d83d1255dc51a',
          'ddd3b75a2b1ae0784504df543af8969b',
          'e3ea7082ff7fc9888c144da2af58429e',
          'c96031dbcad3dad9af0dcbaaaf268cb8',
          'fcffead94f3c7ca495e056a9b47acdb7',
          '51fb73e666c6c655ade8297297d07ad1',
          'ba5e43f1bca32301651339e22904cc8c',
          '42f58c30c04aafdb038dda0847dd988d',
          'cda6f3bfd15c4b4c4525004aa06eeff8',
          'ca61783aacec57fb3d1f92b0fe2fd1a8',
          '5f6724517b65e614ad6808d6f6ee34df',
          'f7310fdc82aebfd904b01e1dc54b2927',
          '094b2db68d6f903b68401adebf5a7e08',
          'd78ff4ef5d63653a65040cf9bfd4aca7',
          '984a74d37145986780fc0b16ac451649',
          'de6188a7dbdf191f64b5fc5e2ab47b57',
          'f7f7276cd419c17a3ca8e1b939ae49e4',
          '88acba6b965610b5480109c8b17b80e1',
          'b7b750dfc7598d5d5011fd2dcc5600a3',
          '2ef5b52a1ecc820e308aa342721aac09',
          '43bf6686b64b2579376504ccc493d97e',
          '6aed3fb0f9cd71a43dd497f01f17c0e2',
          'cb3797aa2a2f256656168e6c496afc5f',
          'b93246f6b1116398a346f1a641f3b041',
          'e989f7914f90cc2c7fff357876e506b5',
          '0d334ba77c225bc307ba537152f3f161',
          '0e4eafe595f6d9d90d11faa933a15ef1',
          '369546868a7f3a45a96768d40fd9d034',
          '12c091c6315cf4fde7cb68606937380d',
          'b2eaaa707b4c4185c32eddcdd306705e',
          '4dc1ffc872eeee475a64dfac86aba41c',
          '0618983f8741c5ef68d3a101e8a3b8ca',
          'c60c905c15fc910840b94c00a0b9d0'
        ].join('')),
        SIGNATURE:
        { R: ['0aab4c900501b3e24d7cdf4663326a3a',
              '87df5e4843b2cbdb67cbf6e460fec350'].join(''),
          S: ['aa5371b1508f9f4528ecea23c436d94b',
              '5e8fcd4f681e30a6ac00a9704a188a03'].join('') }
      });
    });

    it('Signature of SHA(abc)', function () {
      return testVector({
        SECRET_KEY:
        ['833fe62409237b9d62ec77587520911e',
         '9a759cec1d19755b7da901b96dca3d42'].join(''),
        PUBLIC_KEY:
        ['ec172b93ad5e563bf4932c70e1245034',
         'c35467ef2efd4d64ebf819683467e2bf'].join(''),
        MESSAGE: util.hex_to_str([
          'ddaf35a193617abacc417349ae204131',
          '12e6fa4e89a97ea20a9eeee64b55d39a',
          '2192992a274fc1a836ba3c23a3feebbd',
          '454d4423643ce80e2a9ac94fa54ca49f'
        ].join('')),
        SIGNATURE:
        { R: ['dc2a4459e7369633a52b1bf277839a00',
              '201009a3efbf3ecb69bea2186c26b589'].join(''),
          S: ['09351fc9ac90b3ecfdfbc7c66431e030',
              '3dca179c138ac17ad9bef1177331a704'].join('') }
      });
    });
  });

/* TODO how does GPG2 accept this?
  it('Should handle little-endian parameters in EdDSA', function () {
    const pubKey = [
      '-----BEGIN PGP PUBLIC KEY BLOCK-----',
      'Version: OpenPGP.js v3.0.0',
      'Comment: https://openpgpjs.org',
      '',
      'xjMEWnRgnxYJKwYBBAHaRw8BAQdAZ8gxxCdUxIv4tBwhfUMW2uoEb1KvOfP8',
      'D+0ObBtsLnfNDkhpIDxoaUBoZWwubG8+wnYEEBYKACkFAlp0YJ8GCwkHCAMC',
      'CRDAYsFlymHCFQQVCAoCAxYCAQIZAQIbAwIeAQAAswsA/3qNZnwBn/ef4twv',
      'uvmFicYK//DDX1jIkpDiQ+/okLUEAPdAr3J/Z2WA7OD0d36trHNB06WLXJUu',
      'aCVm1TwoJHcNzjgEWnRgnxIKKwYBBAGXVQEFAQEHQPBVH+skap0NHMBw2HMe',
      'xWYUQ67I9Did3KoJuuEJ/ctQAwEIB8JhBBgWCAATBQJadGCfCRDAYsFlymHC',
      'FQIbDAAAhNQBAKmy4gPorjbwTwy5usylHttP28XnTdaGkZ1E7Rc3G9luAQCs',
      'Gbm1oe83ZB+0aSp5m34YkpHQNb80y8PGFy7nIexiAA==',
      '=xeG/',
      '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');
    const hi = (await openpgp.key.readArmored(pubKey)).keys[0];
    const results = hi.getPrimaryUser();
    expect(results).to.exist;
    expect(results.user).to.exist;
    const user = results.user;
    expect(user.selfCertifications[0].verify(
      hi.primaryKey, {userId: user.userId, key: hi.primaryKey}
    )).to.eventually.be.true;
    await user.verifyCertificate(
      hi.primaryKey, user.selfCertifications[0], [hi]
    );
  }); */
});

// TODO export, then reimport key and validate
function omnibus() {
  it('Omnibus Ed25519/Curve25519 Test', function() {
    const options = {
      userIds: { name: "Hi", email: "hi@hel.lo" },
      curve: "ed25519"
    };
    return openpgp.generateKey(options).then(async function(firstKey) {
      expect(firstKey).to.exist;
      expect(firstKey.privateKeyArmored).to.exist;
      expect(firstKey.publicKeyArmored).to.exist;
      expect(firstKey.key).to.exist;
      expect(firstKey.key.primaryKey).to.exist;
      expect(firstKey.key.subKeys).to.have.length(1);
      expect(firstKey.key.subKeys[0].keyPacket).to.exist;

      const hi = firstKey.key;
      const primaryKey = hi.primaryKey;
      const subKey = hi.subKeys[0];
      expect(hi.getAlgorithmInfo().curve).to.equal('ed25519');
      expect(hi.getAlgorithmInfo().algorithm).to.equal('eddsa');
      expect(subKey.getAlgorithmInfo().curve).to.equal('curve25519');
      expect(subKey.getAlgorithmInfo().algorithm).to.equal('ecdh');

      // Self Certificate is valid
      const user = hi.users[0];
      await expect(user.selfCertifications[0].verify(
        primaryKey, openpgp.enums.signature.cert_generic, { userId: user.userId, key: primaryKey }
      )).to.eventually.be.true;
      await user.verifyCertificate(
        primaryKey, user.selfCertifications[0], [hi.toPublic()]
      );

      const options = {
        userIds: { name: "Bye", email: "bye@good.bye" },
        curve: "curve25519"
      };
      return openpgp.generateKey(options).then(async function(secondKey) {
        const bye = secondKey.key;
        expect(bye.getAlgorithmInfo().curve).to.equal('ed25519');
        expect(bye.getAlgorithmInfo().algorithm).to.equal('eddsa');
        expect(bye.subKeys[0].getAlgorithmInfo().curve).to.equal('curve25519');
        expect(bye.subKeys[0].getAlgorithmInfo().algorithm).to.equal('ecdh');

        // Self Certificate is valid
        const user = bye.users[0];
        await expect(user.selfCertifications[0].verify(
          bye.primaryKey, openpgp.enums.signature.cert_generic, { userId: user.userId, key: bye.primaryKey }
        )).to.eventually.be.true;
        await user.verifyCertificate(
          bye.primaryKey, user.selfCertifications[0], [bye.toPublic()]
        );

        return Promise.all([
          // Hi trusts Bye!
          bye.toPublic().signPrimaryUser([hi]).then(trustedBye => {
            expect(trustedBye.users[0].otherCertifications[0].verify(
              primaryKey, openpgp.enums.signature.cert_generic, { userId: user.userId, key: bye.toPublic().primaryKey }
            )).to.eventually.be.true;
          }),
          // Signing message
          openpgp.sign(
            { message: openpgp.cleartext.fromText('Hi, this is me, Hi!'), privateKeys: hi }
          ).then(async signed => {
            const msg = await openpgp.cleartext.readArmored(signed.data);
            // Verifying signed message
            return Promise.all([
              openpgp.verify(
                { message: msg, publicKeys: hi.toPublic() }
              ).then(output => expect(output.signatures[0].valid).to.be.true),
              // Verifying detached signature
              openpgp.verify(
                {
                  message: openpgp.message.fromText('Hi, this is me, Hi!'),
                  publicKeys: hi.toPublic(),
                  signature: await openpgp.signature.readArmored(signed.data)
                }
              ).then(output => expect(output.signatures[0].valid).to.be.true)
            ]);
          }),
          // Encrypting and signing
          openpgp.encrypt(
            {
              message: openpgp.message.fromText('Hi, Hi wrote this but only Bye can read it!'),
              publicKeys: [bye.toPublic()],
              privateKeys: [hi]
            }
          ).then(async encrypted => {
            const msg = await openpgp.message.readArmored(encrypted.data);
            // Decrypting and verifying
            return openpgp.decrypt(
              {
                message: msg,
                privateKeys: bye,
                publicKeys: [hi.toPublic()]
              }
            ).then(output => {
              expect(output.data).to.equal('Hi, Hi wrote this but only Bye can read it!');
              expect(output.signatures[0].valid).to.be.true;
            });
          })
        ]);
      });
    });
  });
}

tryTests('X25519 Omnibus Tests', omnibus, {
  if: !openpgp.config.ci
});

tryTests('X25519 Omnibus Tests - Worker', omnibus, {
  if: typeof window !== 'undefined' && window.Worker,
  before: async function() {
    await openpgp.initWorker({ path: '../dist/openpgp.worker.js' });
  },
  beforeEach: function() {
    openpgp.config.use_native = true;
  },
  after: function() {
    openpgp.destroyWorker();
  }
});
