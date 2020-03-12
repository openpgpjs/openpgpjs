const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const chai = require('chai');

const { expect } = chai;

describe("ASCII armor", function() {

  function getArmor(headers, signatureHeaders) {
    return ['-----BEGIN PGP SIGNED MESSAGE-----']
      .concat(headers)
      .concat(
        ['',
        'sign this',
        '-----BEGIN PGP SIGNATURE-----']
      )
      .concat(signatureHeaders || ['Version: GnuPG v2.0.22 (GNU/Linux)'])
      .concat(
        ['',
        'iJwEAQECAAYFAlMrPj0ACgkQ4IT3RGwgLJfYkQQAgHMQieazCVdfGAfzQM69Egm5',
        'HhcQszODD898wpoGCHgiNdNo1+5nujQAtXnkcxM+Vf7onfbTvUqut/siyO3fzqhK',
        'LQ9DiQUwJMBE8nOwVR7Mpc4kLNngMTNaHAjZaVaDpTCrklPY+TPHIZnu0B6Ur+6t',
        'skTzzVXIxMYw8ihbHfk=',
        '=e/eA',
        '-----END PGP SIGNATURE-----']
      ).join('\n');
  }

  it('Parse cleartext signed message', async function () {
    let msg = getArmor(['Hash: SHA1']);
    msg = await openpgp.cleartext.readArmored(msg);
    expect(msg).to.be.an.instanceof(openpgp.cleartext.CleartextMessage);
  });

  it('Exception if mismatch in armor header and signature', async function () {
    let msg = getArmor(['Hash: SHA256']);
    msg = openpgp.cleartext.readArmored(msg);
    await expect(msg).to.be.rejectedWith(Error, /Hash algorithm mismatch in armor header and signature/);
  });

  it('Exception if no header and non-MD5 signature', async function () {
    let msg = getArmor(null);
    msg = openpgp.cleartext.readArmored(msg);
    await expect(msg).to.be.rejectedWith(Error, /If no "Hash" header in cleartext signed message, then only MD5 signatures allowed/);
  });

  it('Exception if unknown hash algorithm', async function () {
    let msg = getArmor(['Hash: LAV750']);
    msg = openpgp.cleartext.readArmored(msg);
    await expect(msg).to.be.rejectedWith(Error, /Unknown hash algorithm in armor header/);
  });

  it('Multiple hash values', async function () {
    let msg = getArmor(['Hash: SHA1, SHA256']);
    msg = await openpgp.cleartext.readArmored(msg);
    expect(msg).to.be.an.instanceof(openpgp.cleartext.CleartextMessage);
  });

  it('Multiple hash header lines', async function () {
    let msg = getArmor(['Hash: SHA1', 'Hash: SHA256']);
    msg = await openpgp.cleartext.readArmored(msg);
    expect(msg).to.be.an.instanceof(openpgp.cleartext.CleartextMessage);
  });

  it('Non-hash header line throws exception', async function () {
    let msg = getArmor(['Hash: SHA1', 'Comment: could be anything']);
    msg = openpgp.cleartext.readArmored(msg);
    await expect(msg).to.be.rejectedWith(Error, /Only "Hash" header allowed in cleartext signed message/);
  });

  it('Multiple wrong hash values', async function () {
    let msg = getArmor(['Hash: SHA512, SHA256']);
    msg = openpgp.cleartext.readArmored(msg);
    await expect(msg).to.be.rejectedWith(Error, /Hash algorithm mismatch in armor header and signature/);
  });

  it('Multiple wrong hash values', async function () {
    let msg = getArmor(['Hash: SHA512, SHA256']);
    msg = openpgp.cleartext.readArmored(msg);
    await expect(msg).to.be.rejectedWith(Error, /Hash algorithm mismatch in armor header and signature/);
  });

  it('Filter whitespace in blank line', async function () {
    let msg =
      ['-----BEGIN PGP SIGNED MESSAGE-----',
      'Hash: SHA1',
      ' \f\r\t\u00a0\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000',
      'sign this',
      '-----BEGIN PGP SIGNATURE-----',
      'Version: GnuPG v2.0.22 (GNU/Linux)',
      '',
      'iJwEAQECAAYFAlMrPj0ACgkQ4IT3RGwgLJfYkQQAgHMQieazCVdfGAfzQM69Egm5',
      'HhcQszODD898wpoGCHgiNdNo1+5nujQAtXnkcxM+Vf7onfbTvUqut/siyO3fzqhK',
      'LQ9DiQUwJMBE8nOwVR7Mpc4kLNngMTNaHAjZaVaDpTCrklPY+TPHIZnu0B6Ur+6t',
      'skTzzVXIxMYw8ihbHfk=',
      '=e/eA',
      '-----END PGP SIGNATURE-----'].join('\n');

    msg = await openpgp.cleartext.readArmored(msg);
    expect(msg).to.be.an.instanceof(openpgp.cleartext.CleartextMessage);
  });

  it('Exception if improperly formatted armor header - plaintext section', async function () {
    let msg = getArmor(['Hash:SHA256']);
    msg = openpgp.cleartext.readArmored(msg);
    await expect(msg).to.be.rejectedWith(Error, /Improperly formatted armor header/);
    msg = getArmor(['Ha sh: SHA256']);
    msg = openpgp.cleartext.readArmored(msg);
    await expect(msg).to.be.rejectedWith(Error, /Only "Hash" header allowed in cleartext signed message/);
    msg = getArmor(['Hash SHA256']);
    msg = openpgp.cleartext.readArmored(msg);
    await expect(msg).to.be.rejectedWith(Error, /Improperly formatted armor header/);
  });

  it('Exception if improperly formatted armor header - signature section', async function () {
    await Promise.all(['Space : trailing', 'Space :switched', ': empty', 'none', 'Space:missing'].map(async function (invalidHeader) {
      await expect(openpgp.cleartext.readArmored(getArmor(['Hash: SHA1'], [invalidHeader]))).to.be.rejectedWith(Error, /Improperly formatted armor header/);
    }));
  });

  it('Ignore unknown armor header - signature section', async function () {
    const validHeaders = ['Version: BCPG C# v1.7.4114.6375', 'Independent Reserve Pty. Ltd. 2017: 1.0.0.0'];
    expect(await openpgp.cleartext.readArmored(getArmor(['Hash: SHA1'], validHeaders))).to.be.an.instanceof(openpgp.cleartext.CleartextMessage);
    await Promise.all(['A: Hello', 'Ab: 1.2.3', 'Abcd: #!/yah', 'Acd 123 5.6.$.8: Hello', '_: Hello', '*: Hello', '* & ## ?? ()(): Hello', '( ): Weird'].map(async function (validHeader) {
      expect(await openpgp.cleartext.readArmored(getArmor(['Hash: SHA1'], [validHeader]))).to.be.an.instanceof(openpgp.cleartext.CleartextMessage);
    }));
  });

  it('Exception if wrong armor header type', async function () {
    let msg =
      ['-----BEGIN PGP SIGNED MESSAGE\u2010\u2010\u2010\u2010\u2010\nHash:SHA1\n\nIs this properly-----',
      '',
      'sign this',
      '-----BEGIN PGP SIGNNATURE-----',
      'Version: GnuPG v2.0.22 (GNU/Linux)',
      '',
      'iJwEAQECAAYFAlMrPj0ACgkQ4IT3RGwgLJfYkQQAgHMQieazCVdfGAfzQM69Egm5',
      'HhcQszODD898wpoGCHgiNdNo1+5nujQAtXnkcxM+Vf7onfbTvUqut/siyO3fzqhK',
      'LQ9DiQUwJMBE8nOwVR7Mpc4kLNngMTNaHAjZaVaDpTCrklPY+TPHIZnu0B6Ur+6t',
      'skTzzVXIxMYw8ihbHfk=',
      '=e/eA',
      '-----END PGP SIGNNATURE-----'].join('\n');

    msg = openpgp.cleartext.readArmored(msg);
    await expect(msg).to.be.rejectedWith(Error, /Unknown ASCII armor type/);
  });

  it('Armor checksum validation - mismatch', async function () {
    const privKey =
      ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
      'Version: OpenPGP.js v0.3.0',
      'Comment: https://openpgpjs.org',
      '',
      'xbYEUubX7gEBANDWhzoP+Tr/IyRSv++vl5jBesQIPTYGQBdzF4YDnGEBABEB',
      'AAH+CQMIfzdw4/PKNl5gVXdtfDFdSIN8yJT2rbeg3+SsWexXZNNdRaONWaiB',
      'Z5cG9Q6+BoXKsEshIdcYOgwsAgRxlPpRA34Vvmg2QBk7PhdrkbK7aqENsJ1w',
      'dIlLD6p9GmLE20yVff58/fMiUtPRgsD83SpKTAX6EM1ulpkuQQNjmrVc5qc8',
      '7AMdF80JdW5kZWZpbmVkwj8EEAEIABMFAlLm1+4JEBD8MASZrpALAhsDAAAs',
      'QgD8CUrwv7Hrp/INR0/UvAvzS52VztREQwQWTJMrgTNHBGjHtgRS5tfuAQEA',
      'nys9SaSgR+l6iZc/M8hGIUmbuahE2/+mtw+/l0RO+WcAEQEAAf4JAwjr39Yi',
      'FzjxImDN1IoYVsonA9M+BtIIJHafuQUHjyEr1paJJK5xS6KlyGgpMTXTD6y/',
      'qxS3ZSPPzHGRrs2CmkVEiPmurn9Ed05tb0y9OnJkWtuh3z9VVq9d8zHzuENa',
      'bUfli+P/v+dRaZ+1rSOxUFbFYbFB5XK/A9b/OPFrv+mb4KrtLxugwj8EGAEI',
      'ABMFAlLm1+4JEBD8MASZrpALAhsMAAC3IgD8DnLGbMnpLtrX72RCkPW1ffLq',
      '71vlXMJNXvoCeuejiRw=',
      '=wJN@',
      '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

    // try with default config
    const result_1 = await openpgp.key.readArmored(privKey);
    expect(result_1.err).to.exist;
    expect(result_1.err[0].message).to.match(/Ascii armor integrity check on message failed/);

    // try opposite config
    openpgp.config.checksum_required = !openpgp.config.checksum_required;
    const result_2 = await openpgp.key.readArmored(privKey);
    expect(result_2.err).to.exist;
    expect(result_2.err[0].message).to.match(/Ascii armor integrity check on message failed/);

    // back to default
    openpgp.config.checksum_required = !openpgp.config.checksum_required;
  });

  it('Armor checksum validation - valid', async function () {
    const privKey =
      ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'Version: OpenPGP.js v0.3.0',
        'Comment: https://openpgpjs.org',
        '',
        'xbYEUubX7gEBANDWhzoP+Tr/IyRSv++vl5jBesQIPTYGQBdzF4YDnGEBABEB',
        'AAH+CQMIfzdw4/PKNl5gVXdtfDFdSIN8yJT2rbeg3+SsWexXZNNdRaONWaiB',
        'Z5cG9Q6+BoXKsEshIdcYOgwsAgRxlPpRA34Vvmg2QBk7PhdrkbK7aqENsJ1w',
        'dIlLD6p9GmLE20yVff58/fMiUtPRgsD83SpKTAX6EM1ulpkuQQNjmrVc5qc8',
        '7AMdF80JdW5kZWZpbmVkwj8EEAEIABMFAlLm1+4JEBD8MASZrpALAhsDAAAs',
        'QgD8CUrwv7Hrp/INR0/UvAvzS52VztREQwQWTJMrgTNHBGjHtgRS5tfuAQEA',
        'nys9SaSgR+l6iZc/M8hGIUmbuahE2/+mtw+/l0RO+WcAEQEAAf4JAwjr39Yi',
        'FzjxImDN1IoYVsonA9M+BtIIJHafuQUHjyEr1paJJK5xS6KlyGgpMTXTD6y/',
        'qxS3ZSPPzHGRrs2CmkVEiPmurn9Ed05tb0y9OnJkWtuh3z9VVq9d8zHzuENa',
        'bUfli+P/v+dRaZ+1rSOxUFbFYbFB5XK/A9b/OPFrv+mb4KrtLxugwj8EGAEI',
        'ABMFAlLm1+4JEBD8MASZrpALAhsMAAC3IgD8DnLGbMnpLtrX72RCkPW1ffLq',
        '71vlXMJNXvoCeuejiRw=',
        '=wJNM',
        '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

    // try with default config
    const result_1 = await openpgp.key.readArmored(privKey);
    expect(result_1.err).to.not.exist;

    // try opposite config
    openpgp.config.checksum_required = !openpgp.config.checksum_required;
    const result_2 = await openpgp.key.readArmored(privKey);
    expect(result_2.err).to.not.exist;

    // back to default
    openpgp.config.checksum_required = !openpgp.config.checksum_required;
  });

  it('Armor checksum validation - missing', async function () {
    const privKeyNoCheckSum =
      ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'Version: OpenPGP.js v0.3.0',
        'Comment: https://openpgpjs.org',
        '',
        'xbYEUubX7gEBANDWhzoP+Tr/IyRSv++vl5jBesQIPTYGQBdzF4YDnGEBABEB',
        'AAH+CQMIfzdw4/PKNl5gVXdtfDFdSIN8yJT2rbeg3+SsWexXZNNdRaONWaiB',
        'Z5cG9Q6+BoXKsEshIdcYOgwsAgRxlPpRA34Vvmg2QBk7PhdrkbK7aqENsJ1w',
        'dIlLD6p9GmLE20yVff58/fMiUtPRgsD83SpKTAX6EM1ulpkuQQNjmrVc5qc8',
        '7AMdF80JdW5kZWZpbmVkwj8EEAEIABMFAlLm1+4JEBD8MASZrpALAhsDAAAs',
        'QgD8CUrwv7Hrp/INR0/UvAvzS52VztREQwQWTJMrgTNHBGjHtgRS5tfuAQEA',
        'nys9SaSgR+l6iZc/M8hGIUmbuahE2/+mtw+/l0RO+WcAEQEAAf4JAwjr39Yi',
        'FzjxImDN1IoYVsonA9M+BtIIJHafuQUHjyEr1paJJK5xS6KlyGgpMTXTD6y/',
        'qxS3ZSPPzHGRrs2CmkVEiPmurn9Ed05tb0y9OnJkWtuh3z9VVq9d8zHzuENa',
        'bUfli+P/v+dRaZ+1rSOxUFbFYbFB5XK/A9b/OPFrv+mb4KrtLxugwj8EGAEI',
        'ABMFAlLm1+4JEBD8MASZrpALAhsMAAC3IgD8DnLGbMnpLtrX72RCkPW1ffLq',
        '71vlXMJNXvoCeuejiRw=',
        '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

    // try with default config
    const result_1 = await openpgp.key.readArmored(privKeyNoCheckSum);
    if(openpgp.config.checksum_required) {
      expect(result_1.err).to.exist;
      expect(result_1.err[0].message).to.match(/Ascii armor integrity check on message failed/);
    } else {
      expect(result_1.err).to.not.exist;
    }

    // try opposite config
    openpgp.config.checksum_required = !openpgp.config.checksum_required;
    const result_2 = await openpgp.key.readArmored(privKeyNoCheckSum);
    if(openpgp.config.checksum_required) {
      expect(result_2.err).to.exist;
      expect(result_2.err[0].message).to.match(/Ascii armor integrity check on message failed/);
    } else {
      expect(result_2.err).to.not.exist;
    }

    // back to default
    openpgp.config.checksum_required = !openpgp.config.checksum_required;
  });

  it('Armor checksum validation - missing - trailing newline', async function () {
    const privKeyNoCheckSumWithTrailingNewline =
      ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'Version: OpenPGP.js v0.3.0',
        'Comment: https://openpgpjs.org',
        '',
        'xbYEUubX7gEBANDWhzoP+Tr/IyRSv++vl5jBesQIPTYGQBdzF4YDnGEBABEB',
        'AAH+CQMIfzdw4/PKNl5gVXdtfDFdSIN8yJT2rbeg3+SsWexXZNNdRaONWaiB',
        'Z5cG9Q6+BoXKsEshIdcYOgwsAgRxlPpRA34Vvmg2QBk7PhdrkbK7aqENsJ1w',
        'dIlLD6p9GmLE20yVff58/fMiUtPRgsD83SpKTAX6EM1ulpkuQQNjmrVc5qc8',
        '7AMdF80JdW5kZWZpbmVkwj8EEAEIABMFAlLm1+4JEBD8MASZrpALAhsDAAAs',
        'QgD8CUrwv7Hrp/INR0/UvAvzS52VztREQwQWTJMrgTNHBGjHtgRS5tfuAQEA',
        'nys9SaSgR+l6iZc/M8hGIUmbuahE2/+mtw+/l0RO+WcAEQEAAf4JAwjr39Yi',
        'FzjxImDN1IoYVsonA9M+BtIIJHafuQUHjyEr1paJJK5xS6KlyGgpMTXTD6y/',
        'qxS3ZSPPzHGRrs2CmkVEiPmurn9Ed05tb0y9OnJkWtuh3z9VVq9d8zHzuENa',
        'bUfli+P/v+dRaZ+1rSOxUFbFYbFB5XK/A9b/OPFrv+mb4KrtLxugwj8EGAEI',
        'ABMFAlLm1+4JEBD8MASZrpALAhsMAAC3IgD8DnLGbMnpLtrX72RCkPW1ffLq',
        '71vlXMJNXvoCeuejiRw=',
        '-----END PGP PRIVATE KEY BLOCK-----',
        ''].join('\n');

    // try with default config
    const result_1 = await openpgp.key.readArmored(privKeyNoCheckSumWithTrailingNewline);
    if(openpgp.config.checksum_required) {
      expect(result_1.err).to.exist;
      expect(result_1.err[0].message).to.match(/Ascii armor integrity check on message failed/);
    } else {
      expect(result_1.err).to.not.exist;
    }

    // try opposite config
    openpgp.config.checksum_required = !openpgp.config.checksum_required;
    const result_2 = await openpgp.key.readArmored(privKeyNoCheckSumWithTrailingNewline);
    if(openpgp.config.checksum_required) {
      expect(result_2.err).to.exist;
      expect(result_2.err[0].message).to.match(/Ascii armor integrity check on message failed/);
    } else {
      expect(result_2.err).to.not.exist;
    }

    // back to default
    openpgp.config.checksum_required = !openpgp.config.checksum_required;
  });

  it('Accept header with trailing whitespace', async function () {
    const privKey =
      ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
      'Version: OpenPGP.js v0.3.0',
      'Comment: https://openpgpjs.org',
      '',
      'xbYEUubX7gEBANDWhzoP+Tr/IyRSv++vl5jBesQIPTYGQBdzF4YDnGEBABEB',
      'AAH+CQMIfzdw4/PKNl5gVXdtfDFdSIN8yJT2rbeg3+SsWexXZNNdRaONWaiB',
      'Z5cG9Q6+BoXKsEshIdcYOgwsAgRxlPpRA34Vvmg2QBk7PhdrkbK7aqENsJ1w',
      'dIlLD6p9GmLE20yVff58/fMiUtPRgsD83SpKTAX6EM1ulpkuQQNjmrVc5qc8',
      '7AMdF80JdW5kZWZpbmVkwj8EEAEIABMFAlLm1+4JEBD8MASZrpALAhsDAAAs',
      'QgD8CUrwv7Hrp/INR0/UvAvzS52VztREQwQWTJMrgTNHBGjHtgRS5tfuAQEA',
      'nys9SaSgR+l6iZc/M8hGIUmbuahE2/+mtw+/l0RO+WcAEQEAAf4JAwjr39Yi',
      'FzjxImDN1IoYVsonA9M+BtIIJHafuQUHjyEr1paJJK5xS6KlyGgpMTXTD6y/',
      'qxS3ZSPPzHGRrs2CmkVEiPmurn9Ed05tb0y9OnJkWtuh3z9VVq9d8zHzuENa',
      'bUfli+P/v+dRaZ+1rSOxUFbFYbFB5XK/A9b/OPFrv+mb4KrtLxugwj8EGAEI',
      'ABMFAlLm1+4JEBD8MASZrpALAhsMAAC3IgD8DnLGbMnpLtrX72RCkPW1ffLq',
      '71vlXMJNXvoCeuejiRw=',
      '=wJNM',
      '-----END PGP PRIVATE KEY BLOCK-----',
      ''].join('\t \r\n');

    const result = await openpgp.key.readArmored(privKey);
    expect(result.err).to.not.exist;
    expect(result.keys[0]).to.be.an.instanceof(openpgp.key.Key);
  });

  it('Do not filter blank lines after header', async function () {
    let msg = getArmor(['Hash: SHA1', '']);
    msg = await openpgp.cleartext.readArmored(msg);
    expect(msg.text).to.equal('\r\nsign this');
  });

  it('Do not add extraneous blank line when base64 ends on line break', async function () {
    let pubKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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

=trqv
-----END PGP PUBLIC KEY BLOCK-----
`;

    const { type, data } = await openpgp.armor.decode(pubKey);
    const armor = await openpgp.stream.readToEnd(openpgp.armor.encode(type, data));
    expect(
      armor
        .replace(/^(Version|Comment): .*$\r\n/mg, '')
    ).to.equal(
      pubKey
        .replace('\n=', '=')
        .replace(/\n/g, '\r\n')
    );
  });

});

