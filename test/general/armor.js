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
      ['-----BEGIN PGP PRIVATE KEY BLOCK-----\t \r',
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

    const result = await openpgp.key.readArmored(privKey);
    expect(result.err).to.not.exist;
    expect(result.keys[0]).to.be.an.instanceof(openpgp.key.Key);
  });

  it('Do not filter blank lines after header', async function () {
    let msg = getArmor(['Hash: SHA1', '']);
    msg = await openpgp.cleartext.readArmored(msg);
    expect(msg.text).to.equal('\r\nsign this');
  });

});

