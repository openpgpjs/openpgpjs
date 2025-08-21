import { expect } from 'chai';

import openpgp from '../initOpenpgp.js';

export default () => describe('ASCII armor', function() {

  function getArmor(headers, signatureHeaders) {
    return ['-----BEGIN PGP SIGNED MESSAGE-----']
      .concat(headers)
      .concat([
        '',
        'sign this',
        '-----BEGIN PGP SIGNATURE-----'
      ])
      .concat(signatureHeaders || ['Version: GnuPG v2.0.22 (GNU/Linux)'])
      .concat([
        '',
        'iJwEAQECAAYFAlMrPj0ACgkQ4IT3RGwgLJfYkQQAgHMQieazCVdfGAfzQM69Egm5',
        'HhcQszODD898wpoGCHgiNdNo1+5nujQAtXnkcxM+Vf7onfbTvUqut/siyO3fzqhK',
        'LQ9DiQUwJMBE8nOwVR7Mpc4kLNngMTNaHAjZaVaDpTCrklPY+TPHIZnu0B6Ur+6t',
        'skTzzVXIxMYw8ihbHfk=',
        '=e/eA',
        '-----END PGP SIGNATURE-----'
      ]).join('\n');
  }

  it('Parse cleartext signed message', async function () {
    let msg = getArmor(['Hash: SHA1']);
    msg = await openpgp.readCleartextMessage({ cleartextMessage: msg });
    expect(msg).to.be.an.instanceof(openpgp.CleartextMessage);
  });

  it('Exception if mismatch in armor header and signature', async function () {
    let msg = getArmor(['Hash: SHA256']);
    msg = openpgp.readCleartextMessage({ cleartextMessage: msg });
    await expect(msg).to.be.rejectedWith(Error, /Hash algorithm mismatch in armor header and signature/);
  });

  it('Exception if unknown hash algorithm', async function () {
    let msg = getArmor(['Hash: LAV750']);
    msg = openpgp.readCleartextMessage({ cleartextMessage: msg });
    await expect(msg).to.be.rejectedWith(Error, /Unknown hash algorithm in armor header/);
  });

  it('Multiple hash values', async function () {
    let msg = getArmor(['Hash: SHA1, SHA256']);
    msg = await openpgp.readCleartextMessage({ cleartextMessage: msg });
    expect(msg).to.be.an.instanceof(openpgp.CleartextMessage);
  });

  it('Multiple hash header lines', async function () {
    let msg = getArmor(['Hash: SHA1', 'Hash: SHA256']);
    msg = await openpgp.readCleartextMessage({ cleartextMessage: msg });
    expect(msg).to.be.an.instanceof(openpgp.CleartextMessage);
  });

  it('Non-hash header line throws exception', async function () {
    let msg = getArmor(['Hash: SHA1', 'Comment: could be anything']);
    msg = openpgp.readCleartextMessage({ cleartextMessage: msg });
    await expect(msg).to.be.rejectedWith(Error, /Only "Hash" header allowed in cleartext signed message/);
  });

  it('Filter whitespace in blank line', async function () {
    let msg = [
      '-----BEGIN PGP SIGNED MESSAGE-----',
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
      '-----END PGP SIGNATURE-----'
    ].join('\n');

    msg = await openpgp.readCleartextMessage({ cleartextMessage: msg });
    expect(msg).to.be.an.instanceof(openpgp.CleartextMessage);
  });

  it('Ignore improperly formatted armor header', async function () {
    await Promise.all(['Space : trailing', 'Space :switched', ': empty', 'none', 'Space:missing'].map(async function (invalidHeader) {
      expect(await openpgp.readCleartextMessage({ cleartextMessage: getArmor(['Hash: SHA1'], [invalidHeader]) })).to.be.an.instanceof(openpgp.CleartextMessage);
    }));
  });

  it('Exception if improperly formatted armor footer', async function () {
    await expect(openpgp.readCleartextMessage({ cleartextMessage: [
      '-----BEGIN PGP SIGNED MESSAGE-----',
      'Hash: SHA256',
      '',
      '-----BEGIN PGP SIGNATURE-----',
      '',
      '-----OOPS'
    ].join('\n') })).to.be.rejectedWith(Error, /Misformed armored text/);
  });

  it('Ignore unknown armor header - signature section', async function () {
    const validHeaders = ['Version: BCPG C# v1.7.4114.6375', 'Independent Reserve Pty. Ltd. 2017: 1.0.0.0'];
    expect(await openpgp.readCleartextMessage({ cleartextMessage: getArmor(['Hash: SHA1'], validHeaders) })).to.be.an.instanceof(openpgp.CleartextMessage);
    await Promise.all(['A: Hello', 'Ab: 1.2.3', 'Abcd: #!/yah', 'Acd 123 5.6.$.8: Hello', '_: Hello', '*: Hello', '* & ## ?? ()(): Hello', '( ): Weird'].map(async function (validHeader) {
      expect(await openpgp.readCleartextMessage({ cleartextMessage: getArmor(['Hash: SHA1'], [validHeader]) })).to.be.an.instanceof(openpgp.CleartextMessage);
    }));
  });

  it('Exception if wrong armor header type', async function () {
    let msg = [
      '-----BEGIN PGP SIGNED MESSAGE\u2010\u2010\u2010\u2010\u2010\nHash:SHA1\n\nIs this properly-----',
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
      '-----END PGP SIGNNATURE-----'
    ].join('\n');

    msg = openpgp.readCleartextMessage({ cleartextMessage: msg });
    await expect(msg).to.be.rejectedWith(Error, /Unknown ASCII armor type/);
  });

  it('Armor checksum validation - mismatch', async function () {
    const privKey = [
      '-----BEGIN PGP PRIVATE KEY BLOCK-----',
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
      '-----END PGP PRIVATE KEY BLOCK-----'
    ].join('\n');

    await openpgp.readKey({ armoredKey: privKey });
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

    await openpgp.readKey({ armoredKey: privKey });
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

    await openpgp.readKey({ armoredKey: privKeyNoCheckSum });
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

    await openpgp.readKey({ armoredKey: privKeyNoCheckSumWithTrailingNewline });
  });

  it('Accept header with trailing whitespace', async function () {
    const privKey = [
      '-----BEGIN PGP PRIVATE KEY BLOCK-----',
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
      ''
    ].join('\t \r\n');

    const result = await openpgp.readKey({ armoredKey: privKey });
    expect(result).to.be.an.instanceof(openpgp.PrivateKey);
  });

  it('Do not filter blank lines after header', async function () {
    let msg = getArmor(['Hash: SHA1', '']);
    msg = await openpgp.readCleartextMessage({ cleartextMessage: msg });
    expect(msg.text).to.equal('\r\nsign this');
  });

  it('Selectively output CRC checksum', async function () {
    const includesArmorChecksum = armoredData => {
      const lines = armoredData.split('\n');
      const lastDataLine = lines[lines.length - 3];
      return (lastDataLine[0] === '=' && lastDataLine.length === 5);
    };

    // unless explicitly forbidden by the spec, we include the checksum to work around a GnuPG bug (https://dev.gnupg.org/T7071)
    const { privateKey: v4Key } = await openpgp.generateKey({ userIDs: { email: 'v4@armor.test' }, format: 'object' });
    expect(includesArmorChecksum(v4Key.armor())).to.be.true;
    const { privateKey: v6Key } = await openpgp.generateKey({ userIDs: { email: 'v6@armor.test' }, config: { v6Keys: true, aeadProtect: true }, format: 'object' });
    expect(includesArmorChecksum(v6Key.armor())).to.be.false;

    const messageWithSEIPDv1 = await openpgp.encrypt({ message: await openpgp.createMessage({ text: 'test' }), encryptionKeys: v4Key });
    expect(includesArmorChecksum(messageWithSEIPDv1)).to.be.true;
    const messageWithSEIPDv2 = await openpgp.encrypt({ message: await openpgp.createMessage({ text: 'test' }), encryptionKeys: v6Key });
    expect(includesArmorChecksum(messageWithSEIPDv2)).to.be.false;

    const signatureV4V6 = await openpgp.sign({ message: await openpgp.createMessage({ text: 'test' }), signingKeys: [v4Key, v6Key] });
    expect(includesArmorChecksum(signatureV4V6)).to.be.true;
    const signatureV6 = await openpgp.sign({ message: await openpgp.createMessage({ text: 'test' }), signingKeys: v6Key });
    expect(includesArmorChecksum(signatureV6)).to.be.false;

    const detachedSignatureV4V6 = await openpgp.sign({ message: await openpgp.createMessage({ text: 'test' }), signingKeys: [v4Key, v6Key], detached: true });
    expect(includesArmorChecksum(detachedSignatureV4V6)).to.be.true;
    const detachedSignatureV6 = await openpgp.sign({ message: await openpgp.createMessage({ text: 'test' }), signingKeys: v6Key, detached: true });
    expect(includesArmorChecksum(detachedSignatureV6)).to.be.false;

    const cleartextSignatureV4V6 = await openpgp.sign({ message: await openpgp.createCleartextMessage({ text: 'test' }), signingKeys: [v4Key, v6Key] });
    expect(includesArmorChecksum(cleartextSignatureV4V6)).to.be.true;
    const cleartextSignatureV6 = await openpgp.sign({ message: await openpgp.createCleartextMessage({ text: 'test' }), signingKeys: v6Key });
    expect(includesArmorChecksum(cleartextSignatureV6)).to.be.false;
  });

  it('Do not add extraneous blank line when base64 ends on line break', async function () {
    const pubKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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

-----END PGP PUBLIC KEY BLOCK-----
`;

    const { type, data } = await openpgp.unarmor(pubKey);
    const armor = await openpgp.armor(type, data);
    expect(
      armor
        .replace(/^(Version|Comment): .*$\n/mg, '')
    ).to.equal(
      pubKey
        .replace('\n-', '-')
        .replace(/\n\r/g, '\n')
    );
  });

});

