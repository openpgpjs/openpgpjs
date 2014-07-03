'use strict';

var openpgp = typeof window != 'undefined' && window.openpgp ? window.openpgp : require('openpgp');

var chai = require('chai'),
  expect = chai.expect;


describe("ASCII armor", function() {

  function getArmor(headers) {
    return ['-----BEGIN PGP SIGNED MESSAGE-----']
      .concat(headers)
      .concat(
        ['',
        'sign this',
        '-----BEGIN PGP SIGNATURE-----',
        'Version: GnuPG v2.0.22 (GNU/Linux)',
        '',
        'iJwEAQECAAYFAlMrPj0ACgkQ4IT3RGwgLJfYkQQAgHMQieazCVdfGAfzQM69Egm5',
        'HhcQszODD898wpoGCHgiNdNo1+5nujQAtXnkcxM+Vf7onfbTvUqut/siyO3fzqhK',
        'LQ9DiQUwJMBE8nOwVR7Mpc4kLNngMTNaHAjZaVaDpTCrklPY+TPHIZnu0B6Ur+6t',
        'skTzzVXIxMYw8ihbHfk=',
        '=e/eA',
        '-----END PGP SIGNATURE-----']
      ).join('\n');
  }

  it('Parse cleartext signed message', function () {
    var msg = getArmor(['Hash: SHA1']);
    msg = openpgp.cleartext.readArmored(msg);
    expect(msg).to.be.an.instanceof(openpgp.cleartext.CleartextMessage);
  });

  it('Exception if mismatch in armor header and signature', function () {
    var msg = getArmor(['Hash: SHA256']);
    msg = openpgp.cleartext.readArmored.bind(null, msg);
    expect(msg).to.throw(Error, /Hash algorithm mismatch in armor header and signature/);
  });

  it('Exception if no header and non-MD5 signature', function () {
    var msg = getArmor(null);
    msg = openpgp.cleartext.readArmored.bind(null, msg);
    expect(msg).to.throw(Error, /If no "Hash" header in cleartext signed message, then only MD5 signatures allowed/);
  });

  it('Exception if unknown hash algorithm', function () {
    var msg = getArmor(['Hash: LAV750']);
    msg = openpgp.cleartext.readArmored.bind(null, msg);
    expect(msg).to.throw(Error, /Unknown hash algorithm in armor header/);
  });

  it('Multiple hash values', function () {
    var msg = getArmor(['Hash: SHA1, SHA256']);
    msg = openpgp.cleartext.readArmored(msg);
    expect(msg).to.be.an.instanceof(openpgp.cleartext.CleartextMessage);
  });

  it('Multiple hash header lines', function () {
    var msg = getArmor(['Hash: SHA1', 'Hash: SHA256']);
    msg = openpgp.cleartext.readArmored(msg);
    expect(msg).to.be.an.instanceof(openpgp.cleartext.CleartextMessage);
  });

  it('Non-hash header line throws exception', function () {
    var msg = getArmor(['Hash: SHA1', 'Comment: could be anything']);
    msg = openpgp.cleartext.readArmored.bind(null, msg);
    expect(msg).to.throw(Error, /Only "Hash" header allowed in cleartext signed message/);
  });

  it('Multiple wrong hash values', function () {
    var msg = getArmor(['Hash: SHA512, SHA256']);
    msg = openpgp.cleartext.readArmored.bind(null, msg);
    expect(msg).to.throw(Error, /Hash algorithm mismatch in armor header and signature/);
  });

  it('Multiple wrong hash values', function () {
    var msg = getArmor(['Hash: SHA512, SHA256']);
    msg = openpgp.cleartext.readArmored.bind(null, msg);
    expect(msg).to.throw(Error, /Hash algorithm mismatch in armor header and signature/);
  });

  it('Filter whitespace in blank line', function () {
    var msg =
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

    msg = openpgp.cleartext.readArmored(msg);
    expect(msg).to.be.an.instanceof(openpgp.cleartext.CleartextMessage);
  });

  it('Exception if improperly formatted armor header', function () {
    var msg = getArmor(['Hash:SHA256']);
    msg = openpgp.cleartext.readArmored.bind(null, msg);
    expect(msg).to.throw(Error, /Improperly formatted armor header/);
    msg = getArmor(['<script>: SHA256']);
    msg = openpgp.cleartext.readArmored.bind(null, msg);
    expect(msg).to.throw(Error, /Improperly formatted armor header/);
    msg = getArmor(['Hash SHA256']);
    msg = openpgp.cleartext.readArmored.bind(null, msg);
    expect(msg).to.throw(Error, /Improperly formatted armor header/);
  });

  it('Exception if wrong armor header type', function () {
    var msg =
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

    msg = openpgp.cleartext.readArmored.bind(null, msg);
    expect(msg).to.throw(Error, /Unknow ASCII armor type/);
  });

  it('Armor checksum validation', function () {
    var privKey =
      ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
      'Version: OpenPGP.js v0.3.0',
      'Comment: http://openpgpjs.org',
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

    var result = openpgp.key.readArmored(privKey);
    expect(result.err).to.exist;
    expect(result.err[0].message).to.match(/Ascii armor integrity check on message failed/);
  });

  it('Accept header with trailing whitespace', function () {
    var privKey =
      ['-----BEGIN PGP PRIVATE KEY BLOCK-----\t \r',
      'Version: OpenPGP.js v0.3.0',
      'Comment: http://openpgpjs.org',
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

    var result = openpgp.key.readArmored(privKey);
    expect(result.err).to.not.exist;
    expect(result.keys[0]).to.be.an.instanceof(openpgp.key.Key);
  });

  it('Do not filter blank lines after header', function () {
    var msg = getArmor(['Hash: SHA1', '']);
    msg = openpgp.cleartext.readArmored(msg);
    expect(msg.text).to.equal('\r\nsign this');
  });

});

 
