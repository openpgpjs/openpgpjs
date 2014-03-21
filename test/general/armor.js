'use strict';

var openpgp = typeof window != 'undefined' && window.openpgp ? window.openpgp : require('../../src/index');

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
      '\u000b\u00a0',
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
      '-----BEGIN PGP SIGNATURE-----',
      'Version: GnuPG v2.0.22 (GNU/Linux)',
      '',
      'iJwEAQECAAYFAlMrPj0ACgkQ4IT3RGwgLJfYkQQAgHMQieazCVdfGAfzQM69Egm5',
      'HhcQszODD898wpoGCHgiNdNo1+5nujQAtXnkcxM+Vf7onfbTvUqut/siyO3fzqhK',
      'LQ9DiQUwJMBE8nOwVR7Mpc4kLNngMTNaHAjZaVaDpTCrklPY+TPHIZnu0B6Ur+6t',
      'skTzzVXIxMYw8ihbHfk=',
      '=e/eA',
      '-----END PGP SIGNATURE-----'].join('\n');

    msg = openpgp.cleartext.readArmored.bind(null, msg);
    expect(msg).to.throw(Error, /Unknow ASCII armor type/);
  });

});

 
