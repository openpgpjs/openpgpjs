const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../../dist/openpgp');

const chai = require('chai');

const { util } = openpgp;
const md5 = openpgp.crypto.hash.md5;
const { expect } = chai;

it('MD5 with test vectors from RFC 1321', async function() {
  expect(util.str_to_hex(util.Uint8Array_to_str(await md5(util.str_to_Uint8Array(''))), 'MD5("") = d41d8cd98f00b204e9800998ecf8427e')).to.equal('d41d8cd98f00b204e9800998ecf8427e');
  expect(util.str_to_hex(util.Uint8Array_to_str(await md5(util.str_to_Uint8Array('abc'))), 'MD5("a") = 0cc175b9c0f1b6a831c399e269772661')).to.equal('900150983cd24fb0d6963f7d28e17f72');
  expect(util.str_to_hex(util.Uint8Array_to_str(await md5(util.str_to_Uint8Array('message digest'))), 'MD5("message digest") = f96b697d7cb7938d525a2f31aaf161d0')).to.equal('f96b697d7cb7938d525a2f31aaf161d0');
  expect(util.str_to_hex(util.Uint8Array_to_str(await md5(util.str_to_Uint8Array('abcdefghijklmnopqrstuvwxyz'))), 'MD5("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b')).to.equal('c3fcd3d76192e4007dfb496cca67e13b');
  expect(util.str_to_hex(util.Uint8Array_to_str(await md5(util.str_to_Uint8Array('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'))), 'MD5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") = d174ab98d277d9f5a5611c2c9f419d9f')).to.equal('d174ab98d277d9f5a5611c2c9f419d9f');
  expect(util.str_to_hex(util.Uint8Array_to_str(await md5(util.str_to_Uint8Array('12345678901234567890123456789012345678901234567890123456789012345678901234567890'))), 'MD5("12345678901234567890123456789012345678901234567890123456789012345678901234567890") = 57edf4a22be3c955ac49da2e2107b67a')).to.equal('57edf4a22be3c955ac49da2e2107b67a');
});
