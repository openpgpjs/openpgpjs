function encrypt() {
  openpgp.init();
  var pub_key = openpgp.read_publicKey($('#pubkey').text());
  $('#message').val(openpgp.write_encrypted_message(pub_key,$('#message').val()));
}
