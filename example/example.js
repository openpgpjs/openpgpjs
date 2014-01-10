function encrypt() {
  if (window.crypto.getRandomValues) {

    // read public key
    var pub_key = openpgp.key.readArmored($('#pubkey').text());
    // encrypt message
    var pgp_message = openpgp.encryptMessage(pub_key.keys, $('#message').val());

    $('#message').val(pgp_message);
    window.alert("This message is going to be sent:\n" + $('#message').val());
    return true;
  } else {
    $("#mybutton").val("browser not supported");
    window.alert("Error: Browser not supported\nReason: We need a cryptographically secure PRNG to be implemented (i.e. the window.crypto method)\nSolution: Use Chrome >= 11, Safari >= 3.1 or Firefox >= 21");   
    return false;
  }
}