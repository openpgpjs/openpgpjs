function encrypt() {
  if (window.crypto.getRandomValues) {
    require("./openpgp.min.js");
    var pub_key = openpgp.key.readArmored($('#pubkey').text());
    $('#message').val(openpgp.encryptMessage(pub_key.keys,$('#message').val()));
    window.alert("This message is going to be sent:\n" + $('#message').val());
    return true;
  } else {
    $("#mybutton").val("browser not supported");
    window.alert("Error: Browser not supported\nReason: We need a cryptographically secure PRNG to be implemented (i.e. the window.crypto method)\nSolution: Use Chrome >= 11, Safari >= 3.1 or Firefox >= 21");   
    return false;
  }
}

function require(script) {
    $.ajax({
        url: script,
        dataType: "script",
        async: false,           // <-- this is the key
        success: function () {
            // all good...
        },
        error: function () {
            throw new Error("Could not load script " + script);
        }
    });
}
