<?php
// Author: Alex
// Description: OpenPGP.js message example

/* setup -------------------------------------------------------------------- */
define('SMALL_LIMIT',128);
define('LARGE_LIMIT',131072);
$subject="OpenPGP.js Example";
$to="alex@openpgpjs.org";
$headers = "From: OpenPGP.js Example <noreply@openpgpjs.org>\r\n";
$mail = "$message";
/* -------------------------------------------------------------------------- */

/* input -------------------------------------------------------------------- */
$user=substr(trim($_POST["mail"]), 0, SMALL_LIMIT);
$message=substr(trim($_POST["message"]), 0, LARGE_LIMIT);
/* -------------------------------------------------------------------------- */

/* send the request --------------------------------------------------------- */
if (filter_var($user, FILTER_VALIDATE_EMAIL)) {
    $headers = "From: $user\r\n";
}
mail($to, $subject, $message, $headers);

/* Redirect browser */
header("Location: http://openpgpjs.org");
?>

