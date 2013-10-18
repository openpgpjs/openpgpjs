
unittests.register("ASCII dearmor test", function() {
	var result = new Array();

	var armoredText = [
	  '-----BEGIN PGP SIGNED MESSAGE-----',
	  'Hash: SHA256',
	  '',
	  'Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua.',
	  '',
	  'At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.',
	  '',
	  '',
	  'Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.',
	  '',
	  '-----BEGIN PGP SIGNATURE-----',
	  'Version: OpenPGP.js v.1.20131017',
	  'Comment: http://openpgpjs.org',
	  '',
	  'wsBcBAEBCAAQBQJSYSqsCRD9ElmC3lAG4QAAT3IIAJfl8tkOW3L31YhpTQAO',
	  'LrBSL//u6sL7I66xgsXTcyDjmdFGf+FvkWKcV0SYD5i47jQuxjQ6nxVg0nWX',
	  'QHxu7/eNG1orUO5CbwkOMImZ6ZIfGVzni3FAHgS0yzajlM8OdLYNNmLfWiAu',
	  'Il6+/Sisjkc/TmE02gqMCUjMLKJceZRufUX985C+8suSJ/sBR8eyACfzZzY2',
	  'QM/2l3e4JTn6eyLPd8bChnYQhstnAB9eO8PMU909zMr1GTJrIz/L4HiHnKpf',
	  'c94cNhWj0DMMJqBrsmP81sBtYFx1C+NOMo4DtmwBJ7uBJpFKrtwdCDkLsYg7',
	  'BKf7Ligbb9NkDnDgZ0Dv9xw=',
	  '=L81u',
	  '-----END PGP SIGNATURE-----'
	].join('\n');
	
	var messageText = [
	  'Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua.',
	  '',
	  'At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.',
	  '',
	  '',
	  'Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.',
	  ''
	].join('\n');
	
	var publicKey = [
	  '-----BEGIN PGP PUBLIC KEY BLOCK-----',
	  'Version: OpenPGP.js v.1.20131017',
	  'Comment: http://openpgpjs.org',
	  '',
	  'xsBNBFJhKmYBCACklSRwGQyihccW6mtaNFABuEli8nsKNvMw21Z64JfsHSBl',
	  '04fNME4bLzGOurjIXRrLq+9EuSq1Ozq9DuSjed2+qV6rLDH+FZc/yVuhmEPs',
	  'KPzBarcD834i57hALMxc0Q5k0G6PU73+VDvoMZP92CTb43jr94Jy6gLMjEBn',
	  'Wru2NayvzhqvFxGpGPHcavazYD39c80PlcAEFA6rqo4R2jQn6P02rtv+yPAJ',
	  'ZXF1GkLnJLI8ByUWWr7bjUr5L50q6W3gNVUQL20KeGw/i7t5HUOOxp8x0zlF',
	  'LjR1tg6m0tEFhhYEBlo1Z75eOoz3oSkoyYNSjfR/0U380I8Q6EHZJRN5ABEB',
	  'AAHNF1Rlc3QgPHRlc3RAZXhhbXBsZS5jb20+wsBcBBABCAAQBQJSYSp6CRD9',
	  'ElmC3lAG4QAAOBQH+wWambBr1klXZ9dkgvZPlHFCCFMJS8xNBZjAmNOpLnWq',
	  'bBxhYGQRUjmTzJD4Xm7zMO/F+dpU84tsNTg09zDwPMjPCPHCHacutm6kf1LV',
	  'mKwMNpmNLVobbccjouxx6mrOOjcj+HNs1Xw42Qm9dNLBRq7wByW5K4Lp6HQH',
	  'QrWaNBvt7h4myn+h/g0SotS1kHiAsuo0KTv16DA+V539ExVyL+AnD7xQMYX5',
	  '42JmsQ1C4bHpiOlsDldVUdwTijRShtCAl9MJG8AYt2rpvcA30ds5QPhswzX/',
	  'wNdsJr5Eg9uc8+zTkRfWP8Zjby0pDWO21tPIDkRQtmBCKUh+h5ab3Y4MSLY=',
	  '=vOpZ',
	  '-----END PGP PUBLIC KEY BLOCK-----'
	].join('\n');

	result[0] = new test_result("Dearmor a multi-paragraph clear-text signed message", (messageText == openpgp_encoding_deArmor(armoredText).text));
	return result;
});
