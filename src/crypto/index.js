
module.exports = {
	cipher: {
		aes: require('./symmetric/aes.js'),
		des: require('./symmetric/dessrc.js'),
		cast5: require('./symmetric/cast5.js'),
		twofish: require('./symmetric/twofish.js'),
		blowfish: require('./symmetric/blowfish.js')
	},
	hash: {
		md5: require('./hash/md5.js'),
		sha: require('./hash/sha.js'),
		ripemd: require('./hash/ripe-md.js')
	}
}

