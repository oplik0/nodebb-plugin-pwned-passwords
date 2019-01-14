'use strict';

const crypto = require('crypto');
const https = require('https');
const LRU = require('lru-cache');
const User = require.main.require('./src/user');

const cache = LRU(100);

const originalIsPasswordValid = User.isPasswordValid;

User.isPasswordValid = function (password, minStrength, callback) {
	const cb = typeof minStrength === 'function' && !callback ?
		minStrength : callback;
	const args = Array.prototype.slice.call(arguments, 0);

	const hash = crypto.createHash('sha1');
	hash.update(password);
	const sha1 = hash.digest('hex').toUpperCase();

	const cachedHashes = cache.get(sha1.substring(0, 5));
	if (cachedHashes) {
		return checkPassword(sha1, cachedHashes, args, cb);
	}

	https.get('https://api.pwnedpasswords.com/range/' + sha1.substring(0, 5), function (res) {
		var body = '';
		res.on('data', function (data) {
			body += data;
		});
		res.on('end', function () {
			const hashes = body.split(/\r?\n/g);
			cache.set(sha1.substring(0, 5), hashes);
			checkPassword(sha1, hashes, args, cb);
		});
	}).on('error', function (err) {
		cb(err);
	});
};

function checkPassword(sha1, hashes, args, callback) {
	const bad = hashes.find(function (line) {
		return line.substring(0, 36) === sha1.substring(5) + ':';
	});
	if (bad) {
		callback(new Error('[[pwned-passwords:bad-password, ' + parseInt(bad.substring(36), 10) + ']]'));
		return;
	}
	originalIsPasswordValid.apply(User, args);
}
