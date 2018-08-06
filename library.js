'use strict';

const crypto = require('crypto');
const https = require('https');
const User = module.parent.require('./user');

const originalIsPasswordValid = User.isPasswordValid;

User.isPasswordValid = function (password, minStrength, callback) {
	const cb = typeof minStrength === 'function' && !callback ?
		minStrength : callback;

	const hash = crypto.createHash('sha1');
	hash.update(password);

	const sha1 = hash.digest('hex').toUpperCase();
	https.get('https://api.pwnedpasswords.com/range/' + sha1.substring(0, 5), function (res) {
		var body = '';
		res.on('data', function (data) {
			body += data;
		});
		res.on('end', function () {
			const hashes = body.split(/\r?\n/g);
			const bad = hashes.find(function (line) {
				return line.substring(0, 36) === sha1.substring(5) + ':';
			});
			if (bad) {
				cb(new Error('[[pwned-passwords:bad-password, ' + parseInt(bad.substring(36), 10) + ']]'));
				return;
			}
			originalIsPasswordValid.apply(User, arguments);
		});
	}).on('error', function (err) {
		cb(err);
	});
};
