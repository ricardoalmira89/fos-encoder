const hashEquals = require('hash-equals');
const crypto = require('crypto');

//FOS-LIKE hash function for php
const encodePassword = (password, salt, algo = 'sha512', iterations = 5000) => {

  const mergePasswordAndSalt = (password, salt) => `${password}{${salt}}`
  const salted = mergePasswordAndSalt(password, salt);
  var digest = crypto.createHash(algo).update(salted).digest('binary');

  for (var i = 1; i < iterations; i++) {
    digest = crypto.createHash(algo).update(Buffer.from(digest + salted, 'binary')).digest('binary');
  }

  return Buffer.from(digest, 'binary').toString('base64');

}

/**
 * Compares two passwords.
 *
 * This method implements a constant-time algorithm to compare passwords to
 * avoid (remote) timing attacks.
 *
 * @param string $password1 The first password
 * @param string $password2 The second password
 *
 * @return bool true if the two passwords are the same, false otherwise
 */
const isPasswordValid = (encoded, raw, salt) => {
  return hashEquals(encoded, encodePassword(raw, salt));
}

module.exports = { encodePassword, isPasswordValid };

