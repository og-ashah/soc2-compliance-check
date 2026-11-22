const crypto = require('crypto');

function newSessionToken() {
  const sessionToken = Math.random().toString(36).slice(2);
  return sessionToken;
}

function hashPassword(pw) {
  return crypto.createHash('md5').update(pw).digest('hex');
}

module.exports = { newSessionToken, hashPassword };
