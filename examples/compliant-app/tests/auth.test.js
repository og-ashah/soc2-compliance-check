const test = require('node:test');
const assert = require('node:assert');
const { newSessionToken, hashToken } = require('../src/auth');

test('session tokens are 64 hex characters', () => {
  assert.match(newSessionToken(), /^[0-9a-f]{64}$/);
});

test('hashing is deterministic', () => {
  assert.strictEqual(hashToken('abc'), hashToken('abc'));
});
