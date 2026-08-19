// supply-chain-sim/npm-package/lib/guardrail.test.js
const { test } = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const { assertAuthorized, assertThrowawayOrg } = require('./guardrail.js');

test('aborts when the host is not in the allowlist', () => {
  process.env.SIM_ALLOWED_HOSTS = 'some-other-host';
  assert.throws(() => assertAuthorized(), /not authorized/i);
});

test('passes when the host is in the allowlist', () => {
  process.env.SIM_ALLOWED_HOSTS = os.hostname();
  assert.doesNotThrow(() => assertAuthorized());
});

test('assertThrowawayOrg rejects a non-throwaway org', () => {
  assert.throws(() => assertThrowawayOrg('real-victim-org'), /not a recognised throwaway org/);
});

test('assertThrowawayOrg allows a throwaway org and empty', () => {
  assert.doesNotThrow(() => assertThrowawayOrg('sim-foo'));
  assert.doesNotThrow(() => assertThrowawayOrg(''));
});
