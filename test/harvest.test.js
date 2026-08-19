// supply-chain-sim/npm-package/test/harvest.test.js
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { harvest, harvestEnv } = require('../lib/harvest.js');

test('harvest reads decoy credential files by their real target paths', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sim-decoy-'));
  fs.mkdirSync(path.join(root, '.aws'), { recursive: true });
  fs.writeFileSync(path.join(root, '.npmrc'), '//registry.npmjs.org/:_authToken=npm_FAKEdecoy0000');
  fs.writeFileSync(path.join(root, '.aws', 'credentials'), '[default]\naws_access_key_id=AKIAFAKEDECOY000000\naws_secret_access_key=fakedecoysecret');
  const out = harvest(root);
  assert.match(out.contents['.npmrc'], /npm_FAKEdecoy/);          // .npmrc lives in contents now
  assert.match(out.cloud['.aws/credentials'], /AKIAFAKEDECOY/);
  assert.strictEqual(out.contents['.ssh/id_rsa'], null);          // absent decoy recorded as null
  assert.ok(out.truffleSecrets.found.includes('.npmrc'));         // present decoys listed
});

test('harvest captures secret-looking environment variables into environment', () => {
  const env = { GITHUB_TOKEN: 'ghp_fake', AWS_SECRET_ACCESS_KEY: 'fake', HOME: '/x', PATH: '/y' };
  const got = harvestEnv(env);
  assert.strictEqual(got.GITHUB_TOKEN, 'ghp_fake');
  assert.strictEqual(got.AWS_SECRET_ACCESS_KEY, 'fake');
  assert.strictEqual(got.HOME, undefined);                         // non-secret vars excluded
  assert.strictEqual(got.PATH, undefined);
});
