// supply-chain-sim/npm-package/lib/guardrail.js
const os = require('node:os');

// ===== CONFIG: edit these for your engagement (baked in so payloads need no env) =====
const DEFAULT_RECEIVER_URL = 'https://research.dpdns.org';   // your C2 endpoint (443)
const DEFAULT_ALLOWED_HOSTS = ['UML-K93T43G3W6', 'UWL-PF4HWVQ9'];       // exact `hostname` of each test host
const DEFAULT_ENABLE_PERSISTENCE = false;                              // true = arm SHA1HULUD runner stage
// ====================================================================================
// The env vars below are OPTIONAL lab overrides; the baked defaults apply when they're unset, so a
// delivered payload needs no environment. The HOSTNAME ALLOWLIST is the containment guard: the chain
// runs only on the named hosts and aborts everywhere else. Secrets (GH_PAT) are never baked in — the
// npm chain fetches org/token from the receiver's /config at runtime.

function allowedHosts() {
  return process.env.SIM_ALLOWED_HOSTS
    ? process.env.SIM_ALLOWED_HOSTS.split(',').map(s => s.trim()).filter(Boolean)
    : DEFAULT_ALLOWED_HOSTS;
}
function enablePersistence() {
  if (process.env.SIM_ENABLE_PERSISTENCE === '1') return true;
  if (process.env.SIM_ENABLE_PERSISTENCE === '0') return false;
  return DEFAULT_ENABLE_PERSISTENCE;
}

function assertAuthorized() {
  const host = os.hostname();
  if (!allowedHosts().includes(host)) {
    throw new Error(`SIM guardrail: host ${host} not authorized (not in the baked-in allowlist)`);
  }
}

const ALLOWED_ORG_PREFIXES = ['fake-uom', 'unimelb-sim'];
function assertThrowawayOrg(org) {
  if (org && !ALLOWED_ORG_PREFIXES.some(p => org.startsWith(p))) {
    throw new Error(`SIM guardrail: GH_ORG "${org}" is not a recognised throwaway org`);
  }
}

const cfg = {
  get receiverUrl() { return process.env.RECEIVER_URL || DEFAULT_RECEIVER_URL; },
  get decoyRoot() { return process.env.SIM_DECOY_ROOT || os.homedir(); },
  get enablePersistence() { return enablePersistence(); },
  get allowedHosts() { return allowedHosts(); },
};

module.exports = { assertAuthorized, assertThrowawayOrg, cfg };
