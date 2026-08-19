// supply-chain-sim/npm-package/scripts/persistence-teardown.js
// Reverse the persistence stage: stop + uninstall the SHA1HULUD runner service, deregister the runner
// from the throwaway repo, and remove the runner directory. Run on the host with config.env sourced;
// on macOS/Linux use `sudo -E node ...` so the service uninstall has privilege.
const { teardownPersistence } = require('../lib/persistence.js');

teardownPersistence()
  .then(r => console.log('[sim] persistence teardown complete:', JSON.stringify(r)))
  .catch(e => { console.error('[sim] teardown error:', e.message); process.exit(1); });
