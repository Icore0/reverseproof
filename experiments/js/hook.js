// The attacker's whole toolkit: record whatever the app sends, no deobfuscation needed.
const fs = require('node:fs');
globalThis.fetch = async (url, opts = {}) => {
  fs.appendFileSync(process.env.HOOK_OUT, JSON.stringify(opts.headers || {}) + '\n');
  return new Response('stub');
};
