#!/usr/bin/env node
'use strict';
const { scan } = require('../src/scan');
const { audit, applyIgnore } = require('../src/audit');

const args = process.argv.slice(2);
const json = args.includes('--json');
const all = args.includes('--all');
const cmd = args.includes('audit') ? 'audit' : 'scan';
const target = args.find((a) => !a.startsWith('--') && a !== 'scan' && a !== 'audit');
if (!target) {
  console.error('usage: reverseproof scan <path-to-app|dir|binary> [--json] [--all]\n       reverseproof audit <repo-dir> [--json]');
  process.exit(2);
}
const findings = applyIgnore(cmd === 'audit' ? audit(target) : scan(target, { all }), target);
if (json) {
  console.log(JSON.stringify(findings, null, 2));
} else {
  const tag = { high: 'HIGH  ', medium: 'MEDIUM', low: 'LOW   ', info: 'INFO  ' };
  for (const f of findings) {
    console.log(`[${tag[f.severity]}] ${f.id}\n    ${f.file}\n    ${f.message}${f.fix ? '\n    fix: ' + f.fix : ''}`);
  }
  const c = (s) => findings.filter((f) => f.severity === s).length;
  console.log(`\n${c('high')} high, ${c('medium')} medium, ${c('low')} low, ${c('info')} info`);
}
process.exit(findings.some((f) => f.severity === 'high') ? 1 : 0);
