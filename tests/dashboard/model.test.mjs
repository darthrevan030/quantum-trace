import assert from 'node:assert/strict';
import { parseRepository, filterSessions, riskOf, formatBytes, algorithmLabel, reportEntries, riskDistribution, algorithmCounts } from '../../frontend/model.mjs';

assert.equal(parseRepository(' https://github.com/team/project/ ').url, 'https://github.com/team/project.git');
assert.equal(parseRepository('https://gitlab.com/group/subgroup/project.git').name, 'group/subgroup/project');
for (const url of ['garbage', 'http://github.com/team/project', 'https://github.com.evil.test/team/project', 'https://user:secret@github.com/team/project', 'https://github.com/team', 'https://github.com/team/project/tree/main', 'https://gitlab.com/team/project/-/tree/main', 'https://gitlab.com/team/project?token=secret', 'https://github.com/team/project#readme', 'https://github.com:8443/team/project']) {
  assert.throws(() => parseRepository(url), undefined, url);
}

const finding = (source, algorithm, tier, primitive) => ({
  type: 'application-code', name: `${source}:1`, source,
  cryptoProperties: { language: 'javascript', detectedAlgorithm: algorithm, primitive },
  quantumRiskAssessment: { tier },
});
const code = { metadata: {}, components: [
  finding('src/a.js', 'AES-128-CBC', 'MEDIUM', 'encryption'),
  finding('src/a.js', 'RSA-2048', 'CRITICAL', 'signature'),
  finding('src/b.ts', 'ECDH P-384', 'CRITICAL', 'keyExchange'),
  finding('src/b.ts', 'X25519MLKEM768', 'SAFE', 'keyExchange'),
  finding('src/c.js', 'AES-256-GCM', 'SAFE', 'encryption'),
  finding('package.json', 'jsonwebtoken (crypto library)', 'UNKNOWN', null),
] };
const original = JSON.stringify(code);
assert.equal(filterSessions(code.components, '', 'ALL').length, 6);
assert.deepEqual(filterSessions(code.components, 'mlkem', 'ALL').map(c => c.source), ['src/b.ts']);
assert.deepEqual(filterSessions(code.components, '', 'CRITICAL').map(c => c.cryptoProperties.detectedAlgorithm), ['RSA-2048', 'ECDH P-384']);
assert.equal(filterSessions(code.components, 'no-such-finding', 'ALL').length, 0);
assert.equal(JSON.stringify(code), original, 'Displaying scanner ratings must preserve the original report');
assert.equal(riskOf({ risk: 'unrecognized' }), 'UNKNOWN');
assert.equal(riskOf(null), 'UNKNOWN');
assert.equal(riskOf({ quantumRiskAssessment: { tier: 'Critical' } }), 'CRITICAL');
assert.equal(riskOf({ quantumRiskAssessment: { tier: 'Safe' } }), 'SAFE');
assert.equal(riskOf({ quantumRiskAssessment: { tier: 'Unexpected' } }), 'UNKNOWN');
assert.equal(riskOf({ risk: 'MEDIUM', quantumRiskAssessment: { tier: 'Critical' } }), 'MEDIUM');
assert.equal(algorithmLabel({ algorithm: 'AES', keySizeBits: 256, mode: 'GCM' }), 'AES · 256-bit · GCM');
assert.equal(algorithmLabel({ algorithm: 'ML-KEM', parameterSet: '768' }), 'ML-KEM · 768');
assert.equal(algorithmLabel(null), 'Not recorded');
assert.equal(formatBytes(0), '0 B');
assert.equal(formatBytes(1024), '1.0 KB');
console.log('Frontend checks passed: repository validation, report filtering, risk fallback, algorithm labels, and file sizes.');

const entries = reportEntries([code]);
assert.equal(entries.length, 6);
assert.deepEqual(riskDistribution(entries, 'findings'), { total: 6, omitted: 0, counts: { CRITICAL: 2, HIGH: 0, MEDIUM: 1, LOW: 0, SAFE: 2, UNKNOWN: 1 } });
// a.js: CRITICAL beats MEDIUM; b.ts: CRITICAL beats SAFE; c.js: SAFE; package.json: UNKNOWN.
assert.deepEqual(riskDistribution(entries, 'files'), { total: 4, omitted: 0, counts: { CRITICAL: 2, HIGH: 0, MEDIUM: 0, LOW: 0, SAFE: 1, UNKNOWN: 1 } });
// Code findings feed the purpose charts through their detected primitive.
assert.deepEqual(algorithmCounts(entries, 'encryption'), { included: 2, rows: [['AES-128-CBC', 1], ['AES-256-GCM', 1]] });
assert.deepEqual(algorithmCounts(entries, 'keyExchange').rows, [['ECDH P-384', 1], ['X25519MLKEM768', 1]]);
assert.equal(algorithmCounts(entries, 'other').included, 6);
// Structured per-purpose details (as an extension report may provide) take precedence and keep their parameters.
const structured = reportEntries([{ components: [{ risk: 'SAFE', cryptoProperties: { encryption: { algorithm: 'AES', keySizeBits: 256 } } }] }]);
assert.deepEqual(algorithmCounts(structured, 'encryption').rows, [['AES · 256-bit', 1]]);
assert.deepEqual(algorithmCounts([], 'encryption'), { included: 0, rows: [] });
assert.equal(riskDistribution([], 'files').total, 0);
const mixed = [
  { component: { risk: 'SAFE' }, source: './input_files/a.py' },
  { component: { risk: 'UNKNOWN' }, source: '../input_files/a.py' },
  { component: { risk: 'MEDIUM' }, source: 'input_files/a.py' },
  { component: { risk: 'SAFE' }, source: null },
];
assert.equal(riskDistribution(mixed, 'files').counts.UNKNOWN, 1);
assert.equal(riskDistribution(mixed, 'files').omitted, 1);
mixed.push({ component: { risk: 'CRITICAL' }, source: 'input_files/a.py' });
assert.equal(riskDistribution(mixed, 'files').counts.CRITICAL, 1);
console.log('Chart checks passed: file deduplication, risk precedence, missing sources, finding totals, algorithm counts, and empty reports.');
