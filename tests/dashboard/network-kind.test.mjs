import assert from 'node:assert/strict';
import { riskOf } from '../../frontend/model.mjs';
import { REPORT_KINDS } from '../../frontend/report-kinds.mjs';
import { PARTS, authenticationRecorded } from '../../frontend/kinds/network.mjs';

// Minimal stand-ins for the ui helpers app.mjs hands to report kinds.
const element = (tag, text = '', className = '') => ({
  tag, textContent: text, className, children: [], events: {},
  append(...children) { this.children.push(...children); },
  addEventListener(type, callback) { this.events[type] = callback; },
});
const shown = [];
const ui = {
  element, title: value => value[0] + value.slice(1).toLowerCase(),
  badge: details => element('span', riskOf(details), 'risk'),
  detailButton: () => element('button', 'inspect'),
  showDetails: (component, trigger) => shown.push([component, trigger]),
  appendDetails: (content, sections) => { content.sections = sections; },
};
const text = node => [node.textContent, ...node.children.map(text)].join(' ');

const network = REPORT_KINDS.network;
assert.deepEqual(Object.keys(REPORT_KINDS), ['code', 'network'], 'network registers after the built-in code kind');
assert.equal(network.unit, 'sessions');
assert.equal(network.columns.length, 7);
assert.equal(network.category, undefined, 'sessions have no language/asset filter');
assert.equal(network.detailKind, 'SESSION DETAILS');

for (const algorithm of [undefined, null, '', 'Not recorded', 'Negotiated separately', 'Not determined']) {
  assert.equal(authenticationRecorded({ algorithm }), false);
}
for (const algorithm of ['RSA', 'ECDSA', 'Unsupported signature', 'None']) assert.equal(authenticationRecorded({ algorithm }), true);
assert.equal(authenticationRecorded(null), false);

const session = {
  type: 'network-session', name: 'TLS-Session-198.51.100.4:443', risk: 'SAFE',
  evidence: { client: '192.0.2.4:50004', server: '198.51.100.4:443' },
  cryptoProperties: {
    protocol: 'TLS', negotiatedVersion: null,
    encryption: { algorithm: 'AES', keySizeBits: 256, mode: 'GCM', risk: 'SAFE' },
    hash: { algorithm: 'SHA-384', risk: 'SAFE' },
    keyExchange: { algorithm: 'Hybrid key exchange', risk: 'SAFE', components: [
      { algorithm: 'X25519', risk: 'CRITICAL' }, { algorithm: 'ML-KEM', parameterSet: '768', risk: 'SAFE' }] },
    authentication: { algorithm: 'Not recorded', risk: 'UNKNOWN' },
    offeredGroups: ['X25519MLKEM768'],
  },
};

const row = network.row(session, ui);
assert.equal(row.tag, 'tr');
assert.equal(row.children.length, 7, 'name, four algorithm cells, overall risk, details');
assert.match(text(row.children[0]), /192\.0\.2\.4:50004 → 198\.51\.100\.4:443/);
assert.match(text(row.children[1]), /AES · 256-bit · GCM SAFE/);
assert.match(text(row.children[4]), /Not recorded .*Excluded from overall risk/, 'missing authentication is shown, not rated');
assert.equal(text(row.children[5]).trim(), 'SAFE');
row.children[0].children[0].events.click();
assert.equal(shown.at(-1)[0], session, 'the session name opens its details');

const content = element('div');
network.details(session, content, ui);
const [grid, conclusion] = content.children;
assert.equal(grid.children.length, PARTS.length);
assert.match(text(grid.children[2]), /X25519 CRITICAL .*ML-KEM · 768 SAFE .*combined hybrid/, 'hybrid parts are rated separately');
assert.match(text(conclusion), /Overall TLS risk .* SAFE/);
assert.deepEqual(Object.keys(content.sections), ['evidence', 'protocol', 'negotiatedVersion', 'offeredGroups'],
  'per-algorithm sections are not repeated as raw details');
console.log('Network kind checks passed: registration, authentication availability, session rows, hybrid details.');
