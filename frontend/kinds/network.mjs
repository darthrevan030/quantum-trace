// Network report kind: TLS sessions from packet captures, rated algorithm by algorithm.
// Imported from app.mjs (not report-kinds.mjs) so the registry exists before this module runs.
import { algorithmLabel } from '../model.mjs';
import { registerReportKind } from '../report-kinds.mjs';

export const PARTS = [['encryption', 'Encryption'], ['hash', 'Hashing'], ['keyExchange', 'Key exchange'], ['authentication', 'Authentication']];

export function authenticationRecorded(details) {
  return !['', 'Negotiated separately', 'Not recorded', 'Not determined'].includes((details?.algorithm || '').trim());
}

function partEvaluation(purpose, details, { element, badge }) {
  const view = element('div', '', 'part-evaluation');
  const missingAuthentication = purpose === 'authentication' && !authenticationRecorded(details);
  view.append(element('span', missingAuthentication ? 'Not recorded' : algorithmLabel(details), 'algorithm-name'), badge(details));
  if (missingAuthentication) view.append(element('small', 'Excluded from overall risk', 'assessment-note'));
  return view;
}

function row(component, ui) {
  const { element, badge, detailButton, showDetails } = ui;
  const crypto = component.cryptoProperties || {};
  const tr = element('tr');
  const nameCell = element('td');
  const name = element('button', component.name || 'Unnamed session', 'session-button');
  name.addEventListener('click', () => showDetails(component, name));
  nameCell.append(name, element('small', `${component.evidence?.client || 'Unknown client'} → ${component.evidence?.server || 'Unknown server'}`));
  nameCell.append(element('span', [crypto.protocol, crypto.negotiatedVersion].filter(Boolean).join(' ') || 'Not recorded', 'protocol'));
  const parts = PARTS.map(([purpose]) => {
    const cell = element('td');
    cell.append(partEvaluation(purpose, crypto[purpose], ui));
    return cell;
  });
  const risk = element('td', '', 'overall-risk');
  risk.append(badge(component));
  const action = element('td');
  action.append(detailButton(component));
  tr.append(nameCell, ...parts, risk, action);
  return tr;
}

function details(component, content, ui) {
  const { element, badge, appendDetails } = ui;
  const evaluations = element('div', '', 'evaluation-grid');
  for (const [purpose, label] of PARTS) {
    const part = component.cryptoProperties?.[purpose];
    const card = element('section', '', 'evaluation-card');
    card.append(element('h3', label), partEvaluation(purpose, part, ui));
    if (part?.components?.length) {
      const primitives = element('ul', '', 'hybrid-parts');
      for (const primitive of part.components) {
        const item = element('li');
        item.append(element('span', algorithmLabel(primitive)), badge(primitive));
        primitives.append(item);
      }
      card.append(primitives, element('p', 'Primitive ratings shown separately. The key-exchange rating assesses the combined hybrid.', 'assessment-note'));
    }
    // Preserve all recorded parameters without displaying nested components as raw JSON.
    const parameters = element('dl');
    for (const [key, value] of Object.entries(part || {})) {
      if (['algorithm', 'risk', 'components'].includes(key)) continue;
      parameters.append(element('dt', key.replace(/([A-Z])/g, ' $1')), element('dd', String(value ?? 'Not recorded')));
    }
    if (parameters.children.length) card.append(parameters);
    evaluations.append(card);
  }
  const conclusion = element('section', '', 'risk-conclusion');
  const explanation = element('div');
  explanation.append(element('h3', 'Overall TLS risk'), element('p', 'Based on encryption, hashing, and key exchange. Authentication contributes only when recorded.'));
  conclusion.append(explanation, badge(component));
  content.append(evaluations, conclusion);
  appendDetails(content, Object.fromEntries(Object.entries({ evidence: component.evidence, ...component.cryptoProperties })
    .filter(([section]) => !PARTS.some(([purpose]) => purpose === section))));
}

registerReportKind('network', {
  label: 'Network traffic',
  detail: 'TLS sessions',
  icon: 'network',
  unit: 'sessions',
  columns: ['Session / endpoint', 'Encryption', 'Hashing', 'Key exchange', 'Authentication', 'Overall TLS risk', 'Details'],
  description: 'Compare each algorithm’s risk and the overall TLS assessment.',
  policy: 'Network classifier ratings · missing authentication is excluded from overall risk.',
  searchPlaceholder: 'Search sessions, endpoints, algorithms…',
  detailKind: 'SESSION DETAILS',
  row,
  details,
});
