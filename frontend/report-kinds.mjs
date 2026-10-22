// Report kinds the dashboard can show, in tab order. An extension adds a module that calls
// registerReportKind() and imports it from app.mjs. Without `row`/`details` renderers a kind uses the
// generic scanner views; with them it receives `ui` helpers (element, badge, detailButton, …).
export const REPORT_KINDS = {};

export function registerReportKind(kind, config) {
  REPORT_KINDS[kind] = config;
}

registerReportKind('code', {
  label: 'Application code',
  detail: 'JS/TS · Python · Java · Go · package.json',
  icon: 'code',
  unit: 'findings',
  columns: ['File / finding', 'Language', 'Detected algorithm', 'Threat', 'Risk', 'Details'],
  description: 'Cryptography found in source code and dependency manifests.',
  policy: 'Ratings from the shared crypto catalog (pipeline/crypto_catalog.py).',
  searchPlaceholder: 'Search files, algorithms, or code…',
  categoryName: 'Language',
  category: component => component.cryptoProperties?.language,
});
