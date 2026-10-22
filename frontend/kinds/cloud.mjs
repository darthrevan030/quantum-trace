// Cloud report kind: AWS KMS keys, ACM certificates and load-balancer TLS policies.
// Imported from app.mjs (not report-kinds.mjs) so the registry exists before this module runs.
import { registerReportKind } from '../report-kinds.mjs';

const ASSET_TYPES = { 'cloud-kms-key': 'KMS key', 'x509-certificate': 'Certificate', 'load-balancer-listener': 'Load balancer' };

registerReportKind('cloud', {
  label: 'Cloud posture',
  detail: 'Keys · Certificates · TLS policies',
  icon: 'cloud',
  unit: 'assets',
  columns: ['Cloud asset', 'Asset type', 'Algorithm / policy', 'Threat', 'Risk', 'Details'],
  description: 'Keys, certificates and TLS policies found in AWS inventory exports.',
  policy: 'Ratings from the shared crypto catalog (pipeline/crypto_catalog.py).',
  searchPlaceholder: 'Search assets, algorithms, or policies…',
  categoryName: 'Asset type',
  category: component => component.type,
  categoryLabel: value => ASSET_TYPES[value],
});
