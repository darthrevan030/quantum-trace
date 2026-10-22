import assert from 'node:assert/strict';
import { REPORT_KINDS } from '../../frontend/report-kinds.mjs';
import '../../frontend/kinds/cloud.mjs';

const cloud = REPORT_KINDS.cloud;
assert.deepEqual(Object.keys(REPORT_KINDS), ['code', 'cloud'], 'cloud registers after the built-in code kind');
assert.equal(cloud.unit, 'assets');
assert.equal(cloud.columns.length, 6, 'generic scanner rows have six cells');
assert.equal(cloud.row, undefined, 'cloud assets use the generic scanner rows');
assert.equal(cloud.details, undefined);
assert.equal(cloud.categoryName, 'Asset type');

const key = { type: 'cloud-kms-key', cryptoProperties: { keySpec: 'ML_DSA_65' } };
assert.equal(cloud.category(key), 'cloud-kms-key');
assert.equal(cloud.categoryLabel('cloud-kms-key'), 'KMS key');
assert.equal(cloud.categoryLabel('x509-certificate'), 'Certificate');
assert.equal(cloud.categoryLabel('load-balancer-listener'), 'Load balancer');
assert.equal(cloud.categoryLabel('something-new'), undefined, 'unknown types fall back to the generic title');
console.log('Cloud kind checks passed: registration, generic rows, asset-type filter labels.');
