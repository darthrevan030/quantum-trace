"""CBOM mapping checks; set CBOM_SCHEMA_DIR to validate against official schemas too."""
from copy import deepcopy
import json
import os
from pathlib import Path
import unittest

from pipeline.analyze_source import run_scanners
from pipeline.export_cbom import export_cbom

ROOT = Path(__file__).resolve().parents[2]
REPORTS = run_scanners(ROOT / 'test_data/js_crypto')


def source():
    return {'id': 'repo-a', 'name': 'team/repo-a', 'kind': 'repository', 'status': 'ready',
            'url': 'https://github.com/team/repo-a.git', 'reports': deepcopy(REPORTS)}


class CbomTest(unittest.TestCase):
    def test_mapping_preserves_evidence_and_valid_references(self):
        saved = source()
        original = deepcopy(saved)
        bom = export_cbom(saved)
        self.assertEqual(saved, original)
        self.assertEqual((bom['bomFormat'], bom['specVersion'], bom['version']), ('CycloneDX', '1.7', 1))
        self.assertNotEqual(bom['serialNumber'], export_cbom(saved)['serialNumber'])
        self.assertEqual(bom['metadata']['component']['externalReferences'][0]['url'], saved['url'])
        components = {c['bom-ref']: c for c in bom['components']}
        self.assertEqual(len(components), len(bom['components']))
        refs = set(components) | {bom['metadata']['component']['bom-ref']}
        for dependency in bom['dependencies']:
            self.assertIn(dependency['ref'], refs)
            self.assertTrue(set(dependency.get('dependsOn', [])).issubset(refs))
        for component in components.values():
            self.assertEqual(component['type'], 'cryptographic-asset')
            for value in component['cryptoProperties'].values():
                if isinstance(value, dict):
                    for asset in value.get('relatedCryptographicAssets', []):
                        self.assertIn(asset['ref'], refs)
        for kind, report in saved['reports'].items():
            for index, finding in enumerate(report['components']):
                component = components[f'{kind}:{index}']
                props = {p['name']: p['value'] for p in component['properties']}
                self.assertEqual(json.loads(props['quantumtrace:scanner:finding']), finding)
                path = finding.get('source') or report.get('metadata', {}).get('sourceFile')
                if path:
                    self.assertEqual(component['evidence']['occurrences'][0]['location'], path)
        self.assertEqual(len(saved['reports']['code']['components']), 31)
        self.assertEqual({ref.split(':')[0] for ref in components}, {'code'})
        primitives = {c['cryptoProperties']['algorithmProperties']['primitive'] for c in components.values()}
        # The fixture has HMAC, hashes, AES, ECDSA, ECDH and ML-KEM findings.
        self.assertTrue({'mac', 'hash', 'block-cipher', 'signature', 'key-agree', 'kem'}.issubset(primitives), primitives)
        for component in components.values():
            crypto = component['cryptoProperties']
            if component['bom-ref'].startswith('code:'):
                # The regex scanner's generic number match is not a verified key size.
                self.assertNotIn('parameterSetIdentifier', crypto['algorithmProperties'])
                self.assertNotIn('nistQuantumSecurityLevel', crypto['algorithmProperties'])
        self.assertEqual(bom['compositions'][0]['aggregate'], 'unknown')

    def test_kind_without_exporter_is_kept_as_generic_asset(self):
        saved = {**source(), 'reports': {'extension': {'components': [{'name': 'kept', 'source': 'x.cfg'}]}}}
        component = export_cbom(saved)['components'][0]
        self.assertEqual((component['bom-ref'], component['name']), ('extension:0', 'kept'))
        self.assertEqual(component['cryptoProperties']['algorithmProperties'], {'primitive': 'unknown'})
        self.assertEqual(component['evidence']['occurrences'][0]['location'], 'x.cfg')

    def test_empty_reports_and_unavailable_sources(self):
        saved = {**source(), 'reports': {}}
        self.assertEqual(export_cbom(saved)['components'], [])
        self.assertEqual(export_cbom(saved)['dependencies'][0]['dependsOn'], [])
        for status in ('processing', 'pending', 'failed'):
            with self.assertRaises(ValueError):
                export_cbom({**saved, 'status': status})

    @unittest.skipUnless(os.environ.get('CBOM_SCHEMA_DIR'), 'Set CBOM_SCHEMA_DIR for official schema validation')
    def test_official_cyclonedx_schema(self):
        from jsonschema import Draft7Validator, FormatChecker
        from referencing import Registry, Resource
        folder = Path(os.environ['CBOM_SCHEMA_DIR'])
        schema = json.loads((folder / 'bom-1.7.schema.json').read_text())
        crypto_schema = json.loads((folder / 'cryptography-defs.schema.json').read_text())
        registry = Registry().with_resource(crypto_schema['$id'], Resource.from_contents(crypto_schema))
        validator = Draft7Validator(schema, registry=registry, format_checker=FormatChecker())
        saved = source()
        # Mixed, single-category, and empty sources must all produce valid documents.
        for reports in (saved['reports'], {}, *({kind: report} for kind, report in saved['reports'].items())):
            with self.subTest(kinds=list(reports)):
                validator.validate(export_cbom({**saved, 'reports': reports}))


if __name__ == '__main__':
    unittest.main()
