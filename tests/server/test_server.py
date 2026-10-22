"""Integration checks use a disposable database and input directory."""
import io
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import uuid
import zipfile

from pipeline.analyze_source import run_scanners
from pipeline.database import init_db, add_code_classification
from pipeline.report import NOT_SAFE, SAFE, VERDICT_DESCRIPTIONS
from pipeline.source_store import SourceStore
from server import DEFAULT_DB, ROOT, SAMPLE, Application, make_server, repository_url


class PersistenceTest(unittest.TestCase):
    def test_migrate_existing_tables_and_preserve_full_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / 'old.db'
            init_db(db)
            add_code_classification({'file_path': 'old.py', 'language': 'python', 'library': 'example', 'primitive': 'RSA', 'risk': 'Critical'}, db)
            store = SourceStore(db)
            legacy = store.get('legacy')['reports']
            self.assertEqual(legacy['code']['components'][0]['cryptoProperties']['detectedAlgorithm'], 'RSA')
            code = run_scanners(ROOT / 'test_data/code')['code']
            store.create({'id': 'code', 'name': 'Code repository', 'kind': 'repository', 'url': 'https://github.com/team/code.git'})
            store.save_reports('code', {'code': code})
            reopened = SourceStore(db)
            self.assertEqual(reopened.get('code')['reports'], {'code': code})
            self.assertEqual({source['id'] for source in reopened.list()}, {'legacy', 'code'})
            first = code['components'][0]
            with closing(sqlite3.connect(db)) as conn:
                self.assertEqual(conn.execute("SELECT key_size, suggestion FROM code_classification WHERE source_id='code' ORDER BY id LIMIT 1").fetchone(),
                                 (first['cryptoProperties']['keySizeBits'], first['quantumRiskAssessment'].get('suggestion')))
            store.delete('code')
            self.assertEqual(store.get('legacy')['reports'], legacy)


class DefaultLocationTest(unittest.TestCase):
    def test_database_defaults_to_outputs_and_its_folder_is_created(self):
        self.assertEqual(DEFAULT_DB, ROOT / 'outputs' / 'quantumtrace.db')
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / 'missing' / 'nested' / 'q.db'
            app = Application(db, Path(folder) / 'inputs')
            try:
                self.assertTrue(db.is_file())
                self.assertEqual(app.store.get('sample')['status'], 'ready')
            finally:
                app.jobs.shutdown()


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.folder = Path(cls.temp.name)
        cls.server = make_server(0, cls.folder / 'test.db', cls.folder / 'inputs')
        cls.quiet = patch('server.Handler.log_message')
        cls.quiet.start()
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server.app.jobs.shutdown(wait=True)
        cls.thread.join()
        cls.temp.cleanup()
        cls.quiet.stop()

    def request(self, path, data=None, method='GET', content_type='application/json', headers=None):
        request = Request(self.base + path, data=data, method=method, headers={'Content-Type': content_type, **(headers or {})})
        try:
            response = urlopen(request, timeout=10)
        except HTTPError as error:
            response = error
        with response:
            raw = response.read()
            return response.status, json.loads(raw) if response.headers.get_content_type() in {'application/json', 'application/vnd.cyclonedx+json'} else raw

    def upload(self, files, client=None, paths=None):
        boundary = 'quantumtrace-test-boundary'
        body = f'--{boundary}\r\nContent-Disposition: form-data; name="clientSourceId"\r\n\r\n{client or uuid.uuid4()}\r\n'.encode()
        if paths is not None:
            body += f'--{boundary}\r\nContent-Disposition: form-data; name="paths"\r\n\r\n{json.dumps(paths)}\r\n'.encode()
        for name, content in files:
            body += f'--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="{name}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode() + content + b'\r\n'
        body += f'--{boundary}--\r\n'.encode()
        status, source = self.request('/api/sources', body, 'POST', f'multipart/form-data; boundary={boundary}')
        return status, source

    def complete(self, source):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            status, result = self.request('/api/sources/' + source['id'])
            self.assertEqual(status, 200)
            if result['status'] in {'ready', 'failed'}:
                return result
            time.sleep(.1)
        self.fail('Analysis did not complete')

    def test_sample_is_a_live_scan_and_seed_is_idempotent(self):
        status, source = self.request('/api/sources/sample')
        self.assertEqual(status, 200)
        self.assertEqual(source['reports'], json.loads(json.dumps(run_scanners(SAMPLE))))
        self.assertEqual(len(source['reports']['code']['components']), 31)
        with closing(sqlite3.connect(self.folder / 'test.db')) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM code_classification WHERE source_id='sample'").fetchone()[0], 31)
        second = Application(self.folder / 'test.db', self.folder / 'inputs')
        try:
            self.assertEqual(second.store.get('sample'), self.server.app.store.get('sample'))
            self.assertEqual(second.store.get('sample')['reports'], source['reports'])
        finally:
            second.jobs.shutdown()

    def test_upload_scans_code_and_isolates_sources(self):
        client = str(uuid.uuid4())
        files = [('test.py', b'RSA.generate(2048)\n'), ('network.pcap', b'\xd4\xc3\xb2\xa1 not scanned on main'),
                 ('package.json', b'{"dependencies": {"node-rsa": "^1"}}')]
        status, source = self.upload(files, client)
        self.assertEqual(status, 202)
        result = self.complete(source)
        self.assertEqual(result['status'], 'ready', result.get('error'))
        self.assertEqual(set(result['reports']), {'code'})
        self.assertEqual([(c['source'], c['cryptoProperties']['detectedAlgorithm']) for c in result['reports']['code']['components']],
                         [('package.json', 'RSA via node-rsa'), ('test.py', 'RSA-2048')])
        self.assertEqual(self.upload(files, client)[1]['id'], source['id'])
        _, other = self.upload([('safe.py', b'mlkem\n')])
        other = self.complete(other)
        self.assertEqual(set(other['reports']), {'code'})
        self.assertEqual(other['reports']['code']['components'][0]['quantumRiskAssessment']['tier'], 'SAFE')
        with closing(sqlite3.connect(self.folder / 'test.db')) as conn:
            self.assertEqual(conn.execute('SELECT primitive FROM code_classification WHERE source_id=? AND file_path=?',
                                          (source['id'], 'test.py')).fetchone()[0], 'RSA-2048')
        self.assertEqual(self.request('/api/sources/' + source['id'], method='DELETE')[0], 200)
        self.assertFalse((self.folder / 'inputs' / source['id']).exists())
        self.assertEqual(self.request('/api/sources/' + source['id'])[0], 404)
        self.assertEqual(self.request('/api/sources/' + other['id'])[1]['reports'], other['reports'])

    def test_ready_source_carries_summary_and_markdown_report(self):
        _, source = self.upload([('app.js', b"crypto.createHash('md5');\n")])
        result = self.complete(source)
        summary = result['summary']
        self.assertEqual(summary['verdict'], NOT_SAFE)
        self.assertEqual(summary['verdictDescription'], VERDICT_DESCRIPTIONS[NOT_SAFE])
        self.assertEqual(summary['riskCounts']['CRITICAL'], 1)
        status, markdown = self.request('/api/sources/' + source['id'] + '/report')
        self.assertEqual(status, 200)
        markdown = markdown.decode('utf-8')
        self.assertTrue(markdown.startswith(f"# Quantum-safety report: {result['name']}"))
        self.assertIn(f'**Verdict: {NOT_SAFE}**', markdown)
        self.assertIn('### `app.js`', markdown)
        _, safe = self.upload([('ok.js', b"crypto.createCipheriv('aes-256-gcm', k, iv);\n")])
        self.assertEqual(self.complete(safe)['summary']['verdict'], SAFE)
        self.assertEqual(self.request('/api/sources/missing/report')[0], 404)
        with patch.object(self.server.app.jobs, 'submit'):
            _, pending = self.upload([('later.js', b'x')])
            self.assertEqual(self.request('/api/sources/' + pending['id'] + '/report')[0], 409)
            self.assertNotIn('summary', self.request('/api/sources/' + pending['id'])[1])
        self.server.app.run(pending['id'])

    def test_failure_message_survives_non_ascii_file_names(self):
        # On Windows the analyzer's stderr used the console code page and lost (or crashed on) such names.
        _, source = self.upload([('bad✓.json', b'{"components": ["not a component"]}')])
        result = self.complete(source)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['error'], 'Analysis failed: Invalid CBOM component in bad✓.json.')

    def test_cbom_zip_failures_retry_and_safe_extraction(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as zipped:
            zipped.writestr('project/src/Test.java', 'KeyPairGenerator.getInstance("RSA");')
            zipped.writestr('project/main.go', 'rsa.GenerateKey(')
        _, source = self.upload([('project.zip', archive.getvalue())])
        result = self.complete(source)
        self.assertEqual(result['status'], 'ready', result.get('error'))
        self.assertEqual(len(result['reports']['code']['components']), 2)
        export = run_scanners(ROOT / 'test_data/code')['code']
        _, imported = self.upload([('cbom.json', json.dumps(export).encode())])
        self.assertEqual(len(self.complete(imported)['reports']['code']['components']), len(export['components']))
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as zipped:
            zipped.writestr('../escape.py', 'RSA.generate(2048)')
        _, bad = self.upload([('unsafe.zip', archive.getvalue())])
        self.assertEqual(self.complete(bad)['status'], 'failed')
        self.assertFalse((self.folder / 'inputs' / bad['id'] / 'input/escape.py').exists())
        _, failed = self.upload([('notes.txt', b'No scanner inputs')])
        self.assertEqual(self.complete(failed)['status'], 'failed')
        retry = self.request('/api/sources/' + failed['id'] + '/retry', method='POST')[1]
        self.assertEqual(retry['id'], failed['id'])
        self.assertEqual(self.complete(retry)['status'], 'failed')

    def test_repository_validation_and_clone_pipeline(self):
        for url in ['file:///tmp/repo', 'https://localhost/team/repo', 'https://github.com@evil.test/a/b', 'https://github.com/a/b/tree/main', 'https://gitlab.com/a/../b']:
            with self.assertRaises(ValueError):
                repository_url(url)
        self.assertEqual(repository_url('https://gitlab.com/team/sub/repo')[0], 'https://gitlab.com/team/sub/repo.git')
        # Exercise the real scanner, replacing only the network-bound git command.
        import subprocess
        original = subprocess.run
        commands = []
        def clone_or_run(command, **kwargs):
            if command[0] == 'git':
                commands.append(command)
                target = Path(command[-1])
                target.mkdir()
                (target / 'test.py').write_text('RSA.generate(2048)')
                return subprocess.CompletedProcess(command, 0, '', '')
            return original(command, **kwargs)
        with patch('server.subprocess.run', side_effect=clone_or_run):
            status, source = self.request('/api/sources', json.dumps({'clientSourceId': str(uuid.uuid4()), 'repositoryUrl': 'https://github.com/team/test'}).encode(), 'POST')
            self.assertEqual(status, 202)
            self.assertEqual(self.complete(source)['status'], 'ready')
        self.assertIn('http.followRedirects=false', commands[0])
        self.assertIn('--', commands[0])
        self.assertEqual(commands[0][-2], 'https://github.com/team/test.git')

    def test_large_repository_is_scanned_not_rejected(self):
        # A clone with more than 2,000 files used to fail before any scanning.
        import subprocess
        original = subprocess.run
        def clone_or_run(command, **kwargs):
            if command[0] == 'git':
                target = Path(command[-1])
                target.mkdir()
                for index in range(2050):
                    (target / f'f{index}.txt').write_text('')
                (target / 'z.js').write_text("crypto.createHash('sha1');\n")
                return subprocess.CompletedProcess(command, 0, '', '')
            return original(command, **kwargs)
        with patch('server.subprocess.run', side_effect=clone_or_run):
            _, source = self.request('/api/sources', json.dumps({'clientSourceId': str(uuid.uuid4()), 'repositoryUrl': 'https://github.com/team/big'}).encode(), 'POST')
            result = self.complete(source)
        self.assertEqual(result['status'], 'ready', result.get('error'))
        self.assertEqual(result['reports']['code']['metadata']['inputFileCount'], 2051)

    def test_http_boundaries(self):
        self.assertEqual(self.request('/frontend/')[0], 200)
        self.assertEqual(self.request('/frontend/app.mjs')[0], 200)
        for path in ['/quantumtrace.db', '/input_files/sample-repos/python/secure_transfer.py', '/frontend/../server.py',
                     '/pdfs/nist_standards.pdf']:
            self.assertEqual(self.request(path)[0], 404)
        self.assertEqual(self.request('/api/sources', b'{}', 'POST', headers={'Origin': 'https://untrusted.test'})[0], 403)
        self.assertEqual(self.request('/api/sources', headers={'Host': 'untrusted.test'})[0], 403)
        self.assertEqual(self.upload([('../bad.py', b'RSA.generate(2048)')])[0], 400)
        self.assertEqual(self.request('/api/sources/sample', method='DELETE')[0], 400)

    def test_cbom_export_reads_selected_source_directly_from_database(self):
        store = self.server.app.store
        saved = {'id': 'export-repo', 'name': 'team/export-repo', 'kind': 'repository', 'url': 'https://github.com/team/export-repo.git'}
        store.create(saved)
        try:
            self.assertEqual(self.request('/api/sources/export-repo/cbom')[0], 409)
            report = {'components': [{'type': 'application-code', 'name': 'database-only.py:4', 'source': 'database-only.py',
                                     'line': 4, 'cryptoProperties': {'detectedAlgorithm': 'AES', 'language': 'python'},
                                     'quantumRiskAssessment': {'tier': 'Medium'}}]}
            store.save_reports(saved['id'], {'code': report})
            self.assertFalse((self.folder / 'inputs' / saved['id']).exists())
            # Export succeeds without any source/report files to read.
            with patch('pathlib.Path.read_text', side_effect=AssertionError('Export must read SQLite')):
                status, bom = self.request('/api/sources/export-repo/cbom')
            self.assertEqual(status, 200)
            self.assertEqual(bom['metadata']['component']['name'], saved['name'])
            self.assertEqual(len(bom['components']), 1, 'Sample findings must not leak into the selected repository')
            self.assertEqual(bom['components'][0]['evidence']['occurrences'][0]['location'], 'database-only.py')
            store.save_reports(saved['id'], {})
            self.assertEqual(self.request('/api/sources/export-repo/cbom')[1]['components'], [], 'Each export must re-read the database')
            store.status(saved['id'], 'failed')
            self.assertEqual(self.request('/api/sources/export-repo/cbom')[0], 409)
            self.assertEqual(self.request('/api/sources/missing-repo/cbom')[0], 404)
        finally:
            store.delete(saved['id'])

    def test_running_source_cannot_be_reset(self):
        with patch.object(self.server.app.jobs, 'submit'):
            _, source = self.upload([('pending.py', b'RSA.generate(2048)')])
            self.assertEqual(self.request('/api/sources/' + source['id'], method='DELETE')[0], 400)
            self.assertEqual(self.request('/api/sources', method='DELETE')[0], 400)
            self.assertTrue((self.folder / 'inputs' / source['id']).exists())
        self.server.app.run(source['id'])
        self.assertEqual(self.complete(source)['status'], 'ready')

    def test_folder_paths_and_retry_preserve_original_files(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as zipped:
            zipped.writestr('main.go', 'rsa.GenerateKey(')
        files = [('main.py', b'RSA.generate(2048)'), ('main.py', b'mlkem'),
                 ('export.json', b'{"components": ["broken"]}'), ('extra.zip', archive.getvalue())]
        paths = ['project/client/main.py', 'project/server/main.py', 'project/reports/export.json', 'project/extra.zip']
        status, source = self.upload(files, paths=paths)
        self.assertEqual(status, 202)
        self.assertEqual(source['name'], 'project')
        self.assertEqual(self.complete(source)['status'], 'failed')
        incoming = self.folder / 'inputs' / source['id'] / 'input'
        self.assertEqual((incoming / paths[0]).read_bytes(), files[0][1])
        (incoming / paths[2]).write_text('{"components": []}')
        self.request('/api/sources/' + source['id'] + '/retry', method='POST')
        result = self.complete(source)
        self.assertEqual(result['status'], 'ready', result.get('error'))
        self.assertEqual(len(result['reports']['code']['components']), 3)
        self.assertTrue(set(paths[:2]).issubset({c['source'] for c in result['reports']['code']['components']}))
        self.assertEqual((incoming / paths[1]).read_bytes(), files[1][1])
        for path in ['../bad.py', '/bad.py', 'a//bad.py', 'a/./bad.py', 'C:/bad.py', '.quantumtrace-extracted/bad.py']:
            self.assertEqual(self.upload([('bad.py', b'code')], paths=[path])[0], 400, path)
        self.assertEqual(self.upload([('bad.py', b'code')], paths=[])[0], 400)
        self.assertEqual(self.upload([('bad.py', b'code')], paths=['other.py'])[0], 400)

    def test_z_reset_preserves_samples(self):
        self.server.app.jobs.shutdown(wait=True)
        self.assertEqual(self.request('/api/sources', method='DELETE')[0], 200)
        self.assertEqual([s['id'] for s in self.request('/api/sources')[1]['sources']], ['sample'])
        self.assertEqual(list((self.folder / 'inputs').iterdir()), [])


if __name__ == '__main__':
    unittest.main()
