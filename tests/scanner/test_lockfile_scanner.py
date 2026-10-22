import json
import tempfile
import unittest
from pathlib import Path

from pipeline.code_scanner import scan_code
from pipeline.manifest_scanner import scan_package_lock
from pipeline.walker import walk


def lock_v3(root_deps, packages, dev_deps=None):
    """A lockfileVersion 3 document: packages maps install paths to entries."""
    root = {"name": "app", "dependencies": root_deps}
    if dev_deps:
        root["devDependencies"] = dev_deps
    return {"name": "app", "lockfileVersion": 3, "packages": {"": root, **packages}}


def package(version, deps=None, **extra):
    return {"version": version, **({"dependencies": deps} if deps else {}), **extra}


def scan(lock, manifest=None, name="package-lock.json"):
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        (root / name).write_text(json.dumps(lock, indent=2), encoding="utf-8")
        if manifest is not None:
            (root / "package.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return scan_package_lock(root / name, name)


def by_package(components):
    return {c["cryptoProperties"]["library"]: c for c in components}


class TransitiveTest(unittest.TestCase):
    def setUp(self):
        self.lock = lock_v3(
            {"some-wallet": "^1.0.0", "jsonwebtoken": "^9.0.0"},
            {
                "node_modules/some-wallet": package("1.2.0", {"elliptic": "^6.5.0"}),
                "node_modules/elliptic": package("6.5.4"),
                "node_modules/jsonwebtoken": package("9.0.2"),
                "node_modules/lodash": package("4.17.21"),
            },
        )
        self.manifest = {"dependencies": {"some-wallet": "^1.0.0", "jsonwebtoken": "^9.0.0"}}

    def test_transitive_crypto_library_is_reported_with_its_chain_and_not_assumed_used(self):
        found = by_package(scan(self.lock, self.manifest))
        self.assertEqual(set(found), {"elliptic"})
        elliptic = found["elliptic"]
        props, assessment = elliptic["cryptoProperties"], elliptic["quantumRiskAssessment"]
        self.assertEqual(props["version"], "6.5.4")
        self.assertEqual(props["dependencyPath"], ["some-wallet", "elliptic"])
        self.assertEqual(props["dependencySection"], "transitive")
        self.assertEqual(props["assetType"], "dependency")
        self.assertEqual(props["detectedAlgorithm"], "elliptic@6.5.4 (crypto library)")
        # The lockfile proves the library ships, not that the application calls it.
        self.assertEqual(assessment["tier"], "UNKNOWN")
        self.assertIn("some-wallet > elliptic", assessment["reason"])
        self.assertEqual(elliptic["source"], "package-lock.json")

    def test_line_points_at_the_locked_entry(self):
        elliptic = by_package(scan(self.lock, self.manifest))["elliptic"]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "package-lock.json"
            path.write_text(json.dumps(self.lock, indent=2), encoding="utf-8")
            line = path.read_text(encoding="utf-8").split("\n")[elliptic["line"] - 1]
        self.assertIn('"node_modules/elliptic"', line)
        self.assertEqual(elliptic["codeSnippet"], line.strip())

    def test_direct_dependencies_are_left_to_package_json(self):
        self.assertNotIn("jsonwebtoken", by_package(scan(self.lock, self.manifest)))

    def test_without_a_package_json_direct_dependencies_are_reported_with_the_family_rating(self):
        lock = lock_v3({"elliptic": "^6.5.0", "jsonwebtoken": "^9.0.0"},
                       {"node_modules/elliptic": package("6.5.4"), "node_modules/jsonwebtoken": package("9.0.2")})
        found = by_package(scan(lock))
        self.assertEqual(found["elliptic"]["quantumRiskAssessment"]["tier"], "CRITICAL")
        self.assertEqual(found["elliptic"]["cryptoProperties"]["detectedAlgorithm"], "EC via elliptic@6.5.4")
        self.assertEqual(found["elliptic"]["cryptoProperties"]["dependencySection"], "dependencies")
        self.assertEqual(found["jsonwebtoken"]["quantumRiskAssessment"]["tier"], "UNKNOWN")

    def test_deep_chain_and_dev_only_flag(self):
        lock = lock_v3(
            {"a": "1"},
            {
                "node_modules/a": package("1.0.0", {"b": "1"}),
                "node_modules/b": package("1.0.0", {"node-forge": "1"}),
                "node_modules/node-forge": package("1.3.1", dev=True),
            },
        )
        forge = by_package(scan(lock, {"dependencies": {"a": "1"}}))["node-forge"]
        self.assertEqual(forge["cryptoProperties"]["dependencyPath"], ["a", "b", "node-forge"])
        self.assertTrue(forge["cryptoProperties"]["devOnly"])


class PackageShapesTest(unittest.TestCase):
    def test_scoped_aliased_and_nested_duplicate_versions(self):
        lock = lock_v3(
            {"holder": "1", "my-forge": "npm:node-forge@1.3.1", "@noble/curves": "1"},
            {
                "node_modules/holder": package("1.0.0", {"node-forge": "^0.10.0"}),
                "node_modules/holder/node_modules/node-forge": package("0.10.0"),
                "node_modules/my-forge": package("1.3.1", name="node-forge"),
                "node_modules/@noble/curves": package("1.4.0"),
            },
        )
        found = scan(lock)
        labels = sorted(c["cryptoProperties"]["detectedAlgorithm"] for c in found)
        self.assertEqual(labels, ["EC via @noble/curves@1.4.0", "node-forge@0.10.0 (crypto library)",
                                  "node-forge@1.3.1 (crypto library)"])
        nested = next(c for c in found if c["cryptoProperties"].get("version") == "0.10.0")
        self.assertEqual(nested["cryptoProperties"]["dependencyPath"], ["holder", "node-forge"])

    def test_same_name_and_version_installed_twice_is_one_finding(self):
        lock = lock_v3(
            {"a": "1", "b": "1"},
            {
                "node_modules/a": package("1.0.0", {"elliptic": "6"}),
                "node_modules/b": package("1.0.0", {"elliptic": "6"}),
                "node_modules/a/node_modules/elliptic": package("6.5.4"),
                "node_modules/b/node_modules/elliptic": package("6.5.4"),
            },
        )
        self.assertEqual(len(scan(lock, {"dependencies": {"a": "1", "b": "1"}})), 1)

    def test_workspace_dependencies_count_as_direct(self):
        lock = lock_v3(
            {},
            {
                "packages/api": {"name": "api", "version": "1.0.0", "dependencies": {"elliptic": "6"}},
                "node_modules/elliptic": package("6.5.4"),
            },
        )
        found = by_package(scan(lock))
        self.assertEqual(found["elliptic"]["cryptoProperties"]["dependencySection"], "dependencies")

    def test_shrinkwrap_is_read_like_a_lockfile(self):
        lock = lock_v3({"a": "1"}, {"node_modules/a": package("1.0.0", {"elliptic": "6"}),
                                    "node_modules/elliptic": package("6.5.4")})
        self.assertEqual(len(scan(lock, {"dependencies": {"a": "1"}}, name="npm-shrinkwrap.json")), 1)


class LockfileV1Test(unittest.TestCase):
    LOCK = {
        "lockfileVersion": 1,
        "dependencies": {
            "a": {"version": "1.0.0", "requires": {"elliptic": "^6.5.0"}},
            "elliptic": {"version": "6.5.4", "dev": True},
            "b": {"version": "2.0.0", "dependencies": {"node-forge": {"version": "0.10.0"}}, "requires": {"node-forge": "0.10"}},
        },
    }

    def test_v1_uses_the_sibling_package_json_to_find_direct_dependencies(self):
        found = by_package(scan(self.LOCK, {"dependencies": {"a": "1", "b": "2"}}))
        self.assertEqual(found["elliptic"]["cryptoProperties"]["dependencyPath"], ["a", "elliptic"])
        self.assertEqual(found["node-forge"]["cryptoProperties"]["dependencyPath"], ["b", "node-forge"])
        self.assertTrue(found["elliptic"]["cryptoProperties"]["devOnly"])

    def test_v1_without_a_package_json_does_not_claim_direct_or_transitive(self):
        found = by_package(scan(self.LOCK))
        for library in ("elliptic", "node-forge"):
            self.assertEqual(found[library]["cryptoProperties"]["dependencySection"], "lockfile")
            self.assertEqual(found[library]["quantumRiskAssessment"]["tier"], "UNKNOWN")
            self.assertNotIn("dependencyPath", found[library]["cryptoProperties"])


class RobustnessTest(unittest.TestCase):
    def test_unusable_lockfiles_yield_nothing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for content in ["{not json", "[]", '"text"', "{}", '{"packages": []}', '{"packages": {"": {}, "node_modules/x": 3}}']:
                (root / "package-lock.json").write_text(content, encoding="utf-8")
                with self.subTest(content=content):
                    self.assertEqual(scan_package_lock(root / "package-lock.json", "package-lock.json"), [])

    def test_lockfile_without_crypto_libraries_is_clean(self):
        lock = lock_v3({"lodash": "4"}, {"node_modules/lodash": package("4.17.21")})
        self.assertEqual(scan(lock, {"dependencies": {"lodash": "4"}}), [])

    def test_cyclic_dependencies_terminate(self):
        lock = lock_v3({"a": "1"}, {"node_modules/a": package("1.0.0", {"b": "1", "elliptic": "6"}),
                                    "node_modules/b": package("1.0.0", {"a": "1"}),
                                    "node_modules/elliptic": package("6.5.4")})
        self.assertEqual(len(scan(lock, {"dependencies": {"a": "1"}})), 1)


class IntegrationTest(unittest.TestCase):
    def test_lockfile_flows_through_the_code_scanner(self):
        lock = lock_v3({"a": "1"}, {"node_modules/a": package("1.0.0", {"elliptic": "6"}),
                                    "node_modules/elliptic": package("6.5.4")})
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "package.json").write_text('{"dependencies": {"a": "1"}}', encoding="utf-8")
            (root / "package-lock.json").write_text(json.dumps(lock, indent=2), encoding="utf-8")
            (root / "tests").mkdir()
            (root / "tests/package-lock.json").write_text(json.dumps(lock, indent=2), encoding="utf-8")
            report = scan_code(root)
        components = report["components"]
        self.assertEqual({c["source"] for c in components}, {"package-lock.json", "tests/package-lock.json"})
        production = next(c for c in components if c["source"] == "package-lock.json")
        self.assertEqual(production["cryptoProperties"]["context"], "source")
        self.assertEqual(production["cryptoProperties"]["language"], "npm")
        self.assertEqual(next(c for c in components if c["source"].startswith("tests/"))["cryptoProperties"]["context"], "test")
        self.assertEqual(report["metadata"]["quantumRiskSummary"]["riskCounts"]["UNKNOWN"], 2)

    def test_large_lockfiles_are_scanned_but_other_large_files_are_still_skipped(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            filler = {f"node_modules/pkg-{i}": package("1.0.0") for i in range(40_000)}
            lock = lock_v3({}, filler)
            (root / "package-lock.json").write_text(json.dumps(lock, indent=2), encoding="utf-8")
            (root / "data.json").write_text(json.dumps({"x": "y" * (3 * 1024 * 1024)}), encoding="utf-8")
            self.assertGreater((root / "package-lock.json").stat().st_size, 2 * 1024 * 1024)
            files, skipped = walk(root)
        self.assertEqual([path.name for path in files], ["package-lock.json"])
        self.assertEqual(skipped["largeFiles"], 1)


if __name__ == "__main__":
    unittest.main()
