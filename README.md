# QuantumTrace

QuantumTrace scans a code repository, finds the cryptography it uses, and reports whether each algorithm is safe against quantum computers. It produces a Markdown and JSON report from the command line, and a dashboard for exploring the findings.

JavaScript and TypeScript have the deepest coverage. Python, Java, Go and `package.json` dependencies are also scanned, and TLS packet captures are analysed session by session.

[Watch the demo on YouTube](https://youtu.be/FoSCUCO0r4U).

## Quick start

QuantumTrace uses [uv](https://docs.astral.sh/uv/) and needs Python 3.11 or later. `git` is only needed to scan repository URLs.

```sh
uv sync
```

Scan a local folder or a public GitHub/GitLab repository:

```sh
uv run python -m pipeline.scan path/to/repo
uv run python -m pipeline.scan https://github.com/owner/repo
```

```text
js_crypto: NOT QUANTUM SAFE (15 CRITICAL, 5 MEDIUM, 9 SAFE, 2 UNKNOWN)
Report: outputs/js_crypto/report.md
```

Or start the dashboard and open <http://localhost:8000/frontend/>:

```sh
uv run python server.py
```

## The report

Each scan writes two files to `outputs/<target>/`, for example `outputs/js_crypto/` or `outputs/owner-repo/` (change it with `-o`):

- **`report.md`**: the verdict, a risk summary, a table of algorithms, every finding grouped by file (line, code snippet, suggested replacement, NIST standard), and a list of what the scan cannot see.
- **`report.json`**: `{ "target", "summary", "reports" }`, with the same data in machine-readable form.

### Verdict

| Verdict | When |
| --- | --- |
| **NOT QUANTUM SAFE** | Any CRITICAL or HIGH finding |
| **PARTIALLY QUANTUM SAFE** | No CRITICAL/HIGH, but at least one MEDIUM, LOW or UNKNOWN finding |
| **QUANTUM SAFE (for detected cryptography)** | Every finding is SAFE |
| **NO CRYPTOGRAPHY DETECTED** | No findings at all |

The policy lives in `verdict()` in [pipeline/report.py](pipeline/report.py).

### Use in CI

| Option | Effect |
| --- | --- |
| `--fail-on critical` (default), `high`, `medium`, `none` | Exit with status `1` when a finding at or above that risk exists |
| `--exclude-tests` | Leave findings in test files out of the report and the verdict |
| `-o DIR` | Write the reports somewhere other than `outputs/<target>/` |

Exit status is `0` when the threshold is not reached, `1` when it is, and `2` when the scan could not run (for example, a bad path or a failed clone).

## How risk is rated

Scanners only *detect* algorithms. One catalog, [pipeline/crypto_catalog.py](pipeline/crypto_catalog.py), decides every rating, so the same algorithm always gets the same answer whichever scanner found it.

| Risk | Meaning | Examples |
| --- | --- | --- |
| CRITICAL | Broken by Shor's algorithm, or already broken classically | RSA, ECDSA, ECDH, Ed25519, X25519, DH, DSA, MD5, DES, RC4, TLS 1.0/1.1, JWT `none` |
| HIGH | Blocks post-quantum key exchange | TLS 1.2 |
| MEDIUM | Weakened by Grover's algorithm, or legacy | AES-128/192, SHA-1, 3DES, Blowfish |
| LOW | Slightly short security margin | SHA-224 |
| SAFE | Resists known quantum attacks | AES-256, ChaCha20, SHA-256+, SHA-3, HMAC-SHA-256, Argon2, ML-KEM, ML-DSA, SLH-DSA, X25519MLKEM768 |
| UNKNOWN | Not enough evidence to rate | A cipher chosen at runtime, a crypto library with no visible usage |

Ratings follow the challenge brief and NIST guidance in [pdfs/](pdfs/). Contested choices, such as SHA-1 being MEDIUM, are recorded in `POLICY` in the catalog.

When a key size is hidden at the call site (`AES.new(key)`), the finding is rated as the weakest size that algorithm allows (AES → AES-128 → MEDIUM). The report says so, so the size can be checked.

## What is detected

| Language | Coverage |
| --- | --- |
| JavaScript / TypeScript (`.js .mjs .cjs .jsx .ts .tsx .mts .cts`) | Node `crypto` (ciphers, hashes, HMAC, key pairs including multi-line `modulusLength`/`namedCurve` options, ECDH, DH, RSA encrypt, KDFs); WebCrypto `subtle`; TLS `minVersion`/`secureProtocol`/`ecdhCurve`; JWT/JOSE `alg`; crypto-js, node-forge, elliptic, @noble/curves, @noble/hashes, @noble/post-quantum, tweetnacl, libsodium, bcrypt, argon2, node-rsa; Mojaloop JWS (`JwsSigner`/`JwsValidator`, RS256/ES256) |
| `package.json` | Known crypto libraries under `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`, `overrides` and `resolutions` |
| Python | `cryptography`, PyCryptodome, `hashlib`, `hmac`, `ssl`, KDFs, bcrypt, PyJWT, post-quantum names |
| Java / Kotlin | JCA `getInstance` calls (`KeyPairGenerator`, `Cipher`, `Signature`, `MessageDigest`, `Mac`, `KeyAgreement`, `SecretKeyFactory`, `SSLContext`), post-quantum names |
| Go | `crypto/rsa`, `ecdsa`, `ecdh`, `ed25519`, `aes`, `des`, `rc4`, hashes, `hmac`, `tls` versions and curves, `mlkem` |
| TLS packet captures (`.pcap .pcapng .cap`) | The cipher suite and key-exchange group each session negotiated, rated per algorithm (encryption, hash, key exchange, authentication); ML-KEM hybrids such as X25519MLKEM768 are recognised. Unreadable captures are listed in the report metadata instead of failing the scan |

Comments, minified bundles (`*.min.js`), type declarations (`*.d.ts`), and `node_modules`, `vendor`, `dist` and `build` directories are skipped. Findings in test files are tagged `test`, so they can be excluded. Files over 2 MB are skipped, and scanning stops after 50,000 files. The report records how many files were skipped either way.

**Limits.** Detection is pattern based: it finds cryptographic *usage* such as API calls, settings and dependencies. It does not prove that no cryptography exists. Algorithms implemented from scratch (for example, the AES code inside crypto-js itself) and algorithms picked at runtime are not identified. The latter appear as UNKNOWN.

## Dashboard

`uv run python server.py` serves the dashboard and its API at <http://localhost:8000>. Options: `--port 8001`, `--db path/to/database.db`.

- **Input sources:** drop files or folders (up to 2,000 files / 50 MiB; ZIPs are extracted on the server), or add a public GitHub/GitLab URL. Analysis starts automatically.
- **Risk analysis:** the verdict banner, risk metrics, a risk donut, encryption/key-exchange/algorithm charts, and a searchable inventory with code evidence for each finding. **Export report** downloads the Markdown report; **Export source CBOM** downloads a CycloneDX 1.7 CBOM.

Results are stored in SQLite (`outputs/quantumtrace.db` by default). The built-in sample workspace is a live scan of `test_data/js_crypto/`. Mock accounts are described in [frontend/README.md](frontend/README.md).

### API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/sources` | List saved sources |
| `POST /api/sources` | Create a source and analyse it. JSON `{ clientSourceId, repositoryUrl }` for a repository, or multipart `clientSourceId`, repeated `files`, and `paths` for uploads |
| `GET /api/sources/<id>` | Source status. When ready, it includes `reports` and a `summary` with the verdict |
| `POST /api/sources/<id>/retry` | Retry a failed analysis |
| `GET /api/sources/<id>/report` | The Markdown report (`409` until ready) |
| `GET /api/sources/<id>/cbom` | CycloneDX 1.7 CBOM built from the database (`409` until ready) |
| `DELETE /api/sources[/<id>]` | Delete added sources and their stored inputs |

The server listens on loopback only and rejects cross-origin requests. Cloning disables git hooks, redirects and non-HTTPS protocols. Uploaded code is never executed.

## Project layout

```text
pipeline/
  crypto_catalog.py    every quantum-risk rating
  rules/*.json         detection rules, one file per language
  code_scanner.py      runs the rules over source files
  manifest_scanner.py  crypto libraries in package.json
  network_scanner.py   network report kind: TLS sessions in packet captures
  pcap_scanner.py      TLS hello parsing (scapy)
  translate_network_cbom.py / classify_network_cbom.py   IANA names, per-algorithm ratings
  walker.py            repository walk with skip rules and limits
  registry.py          report kinds; extensions register here
  analyze_source.py    runs every registered scanner on a folder
  report.py            summary, verdict and Markdown
  scan.py              command-line entry point
  repo_fetch.py        safe shallow clone of GitHub/GitLab URLs
  source_store.py      SQLite persistence (per-kind storage registry)
  export_cbom.py       CycloneDX export (per-kind exporters)
server.py              API and static dashboard
frontend/              dashboard (no build step); extension views in frontend/kinds/
tests/<feature>/       tests grouped by feature: catalog, scanner, network, report,
                       storage, export, server, fixtures (unittest) and dashboard (node --test)
test_data/             fixtures (js_crypto/, code/, network/), their generators/ and expected/ results
outputs/               generated reports and the dashboard database (gitignored)
```

## Extending

**A new language** needs one rule file, `pipeline/rules/<language>.json`, plus a fixture and a test. Rules only detect; the catalog rates.

```json
{
  "language": "ruby",
  "extensions": { ".rb": "ruby" },
  "commentPrefixes": ["#"],
  "rules": [
    { "id": "rb-digest", "regex": "\\bDigest::(MD5|SHA1|SHA256)\\b", "algorithm": "{1}", "purpose": "hash" }
  ]
}
```

Rule fields:

- `algorithm`: a fixed name or a `{n}` capture-group template. Use `"?"` for a value chosen at runtime.
- `algorithmMap`, `algorithmPattern`: alternative ways to resolve the algorithm.
- `keySizeGroup`/`keySizePattern`, `curveGroup`/`curvePattern`: where to read parameters from.
- `lookahead` and `windowEnd`: let a rule read multi-line arguments.
- Others: `split`, `label`, `classifyAs`, `fileRequires`, `dropUnknown`, `flags`.

[pipeline/rules/javascript.json](pipeline/rules/javascript.json) uses all of them.

**A new report kind** (for example, network captures or cloud inventories) registers itself at each layer, so `main` needs no changes beyond one module name:

| Layer | Hook |
| --- | --- |
| Analysis | `registry.register(kind, scanner, component_types)`, and add the module to `SCANNER_MODULES` |
| Storage | `source_store.register_storage(kind, table, schema, columns, legacy)` |
| CBOM | `export_cbom.register_exporter(kind, exporter)` |
| Dashboard | `registerReportKind(kind, config)` from a module in `frontend/kinds/`, imported by `frontend/app.mjs`, with optional `row`/`details` renderers |

Network captures are added this way: `pipeline/network_scanner.py` registers the analysis, storage and CBOM hooks, and `frontend/kinds/network.mjs` the session view. Cloud inventories (AWS KMS, ACM and load balancers) follow on a separate branch.

## Tests

```sh
uv run python -m unittest discover -s tests -t .
node --test "tests/dashboard/*.test.mjs"
```

Python tests use disposable databases and folders; only cloning is mocked. Fixtures and their per-feature generators are described in [test_data/README.md](test_data/README.md). To also validate CBOM exports against the official CycloneDX schemas, download `bom-1.7.schema.json` and `cryptography-defs.schema.json` into a folder and run:

```sh
CBOM_SCHEMA_DIR=path/to/schemas uv run --with jsonschema python -m unittest tests.export.test_cbom -v
```
