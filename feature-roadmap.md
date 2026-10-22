# Feature roadmap

What is built, what comes next, and what is deliberately out of scope. Items are in rough priority order within each section.

## Done recently

- [x] `package-lock.json` and `npm-shrinkwrap.json` (lockfile v1, v2, v3): transitive crypto libraries with version and dependency chain, rated UNKNOWN.

## Dependency coverage

Each item is one parser registered in `pipeline/manifest_scanner.py` (`MANIFESTS`), plus a library table and tests, following the `package-lock.json` scanner.

- [ ] `yarn.lock` (v1 and Berry)
- [ ] `pnpm-lock.yaml`
- [ ] Python: `uv.lock`, `poetry.lock`, `requirements.txt` (needs a Python crypto-library table: `cryptography`, `pycryptodome`, `PyJWT`, `ecdsa`, `rsa`)
- [ ] Java: `pom.xml`, Gradle lockfiles
- [ ] Go: `go.mod`, `go.sum`
- [ ] Raise the walker's size allowance for the other lockfile formats as they are added

## Detection

- [ ] AST-based analysis for JavaScript/TypeScript and Python, to follow indirection across files and configuration
- [ ] Cross-file constant resolution (today only same-file `const NAME = "x"` is resolved)
- [ ] Algorithms chosen from environment variables or config files
- [ ] Rule coverage for more languages (C#, Rust, PHP, Ruby)

## Network

- [ ] Detect the negotiated TLS version (read the `supported_versions` extension in the ServerHello)
- [ ] Record certificate algorithms when they are visible (TLS 1.2 and earlier)
- [ ] Real-world capture fixtures alongside the synthetic ones
- [ ] Sandboxed capture parsing (Scapy parses untrusted input today, in a timed subprocess only)

## Cloud

- [ ] Read AWS directly through the API instead of exported JSON
- [ ] Other providers: Azure Key Vault, Google Cloud KMS
- [ ] More AWS services: CloudFront, API Gateway, RDS, S3 encryption settings

## Rating policy

- [ ] Decide the rating for FrodoKEM, Classic-McEliece and HQC (quantum resistant, but not yet NIST standards)
- [ ] Track NIST IR 8547 and FIPS 206 (FN-DSA) as they are finalised
- [ ] A policy file so a team can tighten or relax a tier (for example AES-128) without editing the catalog

## Reporting and dashboard

- [ ] Filter and sort findings by urgency (HNDL and Forgery)
- [ ] Migration plan view: order findings by urgency, then by effort
- [ ] Trend between two scans of the same source
- [ ] Optional score that is documented and tied to the risk counts (today it is a heuristic)

## Operations

- [ ] CI recipes (GitHub Actions) using the existing `--fail-on` exit code
- [ ] Authentication and multi-user storage if the server is ever run beyond a developer machine
- [ ] Investigate the occasional connection reset in `test_http_boundaries` on Windows under load

## Out of scope

- Scanning the internals of third-party libraries for the algorithms they use.
- Proving that no cryptography exists. Reports state this limit.
- Running or instrumenting the scanned code.
