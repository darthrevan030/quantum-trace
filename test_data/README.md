# Test data

Synthetic fixtures for the scanner tests and for trying the dashboard. Nothing here is executed, and none of the code is security guidance.

Each fixture folder is scanned as its own root. Upload one folder at a time, not the whole `test_data/` directory: `generators/` and `expected/` are supporting material, and the generators contain fixture code as strings.

```text
test_data/
  js_crypto/      hand-written JavaScript/TypeScript fixture (the dashboard's sample workspace)
  code/           generated Python, Java and Go fixture
  generators/     one generator per fixture, plus shared helpers
  expected/       recorded scanner results, one file per fixture
```

Network (`network/`) and cloud (`cloud/`) fixtures, with their generators and expected results, come with the network and cloud scanner branches.

## js_crypto/

Covers the JavaScript/TypeScript rules: Node `crypto`, WebCrypto, TLS options, JWT, crypto-js, tweetnacl, noble, Mojaloop JWS and `package.json` dependencies. It also contains negative controls: a commented-out call, a minified bundle, a `.d.ts` file, an unrelated number and a non-crypto dependency. `tests/scanner/test_code_scanner.py` asserts the exact set of 31 findings. The file is maintained by hand.

## code/

Python, Java and Go examples of legacy algorithms, AES with an unknown key size, and a declared post-quantum migration target. `python/no_crypto.py` is a negative control. Repeated `main.py` and `main.go` names in different folders exercise folder-path preservation.

| Language | Critical | Medium | Safe |
| --- | ---: | ---: | ---: |
| Python | 1 | 2 | 1 |
| Java | 3 | 1 | 1 |
| Go | 2 | 1 | 1 |
| **All** | **6** | **4** | **3** |

The post-quantum examples only declare algorithm names; they are rated Safe as keyword matches. The AES examples are Medium because the key size is not visible at the call site. `expected/code.json` lists each finding.

## Regenerate

Each generator writes its fixture with LF line endings, scans that folder on its own, checks the risk counts, and rewrites `expected/<fixture>.json`:

```sh
uv run python -m test_data.generators.code
```

If the scanner's output changes, the generator stops and shows the new counts. Update `EXPECTED_COUNTS` in the generator once the change is intended. `tests/fixtures/test_generators.py` fails if the generator and the committed fixture drift apart.
