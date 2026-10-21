# js_crypto fixture

Static-analysis fixture for the JS/TS rules. Nothing here is executed and none of
these choices are security guidance. `pipeline/test_code_scanner.py` asserts the
exact set of findings, so every line here is either an expected finding or a
negative control (comment, minified bundle, `.d.ts`, unrelated number, `express`).
