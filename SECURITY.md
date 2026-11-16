# Security policy

sentinel-boot is an educational reference implementation. It is **not** certified,
not audited and not intended for production use. The limitations are listed in
[docs/threat-model.md](docs/threat-model.md).

If you find a flaw in the verification, update or recovery logic, please open a
GitHub issue; because the project has no deployments, public disclosure is fine.
A failing test, or a fuzzer input that violates the invariant in
`tests/fuzz/fuzz_update.cpp`, is the most useful report.
