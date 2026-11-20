# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-20

### Added
- Rule registry with eight rules (`CLINO-001` to `CLINO-008`), each with severity, category, CWE mapping, description and remediation. List them with `--list-rules`.
- New rules: FFI stack escape into retaining C APIs (`CLINO-004`), `reflect.StringHeader` use (`CLINO-005`), direct slice and string header reinterpretation (`CLINO-006`), pointer arithmetic bounds such as negative `unsafe.Add`, negative `unsafe.Slice` lengths, integer-forged pointers and oversized fake arrays (`CLINO-007`), and CGo pinning hazards such as unbalanced `runtime.Pinner`, leaked `cgo.Handle`, Go closures passed to C and pointers smuggled through `C.uintptr_t` (`CLINO-008`).
- Scope-aware inspection that tracks uintptr taint, Go pointer provenance, C allocations and pinner state per function.
- Inline suppression with `// clino:ignore [RULE...] -- reason`, counted in the summary.
- Output formats `text`, `json` and SARIF 2.1.0 (`--format sarif`) for GitHub code scanning.
- Filtering with `--rules`, `--exclude-rules`, `--min-severity` and `--exclude`, an explicit `--fail-on` threshold, `--output`, and a parallel directory walker (`--workers`) with deterministic result ordering.
- Tests for every rule, false-positive guards, suppression, filtering, deterministic parallel audits, and JSON and SARIF schema checks.

### Changed
- Version numbering realigned with the published tag: the previous `1.0.0` heading is the `v0.1.0` release.

## [0.1.0] - 2026-11-08

### Added
- Initial release of Clino AST-level unsafe.Pointer and CGo boundary escape auditor in Go.
- AST parsing and control-flow pattern recognition for subtle Go memory safety hazards.
- Detection of illegal intermediate uintptr variables converted to unsafe.Pointer violating GC liveness.
- Detection of CGo rule violations when passing Go pointers containing nested internal pointers to C routines.
- Detection and warning of deprecated reflect.SliceHeader and reflect.StringHeader mutations.
- Dual procedure execution: `--mode fast` (syntactic AST checks in < 5ms) vs `--mode strict` (blocking CI gate with non-zero exit).
