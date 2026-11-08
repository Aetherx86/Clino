# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-08

### Added
- Initial release of Clino AST-level unsafe.Pointer and CGo boundary escape auditor in Go.
- AST parsing and control-flow pattern recognition for subtle Go memory safety hazards.
- Detection of illegal intermediate uintptr variables converted to unsafe.Pointer violating GC liveness.
- Detection of CGo rule violations when passing Go pointers containing nested internal pointers to C routines.
- Detection and warning of deprecated reflect.SliceHeader and reflect.StringHeader mutations.
- Dual procedure execution: `--mode fast` (syntactic AST checks in < 5ms) vs `--mode strict` (blocking CI gate with non-zero exit).
