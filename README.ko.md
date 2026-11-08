# Clino: AST 레벨 unsafe.Pointer & CGo 경계 탈출 정적 분석기

[English](README.md) · [라이선스](LICENSE)

Clino는 Go 표준 컴파일러 툴체인(`go/ast`, `go/parser`, `go/token`)만을 기반으로 구축된 제로 의존성 정적 분석 도구입니다. 네이티브 C-ABI, FFI, WebAssembly 경계를 넘나드는 메모리 수명주기 불변식을 추적하고 포인터 탈출을 감지합니다.

표준 린터가 감지하지 못하는 미묘한 정의되지 않은 동작(Undefined Behavior) 패턴을 정확히 검출합니다:
1. 중간 `uintptr` 변수를 선언한 후 다시 `unsafe.Pointer`로 역변환하는 패턴 (GC 이동/해제 위험).
2. Go 런타임이 관리하는 내부 중첩 포인터를 가진 구조체를 `C.func()` CGo 함수로 전달하는 패턴.
3. 지원 중단된 `reflect.SliceHeader` 또는 `reflect.StringHeader`를 사용한 슬라이스/문자열 변조 패턴.

## 왜 AST 레벨 경계 감사인가?

Go의 가비지 컬렉터(GC)는 애플리케이션과 동시 실행되며, 유효한 타입의 포인터가 가리키지 않는 메모리는 언제든지 회수하거나 압축 이동시킬 수 있습니다. 공식 `unsafe.Pointer` 규칙(Rule 1~6)은 매우 엄격합니다.

대표적인 치명적 안티패턴:
```go
// 정의되지 않은 동작 (Undefined Behavior, Rule 3 위반)
u := uintptr(ptr)
// 이 시점에 GC가 실행되면 'u'는 정수일 뿐이므로 포인터로 추적되지 않습니다.
// 참조하던 객체가 해제되거나 다른 주소로 이동할 수 있습니다!
p := unsafe.Pointer(u + offset)
```

Clino는 AST 할당 노드와 변수 바인딩을 분석하여, 모든 `uintptr` 포인터 산술이 단일 표현식(`unsafe.Pointer(uintptr(p) + offset)`) 내에서 원자적으로 평가되는지 검증합니다. 포인터가 연산 도중 GC 루트에서 누락되는 것을 원천 차단합니다.

## 듀얼 운영 프로시저

### 1. Fast 모드 (`--mode fast`)
- 전체 코드베이스 대상의 초고속 문법 AST 검사.
- 50개 이상의 소스 파일도 500 마이크로초(µs) 미만에 분석 완료.
- Git pre-commit 훅 및 IDE 저장 시 실시간 피드백에 적합하며, 경고만 출력하고 프로세스를 종료하지 않습니다.

### 2. Strict 모드 (`--mode strict`)
- 프로덕션 릴리스 및 CI 빌드 게이트키퍼.
- 메모리 위험 패턴(`CLINO-001`, `CLINO-002`) 발견 시 즉시 에러를 발생시키며 0이 아닌 종료 코드(`exit 1`)로 PR 머지를 차단합니다.

## 탐지 규칙 매트릭스

| 규칙 코드 | 위험 수준 | 감지 대상 및 원인 |
|---|---|---|
| `CLINO-001` | 치명적(FATAL) | 중간 `uintptr` 변수 저장 후 `unsafe.Pointer` 역변환 (GC 세그폴트 위험) |
| `CLINO-002` | 치명적(FATAL) | Go 관리 내부 포인터가 포함된 구조체를 CGo 함수 매개변수로 전달 |
| `CLINO-003` | 경고(WARN) | 지원 중단된 `reflect.SliceHeader` / `reflect.StringHeader` 사용 |

## 설치 및 빌드

```bash
git clone https://github.com/Aetherx86/Clino.git
cd Clino
go build -o bin/clino ./cmd/clino
```

## CLI 사용법

```bash
# 전체 프로젝트 디렉터리 엄격 검사 (CI 게이트키퍼)
./bin/clino --dir ./pkg --mode strict

# 단일 파일 고속 진단
./bin/clino --file bridge.go --mode fast
```

## 공급망 보안 검증

```bash
python3 .github/scripts/repo_guard.py . --strict
go test -v -race ./...
```

## 라이선스

MIT License. Copyright (c) 2026 Jeong Hoon Kim (Aether Systems & Research Lab).
