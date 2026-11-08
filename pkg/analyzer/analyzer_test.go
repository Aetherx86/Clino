package analyzer

import (
	"testing"
)

func TestIllegalUintptrCast(t *testing.T) {
	code := `package main
import "unsafe"

func badPointerMath() {
	var x int = 42
	ptr := unsafe.Pointer(&x)
	addr := uintptr(ptr)
	// Between here and the cast, GC could collect or relocate x!
	newPtr := unsafe.Pointer(addr)
	_ = newPtr
}
`
	a := New(ModeStrict)
	violations, err := a.AuditSource("bad.go", []byte(code))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Rule != RuleIllegalUintptrCast {
		t.Fatalf("expected rule %s, got %s", RuleIllegalUintptrCast, violations[0].Rule)
	}
}

func TestLegalAtomicUintptrArithmetic(t *testing.T) {
	code := `package main
import "unsafe"

func atomicPointerMath() {
	var arr [4]byte
	base := unsafe.Pointer(&arr[0])
	// Atomic conversion pattern: legal under Go Rule 3
	offsetPtr := unsafe.Pointer(uintptr(base) + 2)
	_ = offsetPtr
}
`
	a := New(ModeStrict)
	violations, err := a.AuditSource("legal.go", []byte(code))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(violations) != 0 {
		t.Fatalf("expected 0 violations for legal atomic math, got %d", len(violations))
	}
}

func TestReflectHeaderWarning(t *testing.T) {
	code := `package main
import (
	"reflect"
	"unsafe"
)

func mutateSlice(b []byte) {
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	_ = hdr
}
`
	a := New(ModeStrict)
	violations, err := a.AuditSource("slice.go", []byte(code))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(violations) != 1 {
		t.Fatalf("expected 1 violation for reflect.SliceHeader, got %d", len(violations))
	}
	if violations[0].Rule != RuleUnsafeSliceHeader {
		t.Fatalf("expected rule %s, got %s", RuleUnsafeSliceHeader, violations[0].Rule)
	}
}

func TestCleanGoCode(t *testing.T) {
	code := `package main
import (
	"fmt"
	"strings"
)

func main() {
	s := strings.ToUpper("hello world")
	fmt.Println(s)
}
`
	a := New(ModeStrict)
	violations, err := a.AuditSource("clean.go", []byte(code))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected 0 violations, got %d", len(violations))
	}
}
