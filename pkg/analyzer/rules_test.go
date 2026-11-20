package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func auditRules(t *testing.T, a *Auditor, src string) []RuleID {
	t.Helper()
	vs, err := a.AuditSource("case.go", []byte(src))
	if err != nil {
		t.Fatalf("AuditSource: %v", err)
	}
	out := make([]RuleID, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Rule)
	}
	return out
}

func hasRule(rules []RuleID, want RuleID) bool {
	for _, r := range rules {
		if r == want {
			return true
		}
	}
	return false
}

// TestRuleMatrix exercises one positive trigger for every rule in the registry.
func TestRuleMatrix(t *testing.T) {
	cases := []struct {
		name string
		want RuleID
		src  string
	}{
		{"uintptr round trip", RuleIllegalUintptrCast, `package p
import "unsafe"
func f() {
	x := 1
	u := uintptr(unsafe.Pointer(&x))
	_ = unsafe.Pointer(u)
}`},
		{"nested go pointer to C", RuleCGoInternalPointer, `package p
/*
void take(void* p) {}
*/
import "C"
import "unsafe"
type node struct { next *node; name string }
func f() {
	n := &node{}
	C.take(unsafe.Pointer(n))
}`},
		{"slice header", RuleUnsafeSliceHeader, `package p
import ("reflect"; "unsafe")
func f(b []byte) {
	h := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	h.Len = 0
}`},
		{"string header", RuleUnsafeStringHeader, `package p
import ("reflect"; "unsafe")
func f(s string) int {
	h := (*reflect.StringHeader)(unsafe.Pointer(&s))
	return h.Len
}`},
		{"direct slice reinterpretation", RuleUnsafeSliceConversion, `package p
import "unsafe"
func f(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(&s))
}`},
		{"negative unsafe.Add", RulePointerArithmeticBounds, `package p
import "unsafe"
func f(p unsafe.Pointer) unsafe.Pointer {
	return unsafe.Add(p, -8)
}`},
		{"negative unsafe.Slice length", RulePointerArithmeticBounds, `package p
import "unsafe"
func f(p *byte) []byte {
	return unsafe.Slice(p, -1)
}`},
		{"pinner without unpin", RuleCGoPinningHazard, `package p
import "runtime"
func f() {
	x := new(int)
	var pin runtime.Pinner
	pin.Pin(x)
}`},
		{"go pointer smuggled as uintptr", RuleCGoPinningHazard, `package p
/*
#include <stdint.h>
void keep(uintptr_t v) {}
*/
import "C"
import "unsafe"
func f() {
	x := 5
	C.keep(C.uintptr_t(uintptr(unsafe.Pointer(&x))))
}`},
	}

	a := New(ModeStrict)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := auditRules(t, a, tc.src)
			if !hasRule(got, tc.want) {
				t.Fatalf("expected %s, got %v", tc.want, got)
			}
		})
	}
}

// TestSafePatternsStayClean guards against false positives on idioms the Go
// unsafe.Pointer rules explicitly allow.
func TestSafePatternsStayClean(t *testing.T) {
	cases := map[string]string{
		"unsafe.Slice": `package p
import "unsafe"
func f(p *byte, n int) []byte { return unsafe.Slice(p, n) }`,
		"unsafe.String": `package p
import "unsafe"
func f(b []byte) string { return unsafe.String(&b[0], len(b)) }`,
		"positive unsafe.Add": `package p
import "unsafe"
func f(p unsafe.Pointer) unsafe.Pointer { return unsafe.Add(p, 16) }`,
		"pinner balanced": `package p
import "runtime"
func f() {
	x := new(int)
	var pin runtime.Pinner
	pin.Pin(x)
	defer pin.Unpin()
}`,
		"syscall-free arithmetic": `package p
import "unsafe"
func f(b []byte) byte { return *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&b[0])) + 1)) }`,
	}
	a := New(ModeStrict)
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if got := auditRules(t, a, src); len(got) != 0 {
				t.Fatalf("expected no findings, got %v", got)
			}
		})
	}
}

func TestInlineSuppression(t *testing.T) {
	src := `package p
import "unsafe"
func f(p unsafe.Pointer) unsafe.Pointer {
	// clino:ignore CLINO-007 -- header sits 8 bytes before the payload
	return unsafe.Add(p, -8)
}
func g(p unsafe.Pointer) unsafe.Pointer {
	return unsafe.Add(p, -8) // clino:ignore CLINO-001
}`
	rep, err := New(ModeStrict).AuditSourceReport("s.go", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Violations) != 1 {
		t.Fatalf("expected only g() to be reported (wrong rule suppressed), got %d: %v", len(rep.Violations), rep.Violations)
	}
	if rep.Violations[0].Function != "g" {
		t.Fatalf("expected finding in g, got %q", rep.Violations[0].Function)
	}
	if rep.Summary.Suppressed != 1 {
		t.Fatalf("expected 1 suppressed finding, got %d", rep.Summary.Suppressed)
	}
}

func TestRuleAndSeverityFiltering(t *testing.T) {
	src := `package p
import ("reflect"; "unsafe")
func f(b []byte, p unsafe.Pointer) unsafe.Pointer {
	h := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	h.Len = 0
	return unsafe.Add(p, -1)
}`
	all := auditRules(t, New(ModeStrict), src)
	if !hasRule(all, RuleUnsafeSliceHeader) || !hasRule(all, RulePointerArithmeticBounds) {
		t.Fatalf("baseline missing expected rules: %v", all)
	}

	onlyErr := auditRules(t, NewWithOptions(Options{Mode: ModeStrict, MinSeverity: SeverityError}), src)
	if hasRule(onlyErr, RuleUnsafeSliceHeader) {
		t.Fatalf("warning-level rule leaked through MinSeverity=ERROR: %v", onlyErr)
	}

	inc := auditRules(t, NewWithOptions(Options{Mode: ModeStrict, IncludeRules: []RuleID{RuleUnsafeSliceHeader}}), src)
	for _, r := range inc {
		if r != RuleUnsafeSliceHeader {
			t.Fatalf("include filter leaked %s", r)
		}
	}

	exc := auditRules(t, NewWithOptions(Options{Mode: ModeStrict, ExcludeRules: []RuleID{RulePointerArithmeticBounds}}), src)
	if hasRule(exc, RulePointerArithmeticBounds) {
		t.Fatalf("exclude filter did not drop CLINO-007: %v", exc)
	}
}

func TestResolveRuleIDAcceptsShortAndLongForms(t *testing.T) {
	for _, in := range []string{"CLINO-007", "clino-007", string(RulePointerArithmeticBounds)} {
		id, ok := ResolveRuleID(in)
		if !ok || id != RulePointerArithmeticBounds {
			t.Fatalf("ResolveRuleID(%q) = %q, %v", in, id, ok)
		}
	}
	if _, ok := ResolveRuleID("CLINO-999"); ok {
		t.Fatal("unknown rule resolved")
	}
	if len(AllRules()) != 8 {
		t.Fatalf("expected 8 registered rules, got %d", len(AllRules()))
	}
	for _, r := range AllRules() {
		if r.Severity != SeverityError && r.Severity != SeverityWarning {
			t.Fatalf("rule %s has invalid severity %q", r.ID, r.Severity)
		}
		if r.Description == "" {
			t.Fatalf("rule %s missing description", r.ID)
		}
	}
}

func TestMalformedSourceReturnsError(t *testing.T) {
	if _, err := New(ModeFast).AuditSource("bad.go", []byte("package p\nfunc {")); err == nil {
		t.Fatal("expected parse error for malformed source")
	}
}

func TestDirectoryAuditExcludesAndIsDeterministic(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bad := `package p
import "unsafe"
func f(p unsafe.Pointer) unsafe.Pointer { return unsafe.Add(p, -4) }`
	for i := 0; i < 12; i++ {
		write(filepath.Join("pkg", "a"+strings.Repeat("x", i)+".go"), bad)
	}
	write(filepath.Join("vendor", "dep", "v.go"), bad)
	write(filepath.Join("third_party", "t.go"), bad)
	write("README.md", "not go")

	a := NewWithOptions(Options{Mode: ModeStrict, ExcludePaths: []string{"third_party"}, Workers: 4})
	rep, err := a.AuditDirectoryReport(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range rep.Violations {
		if strings.Contains(v.File, "third_party") {
			t.Fatalf("excluded path was audited: %s", v.File)
		}
	}
	if rep.Summary.TotalViolations < 12 {
		t.Fatalf("expected at least 12 findings, got %d", rep.Summary.TotalViolations)
	}

	// Parallel workers must still produce a stable ordering.
	var wg sync.WaitGroup
	results := make([][]Violation, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := a.AuditDirectoryReport(root)
			if err != nil {
				t.Error(err)
				return
			}
			results[i] = r.Violations
		}(i)
	}
	wg.Wait()
	for i := 1; i < len(results); i++ {
		if len(results[i]) != len(results[0]) {
			t.Fatalf("run %d produced %d findings vs %d", i, len(results[i]), len(results[0]))
		}
		for j := range results[i] {
			if results[i][j].File != results[0][j].File || results[i][j].Line != results[0][j].Line {
				t.Fatalf("non-deterministic ordering at %d", j)
			}
		}
	}
}
