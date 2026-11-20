package analyzer

import "strings"

// RuleID uniquely identifies a Clino static analysis rule.
type RuleID string

const (
	RuleIllegalUintptrCast      RuleID = "CLINO-001-ILLEGAL-UINTPTR-CAST"
	RuleCGoInternalPointer      RuleID = "CLINO-002-CGO-INTERNAL-POINTER"
	RuleUnsafeSliceHeader       RuleID = "CLINO-003-UNSAFE-SLICE-HEADER"
	RuleFFIStackEscape          RuleID = "CLINO-004-FFI-STACK-ESCAPE"
	RuleUnsafeStringHeader      RuleID = "CLINO-005-UNSAFE-STRING-HEADER"
	RuleUnsafeSliceConversion   RuleID = "CLINO-006-UNSAFE-SLICE-CONVERSION"
	RulePointerArithmeticBounds RuleID = "CLINO-007-POINTER-ARITHMETIC-BOUNDS"
	RuleCGoPinningHazard        RuleID = "CLINO-008-CGO-PINNING-HAZARD"
)

const (
	SeverityError   = "ERROR"
	SeverityWarning = "WARNING"
)

// RuleMeta describes a Clino audit rule for CLI help, JSON, and SARIF reporting.
type RuleMeta struct {
	ID          RuleID `json:"id"`
	ShortID     string `json:"short_id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	CWE         string `json:"cwe"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

var ruleRegistry = []RuleMeta{
	{
		ID:          RuleIllegalUintptrCast,
		ShortID:     "CLINO-001",
		Name:        "IllegalIntermediateUintptrCast",
		Severity:    SeverityError,
		Category:    "unsafe-pointer",
		CWE:         "CWE-825",
		Summary:     "Converting a stored uintptr variable back to unsafe.Pointer violates Go GC liveness.",
		Description: "Go's garbage collector does not treat uintptr values as live object references. Storing a pointer as a uintptr in a variable or passing it as a parameter before converting back to unsafe.Pointer violates unsafe.Pointer Rules 3, 5, and 6 and can result in use-after-free or stack-move corruption.",
		Remediation: "Perform pointer arithmetic atomically in a single expression using unsafe.Add(ptr, offset) or unsafe.Pointer(uintptr(ptr) + offset).",
	},
	{
		ID:          RuleCGoInternalPointer,
		ShortID:     "CLINO-002",
		Name:        "CGoNestedPointerViolation",
		Severity:    SeverityError,
		Category:    "cgo-boundary",
		CWE:         "CWE-704",
		Summary:     "Passing a Go pointer containing nested Go pointers to a CGo function violates Go runtime pointer rules.",
		Description: "Go's CGo pointer passing rules forbid passing a Go pointer whose referenced memory contains other Go pointers (such as slices, strings, maps, channels, functions, interfaces, or nested struct pointer fields) across C function boundaries.",
		Remediation: "Pass flat C-compatible structs or primitive element pointers (&buf[0]), copy data into C memory with C.CBytes/C.CString, or pass opaque integer handles via runtime/cgo.NewHandle.",
	},
	{
		ID:          RuleUnsafeSliceHeader,
		ShortID:     "CLINO-003",
		Name:        "DeprecatedSliceHeaderCast",
		Severity:    SeverityWarning,
		Category:    "slice-header",
		CWE:         "CWE-704",
		Summary:     "Deprecated reflect.SliceHeader usage for unsafe slice manipulation.",
		Description: "reflect.SliceHeader is deprecated and error-prone because its Data field is a uintptr rather than an unsafe.Pointer, making it easy to violate garbage collector pointer invariants.",
		Remediation: "Migrate to unsafe.Slice and unsafe.SliceData (available since Go 1.17/1.20).",
	},
	{
		ID:          RuleFFIStackEscape,
		ShortID:     "CLINO-004",
		Name:        "FFIStackOrRetainedPointerEscape",
		Severity:    SeverityError,
		Category:    "cgo-boundary",
		CWE:         "CWE-825",
		Summary:     "Unpinned Go pointer stored in C-managed memory or passed to a C retention API.",
		Description: "C code must not retain a Go pointer after a CGo call returns, nor may Go pointers be stored in C-allocated memory unless explicitly pinned with runtime.Pinner for the lifetime of the C reference.",
		Remediation: "Pin the referenced Go object with runtime.Pinner (and defer Unpin), copy data into C-allocated memory, or pass a runtime/cgo.Handle instead of a raw pointer.",
	},
	{
		ID:          RuleUnsafeStringHeader,
		ShortID:     "CLINO-005",
		Name:        "DeprecatedStringHeaderCast",
		Severity:    SeverityWarning,
		Category:    "slice-header",
		CWE:         "CWE-704",
		Summary:     "Deprecated reflect.StringHeader usage for unsafe string manipulation.",
		Description: "reflect.StringHeader is deprecated and error-prone because its Data field is a uintptr rather than an unsafe.Pointer.",
		Remediation: "Migrate to unsafe.String and unsafe.StringData (available since Go 1.20).",
	},
	{
		ID:          RuleUnsafeSliceConversion,
		ShortID:     "CLINO-006",
		Name:        "UnsafeSliceOrStringHeaderConversion",
		Severity:    SeverityError,
		Category:    "slice-header",
		CWE:         "CWE-704",
		Summary:     "Invalid SliceHeader/StringHeader value construction or direct unsafe slice/string header type-punning.",
		Description: "Constructing a standalone reflect.SliceHeader or reflect.StringHeader variable and converting its address to a slice/string pointer violates unsafe.Pointer Rule 6. Directly reinterpreting a slice or string pointer via (*[]T)(unsafe.Pointer(&x)) or (*string)(unsafe.Pointer(&b)) breaks length/capacity scaling and risks mutating immutable string memory.",
		Remediation: "Use unsafe.Slice(unsafe.StringData(s), len(s)) or unsafe.String(unsafe.SliceData(b), len(b)), or explicitly recompute element counts with unsafe.Slice when reinterpreting typed buffers.",
	},
	{
		ID:          RulePointerArithmeticBounds,
		ShortID:     "CLINO-007",
		Name:        "PointerArithmeticBoundsHazard",
		Severity:    SeverityError,
		Category:    "pointer-bounds",
		CWE:         "CWE-119",
		Summary:     "Out-of-bounds, negative, forged, or multi-pointer unsafe arithmetic.",
		Description: "Stepping backward past an allocation base (negative unsafe.Add or uintptr subtraction), forging an unsafe.Pointer from an integer constant, combining two pointer addresses back into unsafe.Pointer, passing a negative length to unsafe.Slice/unsafe.String, or casting to an oversized fake array (*[1<<30]T) violates Go's memory safety and checkptr invariants.",
		Remediation: "Keep pointer offsets non-negative within allocation bounds, replace oversized fake-array casts with unsafe.Slice(ptr, exactLen), and never synthesize unsafe.Pointer values from integer literals.",
	},
	{
		ID:          RuleCGoPinningHazard,
		ShortID:     "CLINO-008",
		Name:        "CGoCallbackAndPinningHazard",
		Severity:    SeverityError,
		Category:    "cgo-pinning",
		CWE:         "CWE-401",
		Summary:     "CGo pinning leak, handle leak, cgocheck uintptr smuggling, or unsafe callback context passing.",
		Description: "Calling runtime.Pinner.Pin without a matching Unpin leaks pinned memory and triggers runtime panics; leaking runtime/cgo.NewHandle pins objects indefinitely; casting a Go pointer through uintptr/C.uintptr_t smuggles it past cgocheck; passing raw Go closures or unpinned Go callback contexts to C functions leads to crashes or memory corruption.",
		Remediation: "Always pair runtime.Pinner.Pin with defer pinner.Unpin(), delete cgo.Handle values when done, use //export trampolines with cgo.NewHandle for callbacks, and never cast Go pointers to C.uintptr_t.",
	},
}

var ruleByID map[RuleID]RuleMeta
var ruleByShort map[string]RuleID

func init() {
	ruleByID = make(map[RuleID]RuleMeta, len(ruleRegistry))
	ruleByShort = make(map[string]RuleID, len(ruleRegistry))
	for _, r := range ruleRegistry {
		ruleByID[r.ID] = r
		ruleByShort[strings.ToUpper(r.ShortID)] = r.ID
	}
}

// AllRules returns metadata for all Clino rules in deterministic order.
func AllRules() []RuleMeta {
	out := make([]RuleMeta, len(ruleRegistry))
	copy(out, ruleRegistry)
	return out
}

// LookupRule returns metadata for a rule ID.
func LookupRule(id RuleID) (RuleMeta, bool) {
	m, ok := ruleByID[id]
	return m, ok
}

// ResolveRuleID resolves a full rule ID (CLINO-001-ILLEGAL-UINTPTR-CAST) or
// short prefix (CLINO-001), case-insensitively.
func ResolveRuleID(input string) (RuleID, bool) {
	norm := strings.ToUpper(strings.TrimSpace(input))
	if norm == "" {
		return "", false
	}
	if _, ok := ruleByID[RuleID(norm)]; ok {
		return RuleID(norm), true
	}
	if id, ok := ruleByShort[norm]; ok {
		return id, true
	}
	return "", false
}

// SeverityRank returns an integer rank for severity comparison.
func SeverityRank(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case SeverityError:
		return 2
	case SeverityWarning:
		return 1
	default:
		return 0
	}
}
