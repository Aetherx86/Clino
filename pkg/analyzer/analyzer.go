package analyzer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

type RuleID string

const (
	RuleIllegalUintptrCast      RuleID = "CLINO-001-ILLEGAL-UINTPTR-CAST"
	RuleCGoInternalPointer      RuleID = "CLINO-002-CGO-INTERNAL-POINTER"
	RuleUnsafeSliceHeader       RuleID = "CLINO-003-UNSAFE-SLICE-HEADER"
	RuleFFIStackEscape          RuleID = "CLINO-004-FFI-STACK-ESCAPE"
	RuleUnsafeStringHeader      RuleID = "CLINO-005-UNSAFE-STRING-HEADER"
)

type Violation struct {
	Rule     RuleID
	Severity string // ERROR, WARNING
	File     string
	Line     int
	Column   int
	Message  string
	Snippet  string
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s:%d:%d: %s\n    Code: %s",
		v.Rule, v.File, v.Line, v.Column, v.Message, v.Snippet)
}

type Mode string

const (
	ModeFast   Mode = "fast"   // Syntactic AST inspection (< 5ms per repo)
	ModeStrict Mode = "strict" // Deep boundary checking with zero-tolerance exit codes
)

type Auditor struct {
	fset *token.FileSet
	mode Mode
}

func New(mode Mode) *Auditor {
	return &Auditor{
		fset: token.NewFileSet(),
		mode: mode,
	}
}

// AuditSource parses and inspects Go source code in memory.
func (a *Auditor) AuditSource(filename string, src []byte) ([]Violation, error) {
	node, err := parser.ParseFile(a.fset, filename, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse error in %s: %w", filename, err)
	}

	lines := strings.Split(string(src), "\n")
	return a.inspectFile(filename, node, lines), nil
}

// AuditDirectory recursively walks a directory and audits all .go files.
func (a *Auditor) AuditDirectory(root string) ([]Violation, error) {
	var allViolations []Violation

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			name := info.Name()
			if strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		violations, err := a.AuditSource(path, src)
		if err != nil {
			return err
		}
		allViolations = append(allViolations, violations...)
		return nil
	})

	return allViolations, err
}

func (a *Auditor) inspectFile(filename string, file *ast.File, lines []string) []Violation {
	var violations []Violation

	// Track variables assigned from uintptr
	uintptrVars := make(map[string]bool)

	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			return true
		}

		switch expr := n.(type) {
		// 1. Detect intermediate variable assignments holding uintptr
		case *ast.AssignStmt:
			for i, rhs := range expr.Rhs {
				if isUintptrConversion(rhs) {
					if i < len(expr.Lhs) {
						if ident, ok := expr.Lhs[i].(*ast.Ident); ok {
							uintptrVars[ident.Name] = true
						}
					}
				}
			}

		// 2. Detect illegal unsafe.Pointer(uintptr_var) conversions
		case *ast.CallExpr:
			if isUnsafePointerCall(expr) {
				if len(expr.Args) == 1 {
					arg := expr.Args[0]
					// Check if arg is an intermediate variable previously holding uintptr
					if ident, ok := arg.(*ast.Ident); ok {
						if uintptrVars[ident.Name] {
							pos := a.fset.Position(expr.Pos())
							snippet := getLineSnippet(lines, pos.Line)
							violations = append(violations, Violation{
								Rule:     RuleIllegalUintptrCast,
								Severity: "ERROR",
								File:     filename,
								Line:     pos.Line,
								Column:   pos.Column,
								Message:  fmt.Sprintf("illegal unsafe.Pointer conversion from intermediate variable %q; uintptr arithmetic must be atomic within a single expression", ident.Name),
								Snippet:  snippet,
							})
						}
					}
				}
			}

			// 3. Detect CGo function calls passing pointers with internal Go pointers
			if isCGoCall(expr) {
				for _, arg := range expr.Args {
					if hasInternalPointerRisk(arg) {
						pos := a.fset.Position(arg.Pos())
						snippet := getLineSnippet(lines, pos.Line)
						violations = append(violations, Violation{
							Rule:     RuleCGoInternalPointer,
							Severity: "ERROR",
							File:     filename,
							Line:     pos.Line,
							Column:   pos.Column,
							Message:  "CGo boundary violation: passing Go pointer containing nested internal pointers/slices to foreign C function violates Go runtime pointer rules",
							Snippet:  snippet,
						})
					}
				}
			}

		// 4. Detect legacy reflect.SliceHeader or reflect.StringHeader unsafe mutations
		case *ast.SelectorExpr:
			if isReflectHeader(expr) {
				pos := a.fset.Position(expr.Pos())
				snippet := getLineSnippet(lines, pos.Line)
				rule := RuleUnsafeSliceHeader
				if expr.Sel.Name == "StringHeader" {
					rule = RuleUnsafeStringHeader
				}
				violations = append(violations, Violation{
					Rule:     rule,
					Severity: "WARNING",
					File:     filename,
					Line:     pos.Line,
					Column:   pos.Column,
					Message:  fmt.Sprintf("deprecated use of reflect.%s for pointer arithmetic; migrate to unsafe.Slice or unsafe.String", expr.Sel.Name),
					Snippet:  snippet,
				})
			}
		}

		return true
	})

	return violations
}

func isUintptrConversion(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	if ident, ok := call.Fun.(*ast.Ident); ok {
		return ident.Name == "uintptr"
	}
	return false
}

func isUnsafePointerCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if pkgIdent, ok := sel.X.(*ast.Ident); ok {
		return pkgIdent.Name == "unsafe" && sel.Sel.Name == "Pointer"
	}
	return false
}

func isCGoCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if pkgIdent, ok := sel.X.(*ast.Ident); ok {
		return pkgIdent.Name == "C"
	}
	return false
}

func hasInternalPointerRisk(expr ast.Expr) bool {
	// Taking address of composite literal with slice or pointer fields
	if u, ok := expr.(*ast.UnaryExpr); ok && u.Op == token.AND {
		if comp, ok := u.X.(*ast.CompositeLit); ok {
			for _, elt := range comp.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if _, isComp := kv.Value.(*ast.CompositeLit); isComp {
						return true
					}
				}
			}
		}
	}
	return false
}

func isReflectHeader(expr *ast.SelectorExpr) bool {
	if pkgIdent, ok := expr.X.(*ast.Ident); ok {
		if pkgIdent.Name == "reflect" {
			return expr.Sel.Name == "SliceHeader" || expr.Sel.Name == "StringHeader"
		}
	}
	return false
}

func getLineSnippet(lines []string, line int) string {
	if line > 0 && line <= len(lines) {
		return strings.TrimSpace(lines[line-1])
	}
	return ""
}
