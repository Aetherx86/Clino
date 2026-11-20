package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
	"strings"
)

const oversizedFakeArrayThreshold int64 = 1 << 20 // 1,048,576 elements

type dedupKey struct {
	line int
	rule RuleID
}

type fileContext struct {
	fset                *token.FileSet
	filename            string
	lines               []string
	hasCGo              bool
	hasExportDirective  bool
	unsafePkgs          map[string]bool
	reflectPkgs         map[string]bool
	runtimePkgs         map[string]bool
	cgoPkgs             map[string]bool
	structTypes         map[string]*ast.StructType
	typeAliases         map[string]ast.Expr
	suppressions        map[int]map[RuleID]bool
	emitted             map[dedupKey]bool
	handledReflectNodes map[ast.Node]bool
	violations          []Violation
	suppressed          int
}

type sliceHeaderInfo struct {
	pos               token.Pos
	isString          bool
	fromLocalDecl     bool
	convertedToUnsafe bool
	alreadyReported   bool
}

type pinnerState struct {
	name          string
	pinned        bool
	pinPos        token.Pos
	unpinned      bool
	escaped       bool
	pinnedTargets map[string]bool
}

type handleState struct {
	name      string
	createPos token.Pos
	deleted   bool
	escaped   bool
}

type funcScope struct {
	parent              *funcScope
	funcName            string
	taintedUintptr      map[string]string
	anyUintptr          map[string]bool
	unsafePtrVars       map[string]bool
	goPtrVars           map[string]bool
	containsGoPtrs      map[string]bool
	pointsToNestedGoPtr map[string]bool
	cAllocVars          map[string]bool
	sliceVars           map[string]ast.Expr
	stringVars          map[string]bool
	reflectValVars      map[string]bool
	sliceHeaderVars     map[string]*sliceHeaderInfo
	sliceHeaderPtrVars  map[string]bool
	pinnerVars          map[string]*pinnerState
	cgoHandleVars       map[string]*handleState
	localVars           map[string]bool
	funcVars            map[string]bool
}

func newFuncScope(parent *funcScope, name string) *funcScope {
	return &funcScope{
		parent:              parent,
		funcName:            name,
		taintedUintptr:      make(map[string]string),
		anyUintptr:          make(map[string]bool),
		unsafePtrVars:       make(map[string]bool),
		goPtrVars:           make(map[string]bool),
		containsGoPtrs:      make(map[string]bool),
		pointsToNestedGoPtr: make(map[string]bool),
		cAllocVars:          make(map[string]bool),
		sliceVars:           make(map[string]ast.Expr),
		stringVars:          make(map[string]bool),
		reflectValVars:      make(map[string]bool),
		sliceHeaderVars:     make(map[string]*sliceHeaderInfo),
		sliceHeaderPtrVars:  make(map[string]bool),
		pinnerVars:          make(map[string]*pinnerState),
		cgoHandleVars:       make(map[string]*handleState),
		localVars:           make(map[string]bool),
		funcVars:            make(map[string]bool),
	}
}

func (s *funcScope) lookupTaintedUintptr(name string) (string, bool) {
	for cur := s; cur != nil; cur = cur.parent {
		if reason, ok := cur.taintedUintptr[name]; ok {
			return reason, true
		}
	}
	return "", false
}

func (s *funcScope) isAnyUintptr(name string) bool {
	for cur := s; cur != nil; cur = cur.parent {
		if cur.anyUintptr[name] {
			return true
		}
	}
	return false
}

func (s *funcScope) isUnsafePtr(name string) bool {
	for cur := s; cur != nil; cur = cur.parent {
		if cur.unsafePtrVars[name] {
			return true
		}
	}
	return false
}

func (s *funcScope) isGoPtr(name string) bool {
	for cur := s; cur != nil; cur = cur.parent {
		if cur.goPtrVars[name] {
			return true
		}
	}
	return false
}

func (s *funcScope) hasGoPtrs(name string) bool {
	for cur := s; cur != nil; cur = cur.parent {
		if cur.containsGoPtrs[name] {
			return true
		}
	}
	return false
}

func (s *funcScope) pointsToGoPtrs(name string) bool {
	for cur := s; cur != nil; cur = cur.parent {
		if cur.pointsToNestedGoPtr[name] {
			return true
		}
	}
	return false
}

func (s *funcScope) isCAlloc(name string) bool {
	for cur := s; cur != nil; cur = cur.parent {
		if cur.cAllocVars[name] {
			return true
		}
	}
	return false
}

func (s *funcScope) sliceElemType(name string) (ast.Expr, bool) {
	for cur := s; cur != nil; cur = cur.parent {
		if elt, ok := cur.sliceVars[name]; ok {
			return elt, true
		}
	}
	return nil, false
}

func (s *funcScope) isStringVar(name string) bool {
	for cur := s; cur != nil; cur = cur.parent {
		if cur.stringVars[name] {
			return true
		}
	}
	return false
}

func (s *funcScope) isReflectVal(name string) bool {
	for cur := s; cur != nil; cur = cur.parent {
		if cur.reflectValVars[name] {
			return true
		}
	}
	return false
}

func (s *funcScope) lookupSliceHeader(name string) (*sliceHeaderInfo, bool) {
	for cur := s; cur != nil; cur = cur.parent {
		if info, ok := cur.sliceHeaderVars[name]; ok {
			return info, true
		}
	}
	return nil, false
}

func (s *funcScope) isSliceHeaderPtr(name string) bool {
	for cur := s; cur != nil; cur = cur.parent {
		if cur.sliceHeaderPtrVars[name] {
			return true
		}
	}
	return false
}

func (s *funcScope) lookupPinner(name string) (*pinnerState, bool) {
	for cur := s; cur != nil; cur = cur.parent {
		if p, ok := cur.pinnerVars[name]; ok {
			return p, true
		}
	}
	return nil, false
}

func (s *funcScope) lookupHandle(name string) (*handleState, bool) {
	for cur := s; cur != nil; cur = cur.parent {
		if h, ok := cur.cgoHandleVars[name]; ok {
			return h, true
		}
	}
	return nil, false
}

func (s *funcScope) isFuncVar(name string) bool {
	for cur := s; cur != nil; cur = cur.parent {
		if cur.funcVars[name] {
			return true
		}
	}
	return false
}

func (s *funcScope) isPinnedTarget(name string) bool {
	if name == "" {
		return false
	}
	for cur := s; cur != nil; cur = cur.parent {
		for _, p := range cur.pinnerVars {
			if p.pinnedTargets[name] {
				return true
			}
		}
	}
	return false
}

func inspectFile(fset *token.FileSet, filename string, file *ast.File, lines []string) ([]Violation, int) {
	fc := &fileContext{
		fset:                fset,
		filename:            filename,
		lines:               lines,
		unsafePkgs:          make(map[string]bool),
		reflectPkgs:         make(map[string]bool),
		runtimePkgs:         make(map[string]bool),
		cgoPkgs:             make(map[string]bool),
		structTypes:         make(map[string]*ast.StructType),
		typeAliases:         make(map[string]ast.Expr),
		suppressions:        make(map[int]map[RuleID]bool),
		emitted:             make(map[dedupKey]bool),
		handledReflectNodes: make(map[ast.Node]bool),
	}

	fc.parseImports(file)
	fc.parseComments(file)
	fc.collectFileTypes(file)

	pkgScope := newFuncScope(nil, "")
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			if d.Tok == token.VAR {
				fc.inspectGenDecl(pkgScope, d, true)
			}
		case *ast.FuncDecl:
			name := d.Name.Name
			if d.Recv != nil && len(d.Recv.List) > 0 {
				recvType := formatRecvType(d.Recv.List[0].Type)
				if recvType != "" {
					name = recvType + "." + name
				}
			}
			fc.inspectFunc(pkgScope, name, d.Recv, d.Type, d.Body)
		}
	}

	return fc.violations, fc.suppressed
}

func formatRecvType(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return formatRecvType(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return formatRecvType(t.X)
	case *ast.IndexListExpr:
		return formatRecvType(t.X)
	default:
		return ""
	}
}

func (fc *fileContext) parseImports(file *ast.File) {
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if path == "C" {
			fc.hasCGo = true
			continue
		}
		var local string
		if imp.Name != nil {
			local = imp.Name.Name
			if local == "_" || local == "." {
				continue
			}
		} else {
			parts := strings.Split(path, "/")
			local = parts[len(parts)-1]
		}

		switch path {
		case "unsafe":
			fc.unsafePkgs[local] = true
		case "reflect":
			fc.reflectPkgs[local] = true
		case "runtime":
			fc.runtimePkgs[local] = true
		case "runtime/cgo":
			fc.cgoPkgs[local] = true
		}
	}
}

func (fc *fileContext) parseComments(file *ast.File) {
	for _, cg := range file.Comments {
		for _, c := range cg.List {
			text := c.Text
			if strings.HasPrefix(text, "//export ") {
				fc.hasExportDirective = true
			}
			fc.parseSuppressionComment(c)
		}
	}
}

func (fc *fileContext) parseSuppressionComment(c *ast.Comment) {
	text := strings.TrimSpace(c.Text)
	if strings.HasPrefix(text, "//") {
		text = strings.TrimSpace(strings.TrimPrefix(text, "//"))
	} else if strings.HasPrefix(text, "/*") && strings.HasSuffix(text, "*/") {
		text = strings.TrimSpace(text[2 : len(text)-2])
	} else {
		return
	}

	lower := strings.ToLower(text)
	const directive = "clino:ignore"
	idx := strings.Index(lower, directive)
	if idx < 0 {
		return
	}
	rest := strings.TrimSpace(text[idx+len(directive):])
	// Stop at explanation separator if user wrote "// clino:ignore CLINO-003 -- reason"
	if sep := strings.Index(rest, "--"); sep >= 0 {
		rest = strings.TrimSpace(rest[:sep])
	}
	if sep := strings.Index(rest, "//"); sep >= 0 {
		rest = strings.TrimSpace(rest[:sep])
	}

	pos := fc.fset.Position(c.Pos())
	targetLine := pos.Line
	if pos.Line > 0 && pos.Line <= len(fc.lines) {
		trimmedLine := strings.TrimSpace(fc.lines[pos.Line-1])
		if strings.HasPrefix(trimmedLine, "//") || strings.HasPrefix(trimmedLine, "/*") {
			targetLine = pos.Line + 1
		}
	}

	if fc.suppressions[targetLine] == nil {
		fc.suppressions[targetLine] = make(map[RuleID]bool)
	}

	if rest == "" {
		fc.suppressions[targetLine][""] = true
		return
	}

	fields := strings.FieldsFunc(rest, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	matchedAny := false
	for _, f := range fields {
		if id, ok := ResolveRuleID(f); ok {
			fc.suppressions[targetLine][id] = true
			matchedAny = true
		}
	}
	if !matchedAny {
		fc.suppressions[targetLine][""] = true
	}
}

func (fc *fileContext) isSuppressed(line int, rule RuleID) bool {
	rules, ok := fc.suppressions[line]
	if !ok {
		return false
	}
	return rules[""] || rules[rule]
}

func (fc *fileContext) collectFileTypes(file *ast.File) {
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			if st, ok := ts.Type.(*ast.StructType); ok {
				fc.structTypes[ts.Name.Name] = st
			} else {
				fc.typeAliases[ts.Name.Name] = ts.Type
			}
		}
	}
}

func (fc *fileContext) emit(pos token.Pos, rule RuleID, fnName, message string) {
	p := fc.fset.Position(pos)
	if fc.isSuppressed(p.Line, rule) {
		fc.suppressed++
		return
	}
	key := dedupKey{line: p.Line, rule: rule}
	if fc.emitted[key] {
		return
	}
	fc.emitted[key] = true

	meta, _ := LookupRule(rule)
	sev := meta.Severity
	if sev == "" {
		sev = SeverityError
	}
	fc.violations = append(fc.violations, Violation{
		Rule:        rule,
		Severity:    sev,
		File:        fc.filename,
		Line:        p.Line,
		Column:      p.Column,
		Function:    fnName,
		Message:     message,
		Snippet:     getLineSnippet(fc.lines, p.Line),
		Remediation: meta.Remediation,
		CWE:         meta.CWE,
	})
}

func (fc *fileContext) inspectFunc(parent *funcScope, name string, recv *ast.FieldList, ftype *ast.FuncType, body *ast.BlockStmt) {
	if body == nil {
		return
	}
	s := newFuncScope(parent, name)

	bindFieldList := func(fl *ast.FieldList, isParam bool) {
		if fl == nil {
			return
		}
		for _, field := range fl.List {
			for _, ident := range field.Names {
				if ident.Name == "_" {
					continue
				}
				s.localVars[ident.Name] = true
				fc.recordVarType(s, ident.Name, field.Type, isParam, ident.Pos())
			}
		}
	}

	bindFieldList(recv, true)
	if ftype != nil {
		bindFieldList(ftype.Params, true)
		bindFieldList(ftype.Results, true)
	}

	fc.inspectBlock(s, body)
	fc.finalizeScope(s)
}

func (fc *fileContext) finalizeScope(s *funcScope) {
	for _, p := range s.pinnerVars {
		if p.pinned && !p.unpinned && !p.escaped {
			fc.emit(
				p.pinPos,
				RuleCGoPinningHazard,
				s.funcName,
				fmt.Sprintf("runtime.Pinner %q calls Pin() without a matching Unpin() in this function; un-unpinned objects leak memory and trigger runtime panics", p.name),
			)
		}
	}

	for _, h := range s.cgoHandleVars {
		if !h.deleted && !h.escaped && !fc.hasExportDirective {
			fc.emit(
				h.createPos,
				RuleCGoPinningHazard,
				s.funcName,
				fmt.Sprintf("cgo.Handle %q created via cgo.NewHandle without Delete() or ownership transfer; leaked handles pin Go objects indefinitely", h.name),
			)
		}
	}

	for _, sh := range s.sliceHeaderVars {
		if !sh.convertedToUnsafe && sh.fromLocalDecl {
			rule := RuleUnsafeSliceHeader
			kind := "SliceHeader"
			if sh.isString {
				rule = RuleUnsafeStringHeader
				kind = "StringHeader"
			}
			fc.emit(
				sh.pos,
				rule,
				s.funcName,
				fmt.Sprintf("deprecated use of reflect.%s for pointer arithmetic; migrate to unsafe.Slice or unsafe.String", kind),
			)
		}
	}
}

func (fc *fileContext) recordVarType(s *funcScope, name string, typ ast.Expr, isParam bool, pos token.Pos) {
	if typ == nil {
		return
	}
	typ = unwrapParen(typ)
	switch t := typ.(type) {
	case *ast.Ident:
		switch t.Name {
		case "uintptr":
			s.anyUintptr[name] = true
		case "string":
			s.stringVars[name] = true
			s.containsGoPtrs[name] = true
		case "any", "error":
			s.containsGoPtrs[name] = true
		default:
			if fc.typeContainsGoPointer(t, nil) {
				s.containsGoPtrs[name] = true
			}
		}
	case *ast.SelectorExpr:
		if fc.isUnsafePointerType(t) {
			s.unsafePtrVars[name] = true
		} else if fc.isRuntimePinnerType(t) {
			s.pinnerVars[name] = &pinnerState{
				name:          name,
				escaped:       isParam,
				pinnedTargets: make(map[string]bool),
			}
		} else if fc.isCGoHandleType(t) {
			s.cgoHandleVars[name] = &handleState{
				name:      name,
				createPos: pos,
				escaped:   isParam,
			}
		} else if fc.isReflectValueType(t) {
			s.reflectValVars[name] = true
		} else if kind, ok := fc.reflectHeaderKind(t); ok {
			fc.handledReflectNodes[t] = true
			s.sliceHeaderVars[name] = &sliceHeaderInfo{
				pos:           pos,
				isString:      kind == "StringHeader",
				fromLocalDecl: !isParam,
			}
		}
	case *ast.StarExpr:
		if fc.isCTypeExpr(t.X) {
			s.cAllocVars[name] = true
		} else if fc.isRuntimePinnerType(t.X) {
			s.pinnerVars[name] = &pinnerState{
				name:          name,
				escaped:       isParam,
				pinnedTargets: make(map[string]bool),
			}
		} else if _, ok := fc.reflectHeaderKind(t.X); ok {
			s.sliceHeaderPtrVars[name] = true
		} else {
			s.goPtrVars[name] = true
			s.containsGoPtrs[name] = true
			if fc.typeContainsGoPointer(t.X, nil) {
				s.pointsToNestedGoPtr[name] = true
			}
		}
	case *ast.ArrayType:
		if t.Len == nil {
			s.sliceVars[name] = t.Elt
			s.containsGoPtrs[name] = true
		} else if fc.typeContainsGoPointer(t.Elt, nil) {
			s.containsGoPtrs[name] = true
		}
	case *ast.MapType, *ast.ChanType, *ast.InterfaceType:
		s.containsGoPtrs[name] = true
	case *ast.FuncType:
		s.containsGoPtrs[name] = true
		s.funcVars[name] = true
	case *ast.StructType:
		if fc.structContainsGoPointer(t, nil) {
			s.containsGoPtrs[name] = true
		}
	}
}

func (fc *fileContext) inspectBlock(s *funcScope, block *ast.BlockStmt) {
	if block == nil {
		return
	}
	for _, stmt := range block.List {
		fc.inspectStmt(s, stmt)
	}
}

func (fc *fileContext) inspectStmt(s *funcScope, stmt ast.Stmt) {
	if stmt == nil {
		return
	}

	switch st := stmt.(type) {
	case *ast.BlockStmt:
		fc.inspectBlock(s, st)

	case *ast.DeclStmt:
		if gd, ok := st.Decl.(*ast.GenDecl); ok {
			fc.inspectGenDecl(s, gd, false)
		}

	case *ast.AssignStmt:
		fc.inspectAssignStmt(s, st)

	case *ast.ExprStmt:
		fc.inspectExpr(s, st.X)

	case *ast.GoStmt:
		fc.inspectExpr(s, st.Call)

	case *ast.DeferStmt:
		fc.inspectExpr(s, st.Call)

	case *ast.ReturnStmt:
		for _, res := range st.Results {
			fc.markReturnedEscapes(s, res)
			fc.inspectExpr(s, res)
		}

	case *ast.IfStmt:
		if st.Init != nil {
			fc.inspectStmt(s, st.Init)
		}
		fc.inspectExpr(s, st.Cond)
		fc.inspectBlock(s, st.Body)
		if st.Else != nil {
			fc.inspectStmt(s, st.Else)
		}

	case *ast.ForStmt:
		if st.Init != nil {
			fc.inspectStmt(s, st.Init)
		}
		fc.inspectExpr(s, st.Cond)
		fc.inspectStmt(s, st.Post)
		fc.inspectBlock(s, st.Body)

	case *ast.RangeStmt:
		fc.inspectExpr(s, st.X)
		fc.inspectBlock(s, st.Body)

	case *ast.SwitchStmt:
		if st.Init != nil {
			fc.inspectStmt(s, st.Init)
		}
		fc.inspectExpr(s, st.Tag)
		fc.inspectBlock(s, st.Body)

	case *ast.TypeSwitchStmt:
		if st.Init != nil {
			fc.inspectStmt(s, st.Init)
		}
		fc.inspectStmt(s, st.Assign)
		fc.inspectBlock(s, st.Body)

	case *ast.CaseClause:
		for _, expr := range st.List {
			fc.inspectExpr(s, expr)
		}
		for _, bodyStmt := range st.Body {
			fc.inspectStmt(s, bodyStmt)
		}

	case *ast.SelectStmt:
		fc.inspectBlock(s, st.Body)

	case *ast.CommClause:
		fc.inspectStmt(s, st.Comm)
		for _, bodyStmt := range st.Body {
			fc.inspectStmt(s, bodyStmt)
		}

	case *ast.SendStmt:
		fc.inspectExpr(s, st.Chan)
		fc.inspectExpr(s, st.Value)

	case *ast.IncDecStmt:
		fc.inspectExpr(s, st.X)

	case *ast.LabeledStmt:
		fc.inspectStmt(s, st.Stmt)
	}
}

func (fc *fileContext) inspectGenDecl(s *funcScope, gd *ast.GenDecl, isPkgLevel bool) {
	switch gd.Tok {
	case token.TYPE:
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			if st, ok := ts.Type.(*ast.StructType); ok {
				fc.structTypes[ts.Name.Name] = st
			} else {
				fc.typeAliases[ts.Name.Name] = ts.Type
			}
		}
	case token.VAR:
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if ident.Name != "_" {
					if !isPkgLevel {
						s.localVars[ident.Name] = true
					}
					fc.recordVarType(s, ident.Name, vs.Type, isPkgLevel, ident.Pos())
				}
				if i < len(vs.Values) {
					rhs := vs.Values[i]
					fc.inspectExpr(s, rhs)
					if ident.Name != "_" {
						fc.recordVarInit(s, ident.Name, rhs, ident.Pos())
					} else {
						fc.checkDiscardedRHS(s, rhs)
					}
				}
			}
		}
	}
}

func (fc *fileContext) inspectAssignStmt(s *funcScope, stmt *ast.AssignStmt) {
	// Inspect RHS expressions first so uses on the RHS are analyzed before LHS rebinding.
	for _, rhs := range stmt.Rhs {
		fc.inspectExpr(s, rhs)
	}

	// Inspect non-identifier LHS expressions (e.g. index or selector bases).
	for _, lhs := range stmt.Lhs {
		if _, isIdent := lhs.(*ast.Ident); !isIdent {
			fc.inspectExpr(s, lhs)
		}
	}

	for i, lhs := range stmt.Lhs {
		var rhs ast.Expr
		if i < len(stmt.Rhs) {
			rhs = stmt.Rhs[i]
		} else if len(stmt.Rhs) == 1 {
			rhs = stmt.Rhs[0]
		}

		// Detect storing Go pointer into C-managed memory (CLINO-004).
		if fc.hasCGo && rhs != nil && fc.isCMemoryTarget(s, lhs) {
			if unpinned, desc := fc.isUnpinnedGoPointerExpr(s, rhs); unpinned {
				fc.emit(
					stmt.Pos(),
					RuleFFIStackEscape,
					s.funcName,
					fmt.Sprintf("storing unpinned Go pointer (%s) into C-managed memory violates CGo pointer retention rules", desc),
				)
			}
		}

		// Assigning a pinner or handle to a struct field, map, slice, or package variable transfers ownership.
		if rhs != nil {
			if _, isIdent := lhs.(*ast.Ident); !isIdent {
				fc.markReturnedEscapes(s, rhs)
			}
		}

		ident, ok := lhs.(*ast.Ident)
		if !ok {
			continue
		}
		if ident.Name == "_" {
			if rhs != nil {
				fc.checkDiscardedRHS(s, rhs)
			}
			continue
		}

		if stmt.Tok == token.DEFINE {
			s.localVars[ident.Name] = true
		}

		// Handle compound assignment like `u += 8`
		if stmt.Tok == token.ADD_ASSIGN || stmt.Tok == token.SUB_ASSIGN || stmt.Tok == token.OR_ASSIGN || stmt.Tok == token.AND_ASSIGN {
			if _, tainted := s.lookupTaintedUintptr(ident.Name); tainted {
				s.taintedUintptr[ident.Name] = "mutated uintptr variable"
			}
			continue
		}

		if rhs != nil {
			fc.recordVarInit(s, ident.Name, rhs, ident.Pos())
		}
	}
}

func (fc *fileContext) checkDiscardedRHS(s *funcScope, rhs ast.Expr) {
	call, ok := unwrapParen(rhs).(*ast.CallExpr)
	if !ok {
		return
	}
	if fc.isCGoNewHandleCall(call) {
		fc.emit(
			call.Pos(),
			RuleCGoPinningHazard,
			s.funcName,
			"discarding runtime/cgo.NewHandle return value leaks the pinned handle permanently",
		)
	}
}

func (fc *fileContext) recordVarInit(s *funcScope, name string, rhs ast.Expr, pos token.Pos) {
	rhs = unwrapParen(rhs)

	// 1. Track pointer-derived uintptr variables (CLINO-001).
	if reason, ok := fc.exprTaintedUintptrReason(s, rhs); ok {
		s.taintedUintptr[name] = reason
		s.anyUintptr[name] = true
	} else if fc.isUintptrCall(rhs) {
		s.anyUintptr[name] = true
	}

	// 2. Track unsafe.Pointer variables.
	if call, ok := rhs.(*ast.CallExpr); ok && fc.isUnsafePointerCall(call) {
		s.unsafePtrVars[name] = true
		if len(call.Args) == 1 {
			if unpinned, _ := fc.isUnpinnedGoPointerExpr(s, call.Args[0]); unpinned {
				s.goPtrVars[name] = true
			}
		}
	}
	if call, ok := rhs.(*ast.CallExpr); ok && fc.isUnsafeAddCall(call) {
		s.unsafePtrVars[name] = true
	}

	// 3. Track C-allocated variables and C pointer casts.
	if fc.isCAllocExpr(s, rhs) {
		s.cAllocVars[name] = true
	}

	// 4. Track runtime.Pinner creation.
	if fc.isPinnerInitExpr(rhs) {
		s.pinnerVars[name] = &pinnerState{
			name:          name,
			pinnedTargets: make(map[string]bool),
		}
	}

	// 5. Track cgo.NewHandle creation.
	if call, ok := rhs.(*ast.CallExpr); ok && fc.isCGoNewHandleCall(call) {
		s.cgoHandleVars[name] = &handleState{
			name:      name,
			createPos: call.Pos(),
		}
	}

	// 6. Track reflect.Value variables.
	if call, ok := rhs.(*ast.CallExpr); ok && fc.isReflectValueOfCall(call) {
		s.reflectValVars[name] = true
	}

	// 7. Track *reflect.SliceHeader / *reflect.StringHeader casts.
	if call, ok := rhs.(*ast.CallExpr); ok {
		if target, ok := unwrapParen(call.Fun).(*ast.StarExpr); ok {
			if _, isHdr := fc.reflectHeaderKind(target.X); isHdr {
				s.sliceHeaderPtrVars[name] = true
			}
		}
	}

	// 8. Track value reflect.SliceHeader / reflect.StringHeader composite literals.
	if comp, ok := rhs.(*ast.CompositeLit); ok {
		if kind, isHdr := fc.reflectHeaderKind(comp.Type); isHdr {
			s.sliceHeaderVars[name] = &sliceHeaderInfo{
				pos:             pos,
				isString:        kind == "StringHeader",
				fromLocalDecl:   false,
				alreadyReported: true, // already reported as CLINO-006 on composite literal
			}
		}
	}

	// 9. Track slices, strings, Go pointers, composite literals with Go pointers, and closures.
	switch e := rhs.(type) {
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			s.goPtrVars[name] = true
			s.containsGoPtrs[name] = true
			target := unwrapParen(e.X)
			switch tgt := target.(type) {
			case *ast.CompositeLit:
				if fc.compositeLitHasGoPointers(s, tgt) || fc.typeContainsGoPointer(tgt.Type, nil) {
					s.pointsToNestedGoPtr[name] = true
				}
			case *ast.Ident:
				if s.hasGoPtrs(tgt.Name) || s.isGoPtr(tgt.Name) {
					s.pointsToNestedGoPtr[name] = true
				}
			case *ast.IndexExpr:
				if baseIdent, ok := unwrapParen(tgt.X).(*ast.Ident); ok {
					if eltType, isSlice := s.sliceElemType(baseIdent.Name); isSlice {
						if fc.typeContainsGoPointer(eltType, nil) {
							s.pointsToNestedGoPtr[name] = true
						}
					}
				}
			}
		}
	case *ast.CompositeLit:
		if arr, ok := e.Type.(*ast.ArrayType); ok && arr.Len == nil {
			s.sliceVars[name] = arr.Elt
			s.containsGoPtrs[name] = true
		} else if _, ok := e.Type.(*ast.MapType); ok {
			s.containsGoPtrs[name] = true
		} else if fc.typeContainsGoPointer(e.Type, nil) || fc.compositeLitHasGoPointers(s, e) {
			s.containsGoPtrs[name] = true
		}
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			s.stringVars[name] = true
			s.containsGoPtrs[name] = true
		}
	case *ast.FuncLit:
		s.funcVars[name] = true
		s.containsGoPtrs[name] = true
	case *ast.CallExpr:
		if ident, ok := e.Fun.(*ast.Ident); ok {
			switch ident.Name {
			case "make":
				if len(e.Args) > 0 {
					if arr, ok := e.Args[0].(*ast.ArrayType); ok && arr.Len == nil {
						s.sliceVars[name] = arr.Elt
					}
					s.containsGoPtrs[name] = true
				}
			case "new":
				if len(e.Args) == 1 {
					if fc.isRuntimePinnerType(e.Args[0]) {
						s.pinnerVars[name] = &pinnerState{
							name:          name,
							pinnedTargets: make(map[string]bool),
						}
					} else {
						s.goPtrVars[name] = true
						s.containsGoPtrs[name] = true
						if fc.typeContainsGoPointer(e.Args[0], nil) {
							s.pointsToNestedGoPtr[name] = true
						}
					}
				}
			case "string":
				s.stringVars[name] = true
				s.containsGoPtrs[name] = true
			}
		}
		if fc.isUnsafeSliceCall(e) {
			s.containsGoPtrs[name] = true
		}
		if fc.isUnsafePointerCall(e) && len(e.Args) == 1 {
			if _, risky := fc.cgoInternalPointerRisk(s, e.Args[0]); risky {
				s.pointsToNestedGoPtr[name] = true
			}
		}
	case *ast.Ident:
		if s.isUnsafePtr(e.Name) {
			s.unsafePtrVars[name] = true
		}
		if s.isGoPtr(e.Name) {
			s.goPtrVars[name] = true
		}
		if s.hasGoPtrs(e.Name) {
			s.containsGoPtrs[name] = true
		}
		if s.pointsToGoPtrs(e.Name) {
			s.pointsToNestedGoPtr[name] = true
		}
		if s.isCAlloc(e.Name) {
			s.cAllocVars[name] = true
		}
		if elt, ok := s.sliceElemType(e.Name); ok {
			s.sliceVars[name] = elt
		}
		if s.isStringVar(e.Name) {
			s.stringVars[name] = true
		}
		if s.isFuncVar(e.Name) {
			s.funcVars[name] = true
		}
	}
}

func (fc *fileContext) markReturnedEscapes(s *funcScope, expr ast.Expr) {
	if expr == nil {
		return
	}
	ast.Inspect(expr, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if p, ok := s.lookupPinner(ident.Name); ok {
			p.escaped = true
		}
		if h, ok := s.lookupHandle(ident.Name); ok {
			h.escaped = true
		}
		return true
	})
}

func (fc *fileContext) inspectExpr(s *funcScope, expr ast.Expr) {
	if expr == nil {
		return
	}

	switch e := expr.(type) {
	case *ast.FuncLit:
		fc.inspectFunc(s, s.funcName+"$func", nil, e.Type, e.Body)

	case *ast.CompositeLit:
		if kind, isHdr := fc.reflectHeaderKind(e.Type); isHdr {
			fc.handledReflectNodes[e.Type] = true
			fc.emit(
				e.Pos(),
				RuleUnsafeSliceConversion,
				s.funcName,
				fmt.Sprintf("constructing a standalone reflect.%s value violates unsafe.Pointer Rule 6; use unsafe.Slice or unsafe.String instead", kind),
			)
		}
		fc.inspectExpr(s, e.Type)
		for _, elt := range e.Elts {
			fc.inspectExpr(s, elt)
		}

	case *ast.CallExpr:
		fc.inspectCallExpr(s, e)

	case *ast.SelectorExpr:
		if !fc.handledReflectNodes[e] {
			if kind, ok := fc.reflectHeaderKind(e); ok {
				rule := RuleUnsafeSliceHeader
				if kind == "StringHeader" {
					rule = RuleUnsafeStringHeader
				}
				fc.emit(
					e.Pos(),
					rule,
					s.funcName,
					fmt.Sprintf("deprecated use of reflect.%s for pointer arithmetic; migrate to unsafe.Slice or unsafe.String", kind),
				)
			}
		}
		fc.inspectExpr(s, e.X)

	case *ast.BinaryExpr:
		fc.inspectExpr(s, e.X)
		fc.inspectExpr(s, e.Y)

	case *ast.UnaryExpr:
		fc.inspectExpr(s, e.X)

	case *ast.ParenExpr:
		fc.inspectExpr(s, e.X)

	case *ast.StarExpr:
		fc.inspectExpr(s, e.X)

	case *ast.IndexExpr:
		fc.inspectExpr(s, e.X)
		fc.inspectExpr(s, e.Index)

	case *ast.IndexListExpr:
		fc.inspectExpr(s, e.X)
		for _, idx := range e.Indices {
			fc.inspectExpr(s, idx)
		}

	case *ast.SliceExpr:
		fc.inspectExpr(s, e.X)
		fc.inspectExpr(s, e.Low)
		fc.inspectExpr(s, e.High)
		fc.inspectExpr(s, e.Max)

	case *ast.TypeAssertExpr:
		fc.inspectExpr(s, e.X)
		fc.inspectExpr(s, e.Type)

	case *ast.KeyValueExpr:
		fc.inspectExpr(s, e.Key)
		fc.inspectExpr(s, e.Value)
	}
}

func (fc *fileContext) inspectCallExpr(s *funcScope, call *ast.CallExpr) {
	// 1. Track runtime.Pinner.Pin / Unpin and cgo.Handle.Delete calls.
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if recvIdent, ok := unwrapParen(sel.X).(*ast.Ident); ok {
			if p, ok := s.lookupPinner(recvIdent.Name); ok {
				switch sel.Sel.Name {
				case "Pin":
					p.pinned = true
					if p.pinPos == token.NoPos {
						p.pinPos = call.Pos()
					}
					if len(call.Args) == 1 {
						if target := extractRootIdentName(call.Args[0]); target != "" {
							p.pinnedTargets[target] = true
						}
					}
				case "Unpin":
					p.unpinned = true
				}
			}
			if h, ok := s.lookupHandle(recvIdent.Name); ok {
				if sel.Sel.Name == "Delete" {
					h.deleted = true
				}
			}
		}
	}

	// If a non-CGo function receives a local pinner or cgo.Handle, treat ownership as potentially transferred.
	if !fc.isAnyCCall(call) {
		for _, arg := range call.Args {
			if ident, ok := unwrapParen(arg).(*ast.Ident); ok {
				if h, ok := s.lookupHandle(ident.Name); ok {
					h.escaped = true
				}
				if p, ok := s.lookupPinner(ident.Name); ok {
					p.escaped = true
				}
			} else if u, ok := unwrapParen(arg).(*ast.UnaryExpr); ok && u.Op == token.AND {
				if ident, ok := unwrapParen(u.X).(*ast.Ident); ok {
					if p, ok := s.lookupPinner(ident.Name); ok {
						p.escaped = true
					}
				}
			}
		}
	}

	// 2. Check unsafe.Pointer(...) conversions (CLINO-001, CLINO-006, CLINO-007).
	if fc.isUnsafePointerCall(call) && len(call.Args) == 1 {
		fc.checkUnsafePointerCall(s, call)
	}

	// 3. Check unsafe.Add(ptr, offset) (CLINO-007).
	if fc.isUnsafeAddCall(call) && len(call.Args) == 2 {
		if isNegativeExpr(call.Args[1]) {
			fc.emit(
				call.Pos(),
				RulePointerArithmeticBounds,
				s.funcName,
				"negative offset in unsafe.Add may step before the start of the allocated object, violating unsafe.Pointer Rule 3",
			)
		}
	}

	// 4. Check unsafe.Slice(ptr, n) / unsafe.String(ptr, n) (CLINO-007).
	if (fc.isUnsafeSliceCall(call) || fc.isUnsafeStringCall(call)) && len(call.Args) == 2 {
		if isNegativeExpr(call.Args[1]) {
			fc.emit(
				call.Pos(),
				RulePointerArithmeticBounds,
				s.funcName,
				"negative length passed to unsafe.Slice/unsafe.String causes runtime panic or memory bounds corruption",
			)
		}
	}

	// 5. Check pointer type conversions:
	//    - (*[]T)(unsafe.Pointer(&x)) / (*string)(unsafe.Pointer(&x)) (CLINO-006)
	//    - (*[1<<30]T)(ptr) oversized fake-array casts (CLINO-007)
	fc.checkUnsafeTypeConversions(s, call)

	// 6. Check CGo calls & C integer smuggling (CLINO-002, CLINO-004, CLINO-008).
	if fc.hasCGo {
		fc.checkCGoCall(s, call)
	}

	// Recurse into Fun and Args.
	fc.inspectExpr(s, call.Fun)
	for _, arg := range call.Args {
		fc.inspectExpr(s, arg)
	}
}

func (fc *fileContext) checkUnsafePointerCall(s *funcScope, call *ast.CallExpr) {
	arg := unwrapParen(call.Args[0])

	// Check unsafe.Pointer(&hdr) where hdr is a value reflect.SliceHeader / reflect.StringHeader (CLINO-006).
	if u, ok := arg.(*ast.UnaryExpr); ok && u.Op == token.AND {
		if ident, ok := unwrapParen(u.X).(*ast.Ident); ok {
			if sh, ok := s.lookupSliceHeader(ident.Name); ok {
				sh.convertedToUnsafe = true
				if sh.alreadyReported {
					return
				}
				kind := "SliceHeader"
				if sh.isString {
					kind = "StringHeader"
				}
				fc.emit(
					call.Pos(),
					RuleUnsafeSliceConversion,
					s.funcName,
					fmt.Sprintf("converting address of standalone reflect.%s variable %q to unsafe.Pointer violates unsafe.Pointer Rule 6", kind, ident.Name),
				)
				return
			}
		}
	}

	// Check forged integer literal converted to unsafe.Pointer (CLINO-007):
	// e.g. unsafe.Pointer(uintptr(0x1000)), unsafe.Pointer(0xdeadbeef), unsafe.Pointer(uintptr(0)).
	if _, ok := evalConstInt(arg); ok {
		fc.emit(
			call.Pos(),
			RulePointerArithmeticBounds,
			s.funcName,
			"converting a constant integer directly to unsafe.Pointer synthesizes an unrooted address and violates Go unsafe.Pointer rules",
		)
		return
	}
	if fc.isUintptrCall(arg) {
		ucall := arg.(*ast.CallExpr)
		if len(ucall.Args) == 1 {
			if _, ok := evalConstInt(ucall.Args[0]); ok {
				fc.emit(
					call.Pos(),
					RulePointerArithmeticBounds,
					s.funcName,
					"forging unsafe.Pointer from constant uintptr literal violates Go unsafe.Pointer rules",
				)
				return
			}
		}
	}

	// Check CLINO-001: tainted intermediate uintptr variable used anywhere inside unsafe.Pointer(...).
	if badVar, reason := fc.findTaintedUintptrInExpr(s, arg); badVar != "" {
		fc.emit(
			call.Pos(),
			RuleIllegalUintptrCast,
			s.funcName,
			fmt.Sprintf("illegal unsafe.Pointer conversion from intermediate uintptr variable %q (%s); uintptr arithmetic must be atomic within a single expression", badVar, reason),
		)
		return
	}

	// Check CLINO-001: non-atomic uintptr variable/parameter used without an inline uintptr(ptr) base.
	hasInlinePtrConversion := fc.hasInlineUintptrPtrConversion(s, arg)
	if !hasInlinePtrConversion {
		if badVar := fc.findAnyUintptrIdentInExpr(s, arg); badVar != "" {
			fc.emit(
				call.Pos(),
				RuleIllegalUintptrCast,
				s.funcName,
				fmt.Sprintf("illegal unsafe.Pointer conversion from uintptr variable %q; pointer-to-uintptr conversions cannot span statements or function boundaries", badVar),
			)
			return
		}
	}

	// Check CLINO-007: pointer subtraction or combining two pointer addresses inside unsafe.Pointer(...).
	if bin, ok := arg.(*ast.BinaryExpr); ok {
		if fc.countPointerUintptrCalls(s, arg) >= 2 {
			fc.emit(
				call.Pos(),
				RulePointerArithmeticBounds,
				s.funcName,
				"combining two pointer addresses (uintptr(p1) +/- uintptr(p2)) and converting back to unsafe.Pointer violates unsafe.Pointer Rule 3",
			)
			return
		}
		if bin.Op == token.SUB && fc.containsUintptrCall(bin.X) {
			fc.emit(
				call.Pos(),
				RulePointerArithmeticBounds,
				s.funcName,
				"backward pointer subtraction inside unsafe.Pointer(uintptr(p) - offset) may point before the start of the allocation",
			)
			return
		}
		if bin.Op == token.ADD && fc.containsUintptrCall(bin.X) && isNegativeExpr(bin.Y) {
			fc.emit(
				call.Pos(),
				RulePointerArithmeticBounds,
				s.funcName,
				"adding a negative offset inside unsafe.Pointer(uintptr(p) + (-offset)) may point before the start of the allocation",
			)
			return
		}
	}
}

func (fc *fileContext) checkUnsafeTypeConversions(s *funcScope, call *ast.CallExpr) {
	if len(call.Args) != 1 {
		return
	}
	star, ok := unwrapParen(call.Fun).(*ast.StarExpr)
	if !ok {
		return
	}

	arg := unwrapParen(call.Args[0])

	// A. Direct unsafe slice/string header type-punning: (*[]T)(unsafe.Pointer(&x)) or (*string)(unsafe.Pointer(&x))
	isSliceTarget := false
	isStringTarget := false
	switch target := unwrapParen(star.X).(type) {
	case *ast.ArrayType:
		if target.Len == nil {
			isSliceTarget = true
		} else if len(fc.unsafePkgs) > 0 || fc.hasCGo {
			// B. Oversized fake-array pointer cast: (*[1<<30]byte)(ptr)
			if arrLen, ok := evalConstInt(target.Len); ok && arrLen >= oversizedFakeArrayThreshold {
				if fc.isUnsafeOrForeignPtrArg(s, arg) {
					fc.emit(
						call.Pos(),
						RulePointerArithmeticBounds,
						s.funcName,
						fmt.Sprintf("oversized fake-array pointer cast (*[%d]T) disables bounds checks and fails under -d=checkptr; use unsafe.Slice(ptr, length) instead", arrLen),
					)
				}
			}
		}
	case *ast.Ident:
		if target.Name == "string" {
			isStringTarget = true
		}
	}

	if !isSliceTarget && !isStringTarget {
		return
	}

	// Check if arg is unsafe.Pointer(&x)
	upCall, ok := arg.(*ast.CallExpr)
	if !ok || !fc.isUnsafePointerCall(upCall) || len(upCall.Args) != 1 {
		return
	}
	u, ok := unwrapParen(upCall.Args[0]).(*ast.UnaryExpr)
	if !ok || u.Op != token.AND {
		return
	}
	targetExpr := unwrapParen(u.X)
	if ident, ok := targetExpr.(*ast.Ident); ok {
		// If ident is a sliceHeaderVar, checkUnsafePointerCall already handles it as CLINO-006.
		if _, isHdr := s.lookupSliceHeader(ident.Name); isHdr {
			return
		}
		targetKind := "slice"
		if isStringTarget {
			targetKind = "string"
		}
		fc.emit(
			call.Pos(),
			RuleUnsafeSliceConversion,
			s.funcName,
			fmt.Sprintf("direct unsafe %s header reinterpretation from &%s bypasses length/capacity invariants and immutability; use unsafe.Slice or unsafe.String", targetKind, ident.Name),
		)
		return
	}
	if sel, ok := targetExpr.(*ast.SelectorExpr); ok {
		targetKind := "slice"
		if isStringTarget {
			targetKind = "string"
		}
		fc.emit(
			call.Pos(),
			RuleUnsafeSliceConversion,
			s.funcName,
			fmt.Sprintf("direct unsafe %s header reinterpretation from &...%s bypasses length/capacity invariants and immutability; use unsafe.Slice or unsafe.String", targetKind, "."+sel.Sel.Name),
		)
	}
}

func (fc *fileContext) checkCGoCall(s *funcScope, call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok || pkgIdent.Name != "C" {
		return
	}
	fnName := sel.Sel.Name

	// 1. Check C.uintptr_t / C.intptr_t / C.size_t smuggling a Go pointer past cgocheck (CLINO-008).
	if fnName == "uintptr_t" || fnName == "intptr_t" || fnName == "size_t" {
		if len(call.Args) == 1 && fc.exprSmugglesGoPointerAsUintptr(s, call.Args[0]) {
			fc.emit(
				call.Pos(),
				RuleCGoPinningHazard,
				s.funcName,
				fmt.Sprintf("converting a Go pointer through C.%s(uintptr(...)) smuggles it past cgocheck; use runtime/cgo.NewHandle instead", fnName),
			)
		}
		return
	}

	// Ignore CGo built-in helpers and C scalar type conversions.
	if isCGoHelperOrScalarType(fnName) {
		return
	}

	hasCallbackArg := false
	for _, arg := range call.Args {
		if fc.isCCallbackArg(fnName, arg) {
			hasCallbackArg = true
			break
		}
	}
	isRetention := isCGoRetentionFunction(fnName)

	for _, arg := range call.Args {
		// A. Go closure / function value passed directly to C (CLINO-008).
		if fc.isGoFuncValueExpr(s, arg) {
			fc.emit(
				arg.Pos(),
				RuleCGoPinningHazard,
				s.funcName,
				fmt.Sprintf("passing a Go function or closure directly to C.%s is invalid across the C-ABI boundary; use a //export trampoline", fnName),
			)
			continue
		}

		// B. Direct uintptr(unsafe.Pointer(&x)) smuggling into C function (CLINO-008).
		if fc.exprSmugglesGoPointerAsUintptr(s, arg) {
			fc.emit(
				arg.Pos(),
				RuleCGoPinningHazard,
				s.funcName,
				fmt.Sprintf("passing a Go pointer cast to uintptr directly to C.%s bypasses cgocheck; use runtime/cgo.NewHandle", fnName),
			)
			continue
		}

		// C. Nested Go pointer violation (CLINO-002).
		if reason, risky := fc.cgoInternalPointerRisk(s, arg); risky {
			fc.emit(
				arg.Pos(),
				RuleCGoInternalPointer,
				s.funcName,
				fmt.Sprintf("CGo boundary violation in C.%s: %s violates Go runtime pointer rules", fnName, reason),
			)
			continue
		}

		// D. Retention / async C API receiving unpinned Go pointer (CLINO-004).
		if isRetention {
			if unpinned, desc := fc.isUnpinnedGoPointerExpr(s, arg); unpinned {
				fc.emit(
					arg.Pos(),
					RuleFFIStackEscape,
					s.funcName,
					fmt.Sprintf("passing unpinned Go pointer (%s) to retaining C function C.%s risks dangling pointer access after call returns", desc, fnName),
				)
				continue
			}
		}

		// E. Callback context pointer passed alongside a C callback symbol without pinning (CLINO-008).
		if hasCallbackArg && !fc.isCCallbackArg(fnName, arg) {
			if unpinned, desc := fc.isUnpinnedGoPointerExpr(s, arg); unpinned {
				fc.emit(
					arg.Pos(),
					RuleCGoPinningHazard,
					s.funcName,
					fmt.Sprintf("passing unpinned Go pointer (%s) as callback context to C.%s without runtime.Pinner or cgo.NewHandle", desc, fnName),
				)
			}
		}
	}
}

func (fc *fileContext) cgoInternalPointerRisk(s *funcScope, arg ast.Expr) (string, bool) {
	inner := fc.unwrapPointerCasts(arg)

	// Case 1: &expr
	if u, ok := inner.(*ast.UnaryExpr); ok && u.Op == token.AND {
		target := unwrapParen(u.X)
		switch t := target.(type) {
		case *ast.CompositeLit:
			if fc.compositeLitHasGoPointers(s, t) || fc.typeContainsGoPointer(t.Type, nil) {
				return "passing pointer to composite literal containing nested Go pointers/slices", true
			}
		case *ast.Ident:
			if s.isCAlloc(t.Name) {
				return "", false
			}
			if _, isSlice := s.sliceElemType(t.Name); isSlice {
				return fmt.Sprintf("passing address of slice header &%s (contains Go backing-array pointer)", t.Name), true
			}
			if s.isStringVar(t.Name) {
				return fmt.Sprintf("passing address of string header &%s (contains Go backing pointer)", t.Name), true
			}
			if s.isGoPtr(t.Name) {
				return fmt.Sprintf("passing pointer-to-Go-pointer &%s", t.Name), true
			}
			if s.hasGoPtrs(t.Name) {
				return fmt.Sprintf("passing pointer &%s whose struct/type contains nested Go pointers", t.Name), true
			}
		case *ast.IndexExpr:
			// &slice[0] is safe ONLY if element type does not contain Go pointers!
			if baseIdent, ok := unwrapParen(t.X).(*ast.Ident); ok {
				if eltType, isSlice := s.sliceElemType(baseIdent.Name); isSlice {
					if fc.typeContainsGoPointer(eltType, nil) {
						return fmt.Sprintf("passing address of element &%s[...] whose element type contains Go pointers", baseIdent.Name), true
					}
				}
			}
		}
	}

	// Case 2: Passing a Go pointer variable that points to a Go pointer / nested struct.
	if ident, ok := inner.(*ast.Ident); ok {
		if s.pointsToGoPtrs(ident.Name) && !s.isCAlloc(ident.Name) {
			return fmt.Sprintf("passing Go pointer %q referencing memory containing nested Go pointers", ident.Name), true
		}
	}

	return "", false
}

func (fc *fileContext) compositeLitHasGoPointers(s *funcScope, comp *ast.CompositeLit) bool {
	for _, elt := range comp.Elts {
		val := elt
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			val = kv.Value
		}
		val = unwrapParen(val)
		switch v := val.(type) {
		case *ast.CompositeLit:
			return true
		case *ast.UnaryExpr:
			if v.Op == token.AND {
				return true
			}
		case *ast.BasicLit:
			if v.Kind == token.STRING {
				return true
			}
		case *ast.FuncLit:
			return true
		case *ast.CallExpr:
			if id, ok := v.Fun.(*ast.Ident); ok && (id.Name == "make" || id.Name == "new") {
				return true
			}
			if fc.isUnsafePointerCall(v) {
				if len(v.Args) == 1 {
					if unpinned, _ := fc.isUnpinnedGoPointerExpr(s, v.Args[0]); unpinned {
						return true
					}
				}
			}
		case *ast.Ident:
			if s.isGoPtr(v.Name) || s.hasGoPtrs(v.Name) || s.isStringVar(v.Name) {
				return true
			}
		}
	}
	return false
}

func (fc *fileContext) typeContainsGoPointer(expr ast.Expr, visiting map[string]bool) bool {
	if expr == nil {
		return false
	}
	expr = unwrapParen(expr)
	switch t := expr.(type) {
	case *ast.StarExpr:
		// A *C.T field typically holds a C pointer; non-C pointers hold Go pointers.
		return !fc.isCTypeExpr(t.X)
	case *ast.ArrayType:
		if t.Len == nil {
			return true // slice
		}
		return fc.typeContainsGoPointer(t.Elt, visiting)
	case *ast.MapType, *ast.ChanType, *ast.FuncType, *ast.InterfaceType:
		return true
	case *ast.StructType:
		return fc.structContainsGoPointer(t, visiting)
	case *ast.SelectorExpr:
		return fc.isUnsafePointerType(t)
	case *ast.Ident:
		if t.Name == "string" || t.Name == "any" || t.Name == "error" {
			return true
		}
		if visiting == nil {
			visiting = make(map[string]bool)
		}
		if visiting[t.Name] {
			return false
		}
		visiting[t.Name] = true
		if st, ok := fc.structTypes[t.Name]; ok {
			return fc.structContainsGoPointer(st, visiting)
		}
		if alias, ok := fc.typeAliases[t.Name]; ok {
			return fc.typeContainsGoPointer(alias, visiting)
		}
	}
	return false
}

func (fc *fileContext) structContainsGoPointer(st *ast.StructType, visiting map[string]bool) bool {
	if st == nil || st.Fields == nil {
		return false
	}
	for _, field := range st.Fields.List {
		if fc.typeContainsGoPointer(field.Type, visiting) {
			return true
		}
	}
	return false
}

func (fc *fileContext) isCMemoryTarget(s *funcScope, lhs ast.Expr) bool {
	lhs = unwrapParen(lhs)
	switch t := lhs.(type) {
	case *ast.SelectorExpr:
		if base, ok := unwrapParen(t.X).(*ast.Ident); ok {
			if base.Name == "C" || s.isCAlloc(base.Name) {
				return true
			}
		}
	case *ast.StarExpr:
		if base, ok := unwrapParen(t.X).(*ast.Ident); ok {
			if s.isCAlloc(base.Name) {
				return true
			}
		}
	case *ast.IndexExpr:
		if base, ok := unwrapParen(t.X).(*ast.Ident); ok {
			if s.isCAlloc(base.Name) {
				return true
			}
		}
	}
	return false
}

func (fc *fileContext) isUnpinnedGoPointerExpr(s *funcScope, expr ast.Expr) (bool, string) {
	inner := fc.unwrapPointerCasts(expr)
	switch e := inner.(type) {
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			root := extractRootIdentName(e.X)
			if root != "" {
				if s.isCAlloc(root) || s.isPinnedTarget(root) {
					return false, ""
				}
				return true, "&" + root
			}
			if _, ok := unwrapParen(e.X).(*ast.CompositeLit); ok {
				return true, "&composite"
			}
		}
	case *ast.Ident:
		if s.isGoPtr(e.Name) && !s.isCAlloc(e.Name) && !s.isPinnedTarget(e.Name) {
			return true, e.Name
		}
	case *ast.CallExpr:
		if fc.isUnsafeSliceDataCall(e) || fc.isUnsafeStringDataCall(e) {
			if len(e.Args) == 1 {
				root := extractRootIdentName(e.Args[0])
				if root != "" && !s.isPinnedTarget(root) {
					return true, root
				}
			}
		}
	}
	return false, ""
}

func (fc *fileContext) unwrapPointerCasts(expr ast.Expr) ast.Expr {
	for {
		expr = unwrapParen(expr)
		call, ok := expr.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return expr
		}
		if fc.isUnsafePointerCall(call) {
			expr = call.Args[0]
			continue
		}
		if star, ok := unwrapParen(call.Fun).(*ast.StarExpr); ok {
			if fc.isCTypeExpr(star.X) {
				expr = call.Args[0]
				continue
			}
		}
		return expr
	}
}

func (fc *fileContext) exprSmugglesGoPointerAsUintptr(s *funcScope, expr ast.Expr) bool {
	expr = unwrapParen(expr)
	if call, ok := expr.(*ast.CallExpr); ok {
		if fc.isUintptrCall(call) && len(call.Args) == 1 {
			if unpinned, _ := fc.isUnpinnedGoPointerExpr(s, call.Args[0]); unpinned {
				return true
			}
			if innerCall, ok := unwrapParen(call.Args[0]).(*ast.CallExpr); ok && fc.isUnsafePointerCall(innerCall) {
				if len(innerCall.Args) == 1 {
					if unpinned, _ := fc.isUnpinnedGoPointerExpr(s, innerCall.Args[0]); unpinned {
						return true
					}
				}
			}
		}
	}
	if ident, ok := expr.(*ast.Ident); ok {
		if _, tainted := s.lookupTaintedUintptr(ident.Name); tainted {
			return true
		}
	}
	return false
}

func (fc *fileContext) isCCallbackArg(fnName string, arg ast.Expr) bool {
	arg = unwrapParen(arg)
	// Explicit CGo function pointer cast: (*[0]byte)(C.fn) or unsafe.Pointer(C.fn)
	if call, ok := arg.(*ast.CallExpr); ok && len(call.Args) == 1 {
		if fc.isUnsafePointerCall(call) {
			return fc.isCCallbackArg(fnName, call.Args[0])
		}
		if star, ok := unwrapParen(call.Fun).(*ast.StarExpr); ok {
			if arr, ok := star.X.(*ast.ArrayType); ok && arr.Len != nil {
				if v, ok := evalConstInt(arr.Len); ok && v == 0 {
					return isCSymbolExpr(call.Args[0])
				}
			}
		}
	}
	sel, ok := arg.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "C" {
		return false
	}
	name := sel.Sel.Name
	if isIgnoredCSymbol(name) {
		return false
	}
	return hasCallbackHint(name) || hasCallbackHint(fnName)
}

func isCSymbolExpr(expr ast.Expr) bool {
	sel, ok := unwrapParen(expr).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "C" {
		return false
	}
	return !isIgnoredCSymbol(sel.Sel.Name)
}

func isIgnoredCSymbol(name string) bool {
	if strings.HasPrefix(name, "sizeof_") || name == "NULL" || isCGoHelperOrScalarType(name) || isAllUpperIdent(name) {
		return true
	}
	switch name {
	case "stdin", "stdout", "stderr", "errno":
		return true
	}
	return false
}

var callbackHintTokens = []string{
	"cb",
	"callback",
	"handler",
	"hook",
	"trampoline",
	"notify",
	"on_",
	"dispatch",
	"visitor",
	"thread",
	"worker",
	"entry",
	"listener",
	"invoke",
}

func hasCallbackHint(name string) bool {
	lower := strings.ToLower(name)
	for _, tok := range callbackHintTokens {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

func (fc *fileContext) isGoFuncValueExpr(s *funcScope, arg ast.Expr) bool {
	arg = unwrapParen(arg)
	if _, ok := arg.(*ast.FuncLit); ok {
		return true
	}
	if ident, ok := arg.(*ast.Ident); ok && s.isFuncVar(ident.Name) {
		return true
	}
	return false
}

func (fc *fileContext) exprTaintedUintptrReason(s *funcScope, expr ast.Expr) (string, bool) {
	expr = unwrapParen(expr)
	switch e := expr.(type) {
	case *ast.CallExpr:
		if fc.isUintptrCall(e) && len(e.Args) == 1 {
			if _, isConst := evalConstInt(e.Args[0]); !isConst {
				return "uintptr conversion", true
			}
		}
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if sel.Sel.Name == "Pointer" || sel.Sel.Name == "UnsafeAddr" {
				if len(fc.reflectPkgs) > 0 && fc.isReflectValueExpr(s, sel.X) {
					return "reflect.Value." + sel.Sel.Name + "()", true
				}
			}
		}
	case *ast.SelectorExpr:
		if e.Sel.Name == "Data" {
			if ident, ok := unwrapParen(e.X).(*ast.Ident); ok {
				if s.isSliceHeaderPtr(ident.Name) {
					return "SliceHeader/StringHeader.Data", true
				}
				if _, isHdr := s.lookupSliceHeader(ident.Name); isHdr {
					return "SliceHeader/StringHeader.Data", true
				}
			}
		}
	case *ast.Ident:
		if reason, ok := s.lookupTaintedUintptr(e.Name); ok {
			return reason, true
		}
	case *ast.BinaryExpr:
		if _, ok := fc.exprTaintedUintptrReason(s, e.X); ok {
			return "derived uintptr arithmetic", true
		}
		if _, ok := fc.exprTaintedUintptrReason(s, e.Y); ok {
			return "derived uintptr arithmetic", true
		}
	case *ast.UnaryExpr:
		if reason, ok := fc.exprTaintedUintptrReason(s, e.X); ok {
			return reason, true
		}
	}
	return "", false
}

func (fc *fileContext) findTaintedUintptrInExpr(s *funcScope, expr ast.Expr) (string, string) {
	var foundName, foundReason string
	ast.Inspect(expr, func(n ast.Node) bool {
		if foundName != "" {
			return false
		}
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if reason, tainted := s.lookupTaintedUintptr(ident.Name); tainted {
			foundName = ident.Name
			foundReason = reason
			return false
		}
		return true
	})
	return foundName, foundReason
}

func (fc *fileContext) findAnyUintptrIdentInExpr(s *funcScope, expr ast.Expr) string {
	var found string
	ast.Inspect(expr, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if s.isAnyUintptr(ident.Name) {
			found = ident.Name
			return false
		}
		return true
	})
	return found
}

func (fc *fileContext) hasInlineUintptrPtrConversion(s *funcScope, expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if fc.isUintptrCall(call) && len(call.Args) == 1 {
			if _, isConst := evalConstInt(call.Args[0]); !isConst {
				found = true
				return false
			}
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if sel.Sel.Name == "Pointer" || sel.Sel.Name == "UnsafeAddr" {
				if len(fc.reflectPkgs) > 0 && fc.isReflectValueExpr(s, sel.X) {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

func (fc *fileContext) containsUintptrCall(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok && fc.isUintptrCall(call) {
			found = true
			return false
		}
		return true
	})
	return found
}

func (fc *fileContext) countPointerUintptrCalls(s *funcScope, expr ast.Expr) int {
	count := 0
	ast.Inspect(expr, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !fc.isUintptrCall(call) || len(call.Args) != 1 {
			return true
		}
		if fc.isPointerExpr(s, call.Args[0]) {
			count++
		}
		return true
	})
	return count
}

func (fc *fileContext) isPointerExpr(s *funcScope, expr ast.Expr) bool {
	expr = unwrapParen(expr)
	switch e := expr.(type) {
	case *ast.CallExpr:
		return fc.isUnsafePointerCall(e) || fc.isUnsafeAddCall(e)
	case *ast.UnaryExpr:
		return e.Op == token.AND
	case *ast.Ident:
		return s.isUnsafePtr(e.Name) || s.isGoPtr(e.Name) || s.isCAlloc(e.Name)
	}
	return false
}

func (fc *fileContext) isUnsafeOrForeignPtrArg(s *funcScope, expr ast.Expr) bool {
	expr = unwrapParen(expr)
	switch e := expr.(type) {
	case *ast.CallExpr:
		return fc.isUnsafePointerCall(e) || fc.isUnsafeAddCall(e) || fc.isCAllocExpr(s, e)
	case *ast.Ident:
		return s.isUnsafePtr(e.Name) || s.isCAlloc(e.Name) || s.isGoPtr(e.Name)
	}
	return false
}

func (fc *fileContext) isUintptrCall(expr ast.Expr) bool {
	call, ok := unwrapParen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == "uintptr"
}

func (fc *fileContext) isUnsafeFunc(call *ast.CallExpr, name string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && fc.unsafePkgs[pkg.Name]
}

func (fc *fileContext) isUnsafePointerCall(call *ast.CallExpr) bool {
	return fc.isUnsafeFunc(call, "Pointer")
}

func (fc *fileContext) isUnsafeAddCall(call *ast.CallExpr) bool {
	return fc.isUnsafeFunc(call, "Add")
}

func (fc *fileContext) isUnsafeSliceCall(call *ast.CallExpr) bool {
	return fc.isUnsafeFunc(call, "Slice")
}

func (fc *fileContext) isUnsafeStringCall(call *ast.CallExpr) bool {
	return fc.isUnsafeFunc(call, "String")
}

func (fc *fileContext) isUnsafeSliceDataCall(call *ast.CallExpr) bool {
	return fc.isUnsafeFunc(call, "SliceData")
}

func (fc *fileContext) isUnsafeStringDataCall(call *ast.CallExpr) bool {
	return fc.isUnsafeFunc(call, "StringData")
}

func (fc *fileContext) isUnsafePointerType(expr ast.Expr) bool {
	sel, ok := unwrapParen(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Pointer" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && fc.unsafePkgs[pkg.Name]
}

func (fc *fileContext) reflectHeaderKind(expr ast.Expr) (string, bool) {
	sel, ok := unwrapParen(expr).(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || !fc.reflectPkgs[pkg.Name] {
		return "", false
	}
	if sel.Sel.Name == "SliceHeader" || sel.Sel.Name == "StringHeader" {
		return sel.Sel.Name, true
	}
	return "", false
}

func (fc *fileContext) isReflectValueType(expr ast.Expr) bool {
	sel, ok := unwrapParen(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Value" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && fc.reflectPkgs[pkg.Name]
}

func (fc *fileContext) isReflectValueOfCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || !fc.reflectPkgs[pkg.Name] {
		return false
	}
	return sel.Sel.Name == "ValueOf" || sel.Sel.Name == "New" || sel.Sel.Name == "Zero"
}

func (fc *fileContext) isReflectValueExpr(s *funcScope, expr ast.Expr) bool {
	expr = unwrapParen(expr)
	switch e := expr.(type) {
	case *ast.Ident:
		return s.isReflectVal(e.Name)
	case *ast.CallExpr:
		if fc.isReflectValueOfCall(e) {
			return true
		}
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			return fc.isReflectValueExpr(s, sel.X)
		}
	}
	return false
}

func (fc *fileContext) isRuntimePinnerType(expr ast.Expr) bool {
	sel, ok := unwrapParen(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Pinner" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && fc.runtimePkgs[pkg.Name]
}

func (fc *fileContext) isPinnerInitExpr(expr ast.Expr) bool {
	expr = unwrapParen(expr)
	switch e := expr.(type) {
	case *ast.CompositeLit:
		return fc.isRuntimePinnerType(e.Type)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			if comp, ok := unwrapParen(e.X).(*ast.CompositeLit); ok {
				return fc.isRuntimePinnerType(comp.Type)
			}
		}
	}
	return false
}

func (fc *fileContext) isCGoHandleType(expr ast.Expr) bool {
	sel, ok := unwrapParen(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Handle" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && fc.cgoPkgs[pkg.Name]
}

func (fc *fileContext) isCGoNewHandleCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "NewHandle" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && fc.cgoPkgs[pkg.Name]
}

func (fc *fileContext) isCTypeExpr(expr ast.Expr) bool {
	if !fc.hasCGo {
		return false
	}
	sel, ok := unwrapParen(expr).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "C"
}

func (fc *fileContext) isAnyCCall(call *ast.CallExpr) bool {
	if !fc.hasCGo {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "C"
}

func (fc *fileContext) isCAllocExpr(s *funcScope, expr ast.Expr) bool {
	if !fc.hasCGo {
		return false
	}
	expr = unwrapParen(expr)
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	// Direct C.malloc / C.calloc / C.realloc / C.CString / C.CBytes
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "C" {
			switch sel.Sel.Name {
			case "malloc", "calloc", "realloc", "aligned_alloc", "strdup", "strndup", "CString", "CBytes":
				return true
			}
		}
	}
	// Type cast (*C.struct_foo)(C.malloc(...))
	if star, ok := unwrapParen(call.Fun).(*ast.StarExpr); ok && fc.isCTypeExpr(star.X) {
		if len(call.Args) == 1 {
			if fc.isCAllocExpr(s, call.Args[0]) {
				return true
			}
			if id, ok := unwrapParen(call.Args[0]).(*ast.Ident); ok && s.isCAlloc(id.Name) {
				return true
			}
		}
	}
	return false
}

func unwrapParen(expr ast.Expr) ast.Expr {
	for {
		p, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = p.X
	}
}

func extractRootIdentName(expr ast.Expr) string {
	expr = unwrapParen(expr)
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return extractRootIdentName(e.X)
		}
	case *ast.IndexExpr:
		return extractRootIdentName(e.X)
	case *ast.SelectorExpr:
		return extractRootIdentName(e.X)
	case *ast.CallExpr:
		if len(e.Args) == 1 {
			return extractRootIdentName(e.Args[0])
		}
	}
	return ""
}

func isNegativeExpr(expr ast.Expr) bool {
	expr = unwrapParen(expr)
	if v, ok := evalConstInt(expr); ok && v < 0 {
		return true
	}
	if u, ok := expr.(*ast.UnaryExpr); ok && u.Op == token.SUB {
		return true
	}
	return false
}

func evalConstInt(expr ast.Expr) (int64, bool) {
	if expr == nil {
		return 0, false
	}
	expr = unwrapParen(expr)
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.INT {
			return 0, false
		}
		v, err := strconv.ParseInt(e.Value, 0, 64)
		if err != nil {
			// Handle large unsigned literals like 0x7fffffff
			uv, uerr := strconv.ParseUint(e.Value, 0, 64)
			if uerr != nil || uv > (1<<63-1) {
				return 0, false
			}
			return int64(uv), true
		}
		return v, true
	case *ast.UnaryExpr:
		v, ok := evalConstInt(e.X)
		if !ok {
			return 0, false
		}
		switch e.Op {
		case token.SUB:
			return -v, true
		case token.ADD:
			return v, true
		}
	case *ast.BinaryExpr:
		lx, lok := evalConstInt(e.X)
		ry, rok := evalConstInt(e.Y)
		if !lok || !rok {
			return 0, false
		}
		switch e.Op {
		case token.ADD:
			return lx + ry, true
		case token.SUB:
			return lx - ry, true
		case token.MUL:
			return lx * ry, true
		case token.QUO:
			if ry == 0 {
				return 0, false
			}
			return lx / ry, true
		case token.SHL:
			if ry < 0 || ry >= 63 {
				return 0, false
			}
			return lx << uint(ry), true
		case token.SHR:
			if ry < 0 || ry >= 63 {
				return 0, false
			}
			return lx >> uint(ry), true
		}
	case *ast.SelectorExpr:
		if pkg, ok := e.X.(*ast.Ident); ok && pkg.Name == "math" {
			switch e.Sel.Name {
			case "MaxInt32":
				return (1 << 31) - 1, true
			case "MaxUint32":
				return (1 << 32) - 1, true
			case "MaxInt16":
				return (1 << 15) - 1, true
			}
		}
	}
	return 0, false
}

var cgoHelpersAndScalars = map[string]bool{
	"CString":       true,
	"CBytes":        true,
	"GoString":      true,
	"GoStringN":     true,
	"GoBytes":       true,
	"char":          true,
	"schar":         true,
	"uchar":         true,
	"short":         true,
	"ushort":        true,
	"int":           true,
	"uint":          true,
	"long":          true,
	"ulong":         true,
	"longlong":      true,
	"ulonglong":     true,
	"float":         true,
	"double":        true,
	"complexfloat":  true,
	"complexdouble": true,
	"bool":          true,
	"_Bool":         true,
	"size_t":        true,
	"ssize_t":       true,
	"ptrdiff_t":     true,
	"intptr_t":      true,
	"uintptr_t":     true,
	"int8_t":        true,
	"uint8_t":       true,
	"int16_t":       true,
	"uint16_t":      true,
	"int32_t":       true,
	"uint32_t":      true,
	"int64_t":       true,
	"uint64_t":      true,
}

func isCGoHelperOrScalarType(name string) bool {
	return cgoHelpersAndScalars[name]
}

var cgoRetentionTokens = []string{
	"register",
	"set_callback",
	"setcallback",
	"set_handler",
	"sethandler",
	"set_context",
	"setcontext",
	"set_userdata",
	"setuserdata",
	"store_",
	"retain",
	"async_",
	"submit_",
	"enqueue",
	"schedule",
	"attach_",
	"spawn_",
	"add_callback",
	"add_listener",
	"subscribe",
	"watch_",
}

func isCGoRetentionFunction(name string) bool {
	lower := strings.ToLower(name)
	for _, tok := range cgoRetentionTokens {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

func isAllUpperIdent(name string) bool {
	hasLetter := false
	for _, r := range name {
		if r >= 'a' && r <= 'z' {
			return false
		}
		if r >= 'A' && r <= 'Z' {
			hasLetter = true
		}
	}
	return hasLetter
}

func getLineSnippet(lines []string, line int) string {
	if line > 0 && line <= len(lines) {
		return strings.TrimSpace(lines[line-1])
	}
	return ""
}
