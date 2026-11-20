package analyzer

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Violation represents a single static analysis finding.
type Violation struct {
	Rule        RuleID `json:"rule"`
	Severity    string `json:"severity"` // ERROR, WARNING
	File        string `json:"file"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Function    string `json:"function,omitempty"`
	Message     string `json:"message"`
	Snippet     string `json:"snippet"`
	Remediation string `json:"remediation,omitempty"`
	CWE         string `json:"cwe,omitempty"`
}

func (v Violation) String() string {
	loc := fmt.Sprintf("%s:%d:%d", v.File, v.Line, v.Column)
	if v.Function != "" {
		return fmt.Sprintf("[%s] (%s) %s (%s): %s\n    Code: %s",
			v.Rule, v.Severity, loc, v.Function, v.Message, v.Snippet)
	}
	return fmt.Sprintf("[%s] (%s) %s: %s\n    Code: %s",
		v.Rule, v.Severity, loc, v.Message, v.Snippet)
}

// Mode controls the default audit behavior.
type Mode string

const (
	ModeFast   Mode = "fast"   // Syntactic AST inspection (non-blocking by default)
	ModeStrict Mode = "strict" // Deep boundary checking with non-zero exit codes
)

// Options configures rule filtering, path exclusions, severity thresholds, and concurrency.
type Options struct {
	Mode         Mode
	IncludeRules []RuleID
	ExcludeRules []RuleID
	MinSeverity  string
	ExcludePaths []string
	Workers      int
}

// AuditSummary captures aggregate telemetry for an audit run.
type AuditSummary struct {
	FilesScanned    int            `json:"files_scanned"`
	LinesScanned    int            `json:"lines_scanned"`
	TotalViolations int            `json:"total_violations"`
	Errors          int            `json:"errors"`
	Warnings        int            `json:"warnings"`
	Suppressed      int            `json:"suppressed"`
	ByRule          map[RuleID]int `json:"by_rule"`
	DurationMS      float64        `json:"duration_ms"`
}

// AuditReport is the structured result of auditing a source buffer, file, or directory.
type AuditReport struct {
	Target     string       `json:"target"`
	Mode       Mode         `json:"mode"`
	Violations []Violation  `json:"violations"`
	Summary    AuditSummary `json:"summary"`
}

// Auditor performs concurrency-safe AST analysis for Go unsafe.Pointer and CGo hazards.
type Auditor struct {
	mode         Mode
	includeRules map[RuleID]bool
	excludeRules map[RuleID]bool
	minSevRank   int
	excludePaths []string
	workers      int
}

// New creates an Auditor with default options for the specified mode.
func New(mode Mode) *Auditor {
	return NewWithOptions(Options{Mode: mode})
}

// NewWithOptions creates a configured Auditor. The returned Auditor is safe for concurrent use.
func NewWithOptions(opts Options) *Auditor {
	mode := opts.Mode
	if mode == "" {
		mode = ModeFast
	}

	var inc map[RuleID]bool
	if len(opts.IncludeRules) > 0 {
		inc = make(map[RuleID]bool, len(opts.IncludeRules))
		for _, r := range opts.IncludeRules {
			inc[r] = true
		}
	}

	var exc map[RuleID]bool
	if len(opts.ExcludeRules) > 0 {
		exc = make(map[RuleID]bool, len(opts.ExcludeRules))
		for _, r := range opts.ExcludeRules {
			exc[r] = true
		}
	}

	minRank := SeverityRank(opts.MinSeverity)
	if minRank == 0 {
		minRank = SeverityRank(SeverityWarning)
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
		if workers < 1 {
			workers = 1
		}
	}

	excludePaths := make([]string, 0, len(opts.ExcludePaths))
	for _, p := range opts.ExcludePaths {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			excludePaths = append(excludePaths, trimmed)
		}
	}

	return &Auditor{
		mode:         mode,
		includeRules: inc,
		excludeRules: exc,
		minSevRank:   minRank,
		excludePaths: excludePaths,
		workers:      workers,
	}
}

// Mode returns the configured audit mode.
func (a *Auditor) Mode() Mode {
	return a.mode
}

func (a *Auditor) allowsViolation(v Violation) bool {
	if len(a.includeRules) > 0 && !a.includeRules[v.Rule] {
		return false
	}
	if len(a.excludeRules) > 0 && a.excludeRules[v.Rule] {
		return false
	}
	if SeverityRank(v.Severity) < a.minSevRank {
		return false
	}
	return true
}

// AuditSource parses and inspects Go source code in memory.
func (a *Auditor) AuditSource(filename string, src []byte) ([]Violation, error) {
	rep, err := a.AuditSourceReport(filename, src)
	if err != nil {
		return nil, err
	}
	return rep.Violations, nil
}

// AuditSourceReport parses and inspects Go source code in memory and returns a full report.
func (a *Auditor) AuditSourceReport(filename string, src []byte) (*AuditReport, error) {
	start := time.Now()
	violations, suppressed, lineCount, err := a.auditSourceInternal(filename, src)
	if err != nil {
		return nil, err
	}
	sortViolations(violations)
	return buildReport(filename, a.mode, violations, 1, lineCount, suppressed, time.Since(start)), nil
}

// AuditFile reads and inspects a single Go source file.
func (a *Auditor) AuditFile(path string) ([]Violation, error) {
	rep, err := a.AuditFileReport(path)
	if err != nil {
		return nil, err
	}
	return rep.Violations, nil
}

// AuditFileReport reads and inspects a single Go source file and returns a full report.
func (a *Auditor) AuditFileReport(path string) (*AuditReport, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return a.AuditSourceReport(path, src)
}

// AuditDirectory recursively walks a directory and audits all .go files.
func (a *Auditor) AuditDirectory(root string) ([]Violation, error) {
	rep, err := a.AuditDirectoryReport(root)
	if err != nil {
		return nil, err
	}
	return rep.Violations, nil
}

// AuditDirectoryReport recursively walks a directory, audits all .go files concurrently,
// and returns a deterministic AuditReport.
func (a *Auditor) AuditDirectoryReport(root string) (*AuditReport, error) {
	start := time.Now()

	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			if path != root {
				name := info.Name()
				if strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata" {
					return filepath.SkipDir
				}
				if a.isExcludedPath(root, path, name) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if a.isExcludedPath(root, path, info.Name()) {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(files)

	type fileResult struct {
		violations []Violation
		suppressed int
		lines      int
		err        error
	}

	results := make([]fileResult, len(files))
	workerCount := a.workers
	if workerCount > len(files) {
		workerCount = len(files)
	}

	if workerCount <= 1 {
		for i, path := range files {
			src, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil, fmt.Errorf("read %s: %w", path, readErr)
			}
			v, sup, lineCount, auditErr := a.auditSourceInternal(path, src)
			if auditErr != nil {
				return nil, auditErr
			}
			results[i] = fileResult{violations: v, suppressed: sup, lines: lineCount}
		}
	} else {
		jobs := make(chan int, len(files))
		for i := range files {
			jobs <- i
		}
		close(jobs)

		var wg sync.WaitGroup
		wg.Add(workerCount)
		for w := 0; w < workerCount; w++ {
			go func() {
				defer wg.Done()
				for idx := range jobs {
					path := files[idx]
					src, readErr := os.ReadFile(path)
					if readErr != nil {
						results[idx] = fileResult{err: fmt.Errorf("read %s: %w", path, readErr)}
						continue
					}
					v, sup, lineCount, auditErr := a.auditSourceInternal(path, src)
					results[idx] = fileResult{violations: v, suppressed: sup, lines: lineCount, err: auditErr}
				}
			}()
		}
		wg.Wait()
	}

	allViolations := make([]Violation, 0)
	totalSuppressed := 0
	totalLines := 0
	for _, res := range results {
		if res.err != nil {
			return nil, res.err
		}
		allViolations = append(allViolations, res.violations...)
		totalSuppressed += res.suppressed
		totalLines += res.lines
	}

	sortViolations(allViolations)
	return buildReport(root, a.mode, allViolations, len(files), totalLines, totalSuppressed, time.Since(start)), nil
}

func (a *Auditor) isExcludedPath(root, path, base string) bool {
	if len(a.excludePaths) == 0 {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	relSlash := filepath.ToSlash(rel)
	pathSlash := filepath.ToSlash(path)

	for _, pat := range a.excludePaths {
		patSlash := filepath.ToSlash(pat)
		if base == patSlash || relSlash == patSlash || strings.HasPrefix(relSlash, strings.TrimSuffix(patSlash, "/")+"/") {
			return true
		}
		if matched, _ := filepath.Match(patSlash, base); matched {
			return true
		}
		if matched, _ := filepath.Match(patSlash, relSlash); matched {
			return true
		}
		if matched, _ := filepath.Match(patSlash, pathSlash); matched {
			return true
		}
	}
	return false
}

func (a *Auditor) auditSourceInternal(filename string, src []byte) ([]Violation, int, int, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("parse error in %s: %w", filename, err)
	}

	lines := strings.Split(string(src), "\n")
	rawViolations, suppressed := inspectFile(fset, filename, node, lines)

	filtered := make([]Violation, 0, len(rawViolations))
	for _, v := range rawViolations {
		if a.allowsViolation(v) {
			filtered = append(filtered, v)
		}
	}
	return filtered, suppressed, len(lines), nil
}

func sortViolations(violations []Violation) {
	sort.Slice(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		if violations[i].Line != violations[j].Line {
			return violations[i].Line < violations[j].Line
		}
		if violations[i].Column != violations[j].Column {
			return violations[i].Column < violations[j].Column
		}
		return violations[i].Rule < violations[j].Rule
	})
}

func buildReport(target string, mode Mode, violations []Violation, filesScanned, linesScanned, suppressed int, elapsed time.Duration) *AuditReport {
	if violations == nil {
		violations = []Violation{}
	}
	byRule := make(map[RuleID]int)
	errorsCount := 0
	warningsCount := 0
	for _, v := range violations {
		if v.Severity == SeverityError {
			errorsCount++
		} else {
			warningsCount++
		}
		byRule[v.Rule]++
	}

	return &AuditReport{
		Target:     target,
		Mode:       mode,
		Violations: violations,
		Summary: AuditSummary{
			FilesScanned:    filesScanned,
			LinesScanned:    linesScanned,
			TotalViolations: len(violations),
			Errors:          errorsCount,
			Warnings:        warningsCount,
			Suppressed:      suppressed,
			ByRule:          byRule,
			DurationMS:      float64(elapsed.Microseconds()) / 1000.0,
		},
	}
}
