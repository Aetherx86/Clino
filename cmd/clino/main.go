package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Aetherx86/Clino/pkg/analyzer"
	"github.com/Aetherx86/Clino/pkg/report"
)

const Version = "0.2.0"

const (
	ExitOK        = 0
	ExitViolation = 1
	ExitError     = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("clino", flag.ContinueOnError)
	fs.SetOutput(stderr)

	modeStr := fs.String("mode", "fast", "Audit procedure: 'fast' (non-blocking) or 'strict' (blocking CI gate)")
	targetDir := fs.String("dir", ".", "Directory to audit recursively")
	targetFile := fs.String("file", "", "Single Go source file to audit")
	formatStr := fs.String("format", "text", "Output format: 'text', 'json', or 'sarif'")
	outputPath := fs.String("output", "", "Write report to file path instead of stdout")
	includeRulesStr := fs.String("rules", "", "Comma-separated rule IDs or short IDs to enable (e.g. CLINO-001,CLINO-007)")
	excludeRulesStr := fs.String("exclude-rules", "", "Comma-separated rule IDs or short IDs to disable")
	minSevStr := fs.String("min-severity", "warning", "Minimum severity to report: 'warning' or 'error'")
	excludePathsStr := fs.String("exclude", "", "Comma-separated directory names or path globs to skip")
	failOnStr := fs.String("fail-on", "", "Exit code 1 threshold: 'none', 'error', or 'warning' (default: error in strict, none in fast)")
	workers := fs.Int("workers", 0, "Number of parallel worker goroutines (0 = auto CPU count)")
	listRules := fs.Bool("list-rules", false, "Print supported audit rules and exit")
	showVersion := fs.Bool("version", false, "Print Clino version and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}

	if *showVersion {
		fmt.Fprintf(stdout, "Clino AST-Level unsafe.Pointer & CGo Escape Auditor v%s\n", Version)
		return ExitOK
	}

	format, err := report.ParseFormat(*formatStr)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return ExitError
	}

	if *listRules {
		if err := printRules(stdout, format); err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return ExitError
		}
		return ExitOK
	}

	mode, err := parseMode(*modeStr)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return ExitError
	}

	failOn, err := report.EffectiveFailOn(mode, *failOnStr)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return ExitError
	}

	minSev, err := parseMinSeverity(*minSevStr)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return ExitError
	}

	includeRules, err := parseRuleList(*includeRulesStr)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return ExitError
	}

	excludeRules, err := parseRuleList(*excludeRulesStr)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return ExitError
	}

	excludePaths := parseCSV(*excludePathsStr)

	// Support optional single positional target path when --file is not set.
	posArgs := fs.Args()
	if len(posArgs) > 1 {
		fmt.Fprintf(stderr, "Error: expected at most 1 positional target path, got %d\n", len(posArgs))
		return ExitError
	}

	auditor := analyzer.NewWithOptions(analyzer.Options{
		Mode:         mode,
		IncludeRules: includeRules,
		ExcludeRules: excludeRules,
		MinSeverity:  minSev,
		ExcludePaths: excludePaths,
		Workers:      *workers,
	})

	var rep *analyzer.AuditReport
	if *targetFile != "" {
		rep, err = auditor.AuditFileReport(*targetFile)
	} else if len(posArgs) == 1 {
		info, statErr := os.Stat(posArgs[0])
		if statErr != nil {
			fmt.Fprintf(stderr, "Audit error: %v\n", statErr)
			return ExitError
		}
		if info.IsDir() {
			rep, err = auditor.AuditDirectoryReport(posArgs[0])
		} else {
			rep, err = auditor.AuditFileReport(posArgs[0])
		}
	} else {
		rep, err = auditor.AuditDirectoryReport(*targetDir)
	}

	if err != nil {
		fmt.Fprintf(stderr, "Audit error: %v\n", err)
		return ExitError
	}

	var buf bytes.Buffer
	renderOpts := report.RenderOptions{
		Version: Version,
		FailOn:  failOn,
	}
	if err := report.Write(&buf, format, rep, renderOpts); err != nil {
		fmt.Fprintf(stderr, "Report error: %v\n", err)
		return ExitError
	}

	if *outputPath != "" {
		if err := os.WriteFile(*outputPath, buf.Bytes(), 0o644); err != nil {
			fmt.Fprintf(stderr, "Write error (%s): %v\n", *outputPath, err)
			return ExitError
		}
	} else {
		if _, err := stdout.Write(buf.Bytes()); err != nil {
			fmt.Fprintf(stderr, "Output error: %v\n", err)
			return ExitError
		}
	}

	if report.ShouldFail(rep, failOn) {
		return ExitViolation
	}
	return ExitOK
}

func parseMode(s string) (analyzer.Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "fast":
		return analyzer.ModeFast, nil
	case "strict":
		return analyzer.ModeStrict, nil
	default:
		return "", fmt.Errorf("unsupported mode %q (expected fast or strict)", s)
	}
}

func parseMinSeverity(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "warning", "warn":
		return analyzer.SeverityWarning, nil
	case "error", "err":
		return analyzer.SeverityError, nil
	default:
		return "", fmt.Errorf("unsupported --min-severity %q (expected warning or error)", s)
	}
}

func parseCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func parseRuleList(s string) ([]analyzer.RuleID, error) {
	items := parseCSV(s)
	if len(items) == 0 {
		return nil, nil
	}
	out := make([]analyzer.RuleID, 0, len(items))
	for _, item := range items {
		id, ok := analyzer.ResolveRuleID(item)
		if !ok {
			return nil, fmt.Errorf("unknown rule %q (run --list-rules to view valid rule IDs)", item)
		}
		out = append(out, id)
	}
	return out, nil
}

func printRules(w io.Writer, format report.Format) error {
	rules := analyzer.AllRules()
	if format == report.FormatJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(rules)
	}
	if _, err := fmt.Fprintf(w, "Clino Supported Rules (%d):\n\n", len(rules)); err != nil {
		return err
	}
	for _, r := range rules {
		if _, err := fmt.Fprintf(w, "%-36s [%s] (%s | %s)\n  %s\n  Fix: %s\n\n",
			r.ID, r.Severity, r.Category, r.CWE, r.Summary, r.Remediation); err != nil {
			return err
		}
	}
	return nil
}
