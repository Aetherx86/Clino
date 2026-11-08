package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Aetherx86/Clino/pkg/analyzer"
)

const Version = "1.0.0"

func main() {
	modeStr := flag.String("mode", "fast", "Audit procedure: 'fast' (syntactic AST checks) or 'strict' (deep verification with non-zero exit)")
	targetDir := flag.String("dir", ".", "Directory to audit recursively")
	showVersion := flag.Bool("version", false, "Print Clino version and exit")

	flag.Parse()

	if *showVersion {
		fmt.Printf("Clino AST-Level unsafe.Pointer & CGo Escape Auditor v%s\n", Version)
		os.Exit(0)
	}

	mode := analyzer.ModeFast
	if strings.ToLower(*modeStr) == "strict" {
		mode = analyzer.ModeStrict
	}

	fmt.Printf("Clino Memory & FFI Auditor v%s [Mode: %s | Target: %s]\n", Version, mode, *targetDir)
	fmt.Println("Auditing Go source files for unsafe.Pointer violations and CGo memory escapes...")

	start := time.Now()
	auditor := analyzer.New(mode)
	violations, err := auditor.AuditDirectory(*targetDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Audit error: %v\n", err)
		os.Exit(1)
	}
	elapsed := time.Since(start)

	errorsCount := 0
	warningsCount := 0
	for _, v := range violations {
		if v.Severity == "ERROR" {
			errorsCount++
		} else {
			warningsCount++
		}
		fmt.Println(v.String())
	}

	fmt.Println("\n=== Clino Audit Summary ===")
	fmt.Printf("Duration:        %v\n", elapsed)
	fmt.Printf("Violations:      %d total (%d errors, %d warnings)\n", len(violations), errorsCount, warningsCount)

	if len(violations) == 0 {
		fmt.Println("Result:          CLEAN (Zero memory safety or CGo escape violations)")
		os.Exit(0)
	}

	if mode == analyzer.ModeStrict && errorsCount > 0 {
		fmt.Println("Result:          FAIL (Strict mode active with memory safety errors)")
		os.Exit(1)
	}

	fmt.Println("Result:          PASS (Warnings observed, no strict blocking)")
	os.Exit(0)
}
