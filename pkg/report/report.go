package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Aetherx86/Clino/pkg/analyzer"
)

// Format identifies a supported report output format.
type Format string

const (
	FormatText  Format = "text"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

const (
	ToolName = "Clino"
	ToolURL  = "https://github.com/Aetherx86/Clino"
)

// ParseFormat validates and normalizes a report format string.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "text":
		return FormatText, nil
	case "json":
		return FormatJSON, nil
	case "sarif":
		return FormatSARIF, nil
	default:
		return "", fmt.Errorf("unsupported format %q (expected text, json, or sarif)", s)
	}
}

// RenderOptions configures report rendering.
type RenderOptions struct {
	Version string
	FailOn  string // "none", "error", "warning", or "" (auto from mode)
}

// EffectiveFailOn resolves the active failure threshold from mode and explicit override.
func EffectiveFailOn(mode analyzer.Mode, failOn string) (string, error) {
	norm := strings.ToLower(strings.TrimSpace(failOn))
	if norm == "" {
		if mode == analyzer.ModeStrict {
			return "error", nil
		}
		return "none", nil
	}
	switch norm {
	case "none", "error", "warning":
		return norm, nil
	default:
		return "", fmt.Errorf("unsupported --fail-on threshold %q (expected none, error, or warning)", failOn)
	}
}

// ShouldFail determines whether the audit result violates the failure threshold.
func ShouldFail(rep *analyzer.AuditReport, failOn string) bool {
	if rep == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(failOn)) {
	case "error":
		return rep.Summary.Errors > 0
	case "warning":
		return rep.Summary.TotalViolations > 0
	default:
		return false
	}
}

// StatusLabel returns CLEAN, FAIL, or PASS for an audit report and failure policy.
func StatusLabel(rep *analyzer.AuditReport, failOn string) string {
	if rep == nil || rep.Summary.TotalViolations == 0 {
		return "CLEAN"
	}
	if ShouldFail(rep, failOn) {
		return "FAIL"
	}
	return "PASS"
}

// Write renders an AuditReport in the requested format.
func Write(w io.Writer, format Format, rep *analyzer.AuditReport, opts RenderOptions) error {
	switch format {
	case FormatText:
		return WriteText(w, rep, opts)
	case FormatJSON:
		return WriteJSON(w, rep, opts)
	case FormatSARIF:
		return WriteSARIF(w, rep, opts)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

// WriteText renders a concise, deterministic human-readable report.
func WriteText(w io.Writer, rep *analyzer.AuditReport, opts RenderOptions) error {
	failOn, err := EffectiveFailOn(rep.Mode, opts.FailOn)
	if err != nil {
		return err
	}
	version := opts.Version
	if version == "" {
		version = "dev"
	}

	if _, err := fmt.Fprintf(w, "Clino Memory & FFI Auditor v%s [Mode: %s | Target: %s]\n", version, rep.Mode, rep.Target); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "Auditing Go source files for unsafe.Pointer violations and CGo memory escapes..."); err != nil {
		return err
	}

	for _, v := range rep.Violations {
		if _, err := fmt.Fprintln(w, v.String()); err != nil {
			return err
		}
		if v.Remediation != "" {
			if _, err := fmt.Fprintf(w, "    Fix:  %s\n", v.Remediation); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(w, "\n=== Clino Audit Summary ==="); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Files Scanned:   %d (%d lines)\n", rep.Summary.FilesScanned, rep.Summary.LinesScanned); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Duration:        %.3fms\n", rep.Summary.DurationMS); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Violations:      %d total (%d errors, %d warnings)\n",
		rep.Summary.TotalViolations, rep.Summary.Errors, rep.Summary.Warnings); err != nil {
		return err
	}
	if rep.Summary.Suppressed > 0 {
		if _, err := fmt.Fprintf(w, "Suppressed:      %d (via clino:ignore)\n", rep.Summary.Suppressed); err != nil {
			return err
		}
	}

	if len(rep.Summary.ByRule) > 0 {
		rules := make([]string, 0, len(rep.Summary.ByRule))
		for id := range rep.Summary.ByRule {
			rules = append(rules, string(id))
		}
		sort.Strings(rules)
		if _, err := fmt.Fprintln(w, "Rule Breakdown:"); err != nil {
			return err
		}
		for _, id := range rules {
			if _, err := fmt.Fprintf(w, "  - %-38s %d\n", id, rep.Summary.ByRule[analyzer.RuleID(id)]); err != nil {
				return err
			}
		}
	}

	status := StatusLabel(rep, failOn)
	switch status {
	case "CLEAN":
		_, err = fmt.Fprintln(w, "Result:          CLEAN (Zero memory safety or CGo escape violations)")
	case "FAIL":
		_, err = fmt.Fprintf(w, "Result:          FAIL (Policy fail-on=%s triggered)\n", failOn)
	default:
		_, err = fmt.Fprintf(w, "Result:          PASS (Findings observed, below fail-on=%s threshold)\n", failOn)
	}
	return err
}

type jsonTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"url"`
}

type jsonDocument struct {
	SchemaVersion string                `json:"schema_version"`
	Tool          jsonTool              `json:"tool"`
	Target        string                `json:"target"`
	Mode          analyzer.Mode         `json:"mode"`
	FailOn        string                `json:"fail_on"`
	Status        string                `json:"status"`
	Summary       analyzer.AuditSummary `json:"summary"`
	Violations    []analyzer.Violation  `json:"violations"`
}

// WriteJSON renders a machine-readable JSON audit report.
func WriteJSON(w io.Writer, rep *analyzer.AuditReport, opts RenderOptions) error {
	failOn, err := EffectiveFailOn(rep.Mode, opts.FailOn)
	if err != nil {
		return err
	}
	version := opts.Version
	if version == "" {
		version = "dev"
	}

	violations := rep.Violations
	if violations == nil {
		violations = []analyzer.Violation{}
	}
	summary := rep.Summary
	if summary.ByRule == nil {
		summary.ByRule = map[analyzer.RuleID]int{}
	}

	doc := jsonDocument{
		SchemaVersion: "1.0",
		Tool: jsonTool{
			Name:    ToolName,
			Version: version,
			URL:     ToolURL,
		},
		Target:     rep.Target,
		Mode:       rep.Mode,
		FailOn:     failOn,
		Status:     StatusLabel(rep, failOn),
		Summary:    summary,
		Violations: violations,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

// SARIF v2.1.0 structures (OASIS standard, GitHub Code Scanning compatible).
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags     []string `json:"tags,omitempty"`
	Category string   `json:"category,omitempty"`
	CWE      string   `json:"cwe,omitempty"`
	ShortID  string   `json:"shortId,omitempty"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	ShortDescription     sarifMessage    `json:"shortDescription"`
	FullDescription      sarifMessage    `json:"fullDescription"`
	Help                 sarifMessage    `json:"help"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
	Properties           sarifRuleProps  `json:"properties,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

type sarifResultProps struct {
	Function    string `json:"function,omitempty"`
	CWE         string `json:"cwe,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type sarifResult struct {
	RuleID     string            `json:"ruleId"`
	RuleIndex  int               `json:"ruleIndex"`
	Level      string            `json:"level"`
	Message    sarifMessage      `json:"message"`
	Locations  []sarifLocation   `json:"locations"`
	Properties *sarifResultProps `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int           `json:"startLine"`
	StartColumn int           `json:"startColumn"`
	Snippet     *sarifMessage `json:"snippet,omitempty"`
}

// WriteSARIF renders an OASIS SARIF v2.1.0 report compatible with GitHub Code Scanning.
func WriteSARIF(w io.Writer, rep *analyzer.AuditReport, opts RenderOptions) error {
	version := opts.Version
	if version == "" {
		version = "dev"
	}

	allRules := analyzer.AllRules()
	sarifRules := make([]sarifRule, 0, len(allRules))
	ruleIndex := make(map[analyzer.RuleID]int, len(allRules))
	for i, r := range allRules {
		ruleIndex[r.ID] = i
		tags := []string{"security", "memory-safety", r.Category}
		if r.CWE != "" {
			tags = append(tags, r.CWE)
		}
		sarifRules = append(sarifRules, sarifRule{
			ID:               string(r.ID),
			Name:             r.Name,
			ShortDescription: sarifMessage{Text: r.Summary},
			FullDescription:  sarifMessage{Text: r.Description},
			Help:             sarifMessage{Text: r.Remediation},
			DefaultConfiguration: sarifRuleConfig{
				Level: sarifLevel(r.Severity),
			},
			Properties: sarifRuleProps{
				Tags:     tags,
				Category: r.Category,
				CWE:      r.CWE,
				ShortID:  r.ShortID,
			},
		})
	}

	results := make([]sarifResult, 0, len(rep.Violations))
	for _, v := range rep.Violations {
		line := v.Line
		if line < 1 {
			line = 1
		}
		col := v.Column
		if col < 1 {
			col = 1
		}
		var snippet *sarifMessage
		if v.Snippet != "" {
			snippet = &sarifMessage{Text: v.Snippet}
		}
		var props *sarifResultProps
		if v.Function != "" || v.CWE != "" || v.Remediation != "" {
			props = &sarifResultProps{
				Function:    v.Function,
				CWE:         v.CWE,
				Remediation: v.Remediation,
			}
		}
		results = append(results, sarifResult{
			RuleID:    string(v.Rule),
			RuleIndex: ruleIndex[v.Rule],
			Level:     sarifLevel(v.Severity),
			Message:   sarifMessage{Text: v.Message},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: normalizeSARIFURI(v.File, rep.Target),
						},
						Region: sarifRegion{
							StartLine:   line,
							StartColumn: col,
							Snippet:     snippet,
						},
					},
				},
			},
			Properties: props,
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           ToolName,
						InformationURI: ToolURL,
						Version:        version,
						Rules:          sarifRules,
					},
				},
				Invocations: []sarifInvocation{
					{ExecutionSuccessful: true},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

func sarifLevel(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case analyzer.SeverityError:
		return "error"
	case analyzer.SeverityWarning:
		return "warning"
	default:
		return "note"
	}
}

func normalizeSARIFURI(file, target string) string {
	if target != "" && target != file {
		if rel, err := filepath.Rel(target, file); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	cleaned := filepath.ToSlash(filepath.Clean(file))
	return strings.TrimPrefix(cleaned, "./")
}
