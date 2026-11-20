package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Aetherx86/Clino/pkg/analyzer"
)

const mixedSource = `package p
import ("reflect"; "unsafe")
func f(b []byte, p unsafe.Pointer) unsafe.Pointer {
	h := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	h.Len = 0
	return unsafe.Add(p, -1)
}`

func mixedReport(t *testing.T) *analyzer.AuditReport {
	t.Helper()
	rep, err := analyzer.New(analyzer.ModeStrict).AuditSourceReport("pkg/mixed.go", []byte(mixedSource))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Errors == 0 || rep.Summary.Warnings == 0 {
		t.Fatalf("fixture must produce both errors and warnings, got %+v", rep.Summary)
	}
	return rep
}

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]Format{"": FormatText, "TEXT": FormatText, " json ": FormatJSON, "Sarif": FormatSARIF} {
		got, err := ParseFormat(in)
		if err != nil || got != want {
			t.Fatalf("ParseFormat(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestFailThresholds(t *testing.T) {
	rep := mixedReport(t)
	if f, _ := EffectiveFailOn(analyzer.ModeStrict, ""); f != "error" {
		t.Fatalf("strict default should be error, got %q", f)
	}
	if f, _ := EffectiveFailOn(analyzer.ModeFast, ""); f != "none" {
		t.Fatalf("fast default should be none, got %q", f)
	}
	if _, err := EffectiveFailOn(analyzer.ModeFast, "sometimes"); err == nil {
		t.Fatal("expected error for unknown threshold")
	}
	if ShouldFail(rep, "none") || !ShouldFail(rep, "error") || !ShouldFail(rep, "warning") {
		t.Fatal("threshold evaluation mismatch")
	}
	warnOnly := *rep
	warnOnly.Summary.Errors = 0
	if ShouldFail(&warnOnly, "error") || !ShouldFail(&warnOnly, "warning") {
		t.Fatal("warning-only report thresholds mismatch")
	}
	if StatusLabel(nil, "error") != "CLEAN" || StatusLabel(rep, "none") != "PASS" || StatusLabel(rep, "error") != "FAIL" {
		t.Fatal("status labels mismatch")
	}
}

func TestJSONReportRoundTrips(t *testing.T) {
	rep := mixedReport(t)
	var buf bytes.Buffer
	if err := Write(&buf, FormatJSON, rep, RenderOptions{Version: "test", FailOn: "error"}); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), string(analyzer.RulePointerArithmeticBounds)) {
		t.Fatal("JSON report missing CLINO-007 finding")
	}
}

func TestSARIFIsValid210(t *testing.T) {
	rep := mixedReport(t)
	var buf bytes.Buffer
	if err := Write(&buf, FormatSARIF, rep, RenderOptions{Version: "9.9.9"}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
		t.Fatalf("unexpected SARIF envelope: version=%q runs=%d", doc.Version, len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != ToolName || run.Tool.Driver.Version != "9.9.9" {
		t.Fatalf("unexpected driver: %+v", run.Tool.Driver)
	}
	if len(run.Tool.Driver.Rules) != len(analyzer.AllRules()) {
		t.Fatalf("driver should declare all %d rules, got %d", len(analyzer.AllRules()), len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != rep.Summary.TotalViolations {
		t.Fatalf("results %d != violations %d", len(run.Results), rep.Summary.TotalViolations)
	}
	levels := map[string]bool{}
	for _, r := range run.Results {
		levels[r.Level] = true
		if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation.Region.StartLine <= 0 {
			t.Fatalf("result %s missing location", r.RuleID)
		}
		if strings.Contains(r.Locations[0].PhysicalLocation.ArtifactLocation.URI, `\`) {
			t.Fatalf("SARIF URI must use forward slashes: %s", r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		}
	}
	if !levels["error"] || !levels["warning"] {
		t.Fatalf("expected both error and warning levels, got %v", levels)
	}
}

func TestTextReportMentionsEveryFinding(t *testing.T) {
	rep := mixedReport(t)
	var buf bytes.Buffer
	if err := Write(&buf, FormatText, rep, RenderOptions{FailOn: "error"}); err != nil {
		t.Fatal(err)
	}
	for _, v := range rep.Violations {
		if !strings.Contains(buf.String(), string(v.Rule)) {
			t.Fatalf("text report missing %s", v.Rule)
		}
	}
}
