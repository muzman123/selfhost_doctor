// Package report renders audit results for humans (ANSI terminal) and
// machines (JSON), so the tool works interactively AND in cron/CI.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/muzman123/selfhost_doctor/internal/checks"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	yellow = "\033[33m"
	green  = "\033[32m"
	cyan   = "\033[36m"
	mag    = "\033[35m"
)

func sevColor(s checks.Severity) string {
	switch s {
	case checks.Critical:
		return bold + red
	case checks.High:
		return red
	case checks.Medium:
		return yellow
	case checks.Low:
		return cyan
	default:
		return dim
	}
}

// Result is the full machine-readable output.
type Result struct {
	Score      int              `json:"score"`
	Grade      string           `json:"grade"`
	Containers int              `json:"containers_scanned"`
	Findings   []checks.Finding `json:"findings"`
}

// JSON writes the result as JSON to w.
func JSON(w io.Writer, r Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Terminal writes a colored human-readable report to w.
func Terminal(w io.Writer, r Result) {
	color := isTTY()

	c := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + reset
	}

	fmt.Fprintf(w, "\n%s\n", c(bold, "selfhost-doctor report"))
	fmt.Fprintf(w, "%s\n\n", c(dim, fmt.Sprintf("scanned %d containers", r.Containers)))

	// Sort: worst first, then by subject for stable output.
	fs := make([]checks.Finding, len(r.Findings))
	copy(fs, r.Findings)
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		return fs[i].Subject < fs[j].Subject
	})

	if len(fs) == 0 {
		fmt.Fprintf(w, "  %s no findings — clean bill of health\n", c(green, "✔"))
	}
	for _, f := range fs {
		fmt.Fprintf(w, "  %s %s %s\n",
			c(sevColor(f.Severity), fmt.Sprintf("[%-8s]", f.Severity)),
			c(bold, f.Subject+":"),
			f.Message)
		if f.Fix != "" {
			fmt.Fprintf(w, "             %s %s\n", c(mag, "fix:"), f.Fix)
		}
	}

	gradeColor := green
	if r.Grade == "C" || r.Grade == "D" {
		gradeColor = yellow
	} else if r.Grade == "F" {
		gradeColor = red
	}
	fmt.Fprintf(w, "\n  %s %s  %s\n\n",
		c(bold, "health score:"),
		c(bold+gradeColor, fmt.Sprintf("%d/100 (%s)", r.Score, r.Grade)),
		c(dim, gradeSummary(r.Grade)))
}

func gradeSummary(g string) string {
	switch g {
	case "A":
		return "solid setup — keep it patched"
	case "B":
		return "good, a few things worth tightening"
	case "C":
		return "functional but fragile — work through the fixes above"
	case "D":
		return "several serious gaps — prioritize CRITICAL and HIGH items"
	default:
		return "this box is one bad day from disaster — fix CRITICAL items today"
	}
}

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
