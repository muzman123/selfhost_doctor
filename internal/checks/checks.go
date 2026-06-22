// Package checks defines the audit framework. Each rule implements Check;
// adding a new rule = adding one file + one line in Registry(). That's the
// whole contribution story.
package checks

import "github.com/muzman123/selfhost_doctor/internal/docker"

// Severity ranks how bad a finding is.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	return [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}[s]
}

// Penalty is how many points a finding subtracts from the 100-point score.
func (s Severity) Penalty() int {
	return [...]int{0, 3, 8, 15, 25}[s]
}

// MarshalJSON renders severity as its name ("HIGH") rather than a bare int,
// which is what anyone piping --json into jq actually wants.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// Finding is one problem discovered by a check.
type Finding struct {
	CheckID  string   `json:"check"`
	Severity Severity `json:"severity"`
	Subject  string   `json:"subject"` // e.g. container name, domain
	Message  string   `json:"message"` // what is wrong
	Fix      string   `json:"fix"`     // copy-pasteable remediation
}

// Target bundles everything checks may inspect. Checks read from this
// snapshot instead of hitting the API themselves, so the daemon is queried
// exactly once and checks stay trivially unit-testable.
type Target struct {
	Containers []ContainerInfo
	Domains    []string // user-supplied domains for TLS checks
}

// ContainerInfo pairs a container's summary with its full inspect data.
type ContainerInfo struct {
	Summary docker.ContainerSummary
	Detail  *docker.ContainerDetail
}

// Check is a single audit rule.
type Check interface {
	ID() string       // short slug, e.g. "exposed-ports"
	Describe() string // one-liner for --list-checks
	Run(t *Target) []Finding
}

// Registry returns all built-in checks, in display order.
func Registry() []Check {
	return []Check{
		&ExposedPorts{},
		&RootUser{},
		&PrivilegedMode{},
		&DockerSocketMount{},
		&NoRestartPolicy{},
		&LatestTag{},
		&NoBackupTool{},
		&TLSExpiry{},
	}
}

// Score converts findings into a 0-100 score and a letter grade.
//
// Repeat findings from the same check are penalized at half weight after the
// first: four root containers is one habit to fix, not four separate
// disasters. Without this, every realistic homelab scores F and people learn
// to ignore the tool.
func Score(findings []Finding) (int, string) {
	score := 100
	seen := map[string]bool{}
	for _, f := range findings {
		p := f.Severity.Penalty()
		if seen[f.CheckID] {
			p /= 2
		}
		seen[f.CheckID] = true
		score -= p
	}
	if score < 0 {
		score = 0
	}
	switch {
	case score >= 90:
		return score, "A"
	case score >= 75:
		return score, "B"
	case score >= 60:
		return score, "C"
	case score >= 40:
		return score, "D"
	default:
		return score, "F"
	}
}
