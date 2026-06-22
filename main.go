// selfhost-doctor audits a homelab Docker host for the classic self-hosting
// footguns: exposed ports, root containers, missing backups, dying TLS certs.
//
// Usage:
//
//	selfhost-doctor                          # audit local Docker daemon
//	selfhost-doctor --domains my.site,x.dev  # also check TLS cert expiry
//	selfhost-doctor --json                   # machine-readable output
//	selfhost-doctor --exit-code              # exit 1 if score < threshold (cron/CI)
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/muzman123/selfhost_doctor/internal/checks"
	"github.com/muzman123/selfhost_doctor/internal/docker"
	"github.com/muzman123/selfhost_doctor/internal/report"
)

func main() {
	socket := flag.String("socket", "/var/run/docker.sock", "path to Docker (or Podman) socket")
	domains := flag.String("domains", "", "comma-separated domains to check for TLS expiry")
	jsonOut := flag.Bool("json", false, "output JSON instead of a terminal report")
	exitCode := flag.Bool("exit-code", false, "exit non-zero if score is below --threshold (for cron/CI)")
	threshold := flag.Int("threshold", 75, "minimum passing score when --exit-code is set")
	listChecks := flag.Bool("list-checks", false, "list available checks and exit")
	flag.Parse()

	if *listChecks {
		for _, c := range checks.Registry() {
			fmt.Printf("  %-16s %s\n", c.ID(), c.Describe())
		}
		return
	}

	target, nContainers, err := gather(*socket, *domains)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintln(os.Stderr, "hint: is Docker running? do you have permission on the socket? (try sudo, or add yourself to the docker group)")
		os.Exit(2)
	}

	var findings []checks.Finding
	for _, c := range checks.Registry() {
		findings = append(findings, c.Run(target)...)
	}

	score, grade := checks.Score(findings)
	res := report.Result{Score: score, Grade: grade, Containers: nContainers, Findings: findings}
	if res.Findings == nil {
		res.Findings = []checks.Finding{} // render [] not null in JSON
	}

	if *jsonOut {
		if err := report.JSON(os.Stdout, res); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
	} else {
		report.Terminal(os.Stdout, res)
	}

	if *exitCode && score < *threshold {
		os.Exit(1)
	}
}

// gather queries the Docker daemon once and builds the immutable snapshot
// every check runs against.
func gather(socket, domainCSV string) (*checks.Target, int, error) {
	cli := docker.New(socket)
	if err := cli.Ping(); err != nil {
		return nil, 0, fmt.Errorf("cannot reach Docker daemon at %s: %w", socket, err)
	}

	summaries, err := cli.ListContainers()
	if err != nil {
		return nil, 0, err
	}

	t := &checks.Target{}
	for _, s := range summaries {
		ci := checks.ContainerInfo{Summary: s}
		// Best-effort inspect; a container vanishing mid-scan shouldn't
		// abort the whole audit.
		if d, err := cli.InspectContainer(s.ID); err == nil {
			ci.Detail = d
		}
		t.Containers = append(t.Containers, ci)
	}

	if domainCSV != "" {
		for _, d := range strings.Split(domainCSV, ",") {
			if d = strings.TrimSpace(d); d != "" {
				t.Domains = append(t.Domains, d)
			}
		}
	}
	return t, len(t.Containers), nil
}
