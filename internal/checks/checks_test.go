package checks

import (
	"testing"

	"github.com/muzman123/selfhost_doctor/internal/docker"
)

func container(name, image, state, user string, privileged bool, restart string, ports []docker.Port, mounts []docker.Mount) ContainerInfo {
	s := docker.ContainerSummary{ID: name, Names: []string{"/" + name}, Image: image, State: state, Ports: ports}
	d := &docker.ContainerDetail{}
	d.Config.User = user
	d.Config.Image = image
	d.HostConfig.Privileged = privileged
	d.HostConfig.RestartPolicy.Name = restart
	d.Mounts = mounts
	return ContainerInfo{Summary: s, Detail: d}
}

func TestExposedPorts(t *testing.T) {
	tgt := &Target{Containers: []ContainerInfo{
		container("db", "postgres:16", "running", "", false, "always",
			[]docker.Port{{IP: "0.0.0.0", PrivatePort: 5432, PublicPort: 5432, Type: "tcp"}}, nil),
		container("web", "caddy:2.8", "running", "1000", false, "always",
			[]docker.Port{{IP: "0.0.0.0", PrivatePort: 443, PublicPort: 443, Type: "tcp"}}, nil),
		container("safe", "vaultwarden/server:1.32.0", "running", "1000", false, "always",
			[]docker.Port{{IP: "127.0.0.1", PrivatePort: 80, PublicPort: 8222, Type: "tcp"}}, nil),
		container("stopped", "nginx:1.27", "exited", "", false, "no",
			[]docker.Port{{IP: "0.0.0.0", PrivatePort: 80, PublicPort: 9999, Type: "tcp"}}, nil),
	}}
	fs := (&ExposedPorts{}).Run(tgt)
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(fs), fs)
	}
	if fs[0].Subject != "db" || fs[0].Severity != High {
		t.Errorf("db should be HIGH, got %+v", fs[0])
	}
	if fs[1].Subject != "web" || fs[1].Severity != Info {
		t.Errorf("443 should be downgraded to INFO, got %+v", fs[1])
	}
}

func TestRootUser(t *testing.T) {
	tgt := &Target{Containers: []ContainerInfo{
		container("rooty", "img:1", "running", "", false, "always", nil, nil),
		container("zero", "img:1", "running", "0:0", false, "always", nil, nil),
		container("fine", "img:1", "running", "1000:1000", false, "always", nil, nil),
		container("dead", "img:1", "exited", "", false, "always", nil, nil),
	}}
	fs := (&RootUser{}).Run(tgt)
	if len(fs) != 2 {
		t.Fatalf("want 2 findings (rooty, zero), got %d: %+v", len(fs), fs)
	}
}

func TestDockerSocketSeverityDependsOnRW(t *testing.T) {
	sock := func(rw bool) []docker.Mount {
		return []docker.Mount{{Type: "bind", Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock", RW: rw}}
	}
	tgt := &Target{Containers: []ContainerInfo{
		container("rw", "watchtower", "running", "", false, "always", nil, sock(true)),
		container("ro", "traefik:v3", "running", "", false, "always", nil, sock(false)),
	}}
	fs := (&DockerSocketMount{}).Run(tgt)
	if len(fs) != 2 || fs[0].Severity != High || fs[1].Severity != Medium {
		t.Fatalf("want HIGH for rw and MEDIUM for ro, got %+v", fs)
	}
}

func TestBackupHeuristic(t *testing.T) {
	noBackup := &Target{Containers: []ContainerInfo{
		container("app", "nginx:1.27", "running", "1000", false, "always", nil, nil),
	}}
	if fs := (&NoBackupTool{}).Run(noBackup); len(fs) != 1 {
		t.Fatalf("want 1 finding when no backup tool, got %d", len(fs))
	}
	withBackup := &Target{Containers: []ContainerInfo{
		container("app", "nginx:1.27", "running", "1000", false, "always", nil, nil),
		container("backrest", "garethgeorge/backrest:1.5", "running", "1000", false, "always", nil, nil),
	}}
	if fs := (&NoBackupTool{}).Run(withBackup); len(fs) != 0 {
		t.Fatalf("want 0 findings with backrest present, got %+v", fs)
	}
}

func TestScoreDiminishingReturns(t *testing.T) {
	// 1 medium = -8 → 92
	one := []Finding{{CheckID: "root-user", Severity: Medium}}
	if s, _ := Score(one); s != 92 {
		t.Fatalf("want 92, got %d", s)
	}
	// 4 mediums from the SAME check = -8 -4 -4 -4 = -20 → 80, not -32 → 68
	four := []Finding{
		{CheckID: "root-user", Severity: Medium},
		{CheckID: "root-user", Severity: Medium},
		{CheckID: "root-user", Severity: Medium},
		{CheckID: "root-user", Severity: Medium},
	}
	if s, _ := Score(four); s != 80 {
		t.Fatalf("want 80 with diminishing returns, got %d", s)
	}
}

func TestGradeBoundaries(t *testing.T) {
	if _, g := Score(nil); g != "A" {
		t.Fatalf("clean run should be A, got %s", g)
	}
}
