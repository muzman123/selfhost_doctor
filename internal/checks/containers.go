package checks

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// exposed-ports: container ports published on 0.0.0.0 / :: are reachable from
// every network interface — and if the router port-forwards or the host has a
// public IP, from the internet. The #1 way self-hosters get owned.
// ---------------------------------------------------------------------------

type ExposedPorts struct{}

func (c *ExposedPorts) ID() string { return "exposed-ports" }
func (c *ExposedPorts) Describe() string {
	return "Containers publishing ports on all interfaces (0.0.0.0/::)"
}

// Services that are *designed* to be public; flag them Info instead of High.
var intentionallyPublic = map[int]bool{80: true, 443: true}

func (c *ExposedPorts) Run(t *Target) []Finding {
	var fs []Finding
	for _, ct := range t.Containers {
		if ct.Summary.State != "running" {
			continue
		}
		for _, p := range ct.Summary.Ports {
			if p.PublicPort == 0 {
				continue // not published at all — fine
			}
			if p.IP == "0.0.0.0" || p.IP == "::" || p.IP == "" {
				sev := High
				msg := fmt.Sprintf("port %d/%s is bound to all interfaces", p.PublicPort, p.Type)
				fix := fmt.Sprintf("bind to localhost and route through your reverse proxy: \"127.0.0.1:%d:%d\" in the ports section",
					p.PublicPort, p.PrivatePort)
				if intentionallyPublic[p.PublicPort] {
					sev = Info
					msg += " (80/443 are normal for a reverse proxy — verify this is your proxy)"
					fix = "" // nothing to fix if this is the reverse proxy
				}
				fs = append(fs, Finding{
					CheckID:  c.ID(),
					Severity: sev,
					Subject:  ct.Summary.Name(),
					Message:  msg,
					Fix:      fix,
				})
			}
		}
	}
	return fs
}

// ---------------------------------------------------------------------------
// root-user: containers running as root mean a container escape = root on the
// host. Most popular images support a non-root user or PUID/PGID env vars.
// ---------------------------------------------------------------------------

type RootUser struct{}

func (c *RootUser) ID() string       { return "root-user" }
func (c *RootUser) Describe() string { return "Containers running as root" }

func (c *RootUser) Run(t *Target) []Finding {
	var fs []Finding
	for _, ct := range t.Containers {
		if ct.Detail == nil || ct.Summary.State != "running" {
			continue
		}
		u := ct.Detail.Config.User
		if u == "" || u == "root" || u == "0" || strings.HasPrefix(u, "0:") {
			fs = append(fs, Finding{
				CheckID:  c.ID(),
				Severity: Medium,
				Subject:  ct.Summary.Name(),
				Message:  "running as root (no user set)",
				Fix:      "set `user: \"1000:1000\"` in compose, or PUID/PGID=1000 for linuxserver.io images",
			})
		}
	}
	return fs
}

// ---------------------------------------------------------------------------
// privileged: --privileged disables nearly all container isolation.
// ---------------------------------------------------------------------------

type PrivilegedMode struct{}

func (c *PrivilegedMode) ID() string       { return "privileged" }
func (c *PrivilegedMode) Describe() string { return "Containers in --privileged mode" }

func (c *PrivilegedMode) Run(t *Target) []Finding {
	var fs []Finding
	for _, ct := range t.Containers {
		if ct.Detail == nil {
			continue
		}
		if ct.Detail.HostConfig.Privileged {
			fs = append(fs, Finding{
				CheckID:  c.ID(),
				Severity: Critical,
				Subject:  ct.Summary.Name(),
				Message:  "runs with --privileged: container has nearly full control of the host",
				Fix:      "remove `privileged: true`; grant only needed devices/capabilities (cap_add, devices)",
			})
		}
	}
	return fs
}

// ---------------------------------------------------------------------------
// docker-socket: mounting /var/run/docker.sock into a container is root on
// the host by another name. Legit for some tools (watchtower, traefik) but
// people should mount it read-only and know the risk.
// ---------------------------------------------------------------------------

type DockerSocketMount struct{}

func (c *DockerSocketMount) ID() string       { return "docker-socket" }
func (c *DockerSocketMount) Describe() string { return "Containers with the Docker socket mounted" }

func (c *DockerSocketMount) Run(t *Target) []Finding {
	var fs []Finding
	for _, ct := range t.Containers {
		if ct.Detail == nil {
			continue
		}
		for _, m := range ct.Detail.Mounts {
			if strings.Contains(m.Source, "docker.sock") {
				sev := High
				note := ""
				if !m.RW {
					sev = Medium
					note = " (read-only, which limits but does not remove the risk)"
				}
				fs = append(fs, Finding{
					CheckID:  c.ID(),
					Severity: sev,
					Subject:  ct.Summary.Name(),
					Message:  "has the Docker socket mounted — equivalent to root on the host" + note,
					Fix:      "if required (e.g. traefik/watchtower), mount :ro and consider a socket proxy like tecnativa/docker-socket-proxy",
				})
			}
		}
	}
	return fs
}

// ---------------------------------------------------------------------------
// restart-policy: no restart policy means one power blip silently takes your
// services down until you notice. The classic homelab footgun.
// ---------------------------------------------------------------------------

type NoRestartPolicy struct{}

func (c *NoRestartPolicy) ID() string       { return "restart-policy" }
func (c *NoRestartPolicy) Describe() string { return "Running containers without a restart policy" }

func (c *NoRestartPolicy) Run(t *Target) []Finding {
	var fs []Finding
	for _, ct := range t.Containers {
		if ct.Detail == nil || ct.Summary.State != "running" {
			continue
		}
		rp := ct.Detail.HostConfig.RestartPolicy.Name
		if rp == "" || rp == "no" {
			fs = append(fs, Finding{
				CheckID:  c.ID(),
				Severity: Low,
				Subject:  ct.Summary.Name(),
				Message:  "no restart policy — won't come back after reboot or crash",
				Fix:      "add `restart: unless-stopped` to the service in docker-compose.yml",
			})
		}
	}
	return fs
}

// ---------------------------------------------------------------------------
// latest-tag: :latest means you don't know what you're running and can't
// roll back. Low severity, but it's the difference between "it broke after
// a pull" and "I can pin back to 1.41.0".
// ---------------------------------------------------------------------------

type LatestTag struct{}

func (c *LatestTag) ID() string       { return "latest-tag" }
func (c *LatestTag) Describe() string { return "Containers using the :latest image tag" }

func (c *LatestTag) Run(t *Target) []Finding {
	var fs []Finding
	for _, ct := range t.Containers {
		if ct.Detail == nil {
			continue
		}
		img := ct.Detail.Config.Image
		if strings.HasSuffix(img, ":latest") || !strings.Contains(img, ":") {
			fs = append(fs, Finding{
				CheckID:  c.ID(),
				Severity: Low,
				Subject:  ct.Summary.Name(),
				Message:  fmt.Sprintf("image %q is unpinned — updates are unpredictable and rollback is impossible", img),
				Fix:      "pin a version tag (e.g. image: nginx:1.27) and update deliberately",
			})
		}
	}
	return fs
}

// ---------------------------------------------------------------------------
// backups: we can't prove your backups work (nobody can but a restore test),
// but we CAN notice that no known backup tool exists anywhere on the box.
// ---------------------------------------------------------------------------

type NoBackupTool struct{}

func (c *NoBackupTool) ID() string       { return "backups" }
func (c *NoBackupTool) Describe() string { return "No recognizable backup tool found" }

var backupHints = []string{"restic", "borg", "duplicati", "kopia", "duplicacy", "rsnapshot", "backrest", "velero", "urbackup"}

func (c *NoBackupTool) Run(t *Target) []Finding {
	for _, ct := range t.Containers {
		hay := strings.ToLower(ct.Summary.Image + " " + ct.Summary.Name())
		for _, h := range backupHints {
			if strings.Contains(hay, h) {
				return nil // found one — assume the user has backups handled
			}
		}
	}
	if len(t.Containers) == 0 {
		return nil
	}
	return []Finding{{
		CheckID:  c.ID(),
		Severity: High,
		Subject:  "host",
		Message:  "no known backup tool detected among containers (looked for restic, borg, kopia, duplicati, ...)",
		Fix:      "set up automated volume backups — e.g. backrest (restic UI) or borgmatic — and TEST a restore",
	}}
}
