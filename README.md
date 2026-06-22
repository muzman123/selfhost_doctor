# selfhost-doctor 🩺

**One command that tells you what's wrong with your homelab — before the internet does.**

```
$ selfhost-doctor

selfhost-doctor report
scanned 6 containers

  [CRITICAL] plex: runs with --privileged: container has nearly full control of the host
             fix: remove `privileged: true`; grant only needed devices/capabilities
  [HIGH    ] postgres: port 5432/tcp is bound to all interfaces
             fix: bind to localhost and route through your reverse proxy: "127.0.0.1:5432:5432"
  [HIGH    ] host: no known backup tool detected among containers
             fix: set up automated volume backups — e.g. backrest or borgmatic — and TEST a restore
  ...

  health score: 34/100 (D)  several serious gaps — prioritize CRITICAL and HIGH items
```

Self-hosting is great until the setup tax catches up with you: a port you forgot was
forwarded, a Let's Encrypt renewal that silently died, volumes that were never backed
up. `selfhost-doctor` audits your box for the classic footguns and prints a graded
report with copy-pasteable fixes.

## What it checks

| Check            | What it catches                                              |
| ---------------- | ------------------------------------------------------------ |
| `exposed-ports`  | Container ports bound to `0.0.0.0`/`::` (databases especially) |
| `root-user`      | Containers running as root                                    |
| `privileged`     | `--privileged` containers (near-total host access)             |
| `docker-socket`  | `/var/run/docker.sock` mounted into containers                 |
| `restart-policy` | Services that won't survive a reboot                           |
| `latest-tag`     | Unpinned `:latest` images you can't roll back                  |
| `backups`        | No recognizable backup tool anywhere on the box                |
| `tls-expiry`     | Certificates expired or about to (renewal-failure detection)   |

## Install

Download a binary from [Releases], or build from source (any Go ≥ 1.21):

```sh
go install github.com/yourname/selfhost-doctor@latest
```

## Usage

```sh
selfhost-doctor                              # audit the local Docker daemon
selfhost-doctor --domains jellyfin.my.site   # also check TLS cert expiry
selfhost-doctor --json                       # machine-readable output
selfhost-doctor --exit-code --threshold 75   # fail (exit 1) below 75 — for cron/CI
selfhost-doctor --socket /run/user/1000/podman/podman.sock   # Podman works too
```

Run it weekly from cron and get pinged only when something regresses:

```sh
0 9 * * 1 selfhost-doctor --exit-code || curl -d "homelab health dropped" ntfy.sh/mytopic
```

## Design principles

- **Zero dependencies.** Pure Go stdlib. The Docker Engine API is just JSON over a
  Unix socket; we don't need 100 transitive deps to read it. Small attack surface
  matters in a tool you point at your infrastructure.
- **Read-only.** It never changes anything. It tells you what to change.
- **No noise.** 80/443 on your reverse proxy is fine. A read-only socket mount is
  less bad than read-write. Repeat findings get diminishing score penalties.
  An auditor that cries wolf gets uninstalled.

## Adding a check

Every rule is one small file implementing one interface:

```go
type Check interface {
    ID() string
    Describe() string
    Run(t *Target) []Finding
}
```

Write your check in `internal/checks/`, add one line to `Registry()`, add a test.
That's the whole contribution. Good first issues are labeled.

## Roadmap

- [ ] Scan `docker-compose.yml` files directly (audit before you deploy)
- [ ] Reverse-proxy config parsing (Caddy/Traefik/nginx) to map what's actually public
- [ ] External vantage-point port scan (opt-in)
- [ ] Update-lag check via registry digests
- [ ] `--fix` mode that prints a patched compose file diff

## License

MIT
