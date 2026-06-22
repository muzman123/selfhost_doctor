// Command fakedaemon serves a minimal Docker Engine API on a unix socket,
// pretending to be a messy-but-realistic homelab. Used for demos and
// integration tests without needing a real Docker daemon.
//
//	go run ./hack/fakedaemon /tmp/fake-docker.sock
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

const containersJSON = `[
 {"Id":"aaa111","Names":["/jellyfin"],"Image":"jellyfin/jellyfin:latest","State":"running",
  "Ports":[{"IP":"0.0.0.0","PrivatePort":8096,"PublicPort":8096,"Type":"tcp"}]},
 {"Id":"bbb222","Names":["/postgres"],"Image":"postgres:16","State":"running",
  "Ports":[{"IP":"0.0.0.0","PrivatePort":5432,"PublicPort":5432,"Type":"tcp"}]},
 {"Id":"ccc333","Names":["/caddy"],"Image":"caddy:2.8","State":"running",
  "Ports":[{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":80,"Type":"tcp"},
           {"IP":"0.0.0.0","PrivatePort":443,"PublicPort":443,"Type":"tcp"}]},
 {"Id":"ddd444","Names":["/plex"],"Image":"plexinc/pms-docker","State":"running","Ports":[]},
 {"Id":"eee555","Names":["/watchtower"],"Image":"containrrr/watchtower:1.7.1","State":"running","Ports":[]},
 {"Id":"fff666","Names":["/vaultwarden"],"Image":"vaultwarden/server:1.32.0","State":"running",
  "Ports":[{"IP":"127.0.0.1","PrivatePort":80,"PublicPort":8222,"Type":"tcp"}]}
]`

var inspects = map[string]string{
	// jellyfin: root, :latest, no restart policy — the classic copy-pasted compose file
	"aaa111": `{"Name":"/jellyfin","Config":{"User":"","Image":"jellyfin/jellyfin:latest"},
	 "HostConfig":{"Privileged":false,"RestartPolicy":{"Name":""}},"Mounts":[]}`,
	// postgres: root + 5432 exposed to the world — the nightmare combo
	"bbb222": `{"Name":"/postgres","Config":{"User":"","Image":"postgres:16"},
	 "HostConfig":{"Privileged":false,"RestartPolicy":{"Name":"always"}},"Mounts":[]}`,
	// caddy: well-configured reverse proxy
	"ccc333": `{"Name":"/caddy","Config":{"User":"1000:1000","Image":"caddy:2.8"},
	 "HostConfig":{"Privileged":false,"RestartPolicy":{"Name":"unless-stopped"}},"Mounts":[]}`,
	// plex: PRIVILEGED because a forum post said it fixes hardware transcoding
	"ddd444": `{"Name":"/plex","Config":{"User":"","Image":"plexinc/pms-docker"},
	 "HostConfig":{"Privileged":true,"RestartPolicy":{"Name":"unless-stopped"}},"Mounts":[]}`,
	// watchtower: docker.sock mounted read-write
	"eee555": `{"Name":"/watchtower","Config":{"User":"","Image":"containrrr/watchtower:1.7.1"},
	 "HostConfig":{"Privileged":false,"RestartPolicy":{"Name":"unless-stopped"}},
	 "Mounts":[{"Type":"bind","Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock","RW":true}]}`,
	// vaultwarden: localhost-bound, pinned, non-root — doing it right
	"fff666": `{"Name":"/vaultwarden","Config":{"User":"1000","Image":"vaultwarden/server:1.32.0"},
	 "HostConfig":{"Privileged":false,"RestartPolicy":{"Name":"unless-stopped"}},"Mounts":[]}`,
}

func main() {
	sock := os.Args[1]
	os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("OK")) })
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, containersJSON)
	})
	mux.HandleFunc("/containers/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if body, ok := inspects[parts[1]]; ok {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, body)
			return
		}
		http.NotFound(w, r)
	})
	fmt.Println("fake docker daemon listening on", sock)
	http.Serve(ln, mux)
}
