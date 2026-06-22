// Package docker is a minimal, zero-dependency client for the Docker Engine
// API over a Unix socket. We deliberately avoid the official SDK: it pulls in
// ~100 transitive dependencies to do what is ultimately JSON over HTTP.
// This also works against Podman's Docker-compatible socket.
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Client talks to the Docker Engine API.
type Client struct {
	http *http.Client
}

// New returns a client that dials the given unix socket path
// (normally /var/run/docker.sock).
func New(socketPath string) *Client {
	return &Client{
		http: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				// The magic: every request "to" http://docker/... actually
				// dials the unix socket instead of TCP.
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

func (c *Client) get(path string, out any) error {
	// Host is ignored by our DialContext but required for a valid URL.
	resp, err := c.http.Get("http://docker" + path)
	if err != nil {
		return fmt.Errorf("docker API request %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker API %s returned %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Ping verifies the daemon is reachable.
func (c *Client) Ping() error {
	resp, err := c.http.Get("http://docker/_ping")
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// ListContainers returns summaries of all containers (running and stopped).
func (c *Client) ListContainers() ([]ContainerSummary, error) {
	var out []ContainerSummary
	err := c.get("/containers/json?all=true", &out)
	return out, err
}

// InspectContainer returns the full configuration of one container.
func (c *Client) InspectContainer(id string) (*ContainerDetail, error) {
	var out ContainerDetail
	err := c.get("/containers/"+id+"/json", &out)
	return &out, err
}
