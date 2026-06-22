package docker

// ContainerSummary is one entry from GET /containers/json.
type ContainerSummary struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
	State string   `json:"State"` // "running", "exited", ...
	Ports []Port   `json:"Ports"`
}

// Name returns a human-friendly container name.
func (s ContainerSummary) Name() string {
	if len(s.Names) > 0 {
		n := s.Names[0]
		if len(n) > 0 && n[0] == '/' {
			return n[1:]
		}
		return n
	}
	if len(s.ID) >= 12 {
		return s.ID[:12]
	}
	return s.ID
}

// Port is a published port mapping.
type Port struct {
	IP          string `json:"IP"`          // "0.0.0.0", "::", "127.0.0.1", or "" (unpublished)
	PrivatePort int    `json:"PrivatePort"` // port inside the container
	PublicPort  int    `json:"PublicPort"`  // port on the host (0 if unpublished)
	Type        string `json:"Type"`        // "tcp"/"udp"
}

// ContainerDetail is GET /containers/{id}/json, trimmed to what we audit.
type ContainerDetail struct {
	Name   string `json:"Name"`
	Config struct {
		User  string `json:"User"`  // "" means root unless image declares otherwise
		Image string `json:"Image"` // image ref as written, e.g. "nginx:latest"
	} `json:"Config"`
	HostConfig struct {
		Privileged    bool     `json:"Privileged"`
		CapAdd        []string `json:"CapAdd"`
		RestartPolicy struct {
			Name string `json:"Name"` // "", "no", "always", "unless-stopped", "on-failure"
		} `json:"RestartPolicy"`
		Binds []string `json:"Binds"` // host:container[:mode]
	} `json:"HostConfig"`
	Mounts []Mount `json:"Mounts"`
}

// Mount is a bind/volume mount on a container.
type Mount struct {
	Type        string `json:"Type"` // "bind", "volume"
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}
