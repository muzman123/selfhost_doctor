package checks

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// ---------------------------------------------------------------------------
// tls-expiry: connects to each user-supplied domain on :443 and inspects the
// leaf certificate. Catches the "my Let's Encrypt renewal cron silently died
// three weeks ago" failure mode before visitors do.
// ---------------------------------------------------------------------------

type TLSExpiry struct {
	// DialTimeout is overridable for tests.
	DialTimeout time.Duration
}

func (c *TLSExpiry) ID() string       { return "tls-expiry" }
func (c *TLSExpiry) Describe() string { return "TLS certificates that are expired or expiring soon" }

func (c *TLSExpiry) Run(t *Target) []Finding {
	var fs []Finding
	timeout := c.DialTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	for _, domain := range t.Domains {
		f := c.checkDomain(domain, timeout)
		if f != nil {
			fs = append(fs, *f)
		}
	}
	return fs
}

func (c *TLSExpiry) checkDomain(domain string, timeout time.Duration) *Finding {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", domain+":443", &tls.Config{
		ServerName: domain,
		// We still want to inspect expired/invalid certs rather than
		// erroring out, so skip verification and judge manually.
		InsecureSkipVerify: true,
	})
	if err != nil {
		return &Finding{
			CheckID:  c.ID(),
			Severity: Medium,
			Subject:  domain,
			Message:  fmt.Sprintf("could not establish TLS connection: %v", err),
			Fix:      "verify the service is up and port 443 is reachable from this host",
		}
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return &Finding{CheckID: c.ID(), Severity: Medium, Subject: domain,
			Message: "server presented no certificate", Fix: "check reverse proxy TLS config"}
	}
	leaf := certs[0]
	left := time.Until(leaf.NotAfter)

	switch {
	case left <= 0:
		return &Finding{
			CheckID: c.ID(), Severity: Critical, Subject: domain,
			Message: fmt.Sprintf("certificate EXPIRED %s ago", (-left).Round(time.Hour)),
			Fix:     "renew now; check your ACME client logs (certbot/caddy/traefik) for why auto-renewal failed",
		}
	case left < 7*24*time.Hour:
		return &Finding{
			CheckID: c.ID(), Severity: High, Subject: domain,
			Message: fmt.Sprintf("certificate expires in %.0f days", left.Hours()/24),
			Fix:     "auto-renewal usually triggers at 30 days remaining — being under 7 means it is failing; check ACME logs",
		}
	case left < 21*24*time.Hour:
		return &Finding{
			CheckID: c.ID(), Severity: Low, Subject: domain,
			Message: fmt.Sprintf("certificate expires in %.0f days", left.Hours()/24),
			Fix:     "keep an eye on it; renewal should happen around the 30-day mark",
		}
	}
	return nil // healthy
}
