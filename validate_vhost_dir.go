package validatehostdir

import (
	"net/http"
	"os"
	"path/filepath"
  "log"
	"strings"

	"github.com/caddyserver/caddy/v2"
  "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func init() {
	caddy.RegisterModule(ValidateVhostDir{})
	httpcaddyfile.RegisterHandlerDirective("validate_vhost_dir", parseDirective)
}

type ValidateVhostDir struct {

	VhostsPath string `json:"vhosts_path"`
}

func parseDirective(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {

	var m ValidateVhostDir
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
			return nil, err
	}
	return m, nil
}

func (m *ValidateVhostDir) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
  
	d.NextArg()

	for d.NextBlock(0) {
		var err error

		switch d.Val() {
			case "vhosts_path":
				if !d.Args(&m.VhostsPath) {
					err = d.ArgErr()
				}
				return nil
			default:
				err = d.Errf("Unknown validate_vhost_dir arg")
		}
    if err != nil {
      return d.Errf("Error parsing %s: %s", d.Val(), err)
    }
	}
	return nil
}


// Interface guard
var _ caddyfile.Unmarshaler = (*ValidateVhostDir)(nil)


func (ValidateVhostDir) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.validate_vhost_dir",
		New: func() caddy.Module { return new(ValidateVhostDir) },
	}
}

func (m ValidateVhostDir) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	// Get the remote IP address
	remoteIP := r.RemoteAddr

	// Print or use the remote IP address as needed
  log.Printf("[ValidateVhostDir] Remote IP: %s\n", remoteIP)

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}

	// Strip "www." prefix if it exists
	if len(domain) > 4 && domain[:4] == "www." {
		domain = domain[4:]
		log.Printf("[ValidateVhostDir] Stripped www. prefix, domain is now: %s", domain)
	}

	// Never authorize on-demand ACME for *.siterubix.com (or the apex). Every
	// siterubix subdomain is served from the single loaded *.siterubix.com
	// wildcard cert (installed as /etc/caddy2/certs/siterubix-wildcard.* and
	// renewed fleet-wide by renew_siterubix_wildcard_cert.pl), so caddy already
	// has a matching cert in its pool and does not need to issue one. Returning
	// 404 here refuses per-domain issuance -- which would otherwise burn the
	// Let's Encrypt "certificates per registered domain" rate limit for
	// siterubix.com and pointlessly churn a per-domain cert for a name the
	// wildcard already covers. (Belt-and-suspenders with the loaded wildcard:
	// on-demand only ever fires on a pool miss, but if the wildcard were ever
	// absent we still must not fall back to per-domain siterubix issuance.)
	if domain == "siterubix.com" || strings.HasSuffix(domain, ".siterubix.com") {
		log.Printf("[ValidateVhostDir] %s is siterubix; refusing on-demand issuance (served from *.siterubix.com wildcard)", domain)
		w.WriteHeader(http.StatusNotFound)
		return nil
	}

	dirPath := filepath.Join(m.VhostsPath, domain)

  log.Printf("[ValidateVhostDir] dirPath: %s", dirPath)

	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		// If the directory does not exist, respond with StatusNotFound
		w.WriteHeader(http.StatusNotFound)
		return nil
	}

  log.Printf("apparently dirPath: %s exists?", dirPath)

	// If the directory exists, respond with StatusOK
	w.WriteHeader(http.StatusOK)
	return nil
}

var (
	_ caddyhttp.MiddlewareHandler = (*ValidateVhostDir)(nil)
)
