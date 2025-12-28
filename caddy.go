package ipv64

import "github.com/caddyserver/caddy/v2"

func init() {
	caddy.RegisterModule(Provider{})
}

func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.ipv64",
		New: func() caddy.Module { return new(Provider) },
	}
}
