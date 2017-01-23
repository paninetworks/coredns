package proxy

import (
	"github.com/miekg/coredns/core/dnsserver"
	"github.com/miekg/coredns/middleware"

	"github.com/mholt/caddy"
)

func init() {
	caddy.RegisterPlugin("proxy", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	upstreams, err := NewStaticUpstreams(&c.Dispenser)
	if err != nil {
		return middleware.Error("proxy", err)
	}

	P := &Proxy{}
	dnsserver.GetConfig(c).AddMiddleware(func(next middleware.Handler) middleware.Handler {
		P.Next = next
		P.Upstreams = &upstreams
		return P
	})

	c.OnStartup(OnStartupMetrics)

	// For each protocol defined we get the exchanger and call the OnStartup/OnShutdown functions.
	exers := map[protocol]Exchanger{}
	for _, u := range upstreams {
		ex := u.Select()
		if ex == nil { /* ... */
		}
		exers[ex.Protocol()] = ex
	}
	for _, ex := range exers {
		c.OnStartup(func() error {
			return ex.OnStartup(P)
		})
		c.OnShutdown(func() error {
			return ex.OnShutdown(P)
		})
	}

	return nil
}
