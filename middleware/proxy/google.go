package proxy

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/miekg/coredns/middleware/pkg/debug"
	"github.com/miekg/coredns/request"

	"github.com/miekg/dns"
)

type google struct {
	client   *http.Client
	endpoint string
	boot     Upstream
	quit     chan bool
}

func newGoogle(endpoint string) *google {
	if endpoint == "" {
		endpoint = ghost
	}
	tls := &tls.Config{ServerName: endpoint}
	client := &http.Client{
		Timeout:   time.Second * defaultTimeout,
		Transport: &http.Transport{TLSClientConfig: tls},
	}
	return &google{client: client, endpoint: dns.Fqdn(endpoint), quit: make(chan bool)}
}

func (g *google) Exchange(addr string, state request.Request) (*dns.Msg, error) {
	v := url.Values{}

	v.Set("name", state.Name())
	v.Set("type", fmt.Sprintf("%d", state.QType()))

	optDebug := false
	if bug := debug.IsDebug(state.Name()); bug != "" {
		optDebug = true
		v.Set("name", bug)
	}

	buf, backendErr := g.exchange(addr, v.Encode())

	if backendErr == nil {
		gm := new(googleMsg)
		if err := json.Unmarshal(buf, gm); err != nil {
			return nil, err
		}

		m, debug, err := toMsg(gm)
		if err != nil {
			return nil, err
		}

		if optDebug {
			// reset question
			m.Question[0].Name = state.QName()
			// prepend debug RR to the additional section
			m.Extra = append([]dns.RR{debug}, m.Extra...)

		}

		m.Id = state.Req.Id
		return m, nil
	}

	log.Printf("[WARNING] Failed to connect to HTTPS backend %q: %s", g.endpoint, backendErr)
	return nil, backendErr
}

// OnStartup looks up the IP address for endpoint every 300 seconds.
func (g *google) OnStartup() error {
	r := new(dns.Msg)
	r.SetQuestion(g.endpoint, dns.TypeA)
	new, err := g.bootstrap(r)
	if err != nil {
		return err
	}

	up, _ := newSimpleUpstream(new)
	g.Lock()
	g.addr = up
	g.Unlock()

	go func() {
		tick := time.NewTicker(300 * time.Second)

		for {
			select {
			case <-tick.C:

				r.SetQuestion(g.endpoint, dns.TypeA)
				new, err := g.bootstrap(r)
				if err != nil {
					log.Printf("[WARNING] Failed to bootstrap A records %q: %s", g.endpoint, err)
					continue
				}

				up, _ := newSimpleUpstream(new)
				g.Lock()
				g.addr = up
				g.Unlock()
			case <-g.quit:
				return
			}
		}
	}()

	return nil
}

func (g *google) exchange(addr, json string) ([]byte, error) {
	url := "https://" + addr + "/resolve?" + json
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Host = g.endpoint // TODO(miek): works with the extra dot at the end?

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}

	buf, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get 200 status code, got %d", resp.StatusCode)
	}

	return buf, nil
}

func (g *google) OnShutdown() error {
	g.quit <- true
	return nil
}

func (g *google) SetUpstream(u *simpleUpstream) error {
	g.upstream = u
	return nil
}

func (g *google) bootstrap(r *dns.Msg) ([]string, error) {
	c := new(dns.Client)
	start := time.Now()

	for time.Now().Sub(start) < tryDuration {
		host := g.upstream.Select()
		if host == nil {
			return nil, fmt.Errorf("no healthy upstream hosts")
		}

		atomic.AddInt64(&host.Conns, 1)

		m, _, backendErr := c.Exchange(r, host.Name)

		atomic.AddInt64(&host.Conns, -1)

		if backendErr == nil {
			if len(m.Answer) == 0 {
				return nil, fmt.Errorf("no answer section in response")
			}
			ret := []string{}
			for _, an := range m.Answer {
				if a, ok := an.(*dns.A); ok {
					ret = append(ret, net.JoinHostPort(a.A.String(), "443"))
				}
			}
			if len(ret) > 0 {
				return ret, nil
			}

			return nil, fmt.Errorf("no address records in answer section")
		}

		timeout := host.FailTimeout
		if timeout == 0 {
			timeout = 7 * time.Second
		}
		atomic.AddInt32(&host.Fails, 1)
		go func(host *UpstreamHost, timeout time.Duration) {
			time.Sleep(timeout)
			atomic.AddInt32(&host.Fails, -1)
		}(host, timeout)
	}
	return nil, fmt.Errorf("no healthy upstream hosts")
}

const (
	// Default endpoint for this service.
	ghost = "dns.google.com."
)
