package proxy

import (
	"github.com/miekg/coredns/request"

	"github.com/miekg/dns"
)

// Exchanger is an interface that specifies a type implementing a DNS resolver that
// can use whatever transport it likes.
type Exchanger interface {
	Exchange(string, request.Request) (*dns.Msg, error)
	Protocol() protocol
}

type protocol string
