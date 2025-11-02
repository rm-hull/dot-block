package internal

import (
	"log"
	"time"

	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/miekg/dns"
)

type DNSDispatcher struct {
	upstream string
	cache    cache.Cache[string, *dns.Msg]
}

func NewDNSDispatcher(upstream string, maxSize int) *DNSDispatcher {
	return &DNSDispatcher{
		upstream: upstream,
		cache:    cache.NewCache[string, *dns.Msg]().WithMaxKeys(maxSize).WithLRU(),
	}
}

func (d *DNSDispatcher) HandleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	for _, q := range r.Question {
		log.Printf("Query for %s %s", q.Name, dns.TypeToString[q.Qtype])
		cacheKey := q.Name + ":" + dns.TypeToString[q.Qtype]
		if msg, ok := d.cache.Get(cacheKey); ok {
			log.Printf("Serving from cache: %s", q.Name)
			msg.Id = r.Id
			w.WriteMsg(msg)
			return
		}
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	resp, err := d.forwardQuery(r)
	if err != nil {
		log.Printf("Upstream error: %v", err)
		dns.HandleFailed(w, r)
		return
	}

	for index, q := range r.Question {
		cacheKey := q.Name + ":" + dns.TypeToString[q.Qtype]
		ttl := resp.Answer[index].Header().Ttl
		d.cache.Set(cacheKey, resp, time.Duration(ttl)*time.Second)
	}

	w.WriteMsg(resp)
}

func (d *DNSDispatcher) forwardQuery(r *dns.Msg) (*dns.Msg, error) {
	c := new(dns.Client)
	c.Timeout = 3 * time.Second
	in, _, err := c.Exchange(r, d.upstream)
	return in, err
}
