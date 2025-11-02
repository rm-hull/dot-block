package main

import (
	"crypto/tls"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/rm-hull/godx"
	"golang.org/x/crypto/acme/autocert"
)

// Upstream resolver for forwarding
const upstream = "1.1.1.1:53" // Cloudflare DNS

func main() {
	godx.GitVersion()
	godx.EnvironmentVars()
	godx.UserInfo()

	host := "dot.destructuring-bind.org"
	cacheDir := "/data/certcache"

	// Set up automatic TLS certificate management
	manager := &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(host),
	}

	r := gin.Default()
	r.Any("/.well-known/acme-challenge/*path", gin.WrapH(manager.HTTPHandler(nil)))
	r.GET("/", func(c *gin.Context) {
		c.String(200, "DNS-over-TLS server running")
	})

	go func() {
		log.Println("Starting HTTP server on port 80 for ACME challenge...")
		if err := r.Run(":80"); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Create TLS config for DoT
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"dot"}, // important for DNS-over-TLS
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			log.Printf("Initiating client hello: %v", clientHello)
			cert, err := manager.GetCertificate(clientHello)
			if err != nil {
				log.Printf("Failed to get certificate for %s: %v", clientHello.ServerName, err)
			} else {
				log.Printf("Certificate obtained for %s", clientHello.ServerName)
			}
			return cert, err
		},
	}

	// Set up DNS server over TCP/TLS
	dnsServer := &dns.Server{
		Addr:      ":853",
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
		Handler:   dns.HandlerFunc(handleDNSRequest),
	}

	log.Println("Starting DNS-over-TLS server on port 853...")
	if err := dnsServer.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DoT server: %v", err)
	}
}

// handleDNSRequest processes each incoming DNS query.
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		// TODO: add blocklist check here later
		log.Printf("Query for %s %s", q.Name, dns.TypeToString[q.Qtype])
	}

	// Forward to upstream resolver
	resp, err := forwardQuery(r)
	if err != nil {
		log.Printf("Upstream error: %v", err)
		dns.HandleFailed(w, r)
		return
	}
	w.WriteMsg(resp)
}

// forwardQuery sends the DNS query to an upstream resolver.
func forwardQuery(r *dns.Msg) (*dns.Msg, error) {
	c := new(dns.Client)
	c.Timeout = 3 * time.Second
	in, _, err := c.Exchange(r, upstream)
	return in, err
}
