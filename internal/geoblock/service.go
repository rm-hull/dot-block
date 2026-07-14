package geoblock

import (
	"log/slog"
	"net/netip"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/oschwald/maxminddb-golang/v2"
)

type GeoData struct {
	ISOCode  string `maxminddb:"country_code" json:"iso_code"`
	Country  string `maxminddb:"country" json:"country"`
	ASN      string `maxminddb:"asn" json:"asn"`
	Provider string `maxminddb:"as_name" json:"provider"`
	Domain   string `maxminddb:"as_domain" json:"domain"`
}

type GeoIpLookup interface {
	Reopen() error
	GetAll(ipAddr string) (*GeoData, error)
	IsValid(ipAddr string) bool
}

type geoBlocker struct {
	path   string
	db     *maxminddb.Reader
	logger *slog.Logger
	mu     sync.RWMutex
}

func NewGeoIpLookup(path string, logger *slog.Logger) (GeoIpLookup, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &geoBlocker{
		path:   path,
		db:     db,
		logger: logger,
	}, nil
}

func (g *geoBlocker) Reopen() error {
	newDb, err := maxminddb.Open(g.path)
	if err != nil {
		return err
	}

	g.mu.Lock()
	oldDb := g.db
	g.db = newDb
	g.mu.Unlock()

	if oldDb != nil {
		if err := oldDb.Close(); err != nil {
			g.logger.Warn("failed to close old geoblock database", "error", err)
		}
	}
	return nil
}

func (g *geoBlocker) GetAll(ipAddr string) (*GeoData, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.db == nil {
		return nil, errors.New("geoblock database not initialized")
	}

	ip, err := netip.ParseAddr(ipAddr)
	if err != nil {
		return nil, errors.Wrap(err, "invalid IP address")
	}

	var geodata GeoData
	err = g.db.Lookup(ip).Decode(&geodata)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	if geodata.ISOCode == "" && geodata.Country == "" && geodata.ASN == "" && geodata.Provider == "" && geodata.Domain == "" {
		return nil, nil
	}

	return &geodata, nil
}

func (g *geoBlocker) IsValid(ipAddr string) bool {
	_, err := netip.ParseAddr(ipAddr)
	return err == nil
}
