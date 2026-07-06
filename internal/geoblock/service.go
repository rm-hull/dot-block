package geoblock

import (
	"sync"

	"net"

	"github.com/cockroachdb/errors"
	"github.com/oschwald/geoip2-golang"
)

type GeoData struct {
	Country string
	ASN     uint
	ISP     string
}

type GeoIpLookup interface {
	Reopen() error
	GetAll(ipAddress string) (GeoData, error)
}

type geoBlocker struct {
	path string
	db   *geoip2.Reader
	mu   sync.RWMutex
}

func NewGeoIpLookup(path string) (GeoIpLookup, error) {
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &geoBlocker{
		path: path,
		db:   db,
	}, nil
}

func (g *geoBlocker) Reopen() error {
	newDb, err := geoip2.Open(g.path)
	if err != nil {
		return err
	}

	g.mu.Lock()
	oldDb := g.db
	g.db = newDb
	g.mu.Unlock()

	if oldDb != nil {
		oldDb.Close()
	}
	return nil
}

func (g *geoBlocker) GetAll(ipAddress string) (GeoData, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.db == nil {
		return GeoData{}, errors.New("geoblock database not initialized")
	}

	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return GeoData{}, errors.New("invalid IP address")
	}

	city, err := g.db.City(ip)
	if err != nil {
		return GeoData{}, err
	}

	asn, err := g.db.ASN(ip)
	if err != nil {
		// Log or handle ASN lookup failure if needed, or just proceed
	}

	var asnNumber uint
	var isp string
	if asn != nil {
		asnNumber = asn.AutonomousSystemNumber
		isp = asn.AutonomousSystemOrganization
	}

	return GeoData{
		Country: city.Country.IsoCode,
		ASN:     asnNumber,
		ISP:     isp,
	}, nil
}
