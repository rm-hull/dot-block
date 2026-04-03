package geoblock

import (
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/ip2location/ip2location-go/v9"
)

type GeoIpLookup interface {
	Reopen() error
	GetAll(ipAddress string) (ip2location.IP2Locationrecord, error)
}

type geoBlocker struct {
	path string
	db   *ip2location.DB
	mu   sync.RWMutex
}

func NewGeoIpLookup(path string) (GeoIpLookup, error) {
	db, err := ip2location.OpenDB(path)
	if err != nil {
		return nil, err
	}
	return &geoBlocker{
		path: path,
		db:   db,
	}, nil
}

func (g *geoBlocker) Reopen() error {
	newDb, err := ip2location.OpenDB(g.path)
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

func (g *geoBlocker) GetAll(ipAddress string) (ip2location.IP2Locationrecord, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.db == nil {
		return ip2location.IP2Locationrecord{}, errors.New("geoblock database not initialized")
	}

	return g.db.Get_all(ipAddress)
}
