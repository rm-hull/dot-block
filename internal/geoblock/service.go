package geoblock

import "github.com/ip2location/ip2location-go/v9"

type GeoIpLookup interface {
	Get_all(ipAddress string) (ip2location.IP2Locationrecord, error)
}
