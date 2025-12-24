package mobileconfig

import (
	"bytes"
	"net"
	"net/http"

	"github.com/cockroachdb/errors"
	"github.com/gin-gonic/gin"
	"howett.net/plist"
)

const ROOT_PAYLOAD_UUID = "5ac4b893-0095-4bea-afeb-5dc00025f4c1"
const DNS_PAYLOAD_UUID = "bc0e0b3a-ef87-4f23-b8b1-f8383f6f5c66"

func NewHandler(serverName string) (gin.HandlerFunc, error) {
	ips, err := net.LookupHost(serverName)
	if err != nil {
		return nil, err
	}

	profile := Profile{
		PayloadType:         "Configuration",
		PayloadVersion:      2,
		PayloadIdentifier:   "org.destructuring-bind.dot.profile",
		PayloadUUID:         ROOT_PAYLOAD_UUID,
		PayloadDisplayName:  "dot-block DNS",
		PayloadScope:        "System",
		PayloadDescription:  "Configures system-wide DNS over TLS with ad and malware blocking.",
		PayloadOrganization: "Destructuring Bind Ltd",

		PayloadContent: []DNSSpec{
			{
				PayloadType:         "com.apple.dnsSettings.managed",
				PayloadVersion:      1,
				PayloadIdentifier:   "org.destructuring-bind.dot.profile.dnsSettings.managed",
				PayloadUUID:         DNS_PAYLOAD_UUID,
				PayloadDisplayName:  "Encrypted DNS",
				PayloadOrganization: "Destructuring Bind Ltd",
				DNSSettings: DNSBlock{
					DNSProtocol:     "TLS",
					ServerName:      serverName,
					ServerAddresses: ips,
				},
			},
		},
	}

	buf := new(bytes.Buffer)
	enc := plist.NewEncoder(buf)
	enc.Indent("  ")

	err = enc.Encode(profile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode profile")
	}

	return func(c *gin.Context) {
		c.Header("Content-Disposition", "attachment; filename=\"dot-block.mobileconfig\"")
		c.Data(http.StatusOK, "application/x-apple-aspen-config", buf.Bytes())
	}, nil
}
