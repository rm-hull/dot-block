package mobileconfig

import (
	"bytes"
	"net/http"

	"github.com/gin-gonic/gin"
	"howett.net/plist"
)

const ROOT_PAYLOAD_UUID = "5ac4b893-0095-4bea-afeb-5dc00025f4c1"
const DNS_PAYLOAD_UUID = "bc0e0b3a-ef87-4f23-b8b1-f8383f6f5c66"

func Handler(dataDir string) gin.HandlerFunc {

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
					ServerName:      "dot.destructuring-bind.org",
					ServerAddresses: []string{"192.241.203.173"}, // FIXME: generate from DNS lookup
				},
			},
		},
	}

	buf := new(bytes.Buffer)
	enc := plist.NewEncoder(buf)
	enc.Indent("  ")

	err := enc.Encode(profile)

	return func(c *gin.Context) {
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}

		c.Header("Content-Disposition", "attachment; filename=\"dot-block.mobileconfig\"")
		c.Data(http.StatusOK, "application/x-apple-aspen-config", buf.Bytes())
	}
}
