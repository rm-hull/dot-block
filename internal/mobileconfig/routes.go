package mobileconfig

import (
	"bytes"
	"net/http"

	"github.com/gin-gonic/gin"
	"howett.net/plist"
)

const PAYLOAD_UUID = "5ac4b893-0095-4bea-afeb-5dc00025f4c1"

func Handler(dataDir string) gin.HandlerFunc {

	profile := Profile{
		PayloadType:         "Configuration",
		PayloadVersion:      1,
		PayloadIdentifier:   "org.destructuring-bind.dot.profile",
		PayloadUUID:         PAYLOAD_UUID,
		PayloadDisplayName:  "dot-block (destructuring-bind)",
		PayloadDescription:  "Configures system-wide DNS over TLS with ad and malware blocking.",
		PayloadOrganization: "Destructuring Bind Ltd",

		PayloadContent: []DNSSpec{
			{
				PayloadType:        "com.apple.dnsSettings.managed",
				PayloadVersion:     1,
				PayloadIdentifier:  "org.destructuring-bind.dot",
				PayloadUUID:        PAYLOAD_UUID,
				PayloadDisplayName: "Encrypted DNS",
				DNSSettings: DNSBlock{
					DNSProtocol:     "TLS",
					ServerAddresses: []string{"dot.destructuring-bind.org"}, // FIXME: generate from config or servername
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

		c.Header("Content-Disposition", "attachment; filename=\"dns.mobileconfig\"")
		c.Data(http.StatusOK, "application/x-apple-aspen-config", buf.Bytes())
	}
}
