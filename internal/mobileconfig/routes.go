package mobileconfig

import (
	"bytes"
	"net"
	"net/http"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"howett.net/plist"
)

const ROOT_PAYLOAD_UUID = "5ac4b893-0095-4bea-afeb-5dc00025f4c1"
const DNS_PAYLOAD_UUID = "bc0e0b3a-ef87-4f23-b8b1-f8383f6f5c66"

func NewHandler(serverName string) gin.HandlerFunc {

	rootPayloadIdentifier := invertServerName(serverName) + ".profile"
	dnsPayloadIdentifier := rootPayloadIdentifier + ".dnsSettings.managed"
	rootUUID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(rootPayloadIdentifier))
	dnsUUID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(dnsPayloadIdentifier))

	return func(c *gin.Context) {
		ips, err := net.LookupHost(serverName)
		if err != nil {
			_ = c.AbortWithError(
				http.StatusInternalServerError,
				errors.Wrapf(err, "failed to lookup IP addr for %s", serverName))

			return
		}

		profile := Profile{
			PayloadType:         "Configuration",
			PayloadVersion:      2,
			PayloadIdentifier:   rootPayloadIdentifier,
			PayloadUUID:         rootUUID,
			PayloadDisplayName:  "dot-block DNS",
			PayloadScope:        "System",
			PayloadDescription:  "Configures system-wide DNS over TLS with ad and malware blocking.",
			PayloadOrganization: "Destructuring Bind Ltd",

			PayloadContent: []DNSSpec{
				{
					PayloadType:         "com.apple.dnsSettings.managed",
					PayloadVersion:      1,
					PayloadIdentifier:   dnsPayloadIdentifier,
					PayloadUUID:         dnsUUID,
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
			_ = c.AbortWithError(
				http.StatusInternalServerError,
				errors.Wrap(err, "failed to encode profile"))

			return
		}

		c.Header("Content-Disposition", "attachment; filename=\"dot-block.mobileconfig\"")
		c.Data(http.StatusOK, "application/x-apple-aspen-config", buf.Bytes())
	}
}

func invertServerName(fqdn string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	parts := strings.Split(fqdn, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}
