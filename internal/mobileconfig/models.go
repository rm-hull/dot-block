package mobileconfig

type Profile struct {
	PayloadType         string    `plist:"PayloadType"`
	PayloadVersion      int       `plist:"PayloadVersion"`
	PayloadIdentifier   string    `plist:"PayloadIdentifier"`
	PayloadUUID         string    `plist:"PayloadUUID"`
	PayloadDisplayName  string    `plist:"PayloadDisplayName"`
	PayloadOrganization string    `plist:"PayloadOrganization,omitempty"`
	PayloadDescription  string    `plist:"PayloadDescription,omitempty"`
	PayloadContent      []DNSSpec `plist:"PayloadContent"`
}

type DNSSpec struct {
	PayloadType         string   `plist:"PayloadType"`
	PayloadVersion      int      `plist:"PayloadVersion"`
	PayloadIdentifier   string   `plist:"PayloadIdentifier"`
	PayloadUUID         string   `plist:"PayloadUUID"`
	PayloadDisplayName  string   `plist:"PayloadDisplayName"`
	PayloadOrganization string   `plist:"PayloadOrganization,omitempty"`
	PayloadDescription  string   `plist:"PayloadDescription,omitempty"`
	DNSSettings         DNSBlock `plist:"DNSSettings"`
}

type DNSBlock struct {
	DNSProtocol     string   `plist:"DNSProtocol"`
	ServerAddresses []string `plist:"ServerAddresses,omitempty"` // DoT
	ServerURL       string   `plist:"ServerURL,omitempty"`       // DoH
}
