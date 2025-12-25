package mobileconfig

import "github.com/google/uuid"

type Profile struct {
	PayloadType         string    `plist:"PayloadType"`
	PayloadVersion      int       `plist:"PayloadVersion"`
	PayloadIdentifier   string    `plist:"PayloadIdentifier"`
	PayloadScope        string    `plist:"PayloadScope"`
	PayloadUUID         uuid.UUID `plist:"PayloadUUID"`
	PayloadDisplayName  string    `plist:"PayloadDisplayName"`
	PayloadOrganization string    `plist:"PayloadOrganization,omitempty"`
	PayloadDescription  string    `plist:"PayloadDescription,omitempty"`
	PayloadContent      []DNSSpec `plist:"PayloadContent"`
}

type DNSSpec struct {
	PayloadType         string         `plist:"PayloadType"`
	PayloadVersion      int            `plist:"PayloadVersion"`
	PayloadIdentifier   string         `plist:"PayloadIdentifier"`
	PayloadUUID         uuid.UUID      `plist:"PayloadUUID"`
	PayloadDisplayName  string         `plist:"PayloadDisplayName"`
	PayloadOrganization string         `plist:"PayloadOrganization,omitempty"`
	PayloadDescription  string         `plist:"PayloadDescription,omitempty"`
	DNSSettings         DNSBlock       `plist:"DNSSettings"`
	OnDemandRules       []OnDemandRule `plist:"OnDemandRules,omitempty"`
}

type DNSBlock struct {
	DNSProtocol     string   `plist:"DNSProtocol"`
	ServerName      string   `plist:"ServerName,omitempty"`
	ServerAddresses []string `plist:"ServerAddresses,omitempty"` // DoT
	ServerURL       string   `plist:"ServerURL,omitempty"`       // DoH
}

type OnDemandRule struct {
	Action           string            `plist:"Action"`
	ActionParameters []ActionParameter `plist:"ActionParameters,omitempty"`
}

type ActionParameter struct {
	DomainAction string   `plist:"DomainAction"`
	Domains      []string `plist:"Domains"`
}

type OnDemandRules []OnDemandRule
