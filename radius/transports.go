/*
Copyright © 2024 Keytos alan@keytos.io

RADIUS transport helpers
*/
package radius

// RADIUS network ports
const (
	UDPAuthenticationPort = 1812 // https://datatracker.ietf.org/doc/html/rfc2865#section-3
	UDPAccountingPort     = 1813 // https://datatracker.ietf.org/doc/html/rfc2866#section-3
	RadSecTCPPort         = 2083 // https://datatracker.ietf.org/doc/html/rfc6614#section-2.1
)
