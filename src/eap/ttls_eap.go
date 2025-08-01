/*
Copyright © 2024 Keytos alan@keytos.io

Define Tunneled-TLS EAP tunnel
*/
package eap

import (
	"fmt"

	"github.com/markeytos/radius-client/src/eap/diameter"
)

type TtlsEAP struct {
	*TTLS
}

func CreateTtlsEAP(session *Session, caCert, tlsVersion, serverName, tlsTunnelKeyLogFilename string, tlsSkipHostnameCheck bool) (*TtlsEAP, error) {
	ttls, err := CreateTTLS(session, caCert, tlsVersion, serverName, tlsTunnelKeyLogFilename, tlsSkipHostnameCheck)
	return &TtlsEAP{ttls}, err
}

func (tt *TtlsEAP) MaxDataSize() int {
	return 10000
}

func (tt *TtlsEAP) Read(b []byte) (int, error) {
	d := &diameter.AttributeValuePair{}
	n, err := d.ReadFrom(tt.client)
	if err != nil {
		return int(n), err
	}
	if d.Code != diameter.CodeEapMessage {
		return int(n), fmt.Errorf("ttls eap: did not receive EAP message")
	}
	return copy(b, d.Data), nil
}

func (tt *TtlsEAP) Write(b []byte) (int, error) {
	n, err := diameter.AttributeValuePair{
		Code:  diameter.CodeEapMessage,
		Flags: diameter.FlagsMandatory,
		Data:  b,
	}.WriteTo(tt.client)
	return int(n), err
}
