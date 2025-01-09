/*
Copyright © 2024 Keytos alan@keytos.io

Define Tunneled-TLS authentication session
*/
package eap

import (
	"bufio"
	"crypto/tls"
	"fmt"

	"github.com/markeytos/radius-client/src/eap/diameter"
)

type TTLS struct {
	*TLS
}

func CreateTTLS(session *Session, caCert, tlsVersion string) (*TTLS, error) {
	tls, err := CreateTLS(session, caCert, tlsVersion)
	tls.packetType = TypeTTLS
	return &TTLS{tls}, err
}

func (tt *TTLS) PAP(uname, pw string) error {
	err := tt.start(TypeTTLS)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		RootCAs:            tt.rootCAs,
		InsecureSkipVerify: true,
		MinVersion:         tt.tlsVersion,
		MaxVersion:         tt.tlsVersion,
	}
	tc := tls.Client(tt, tlsConfig)
	bw := bufio.NewWriter(tc)

	_, err = diameter.AttributeValuePair{
		Code:  diameter.CodeUserName,
		Flags: diameter.FlagsMandatory,
		Data:  []byte(uname),
	}.WriteTo(bw)
	if err != nil {
		return err
	}

	_, err = diameter.AttributeValuePair{
		Code:  diameter.CodeUserPassword,
		Flags: diameter.FlagsMandatory,
		Data:  []byte(pw),
	}.WriteTo(bw)
	if err != nil {
		return err
	}

	err = bw.Flush()
	if err != nil {
		return err
	}

	rd := &Datagram{}
	_, err = tt.ReadDatagram(rd)
	if err != nil {
		return err
	}
	if rd.Header.Code != CodeSuccess {
		return fmt.Errorf("authentication failed")
	}

	// extract key material
	connState := tc.ConnectionState()
	km, err := connState.ExportKeyingMaterial("ttls keying material", nil, 128)
	if err != nil {
		return err
	}
	tt.RecvKey = km[:32]
	tt.SendKey = km[32:64]
	return nil
}
