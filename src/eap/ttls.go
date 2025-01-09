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

const ttlsMasterKeyLabel = "ttls keying material"

type TTLS struct {
	*TLS
	client *tls.Conn
}

func CreateTTLS(session *Session, caCert, tlsVersion string) (*TTLS, error) {
	t, err := internalCreateTLS(session, caCert, tlsVersion, TypeTTLS)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		RootCAs:                t.rootCAs,
		InsecureSkipVerify:     true,
		MinVersion:             t.tlsVersion,
		MaxVersion:             t.tlsVersion,
		SessionTicketsDisabled: true,
	}
	return &TTLS{TLS: t, client: tls.Client(t, tlsConfig)}, nil
}

func (tt *TTLS) PAP(uname, pw string) error {
	bw := bufio.NewWriter(tt.client)
	_, err := diameter.AttributeValuePair{
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

	// auth finalization
	rd := &Datagram{}
	_, err = tt.ReadDatagram(rd)
	if err != nil {
		return err
	}
	if rd.Header.Code != CodeSuccess {
		return fmt.Errorf("authentication failed")
	}
	tt.RecvKey, tt.SendKey, err = exportKeyingMaterial(tt.client, ttlsMasterKeyLabel)
	return err
}

func (tt *TTLS) Close() error {
	var err error
	tt.RecvKey, tt.SendKey, err = exportKeyingMaterial(tt.client, ttlsMasterKeyLabel)
	if err != nil {
		return err
	}
	return tt.TLS.Close()
}
