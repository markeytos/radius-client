/*
Copyright © 2024 Keytos alan@keytos.io

Define Protected EAP tunnel
*/
package eap

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
)

type PEAP struct {
	*TLS
	client *tls.Conn
}

func CreatePEAP(session *Session, caCert, tlsVersion string) (*PEAP, error) {
	t, err := internalCreateTLS(session, caCert, tlsVersion, TypePEAP)
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
	return &PEAP{TLS: t, client: tls.Client(t, tlsConfig)}, nil
}

func (tt *PEAP) MaxDataSize() int {
	return 10000
}

func (tt *PEAP) Read(b []byte) (int, error) {
	n, err := tt.client.Read(b[4:])
	if err != nil {
		return n, err
	}
	n += 4
	b[0] = byte(CodeRequest)
	b[1] = tt.identifier + 1
	binary.BigEndian.PutUint16(b[2:4], uint16(n))
	return n, nil
}

func (tt *PEAP) Write(b []byte) (int, error) {
	if len(b) == 0 {
		err := tt.client.Handshake()
		if err != nil {
			return 0, err
		}
		wd := tt.newDatagram(&Content{Type: tt.packetType, Data: []byte{0}})
		_, err = tt.WriteDatagram(wd)
		return 0, err
	}
	d := &Datagram{}
	err := d.Deserialize(b)
	if err != nil {
		return 0, err
	}
	return tt.client.Write(b[4:])
}

func (tt *PEAP) Close() error {
	rd := &Datagram{}
	_, err := rd.ReadFrom(tt.client)
	if err != nil {
		return err
	}
	if rd.Header.Code != CodeRequest || rd.Content.Type != TypeExtensions {
		return fmt.Errorf("peap: expected extension packet on close")
	}
	success := bytes.Equal(rd.Content.Data, []byte{0x80, 3, 0, 2, 0, 1})
	ret := byte(1)
	if !success {
		ret = 2
	}

	wd := newDatagram(&Header{Code: CodeResponse, Identifier: rd.Header.Identifier, Length: 4}, &Content{Type: TypeExtensions, Data: []byte{0x80, 3, 0, 2, 0, ret}})
	_, err = wd.WriteTo(tt.client)
	if err != nil {
		return err
	}
	_, err = tt.ReadDatagram(rd)
	if err != nil {
		return err
	}

	tt.RecvKey, tt.SendKey, err = exportKeyingMaterial(tt.client, eapMasterKeyLabel)
	return err
}
