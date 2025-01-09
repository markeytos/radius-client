/*
Copyright © 2024 Keytos alan@keytos.io

Define TLS authentication session
*/
package eap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	eaptls "github.com/markeytos/radius-client/src/eap/tls"
)

const (
	eapMasterKeyLabel = "client EAP encryption"
)

func exportKeyingMaterial(client *tls.Conn, label string) (recv, send []byte, err error) {
	connState := client.ConnectionState()
	km, err := connState.ExportKeyingMaterial(label, nil, 128)
	if err != nil {
		return nil, nil, err
	}
	recv, send = km[:32], km[32:64]
	return
}

type TLS struct {
	*Session
	rootCAs    *x509.CertPool
	tlsVersion uint16
	packetType Type
	readBuffer []byte
	readMore   bool
}

func CreateTLS(session *Session, caCert, tlsVersion string) (*TLS, error) {
	return internalCreateTLS(session, caCert, tlsVersion, TypeTLS)
}

func internalCreateTLS(session *Session, caCert, tlsVersion string, pt Type) (*TLS, error) {
	content, err := os.ReadFile(caCert)
	if err != nil {
		return nil, err
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(content)

	var tlsv uint16
	switch tlsVersion {
	case "1.2":
		tlsv = tls.VersionTLS12
	case "1.3":
		tlsv = tls.VersionTLS13
	default:
		tlsv = tls.VersionTLS12
	}

	err = session.start(pt)
	if err != nil {
		return nil, err
	}

	return &TLS{
		Session:    session,
		rootCAs:    rootCAs,
		tlsVersion: tlsv,
		packetType: pt,
	}, nil
}

func (tt *TLS) Authenticate(certpath string) error {
	cert, err := tls.LoadX509KeyPair(certpath, certpath)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{
		RootCAs:            tt.rootCAs,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		MinVersion:         tt.tlsVersion,
		MaxVersion:         tt.tlsVersion,
	}
	tc := tls.Client(tt, tlsConfig)
	authErr := tc.Handshake()

	wd := tt.newDatagram(&Content{Type: tt.packetType, Data: []byte{0}})
	_, err = tt.WriteDatagram(wd)
	if err != nil {
		return err
	}

	if tt.inEncryptedTunnel {
		return tt.Tunnel.Close()
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
	if authErr == nil {
		tt.RecvKey, tt.SendKey, err = exportKeyingMaterial(tc, eapMasterKeyLabel)
		if err != nil {
			return err
		}
	}

	return authErr
}

func (tt *TLS) Read(b []byte) (int, error) {
	n := 0
	if len(tt.readBuffer) > 0 {
		n = copy(b, tt.readBuffer)
		tt.readBuffer = tt.readBuffer[n:]
		if n == len(b) {
			return n, nil
		}
		b = b[n:]
	}

	for len(b) > 0 {
		rd := &Datagram{}
		switch tt.lastAction {
		case sessionLastActionWriteDatagram:
			_, err := tt.ReadDatagram(rd)
			if err != nil {
				return n, fmt.Errorf("eap tls: %w", err)
			}
		case sessionLastActionNone, sessionLastActionReadDatagram:
			if !tt.readMore {
				if n == 0 {
					return n, fmt.Errorf("eap tls: no packets in session")
				}
				return n, nil
			}
			wd := tt.newDatagram(&Content{Type: tt.packetType, Data: []byte{0}})
			err := tt.WriteReadDatagram(wd, rd)
			if err != nil {
				return n, err
			}
		default:
			return n, fmt.Errorf("eap tls: last action was error")
		}

		switch rd.Header.Code {
		case CodeResponse:
			return n, fmt.Errorf("eap tls: server sent a response packet")
		case CodeFailure:
			return n, fmt.Errorf("eap tls: server sent a failure packet")
		}
		if rd.Content == nil {
			return n, fmt.Errorf("eap tls: server did not send EAP with content")
		}
		if rd.Content.Type != tt.packetType {
			return n, fmt.Errorf("eap tls: server sent a packet of unexpected EAP type")
		}
		data := eaptls.CreateDataFromBuffer(rd.Content.Data)
		tt.readMore = data.Flags&eaptls.FlagsMore != 0
		tt.readBuffer = data.Data

		cn := copy(b, tt.readBuffer)
		b = b[cn:]
		tt.readBuffer = tt.readBuffer[cn:]
		n += cn
	}

	return n, nil
}

func (tt *TLS) Write(b []byte) (n int, err error) {
	data := &eaptls.Data{
		Flags: eaptls.FlagsStart,
		Data:  b,
	}
	wd := tt.newDatagram(&Content{Type: tt.packetType, Data: data.ToBinary()})
	return tt.WriteDatagram(wd)
}

func (tt *TLS) Close() error {
	if tt.lastAction != sessionLastActionWriteDatagram {
		return fmt.Errorf("eap tls: invalid state to close: %d", tt.lastAction)
	}
	rd := &Datagram{}
	_, err := tt.ReadDatagram(rd)
	return err
}

func (tt *TLS) LocalAddr() net.Addr {
	return tt.Tunnel.LocalAddr()
}

func (tt *TLS) RemoteAddr() net.Addr {
	return tt.Tunnel.RemoteAddr()
}

func (tt *TLS) SetDeadline(t time.Time) error {
	return tt.Tunnel.SetDeadline(t)
}

func (tt *TLS) SetReadDeadline(t time.Time) error {
	return tt.Tunnel.SetReadDeadline(t)
}

func (tt *TLS) SetWriteDeadline(t time.Time) error {
	return tt.Tunnel.SetWriteDeadline(t)
}
