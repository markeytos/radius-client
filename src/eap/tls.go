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
)

type TLS struct {
	*Session
	clientCertificate tls.Certificate
	rootCAs           *x509.CertPool
}

func CreateTLS(session *Session, clientCert, caCert string) (*TLS, error) {
	content, err := os.ReadFile(caCert)
	if err != nil {
		return nil, err
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(content)

	cert, err := tls.LoadX509KeyPair(clientCert, clientCert)
	if err != nil {
		return nil, err
	}

	return &TLS{Session: session, clientCertificate: cert, rootCAs: rootCAs}, nil
}

func (tt *TLS) Authenticate() error {
	err := tt.start(TypeTLS)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		RootCAs:            tt.rootCAs,
		Certificates:       []tls.Certificate{tt.clientCertificate},
		InsecureSkipVerify: true,
	}
	tc := tls.Client(tt, tlsConfig)
	return tc.Handshake()
}

func (tt TLS) Read(b []byte) (n int, err error) {
	return 0, fmt.Errorf("read not implemented")
}

func (tt TLS) Write(b []byte) (n int, err error) {
	return 0, fmt.Errorf("write not implemented")
}

func (tt TLS) Close() error {
	return fmt.Errorf("close not implemented")
}

func (tt TLS) LocalAddr() net.Addr {
	return nil
}

func (tt TLS) RemoteAddr() net.Addr {
	return nil
}

func (tt TLS) SetDeadline(t time.Time) error {
	return nil
}

func (tt TLS) SetReadDeadline(t time.Time) error {
	return nil
}

func (tt TLS) SetWriteDeadline(t time.Time) error {
	return nil
}
