package eap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// Run a real TLS handshake so that the exporter is checked against both peers.
func testTLSConnections(t *testing.T, version uint16) (*tls.Conn, *tls.Conn) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "radius.example.test"},
		DNSNames:     []string{"radius.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		serverConn.Close()
		clientConn.Close()
	})
	server := tls.Server(serverConn, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   version,
		MaxVersion:   version,
	})
	client := tls.Client(clientConn, &tls.Config{
		RootCAs:    roots,
		ServerName: "radius.example.test",
		MinVersion: version,
		MaxVersion: version,
	})

	errs := make(chan error, 1)
	go func() { errs <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestEAPTLSKeyDerivation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version uint16
		label   string
		context []byte
	}{
		{"TLS1.2", tls.VersionTLS12, "client EAP encryption", nil},
		{"TLS1.3", tls.VersionTLS13, "EXPORTER_EAP_TLS_Key_Material", []byte{13}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := testTLSConnections(t, tc.version)
			recv, send, err := exportEAPTLSKeyingMaterial(client)
			if err != nil {
				t.Fatal(err)
			}
			serverState := server.ConnectionState()
			expected, err := serverState.ExportKeyingMaterial(tc.label, tc.context, 128)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(recv, expected[:32]) || !bytes.Equal(send, expected[32:64]) {
				t.Fatal("EAP-TLS key material does not match the server")
			}
			if tc.version == tls.VersionTLS13 {
				clientState := client.ConnectionState()
				legacy, err := clientState.ExportKeyingMaterial("client EAP encryption", nil, 128)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(recv, legacy[:32]) {
					t.Fatal("TLS 1.3 incorrectly used the TLS 1.2 exporter")
				}
			}
		})
	}
}
