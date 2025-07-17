/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/markeytos/radius-client/src/radius"
)

type statusSession interface {
	net.Conn
	Status() error
}

func dialUDP(ip string, port int) (net.Conn, error) {
	d := net.Dialer{
		LocalAddr: &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: 0,
		},
		Timeout: 10 * time.Second,
	}
	return d.Dial("udp", fmt.Sprintf("%s:%d", ip, port))
}

func dialTLS(address, caCert, clientCert string) (*tls.Conn, error) {
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
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            rootCAs,
		InsecureSkipVerify: radsecUnsafe,
	}

	if !strings.ContainsRune(address, ':') {
		address = fmt.Sprintf("%s:%d", address, tcpPort)
	}

	conn, err := tls.Dial("tcp", address, tlsConfig)
	if err != nil {
		return nil, err
	}
	return conn, conn.Handshake()
}

func newUDPAuthSession(address, sharedSecret string, mtuSize int, sendattrs, recvattrs radius.AttributeMap) (*radius.AuthenticationSession, error) {
	conn, err := dialUDP(address, udpAuthPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}
	if _, ok := sendattrs[radius.AttributeTypeNasIdentifier]; !ok {
		sendattrs[radius.AttributeTypeNasIdentifier] = []string{"radius-client"}
	}
	sendattrs[radius.AttributeTypeFramedMtu] = []string{strconv.Itoa(mtuSize)}
	return radius.NewAuthenticationSession(conn, sharedSecret, udpTimeout, maxWriteJitter, udpRetries, mtuSize, sendattrs, recvattrs)
}

func newUDPAcctSession(address, sharedSecret string, mtuSize int, sendattrs, recvattrs radius.AttributeMap) (*radius.AccountingSession, error) {
	conn, err := dialUDP(address, udpAcctPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}
	if _, ok := sendattrs[radius.AttributeTypeNasIdentifier]; !ok {
		sendattrs[radius.AttributeTypeNasIdentifier] = []string{"radius-client"}
	}
	sendattrs[radius.AttributeTypeFramedMtu] = []string{strconv.Itoa(mtuSize)}
	return radius.NewAccountingSession(conn, sharedSecret, udpTimeout, maxWriteJitter, udpRetries, mtuSize, sendattrs, recvattrs)
}

func newTLSAuthSession(address, serverCA, clientCer string, sendattrs, recvattrs radius.AttributeMap) (*radius.AuthenticationSession, error) {
	conn, err := dialTLS(address, serverCA, clientCer)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}
	if _, ok := sendattrs[radius.AttributeTypeNasIdentifier]; !ok {
		sendattrs[radius.AttributeTypeNasIdentifier] = []string{"radius-client"}
	}
	return radius.NewAuthenticationSession(conn, "radsec", tlsTimeout, maxWriteJitter, 1, radius.DatagramMaxLen, sendattrs, recvattrs)
}

func newTLSAcctSession(address, serverCA, clientCer string, sendattrs, recvattrs radius.AttributeMap) (*radius.AccountingSession, error) {
	conn, err := dialTLS(address, serverCA, clientCer)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}
	if _, ok := sendattrs[radius.AttributeTypeNasIdentifier]; !ok {
		sendattrs[radius.AttributeTypeNasIdentifier] = []string{"radius-client"}
	}
	return radius.NewAccountingSession(conn, "radsec", tlsTimeout, maxWriteJitter, 1, radius.DatagramMaxLen, sendattrs, recvattrs)
}
