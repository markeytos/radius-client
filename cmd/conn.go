/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/markeytos/radius-client/radius"
)

const (
	defaultMTUSize = 1500
)

func dialUDP(ip string, port int) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.Dial("udp", fmt.Sprintf("%s:%d", ip, port))
}

func dialTLS(address, serverCA, clientCer string) (*tls.Conn, error) {
	content, err := os.ReadFile(serverCA)
	if err != nil {
		return nil, err
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(content)

	var cert []byte
	var privKey crypto.PrivateKey
	content, err = os.ReadFile(clientCer)
	if err != nil {
		return nil, err
	}
	for block, rest := pem.Decode(content); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			cert = block.Bytes
		case "RSA PRIVATE KEY":
			privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		case "PRIVATE KEY":
			privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("unknown block type")
		}
	}

	c := &tls.Config{
		Certificates: []tls.Certificate{tls.Certificate{
			Certificate: [][]byte{cert},
			PrivateKey:  privKey,
		}},
		RootCAs:            rootCAs,
		InsecureSkipVerify: radsecUnsafe,
	}

	if !strings.ContainsRune(address, ':') {
		address = fmt.Sprintf("%s:%d", address, tcpPort)
	}

	conn, err := tls.Dial("tcp", address, c)
	if err != nil {
		return nil, err
	}
	return conn, conn.Handshake()
}

func newUDPAuthSession(address, sharedSecret string) (*radius.AuthenticationSession, error) {
	to, err := time.ParseDuration(udpTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid timeout value: %w", err)
	}
	conn, err := dialUDP(address, udpAuthPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}
	sendAttrs := map[radius.AttributeType]string{
		radius.AttributeTypeNasIdentifier: "radius-client",
		radius.AttributeTypeFramedMtu:     strconv.Itoa(defaultMTUSize),
	}
	return radius.NewAuthenticationSession(conn, sharedSecret, to, udpRetries, defaultMTUSize, sendAttrs)
}

func newUDPAcctSession(address, sharedSecret string) (*radius.AccountingSession, error) {
	to, err := time.ParseDuration(udpTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid timeout value: %w", err)
	}
	conn, err := dialUDP(address, udpAcctPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}
	return radius.NewAccountingSession(conn, sharedSecret, to, udpRetries), nil
}

func newTLSAuthSession(address, serverCA, clientCer string) (*radius.AuthenticationSession, error) {
	to, err := time.ParseDuration(tlsTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid timeout value: %w", err)
	}
	conn, err := dialTLS(address, serverCA, clientCer)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}
	sendAttrs := map[radius.AttributeType]string{
		radius.AttributeTypeNasIdentifier: "radius-client",
	}
	return radius.NewAuthenticationSession(conn, "radsec", to, 1, radius.DatagramMaxLen, sendAttrs)
}

func newTLSAcctSession(address, serverCA, clientCer string) (*radius.AccountingSession, error) {
	to, err := time.ParseDuration(tlsTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid timeout value: %w", err)
	}
	conn, err := dialTLS(address, serverCA, clientCer)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}
	return radius.NewAccountingSession(conn, "radsec", to, 1), nil
}
