/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/markeytos/radius-client/src/eap"
	"github.com/markeytos/radius-client/src/radius"
	"github.com/spf13/cobra"
)

// authentication protocols
const (
	authMAB                = "mab"
	authMabEapMd5          = "mab-eap-md5"
	authPAP                = "pap"
	authEapMsCHAPv2        = "eap-ms-chapv2"
	authEapTLS             = "eap-tls"
	authEapTtlsPAP         = "eap-ttls-pap"
	authEapTtlsEapMsCHAPv2 = "eap-ttls-eap-ms-chapv2"
	authEapTtlsEapTLS      = "eap-ttls-eap-tls"
	authPeapMsCHAPv2       = "peap-ms-chapv2"
)

// required values for protocols
// no sets in go, so using maps with empty structs
var (
	requireMACAddress = map[string]struct{}{
		authMAB:       {},
		authMabEapMd5: {},
	}
	requireUsernameAndPassword = map[string]struct{}{
		authPAP:                {},
		authEapMsCHAPv2:        {},
		authEapTtlsPAP:         {},
		authEapTtlsEapMsCHAPv2: {},
		authPeapMsCHAPv2:       {},
	}
	requireClientAndCACertificate = map[string]struct{}{
		authEapTLS:        {},
		authEapTtlsEapTLS: {},
	}
	requireTunneledCACertificate = map[string]struct{}{
		authEapTtlsPAP:         {},
		authEapTtlsEapMsCHAPv2: {},
		authEapTtlsEapTLS:      {},
		authPeapMsCHAPv2:       {},
	}
)

var (
	macAddress           string
	username             string
	password             string
	anonymousUsername    string
	clientCertificate    string
	caCertificate        string
	tunnelCACertificate  string
	tlsVersion           string
	eapSendStart         bool
	tlsSkipHostnameCheck bool
)

var authCmd = &cobra.Command{
	Use:     "authentication",
	Aliases: []string{"auth"},
	Short:   "RADIUS client authentication",
	Long:    `Carry out RADIUS full client authentication sessions`,
}

var authUdpCmd = &cobra.Command{
	Use:     "udp ADDRESS SHARED_SECRET PROTOCOL",
	Short:   "RADIUS/UDP client authentication",
	Args:    cobra.ExactArgs(3),
	PreRunE: prerun,
	RunE: func(cmd *cobra.Command, args []string) error {
		return retry(func() error {
			return auth(func() (*radius.AuthenticationSession, string, error) {
				session, err := newUDPAuthSession(args[0], args[1], udpMTUSize, sendAttributes, receiveAttributes)
				return session, args[0], err
			}, args[2])
		})
	},
}

var authTlsCmd = &cobra.Command{
	Use:     "tls ADDRESS SERVER_CA CLIENT_CERT PROTOCOL",
	Short:   "RADIUS/TLS client authentication",
	Args:    cobra.ExactArgs(4),
	PreRunE: prerun,
	RunE: func(cmd *cobra.Command, args []string) error {
		return retry(func() error {
			return auth(func() (*radius.AuthenticationSession, string, error) {
				session, err := newTLSAuthSession(args[0], args[1], args[2], sendAttributes, receiveAttributes)
				return session, args[0], err
			}, args[3])
		})
	},
}

func init() {
	authCmd.PersistentFlags().StringVar(&macAddress, "mac", "", "MAC Address")
	authCmd.PersistentFlags().StringVar(&username, "username", "", "Username")
	authCmd.PersistentFlags().StringVar(&password, "password", "", "Password")
	authCmd.PersistentFlags().StringVar(&anonymousUsername, "anonymous-username", "anonymous", "EAP anonymous username")
	authCmd.PersistentFlags().StringVar(&clientCertificate, "client-cert", "", "Client certificate")
	authCmd.PersistentFlags().StringVar(&caCertificate, "ca-cert", "", "CA certificate")
	authCmd.PersistentFlags().StringVar(&tunnelCACertificate, "tunnel-ca-cert", "", "tunnel CA certificate")
	authCmd.PersistentFlags().StringVar(&tlsVersion, "tls-version", "1.2", "TLS version underlying TLS-based protocols")
	authCmd.PersistentFlags().BoolVar(&eapSendStart, "eap-send-start", false, "EAP send EAP-Start")
	authCmd.PersistentFlags().BoolVar(&tlsSkipHostnameCheck, "tls-skip-hostname-check", false, "TLS skip Hostname check in handshake")

	authCmd.MarkFlagsRequiredTogether("username", "password")

	authCmd.AddCommand(authUdpCmd, authTlsCmd)
}

func auth(f func() (*radius.AuthenticationSession, string, error), protocol string) error {
	session, serverName, err := f()
	if err != nil {
		slog.Error("failed to create session",
			"command", "auth",
			"protocol", protocol,
			"error", err,
		)
		return err
	}
	defer func() {
		err := session.Close()
		if err != nil {
			slog.Error("failed to close session",
				"command", "auth",
				"protocol", protocol,
				"error", err,
			)
		}
	}()
	err = internalAuth(session, serverName, protocol)
	if err != nil {
		slog.Error("failed authentication",
			"network", session.RemoteAddr().Network(),
			"address", session.RemoteAddr(),
			"command", "auth",
			"protocol", protocol,
			"error", err,
		)
		return err
	}
	slog.Info("successful authentication",
		"network", session.RemoteAddr().Network(),
		"address", session.RemoteAddr(),
		"command", "auth",
		"protocol", protocol,
	)
	return nil
}

func internalAuth(session *radius.AuthenticationSession, serverName, protocol string) error {
	switch protocol {
	case authMAB:
		return session.MAB(macAddress)
	case authPAP:
		return session.PAP(username, password)
	}
	if !strings.HasPrefix(protocol, "eap-") && !strings.HasPrefix(protocol, "peap-") && protocol != authMabEapMd5 {
		return fmt.Errorf("unknown protocol picked: %s", protocol)
	}
	if protocol == authMabEapMd5 {
		anonymousUsername = macAddress
	}

	eaptunnel := radius.NewEapAuthenticationTunnel(session, anonymousUsername)
	if eaptunnel == nil {
		return fmt.Errorf("failed to create EAP tunnel")
	}
	// nolint:errcheck // function does not return error
	defer eaptunnel.Close()
	eapsession := eap.NewSession(eaptunnel, anonymousUsername, eapSendStart)
	err := eapAuth(eapsession, serverName, protocol)
	if err != nil {
		return err
	}
	return session.VerifyEAP(eapsession.RecvKey, eapsession.SendKey)
}

func eapAuth(session *eap.Session, serverName, protocol string) error {
	switch protocol {
	case authMabEapMd5:
		return session.MD5(macAddress)
	case authEapMsCHAPv2:
		return session.MsCHAPv2(username, password)
	case authEapTLS:
		eaptls, err := eap.CreateTLS(session, caCertificate, tlsVersion, tlsSkipHostnameCheck)
		if err != nil {
			return err
		}
		return eaptls.Authenticate(clientCertificate)
	case authEapTtlsPAP:
		eapttls, err := eap.CreateTTLS(session, tunnelCACertificate, tlsVersion, serverName, tlsSkipHostnameCheck)
		if err != nil {
			return err
		}
		return eapttls.PAP(username, password)
	case authEapTtlsEapMsCHAPv2:
		eapttls, err := eap.CreateTtlsEAP(session, tunnelCACertificate, tlsVersion, serverName, tlsSkipHostnameCheck)
		if err != nil {
			return err
		}
		ts := eap.NewSession(eapttls, anonymousUsername, false)
		return ts.MsCHAPv2(username, password)
	case authEapTtlsEapTLS:
		eapttls, err := eap.CreateTtlsEAP(session, tunnelCACertificate, tlsVersion, serverName, tlsSkipHostnameCheck)
		if err != nil {
			return err
		}
		ts := eap.NewSession(eapttls, anonymousUsername, false)
		eaptls, err := eap.CreateTLS(ts, caCertificate, tlsVersion, tlsSkipHostnameCheck)
		if err != nil {
			return err
		}
		return eaptls.Authenticate(clientCertificate)
	case authPeapMsCHAPv2:
		peap, err := eap.CreatePEAP(session, tunnelCACertificate, tlsVersion, serverName, tlsSkipHostnameCheck)
		if err != nil {
			return err
		}
		ts := eap.NewSession(peap, anonymousUsername, true)
		return ts.MsCHAPv2(username, password)
	default:
		return fmt.Errorf("unknown protocol picked: %s", protocol)
	}
}

func prerun(cmd *cobra.Command, args []string) error {
	protocol := args[len(args)-1]
	mv := missingValues(protocol)
	if len(mv) > 0 {
		return fmt.Errorf(
			"missing values [%s] for protocol [%s]",
			strings.Join(mv, ", "),
			protocol,
		)
	}
	return nil
}

func missingValues(protocol string) (mv []string) {
	if _, ok := requireMACAddress[protocol]; ok && macAddress == "" {
		mv = append(mv, "mac")
	}
	if _, ok := requireUsernameAndPassword[protocol]; ok && username == "" {
		mv = append(mv, "username")
	}
	if _, ok := requireUsernameAndPassword[protocol]; ok && password == "" {
		mv = append(mv, "password")
	}
	if _, ok := requireClientAndCACertificate[protocol]; ok && clientCertificate == "" {
		mv = append(mv, "client-cert")
	}
	if _, ok := requireClientAndCACertificate[protocol]; ok && caCertificate == "" {
		mv = append(mv, "ca-cert")
	}
	if _, ok := requireTunneledCACertificate[protocol]; ok && tunnelCACertificate == "" {
		mv = append(mv, "tunnel-ca-cert")
	}
	return
}
