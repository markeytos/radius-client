/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/markeytos/radius-client/src/eap"
	"github.com/markeytos/radius-client/src/radius"
	"github.com/spf13/cobra"
)

// authentication protocols
const (
	authMAB                = "mab"
	authPAP                = "pap"
	authEapMsCHAPv2        = "eap-ms-chapv2"
	authEapTLS             = "eap-tls"
	authEapTtlsPAP         = "eap-ttls-pap"
	authEapTtlsEapMsCHAPv2 = "eap-ttls-eap-ms-chapv2"
	authEapTtlsEapTLS      = "eap-ttls-eap-tls"
	authPeapMsCHAPv2       = "eap-peap-eap-ms-chapv2"
)

// required values for protocols
// no sets in go, so using maps with empty structs
var (
	requireMACAddress          = map[string]struct{}{authMAB: struct{}{}}
	requireUsernameAndPassword = map[string]struct{}{
		authPAP:                struct{}{},
		authEapMsCHAPv2:        struct{}{},
		authEapTtlsPAP:         struct{}{},
		authEapTtlsEapMsCHAPv2: struct{}{},
		authPeapMsCHAPv2:       struct{}{},
	}
	requireClientAndCACertificate = map[string]struct{}{
		authEapTLS:        struct{}{},
		authEapTtlsEapTLS: struct{}{},
	}
	requireTunneledCACertificate = map[string]struct{}{
		authEapTtlsPAP:         struct{}{},
		authEapTtlsEapMsCHAPv2: struct{}{},
		authEapTtlsEapTLS:      struct{}{},
		authPeapMsCHAPv2:       struct{}{},
	}
)

var (
	macAddress          string
	username            string
	password            string
	anonymousUsername   string
	clientCertificate   string
	caCertificate       string
	tunnelCACertificate string
	tlsVersion          string
	eapSendStart        bool
)

var authCmd = &cobra.Command{
	Use:     "authentication",
	Aliases: []string{"auth"},
	Short:   "RADIUS client authentication",
	Long:    `Carry out RADIUS full client authentication sessions`,
}

var authUdpCmd = &cobra.Command{
	Use:     "udp IP_ADDRESS SHARED_SECRET PROTOCOL",
	Short:   "RADIUS/UDP client authentication",
	Args:    cobra.ExactArgs(3),
	PreRunE: prerun,
	RunE: func(cmd *cobra.Command, args []string) error {
		session, err := newUDPAuthSession(args[0], args[1])
		if err != nil {
			return fmt.Errorf("auth: failed to create udp session: %w", err)
		}
		defer session.Close()
		err = auth(session, args[2])
		if err != nil {
			return fmt.Errorf("auth: %w", err)
		}
		fmt.Printf("Successful %s authentication over UDP\n", args[2])
		return nil
	},
	SilenceUsage: true,
}

var authTlsCmd = &cobra.Command{
	Use:     "tls ADDRESS SERVER_CA CLIENT_CERT PROTOCOL",
	Short:   "RADIUS/TLS client authentication",
	Args:    cobra.ExactArgs(4),
	PreRunE: prerun,
	RunE: func(cmd *cobra.Command, args []string) error {
		session, err := newTLSAuthSession(args[0], args[1], args[2])
		if err != nil {
			return fmt.Errorf("auth: failed to create tls session: %w", err)
		}
		defer session.Close()
		err = auth(session, args[3])
		if err != nil {
			return fmt.Errorf("auth: %w", err)
		}
		fmt.Printf("Successful %s authentication over TLS\n", args[3])
		return nil
	},
	SilenceUsage: true,
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

	authCmd.MarkFlagsRequiredTogether("username", "password")

	authCmd.AddCommand(authUdpCmd, authTlsCmd)
}

func auth(session *radius.AuthenticationSession, protocol string) error {
	switch protocol {
	case authMAB:
		return session.MAB(macAddress)
	case authPAP:
		return session.PAP(username, password)
	}
	if !strings.HasPrefix(protocol, "eap-") {
		return fmt.Errorf("unknown protocol picked: %s", protocol)
	}
	eaptunnel := radius.NewEapAuthenticationTunnel(session, anonymousUsername)
	defer eaptunnel.Close()
	eapsession := eap.NewSession(eaptunnel, anonymousUsername, eapSendStart)
	err := eapAuth(&eapsession, protocol)
	if err != nil {
		return err
	}
	return session.VerifyEAP(eapsession.RecvKey, eapsession.SendKey)
}

func eapAuth(session *eap.Session, protocol string) error {
	switch protocol {
	case authEapMsCHAPv2:
		return session.MsCHAPv2(username, password)
	case authEapTLS:
		eaptls, err := eap.CreateTLS(session, caCertificate, tlsVersion)
		if err != nil {
			return err
		}
		cert, err := tls.LoadX509KeyPair(clientCertificate, clientCertificate)
		if err != nil {
			return err
		}
		return eaptls.Authenticate(cert)
	case authEapTtlsPAP:
		eapttls, err := eap.CreateTTLS(session, tunnelCACertificate, tlsVersion)
		if err != nil {
			return err
		}
		return eapttls.PAP(username, password)
	case authEapTtlsEapMsCHAPv2:
		eapttls, err := eap.CreateTTLS(session, tunnelCACertificate, tlsVersion)
		if err != nil {
			return err
		}
		tunnSession := eap.NewSession(eapttls, anonymousUsername, eapSendStart)
		return tunnSession.MsCHAPv2(username, password)
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
