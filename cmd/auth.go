/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"errors"
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

var (
	macAddress        string
	username          string
	password          string
	anonymousUsername string
	clientCertificate string
	caCertificate     string
	eapSendStart      bool
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
			return fmt.Errorf("failed to create session: %w", err)
		}
		defer session.Close()
		return auth_wrapper(session, args[2])
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
			return fmt.Errorf("failed to create session: %w", err)
		}
		defer session.Close()
		return auth_wrapper(session, args[3])
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
	authCmd.PersistentFlags().BoolVar(&eapSendStart, "eap-send-start", false, "EAP send EAP-Start")

	authCmd.MarkFlagsRequiredTogether("username", "password")

	authCmd.AddCommand(authUdpCmd, authTlsCmd)
}

func auth_wrapper(session *radius.AuthenticationSession, protocol string) error {
	err := auth(session, protocol)
	if err == nil {
		fmt.Printf("Successful %s authentication\n", protocol)
	}
	return err
}

func auth(session *radius.AuthenticationSession, protocol string) error {
	if protocol == authMAB {
		return session.MAB(macAddress)
	}
	if protocol == authPAP {
		return session.PAP(username, password)
	}
	if !strings.HasPrefix(protocol, "eap-") {
		return errors.New("invalid authentication protocol picked")
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
		mschapv2 := eap.MsCHAPv2{
			Session:  session,
			Username: username,
			Password: password,
		}
		return mschapv2.Authenticate()
	case authEapTLS:
		tls, err := eap.CreateTLS(session, clientCertificate, caCertificate)
		if err != nil {
			return err
		}
		return tls.Authenticate()
	case authEapTtlsPAP:
		return session.TtlsPAP(username, password)
	case authEapTtlsEapMsCHAPv2:
		return session.TtlsEapMsCHAPv2(username, password)
	case authEapTtlsEapTLS:
		return session.TtlsEapTLS()
	case authPeapMsCHAPv2:
		return session.PeapMsCHAPv2(username, password)
	default:
		return errors.New("invalid authentication protocol picked")
	}
}

func prerun(cmd *cobra.Command, args []string) error {
	protocol := args[len(args)-1]
	switch protocol {
	case authMAB:
		if macAddress == "" {
			return errors.New("set MAC address to carry out MAC Authentication Bypass")
		}
	case authPAP, authEapMsCHAPv2:
		if username == "" || password == "" {
			return errors.New("set username and password to carry out password-based protocol")
		}
	case authEapTLS:
		if clientCertificate == "" || caCertificate == "" {
			return errors.New("set client and CA certificate to carry out certificate-based authentication")
		}
	default:
		return errors.New("invalid authentication protocol picked")
	}
	return nil
}
