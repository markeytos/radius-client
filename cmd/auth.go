/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"errors"
	"fmt"

	"github.com/markeytos/radius-client/radius"
	"github.com/markeytos/radius-client/radius/eap"
	"github.com/spf13/cobra"
)

// authentication protocols
const (
	authStrMAB                = "mab"
	authStrPAP                = "pap"
	authStrEapMsCHAPv2        = "eap-ms-chapv2"
	authStrEapTLS             = "eap-tls"
	authStrEapTtlsPAP         = "eap-ttls-pap"
	authStrEapTtlsEapMsCHAPv2 = "eap-ttls-eap-ms-chapv2"
	authStrEapTtlsEapTLS      = "eap-ttls-eap-tls"
	authStrPeapMsCHAPv2       = "peap-ms-chapv2"
)

var (
	authMAB                bool
	authPAP                bool
	authEapMsCHAPv2        bool
	authEapTLS             bool
	authEapTtlsPAP         bool
	authEapTtlsEapMsCHAPv2 bool
	authEapTtlsEapTLS      bool
	authPeapMsCHAPv2       bool

	macAddress        string
	username          string
	password          string
	anonymousUsername string
	eapSendStart      bool
)

var authCmd = &cobra.Command{
	Use:     "authentication",
	Aliases: []string{"auth"},
	Short:   "RADIUS client authentication",
	Long:    `Carry out RADIUS full client authentication sessions`,
}

var authUdpCmd = &cobra.Command{
	Use:     "udp IP_ADDRESS SHARED_SECRET",
	Short:   "RADIUS/UDP client authentication",
	Args:    cobra.ExactArgs(2),
	PreRunE: prerun,
	RunE: func(cmd *cobra.Command, args []string) error {
		session, err := newUDPAuthSession(args[0], args[1])
		if err != nil {
			return fmt.Errorf("failed to create session: %w", err)
		}
		return auth_wrapper(session)
	},
	SilenceUsage: true,
}

var authTlsCmd = &cobra.Command{
	Use:     "tls ADDRESS SERVER_CA CLIENT_CERT",
	Short:   "RADIUS/TLS client authentication",
	Args:    cobra.ExactArgs(3),
	PreRunE: prerun,
	RunE: func(cmd *cobra.Command, args []string) error {
		session, err := newTLSAuthSession(args[0], args[1], args[2])
		if err != nil {
			return fmt.Errorf("failed to create session: %w", err)
		}
		return auth_wrapper(session)
	},
	SilenceUsage: true,
}

func init() {
	authCmd.PersistentFlags().BoolVar(&authMAB, authStrMAB, false, "Authenticate with MAC authentication bypass")
	authCmd.PersistentFlags().BoolVar(&authPAP, authStrPAP, false, "Authenticate with MAC authentication bypass")
	authCmd.PersistentFlags().BoolVar(&authEapMsCHAPv2, authStrEapMsCHAPv2, false, "Authenticate with MAC authentication bypass")
	authCmd.PersistentFlags().BoolVar(&authEapTLS, authStrEapTLS, false, "Authenticate with MAC authentication bypass")
	authCmd.PersistentFlags().BoolVar(&authEapTtlsPAP, authStrEapTtlsPAP, false, "Authenticate with MAC authentication bypass")
	authCmd.PersistentFlags().BoolVar(&authEapTtlsEapMsCHAPv2, authStrEapTtlsEapMsCHAPv2, false, "Authenticate with MAC authentication bypass")
	authCmd.PersistentFlags().BoolVar(&authEapTtlsEapTLS, authStrEapTtlsEapTLS, false, "Authenticate with MAC authentication bypass")
	authCmd.PersistentFlags().BoolVar(&authPeapMsCHAPv2, authStrPeapMsCHAPv2, false, "Authenticate with MAC authentication bypass")

	authCmd.PersistentFlags().StringVar(&macAddress, "mac", "", "MAC Address")
	authCmd.PersistentFlags().StringVar(&username, "username", "", "Username")
	authCmd.PersistentFlags().StringVar(&password, "password", "", "Password")
	authCmd.PersistentFlags().StringVar(&anonymousUsername, "anonymous-username", "anonymous", "EAP anonymous username")
	authCmd.PersistentFlags().BoolVar(&eapSendStart, "eap-send-start", false, "EAP send EAP-Start")

	authCmd.MarkFlagsOneRequired(authStrMAB, authStrPAP, authStrEapMsCHAPv2, authStrEapTLS, authStrEapTtlsPAP, authStrEapTtlsEapMsCHAPv2, authStrEapTtlsEapTLS, authStrPeapMsCHAPv2)
	authCmd.MarkFlagsMutuallyExclusive(authStrMAB, authStrPAP, authStrEapMsCHAPv2, authStrEapTLS, authStrEapTtlsPAP, authStrEapTtlsEapMsCHAPv2, authStrEapTtlsEapTLS, authStrPeapMsCHAPv2)

	authCmd.MarkFlagsRequiredTogether(authStrMAB, "mac")
	authCmd.MarkFlagsRequiredTogether("username", "password")

	authCmd.AddCommand(authUdpCmd, authTlsCmd)
}

func auth_wrapper(session *radius.AuthenticationSession) error {
	err := auth(session)
	if err == nil {
		println("Successful authentication")
	}
	return err
}

func auth(session *radius.AuthenticationSession) error {
	if authMAB {
		return session.MAB(macAddress)
	}
	if authPAP {
		return session.PAP(username, password)
	}
	eaptunnel := radius.NewEapAuthenticationTunnel(*session, anonymousUsername)
	eapsession := eap.NewSession(eaptunnel, anonymousUsername, eapSendStart)
	if authEapMsCHAPv2 {
		return eapsession.MsCHAPv2(username, password)
	}
	if authEapTLS {
		return eapsession.TLS()
	}
	if authEapTtlsPAP {
		return eapsession.TtlsPAP(username, password)
	}
	if authEapTtlsEapMsCHAPv2 {
		return eapsession.TtlsEapMsCHAPv2(username, password)
	}
	if authEapTtlsEapTLS {
		return eapsession.TtlsEapTLS()
	}
	if authPeapMsCHAPv2 {
		return eapsession.PeapMsCHAPv2(username, password)
	}
	return errors.New("invalid authentication protocol picked")
}

func prerun(cmd *cobra.Command, args []string) error {
	passwordBased := authPAP || authEapMsCHAPv2 || authEapTtlsPAP || authEapTtlsEapMsCHAPv2 || authPeapMsCHAPv2
	if passwordBased && password == "" {
		return errors.New("Set username and password to carry out password-based protocol")
	}
	return nil
}
