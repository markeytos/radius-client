/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"errors"
	"fmt"

	"github.com/markeytos/radius-client/radius"
	"github.com/spf13/cobra"
)

// authentication protocols
const (
	authStrMAB                = "mab"
	authStrPAP                = "pap"
	authStrEapMsChapV2        = "eap-ms-chapv2"
	authStrEapTLS             = "eap-tls"
	authStrEapTtlsPAP         = "eap-ttls-pap"
	authStrEapTtlsEapMsChapV2 = "eap-ttls-eap-ms-chapv2"
	authStrEapTtlsEapTLS      = "eap-ttls-eap-tls"
	authStrPeapMsChapV2       = "peap-ms-chapv2"
)

var (
	authMAB                bool
	authPAP                bool
	authEapMsChapV2        bool
	authEapTLS             bool
	authEapTtlsPAP         bool
	authEapTtlsEapMsChapV2 bool
	authEapTtlsEapTLS      bool
	authPeapMsChapV2       bool

	macAddress string
	username   string
	password   string
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
	authCmd.PersistentFlags().BoolVar(&authEapMsChapV2, authStrEapMsChapV2, false, "Authenticate with MAC authentication bypass")
	authCmd.PersistentFlags().BoolVar(&authEapTLS, authStrEapTLS, false, "Authenticate with MAC authentication bypass")
	authCmd.PersistentFlags().BoolVar(&authEapTtlsPAP, authStrEapTtlsPAP, false, "Authenticate with MAC authentication bypass")
	authCmd.PersistentFlags().BoolVar(&authEapTtlsEapMsChapV2, authStrEapTtlsEapMsChapV2, false, "Authenticate with MAC authentication bypass")
	authCmd.PersistentFlags().BoolVar(&authEapTtlsEapTLS, authStrEapTtlsEapTLS, false, "Authenticate with MAC authentication bypass")
	authCmd.PersistentFlags().BoolVar(&authPeapMsChapV2, authStrPeapMsChapV2, false, "Authenticate with MAC authentication bypass")

	authCmd.PersistentFlags().StringVar(&macAddress, "mac", "", "MAC Address")
	authCmd.PersistentFlags().StringVar(&username, "username", "", "Username")
	authCmd.PersistentFlags().StringVar(&password, "password", "", "Password")

	authCmd.MarkFlagsOneRequired(authStrMAB, authStrPAP, authStrEapMsChapV2, authStrEapTLS, authStrEapTtlsPAP, authStrEapTtlsEapMsChapV2, authStrEapTtlsEapTLS, authStrPeapMsChapV2)
	authCmd.MarkFlagsMutuallyExclusive(authStrMAB, authStrPAP, authStrEapMsChapV2, authStrEapTLS, authStrEapTtlsPAP, authStrEapTtlsEapMsChapV2, authStrEapTtlsEapTLS, authStrPeapMsChapV2)

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
	if authEapMsChapV2 {
		return session.EapMsChapV2(username, password)
	}
	if authEapTLS {
		return errors.New("not implemented EAP-TLS")
	}
	if authEapTtlsPAP {
		return session.EapTtlsPAP(username, password)
	}
	if authEapTtlsEapMsChapV2 {
		return session.EapMsChapV2(username, password)
	}
	if authEapTtlsEapTLS {
		return errors.New("not implemented EAP-TTLS-EAP-TLS")
	}
	if authPeapMsChapV2 {
		return errors.New("not implemented PEAP-MS-CHAPv2")
	}
	return errors.New("invalid authentication protocol picked")
}

func prerun(cmd *cobra.Command, args []string) error {
	passwordBased := authPAP || authEapMsChapV2 || authEapTtlsPAP || authEapTtlsEapMsChapV2 || authPeapMsChapV2
	if passwordBased && password == "" {
		return errors.New("Set username and password to carry out password-based protocol")
	}
	return nil
}
