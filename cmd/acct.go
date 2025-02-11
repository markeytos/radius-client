/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var acctCmd = &cobra.Command{
	Use:     "accounting",
	Aliases: []string{"acct"},
	Short:   "RADIUS client accounting",
	Long:    `Carry out RADIUS client accounting requests`,
}

var acctUdpCmd = &cobra.Command{
	Use:   "udp IP_ADDRESS SHARED_SECRET",
	Short: "RADIUS/UDP client accounting",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		session, err := newUDPAcctSession(args[0], args[1])
		if err != nil {
			return fmt.Errorf("acct: failed to create udp session: %w", err)
		}
		defer session.Close()
		return fmt.Errorf("acct: not implemented")
	},
}

var acctTlsCmd = &cobra.Command{
	Use:   "tls ADDRESS SERVER_CA CLIENT_CERT",
	Short: "RADIUS/TLS client accounting",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		session, err := newTLSAcctSession(args[0], args[1], args[2])
		if err != nil {
			return fmt.Errorf("acct: failed to create tls session: %w", err)
		}
		defer session.Close()
		return fmt.Errorf("acct: not implemented")
	},
}

func init() {
	acctCmd.AddCommand(acctUdpCmd, acctTlsCmd)
}
