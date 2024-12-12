/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"errors"
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
		_, err := newUDPAcctSession(args[0], args[1])
		if err != nil {
			return fmt.Errorf("failed to create session: %w", err)
		}
		return errors.New("not implemented")
	},
	SilenceUsage: true,
}

var acctTlsCmd = &cobra.Command{
	Use:   "tls ADDRESS SERVER_CA CLIENT_CERT",
	Short: "RADIUS/TLS client accounting",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := newTLSAcctSession(args[0], args[1], args[2])
		if err != nil {
			return fmt.Errorf("failed to create session: %w", err)
		}
		return errors.New("not implemented")
	},
	SilenceUsage: true,
}

func init() {
	acctCmd.AddCommand(acctUdpCmd, acctTlsCmd)
}
