/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:     "status",
	Aliases: []string{"s"},
	Short:   "RADIUS client send status",
	Long:    `Carry out RADIUS client accounting requests`,
}

var statusUdpAuthCmd = &cobra.Command{
	Use:   "udp-auth IP_ADDRESS SHARED_SECRET",
	Short: "Send status to RADIUS/UDP authentication port",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		session, err := newUDPAuthSession(args[0], args[1])
		if err != nil {
			return fmt.Errorf("status: failed to create udp auth session: %w", err)
		}
		defer session.Close()
		err = session.Status()
		if err != nil {
			return fmt.Errorf("status: %w", err)
		}
		println("Successful status UDP authentication")
		return nil
	},
	SilenceUsage: true,
}

var statusUdpAcctCmd = &cobra.Command{
	Use:   "udp-acct IP_ADDRESS SHARED_SECRET",
	Short: "Send status to RADIUS/UDP accounting port",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		session, err := newUDPAcctSession(args[0], args[1])
		if err != nil {
			return fmt.Errorf("status: failed to create udp acct session: %w", err)
		}
		defer session.Close()
		err = session.Status()
		if err != nil {
			return fmt.Errorf("status: %w", err)
		}
		println("Successful status over UDP accounting")
		return nil
	},
	SilenceUsage: true,
}

var statusTlsCmd = &cobra.Command{
	Use:   "tls ADDRESS SERVER_CA CLIENT_CERT",
	Short: "Send status to RADIUS/TLS port",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		session, err := newTLSAuthSession(args[0], args[1], args[2])
		if err != nil {
			return fmt.Errorf("status: failed to create tls session: %w", err)
		}
		defer session.Close()
		err = session.Status()
		if err != nil {
			return fmt.Errorf("status: %w", err)
		}
		println("Successful TLS status")
		return nil
	},
	SilenceUsage: true,
}

func init() {
	statusCmd.AddCommand(statusUdpAcctCmd, statusUdpAuthCmd, statusTlsCmd)
}
