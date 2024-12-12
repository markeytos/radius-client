/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:     "authentication",
	Aliases: []string{"auth"},
	Short:   "RADIUS client authentication",
	Long:    `Carry out RADIUS full client authentication sessions`,
}

var authUdpCmd = &cobra.Command{
	Use:   "udp IP_ADDRESS SHARED_SECRET",
	Short: "RADIUS/UDP client authentication",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := newUDPAuthSession(args[0], args[1])
		if err != nil {
			return fmt.Errorf("failed to create session: %w", err)
		}
		return errors.New("not implemented")
	},
	SilenceUsage: true,
}

var authTlsCmd = &cobra.Command{
	Use:   "tls ADDRESS SERVER_CA CLIENT_CERT",
	Short: "RADIUS/TLS client authentication",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := newTLSAuthSession(args[0], args[1], args[2])
		if err != nil {
			return fmt.Errorf("failed to create session: %w", err)
		}
		return errors.New("not implemented")
	},
	SilenceUsage: true,
}

func init() {
	authCmd.AddCommand(authUdpCmd, authTlsCmd)
}
