/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"log/slog"

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
		return status(func() (statusSession, error) {
			return newUDPAuthSession(args[0], args[1], udpMTUSize)
		})
	},
}

var statusUdpAcctCmd = &cobra.Command{
	Use:   "udp-acct IP_ADDRESS SHARED_SECRET",
	Short: "Send status to RADIUS/UDP accounting port",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return status(func() (statusSession, error) {
			return newUDPAcctSession(args[0], args[1])
		})
	},
}

var statusTlsCmd = &cobra.Command{
	Use:   "tls ADDRESS SERVER_CA CLIENT_CERT",
	Short: "Send status to RADIUS/TLS port",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		return status(func() (statusSession, error) {
			return newTLSAuthSession(args[0], args[1], args[2])
		})
	},
}

func init() {
	statusCmd.AddCommand(statusUdpAcctCmd, statusUdpAuthCmd, statusTlsCmd)
}

func status(f func() (statusSession, error)) error {
	session, err := f()
	if err != nil {
		slog.Error("failed to create session",
			"command", "status",
			"error", err,
		)
		return err
	}
	defer session.Close()
	err = session.Status()
	if err != nil {
		slog.Error("failed status",
			"network", session.RemoteAddr().Network(),
			"address", session.RemoteAddr(),
			"command", "status",
			"error", err,
		)
		return err
	}
	slog.Info("successful status",
		"network", session.RemoteAddr().Network(),
		"address", session.RemoteAddr(),
		"command", "status",
	)
	return nil
}
