/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"log/slog"

	"github.com/markeytos/radius-client/src/radius"
	"github.com/spf13/cobra"
)

var (
	skipCheckAcctStatusType bool
	skipCheckAcctSessionId  bool
	skipCheckAcctNasId      bool
)

var acctCmd = &cobra.Command{
	Use:     "accounting",
	Aliases: []string{"acct"},
	Short:   "RADIUS client accounting",
	Long:    `Carry out RADIUS client accounting requests`,
}

var acctUdpCmd = &cobra.Command{
	Use:   "udp ADDRESS SHARED_SECRET",
	Short: "RADIUS/UDP client accounting",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return retry(func() error {
			return acct(func() (*radius.AccountingSession, error) {
				return newUDPAcctSession(args[0], args[1], udpMTUSize, sendAttributes, receiveAttributes)
			})
		})
	},
}

var acctTlsCmd = &cobra.Command{
	Use:   "tls ADDRESS SERVER_CA CLIENT_CERT",
	Short: "RADIUS/TLS client accounting",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		return retry(func() error {
			return acct(func() (*radius.AccountingSession, error) {
				return newTLSAcctSession(args[0], args[1], args[2], sendAttributes, receiveAttributes)
			})
		})
	},
}

func init() {
	acctCmd.AddCommand(acctUdpCmd, acctTlsCmd)
	acctCmd.PersistentFlags().BoolVar(&skipCheckAcctStatusType, "skip-check-acct-status-type", false, "Do not require Acct-Status-Type.")
	acctCmd.PersistentFlags().BoolVar(&skipCheckAcctSessionId, "skip-check-acct-session-id", false, "Do not require Acct-Session-Id")
	acctCmd.PersistentFlags().BoolVar(&skipCheckAcctNasId, "skip-check-acct-nas-id", false, "Do not require one of either NAS-Identifier or NAS-IP-Address")
}

func acct(f func() (*radius.AccountingSession, error)) error {
	session, err := f()
	if err != nil {
		slog.Error("failed to create session",
			"command", "acct",
			"error", err)
		return err
	}
	defer func() {
		err := session.Close()
		if err != nil {
			slog.Error("failed to close session",
				"command", "acct",
				"error", err)
		}
	}()
	session.SkipCheckAcctStatusType = skipCheckAcctStatusType
	session.SkipCheckAcctSessionId = skipCheckAcctSessionId
	session.SkipCheckAcctNasId = skipCheckAcctNasId

	err = session.Account()
	if err != nil {
		slog.Error("failed accounting",
			"network", session.RemoteAddr().Network(),
			"address", session.RemoteAddr(),
			"command", "acct",
			"error", err)
		return err
	}
	slog.Info("successful accounting",
		"network", session.RemoteAddr().Network(),
		"address", session.RemoteAddr(),
		"command", "acct",
	)
	return nil
}
