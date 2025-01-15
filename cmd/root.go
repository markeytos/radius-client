/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"os"

	"github.com/markeytos/radius-client/src/radius"
	"github.com/spf13/cobra"
)

var (
	udpAuthPort  int
	udpAcctPort  int
	udpRetries   int
	udpMTUSize   int
	udpTimeout   string
	tcpPort      int
	tlsTimeout   string
	radsecUnsafe bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "radius-client",
	Short: "RADIUS client that can carry out both UDP and TLS sessions",
	Long: `radius-client is a configurable client and library that
can be used to carry out both UDP and TLS authentication
sessions for most common authentication protocol.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().IntVar(&udpAuthPort, "udp-auth-port", radius.UDPAuthenticationPort, "RADIUS/UDP authentication port")
	rootCmd.PersistentFlags().IntVar(&udpAcctPort, "udp-acct-port", radius.UDPAccountingPort, "RADIUS/UDP accounting port")
	rootCmd.PersistentFlags().IntVar(&udpRetries, "udp-retries", 2, "RADIUS/UDP packet send retries")
	rootCmd.PersistentFlags().IntVar(&udpMTUSize, "udp-mtu", 1500, "RADIUS/UDP connection MTU size")
	rootCmd.PersistentFlags().StringVar(&udpTimeout, "udp-timeout", "5s", "RADIUS/UDP connection response timeout")
	rootCmd.PersistentFlags().IntVar(&tcpPort, "tcp-port", radius.RadSecTCPPort, "RADIUS/TLS (RadSec) port")
	rootCmd.PersistentFlags().BoolVar(&radsecUnsafe, "radsec-unsafe", false, "RADIUS/TLS (RadSec) skip server authentication")
	rootCmd.PersistentFlags().StringVar(&tlsTimeout, "tls-timeout", "15s", "RADIUS/TLS connection response timeout")

	rootCmd.AddCommand(authCmd, acctCmd, statusCmd)
}
