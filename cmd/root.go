/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"time"

	"github.com/markeytos/radius-client/src/radius"
	"github.com/spf13/cobra"
)

var (
	retries           int
	retryIntervalStr  string
	retryInterval     time.Duration
	udpAuthPort       int
	udpAcctPort       int
	udpRetries        int
	udpMTUSize        int
	udpTimeoutStr     string
	udpTimeout        time.Duration
	tcpPort           int
	tlsTimeoutStr     string
	tlsTimeout        time.Duration
	minWriteJitterStr string
	minWriteJitter    time.Duration
	maxWriteJitterStr string
	maxWriteJitter    time.Duration
	radsecUnsafe      bool
)

// Attribute variables, each string should be of the format `<label>:<value>[:<type>]`
// The default type for each key-value pair is determined by the key, but it can be
// manually overwritten by appending it to the pair
var (
	sendAttributes    radius.AttributeMap
	receiveAttributes radius.AttributeMap
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "radius-client",
	Short: "RADIUS client that can carry out both UDP and TLS sessions",
	Long: `radius-client is a configurable client that can be
used to carry out both UDP and TLS authentication sessions
for most common authentication protocol.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		rawAttrs, err := cmd.Flags().GetStringArray("attrs-to-send")
		if err != nil {
			return fmt.Errorf("could not get attrs-to-send flag: %w", err)
		}
		sendAttributes, err = parseAttributes(rawAttrs)
		if err != nil {
			return fmt.Errorf("invalid attribute to send: %w", err)
		}

		rawAttrs, err = cmd.Flags().GetStringArray("attrs-to-recv")
		if err != nil {
			return fmt.Errorf("could not get attrs-to-recv flag: %w", err)
		}
		receiveAttributes, err = parseAttributes(rawAttrs)
		if err != nil {
			return fmt.Errorf("invalid attribute to receive: %w", err)
		}
		if retries < 0 {
			return fmt.Errorf("number of retries must be 0 or positive")
		}
		retryInterval, err = time.ParseDuration(retryIntervalStr)
		if err != nil {
			return fmt.Errorf("invalid retry interval: %w", err)
		}
		udpTimeout, err = time.ParseDuration(udpTimeoutStr)
		if err != nil {
			return fmt.Errorf("invalid UDP timeout: %w", err)
		}
		tlsTimeout, err = time.ParseDuration(tlsTimeoutStr)
		if err != nil {
			return fmt.Errorf("invalid TLS timeout: %w", err)
		}
		minWriteJitter, err = time.ParseDuration(minWriteJitterStr)
		if err != nil {
			return fmt.Errorf("invalid min write jitter: %w", err)
		}
		maxWriteJitter, err = time.ParseDuration(maxWriteJitterStr)
		if err != nil {
			return fmt.Errorf("invalid max write jitter: %w", err)
		}
		if minWriteJitter > maxWriteJitter {
			return fmt.Errorf("max write jitter must be greater than min write jitter")
		}

		return nil
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().IntVarP(&retries, "retries", "r", 0, "Number of retries if the command fails")
	rootCmd.PersistentFlags().StringVarP(&retryIntervalStr, "retry-interval", "I", "0s", "Time between each retry")
	rootCmd.PersistentFlags().IntVar(&udpAuthPort, "udp-auth-port", radius.UDPAuthenticationPort, "RADIUS/UDP authentication port")
	rootCmd.PersistentFlags().IntVar(&udpAcctPort, "udp-acct-port", radius.UDPAccountingPort, "RADIUS/UDP accounting port")
	rootCmd.PersistentFlags().IntVar(&udpRetries, "udp-retries", 2, "RADIUS/UDP packet send retries")
	rootCmd.PersistentFlags().IntVar(&udpMTUSize, "udp-mtu", 1500, "RADIUS/UDP connection MTU size")
	rootCmd.PersistentFlags().StringVar(&udpTimeoutStr, "udp-timeout", "5s", "RADIUS/UDP connection response timeout")
	rootCmd.PersistentFlags().IntVar(&tcpPort, "tcp-port", radius.RadSecTCPPort, "RADIUS/TLS (RadSec) port")
	rootCmd.PersistentFlags().BoolVar(&radsecUnsafe, "radsec-unsafe", false, "RADIUS/TLS (RadSec) skip server authentication")
	rootCmd.PersistentFlags().StringVar(&tlsTimeoutStr, "tls-timeout", "15s", "RADIUS/TLS connection response timeout")
	rootCmd.PersistentFlags().StringVar(&minWriteJitterStr, "min-send-jitter", "50ms", "Min packet send time-in-between jitter")
	rootCmd.PersistentFlags().StringVar(&maxWriteJitterStr, "max-send-jitter", "1s", "Max packet send time-in-between jitter")
	rootCmd.PersistentFlags().StringArray("attrs-to-send", []string{}, `Additional attributes to send. Attributes will be
overwritten if required by protocol executed. Each
entry must be of the format
`+"`[type:value[:value-type] ...]`.")
	rootCmd.PersistentFlags().StringArray("attrs-to-recv", []string{}, `Attributes the client expects to receive. These are
only checked in the last packet of the handshake.
Each entry must be of the format
`+"`[type:value[:value-type] ...]`.")

	rootCmd.AddCommand(authCmd, acctCmd, statusCmd)
}

func parseAttributes(attrs []string) (radius.AttributeMap, error) {
	r := regexp.MustCompile(`^(?P<Label>[A-Za-z0-9_-]+):(?P<Value>[\ \.A-Za-z0-9_-]+)$`)

	attrMap := make(radius.AttributeMap)

	for _, a := range attrs {
		submatch := r.FindStringSubmatch(a)
		if submatch == nil {
			return nil, fmt.Errorf("invalid attribute entry: %s", a)
		}

		at, err := radius.AttributeTypeFromString(submatch[r.SubexpIndex("Label")])
		if err != nil {
			return nil, fmt.Errorf("invalid attribute label: %w", err)
		}
		val := submatch[r.SubexpIndex("Value")]
		if slices.Contains(attrMap[at], val) {
			return nil, fmt.Errorf("duplicate attribute value: %s, %s", a, val)
		}
		attrMap[at] = append(attrMap[at], val)
	}

	return attrMap, nil
}
