/*
Copyright © 2024 Keytos alan@keytos.io

Test command line attribute parsing
*/
package cmd

import (
	"testing"

	"github.com/markeytos/radius-client/src/radius"
)

var (
	ciscoAVPairKey = radius.AttributeKey{
		Type:       radius.AttributeTypeVendorSpecific,
		VendorId:   radius.VendorIdCisco,
		VendorType: radius.VendorTypeCiscoAVPair,
	}
	apcServiceTypeKey = radius.AttributeKey{
		Type:       radius.AttributeTypeVendorSpecific,
		VendorId:   radius.VendorIdAPC,
		VendorType: radius.VendorTypeAPCServiceType,
	}
)

func TestParseAttributes(t *testing.T) {
	tests := []struct {
		entry string
		key   radius.AttributeKey
		value string
	}{
		// a Cisco AVPair holds colons and equals signs of its own, so the
		// value is everything that follows the label
		{"Cisco-AVPair:shell:priv-lvl=15", ciscoAVPairKey, "shell:priv-lvl=15"},
		{"Cisco-AVPair:ip:addr-pool=guest", ciscoAVPairKey, "ip:addr-pool=guest"},
		// the generic form names the same attribute and keeps the value whole
		{"Vendor-Specific:9:1:shell:priv-lvl=15", ciscoAVPairKey, "shell:priv-lvl=15"},
		{"Vendor-Specific:318:1:Admin", apcServiceTypeKey, "Admin"},
		{"APC-Service-Type:Admin", apcServiceTypeKey, "Admin"},
		{"User-Name:user@example.com", radius.AttributeKey{Type: radius.AttributeTypeUserName}, "user@example.com"},
		{"NAS-Identifier:fake-router", radius.AttributeKey{Type: radius.AttributeTypeNasIdentifier}, "fake-router"},
		{"Filter-Id:20", radius.AttributeKey{Type: radius.AttributeTypeFilterId}, "20"},
		// the tag stays in the value; encoding interprets it later
		{"Tunnel-Private-Group-ID:1:20", radius.AttributeKey{Type: radius.AttributeTypeTunnelPrivateGroupId}, "1:20"},
		{"Egress-VLANID:tagged:100", radius.AttributeKey{Type: radius.AttributeTypeEgressVlanId}, "tagged:100"},
	}

	for _, test := range tests {
		t.Run(test.entry, func(t *testing.T) {
			m, err := parseAttributes([]string{test.entry})
			if err != nil {
				t.Fatalf("could not parse %s: %v", test.entry, err)
			}
			vs, ok := m[test.key]
			if !ok {
				t.Fatalf("%s did not parse into attribute key %+v, got %+v", test.entry, test.key, m)
			}
			if len(vs) != 1 || vs[0] != test.value {
				t.Fatalf("incorrect value parsed from %s.\nexpected: \t%s\ngot: \t\t%v", test.entry, test.value, vs)
			}
		})
	}
}

func TestParseInvalidAttributes(t *testing.T) {
	badEntries := []string{
		"Cisco-AVPair",
		"Cisco-AVPair:",
		"Vendor-Specific",
		"Vendor-Specific:318",
		"Vendor-Specific:9:1",
		"Vendor-Specific:0:1:0011",
		"Not-An-Attribute:value",
		"Cisco-AVPair:shell\tpriv-lvl=15",
	}
	for _, e := range badEntries {
		if _, err := parseAttributes([]string{e}); err == nil {
			t.Fatalf("expected an error for attribute entry %s", e)
		}
	}
}

// The name and the generic form address the same attribute, so the same value
// written both ways is still a duplicate.
func TestParseDuplicateAttributes(t *testing.T) {
	entries := []string{"Cisco-AVPair:shell:priv-lvl=15", "Vendor-Specific:9:1:shell:priv-lvl=15"}
	if _, err := parseAttributes(entries); err == nil {
		t.Fatalf("expected an error for a duplicate attribute value")
	}

	// two different AVPairs are not duplicates, and both are kept in order
	entries = []string{"Cisco-AVPair:shell:priv-lvl=15", "Cisco-AVPair:ip:addr-pool=guest"}
	m, err := parseAttributes(entries)
	if err != nil {
		t.Fatalf("could not parse distinct AVPairs: %v", err)
	}
	vs := m[ciscoAVPairKey]
	if len(vs) != 2 || vs[0] != "shell:priv-lvl=15" || vs[1] != "ip:addr-pool=guest" {
		t.Fatalf("incorrect values parsed.\nexpected: \t[shell:priv-lvl=15 ip:addr-pool=guest]\ngot: \t\t%v", vs)
	}
}
