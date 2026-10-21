/*
Copyright © 2024 Keytos alan@keytos.io

Test RADIUS vendor specific attribute encoding
*/
package radius

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// onWire renders the attribute the way Datagram.WriteTo puts it on the wire,
// type byte and length byte included.
func onWire(a *Attribute) string {
	return fmt.Sprintf("%02x%02x%s", byte(a.Type), len(a.Value)+2, hex.EncodeToString(a.Value))
}

// serializeOne serializes a single `<label>:<value>` pair the way the command
// line flags do.
func serializeOne(t *testing.T, label, value string) *Attribute {
	t.Helper()
	k, err := AttributeKeyFromString(label)
	if err != nil {
		t.Fatalf("could not resolve attribute label %s: %v", label, err)
	}
	attrs, err := serializeAttributeMap(AttributeMap{k: {value}})
	if err != nil {
		t.Fatalf("could not serialize %s:%s: %v", label, value, err)
	}
	if len(attrs) != 1 {
		t.Fatalf("expected a single attribute, got %d", len(attrs))
	}
	return attrs[0]
}

func TestSerializeVendorSpecificAttributes(t *testing.T) {
	tests := []struct {
		label    string
		value    string
		expected string
	}{
		{
			// vendor 12356, vendor type 1, vendor length 2 + 9 = 11
			label:    "Fortinet-Group-Name",
			value:    "NetAdmins",
			expected: "1a1100003044010b4e657441646d696e73",
		},
		{
			// vendor 318, vendor type 1, vendor length 2 + 4 = 6, Admin = 1
			label:    "APC-Service-Type",
			value:    "Admin",
			expected: "1a0c0000013e010600000001",
		},
		{
			// the enum also takes the raw number, NetworkOnly = 6
			label:    "APC-Service-Type",
			value:    "6",
			expected: "1a0c0000013e010600000006",
		},
		{
			// vendor 9, vendor type 1, vendor length 2 + 16 = 18
			label:    "Cisco-AVPair",
			value:    "shell_privlvl-15",
			expected: "1a180000000901127368656c6c5f707269766c766c2d3135",
		},
		{
			// vendor 14823, vendor type 1, vendor length 2 + 8 = 10
			label:    "Aruba-User-Role",
			value:    "netadmin",
			expected: "1a10000039e7010a6e657461646d696e",
		},
		{
			// the generic form addresses the same attribute by number
			label:    "Vendor-Specific:318:1",
			value:    "Admin",
			expected: "1a0c0000013e010600000001",
		},
		{
			// an unknown vendor attribute takes a hex value
			label:    "Vendor-Specific:25053:3",
			value:    "4e657441646d696e73",
			expected: "1a11000061dd030b4e657441646d696e73",
		},
	}

	for _, test := range tests {
		t.Run(test.label+":"+test.value, func(t *testing.T) {
			got := onWire(serializeOne(t, test.label, test.value))
			if got != test.expected {
				t.Fatalf("incorrect vendor specific attribute produced.\nexpected: \t%s\ngot: \t\t%s", test.expected, got)
			}
		})
	}
}

func TestVendorSpecificAttributeRoundTrip(t *testing.T) {
	attrs := Attributes{serializeOne(t, "Fortinet-Group-Name", "NetAdmins")}
	vsa := attrs.FirstVendorSpecificAttributeOfType(VendorIdFortinet, VendorTypeFortinetGroupName)
	if vsa == nil {
		t.Fatalf("serialized vendor specific attribute was not found again")
	}
	if string(vsa.Value) != "NetAdmins" {
		t.Fatalf("incorrect value read back.\nexpected: \tNetAdmins\ngot: \t\t%s", vsa.Value)
	}
	if attrs.FirstVendorSpecificAttributeOfType(VendorIdAruba, VendorTypeArubaUserRole) != nil {
		t.Fatalf("vendor specific attribute matched a different vendor")
	}
}

// Every vendor specific attribute shares attribute type 26, and all four
// vendor attributes this client names share vendor type 1, so they must be
// kept apart by the vendor ID and vendor type pair.
func TestVendorSpecificAttributesDoNotCollide(t *testing.T) {
	labels := []string{"Cisco-AVPair", "Aruba-User-Role", "Fortinet-Group-Name", "APC-Service-Type"}
	attrMap := make(AttributeMap)
	for _, l := range labels {
		k, err := AttributeKeyFromString(l)
		if err != nil {
			t.Fatalf("could not resolve attribute label %s: %v", l, err)
		}
		if _, ok := attrMap[k]; ok {
			t.Fatalf("attribute label %s collides with an earlier one", l)
		}
		attrMap[k] = []string{"1"}
	}
	attrs, err := serializeAttributeMap(attrMap)
	if err != nil {
		t.Fatalf("could not serialize vendor specific attributes: %v", err)
	}
	if len(attrs) != len(labels) {
		t.Fatalf("expected %d attributes, got %d", len(labels), len(attrs))
	}
	seen := make(map[string]bool)
	for _, a := range attrs {
		w := onWire(a)
		if seen[w] {
			t.Fatalf("two vendor specific attributes serialized identically: %s", w)
		}
		seen[w] = true
	}
}

func TestVendorSpecificAttributeNames(t *testing.T) {
	tests := []struct {
		label    string
		value    string
		expected string
	}{
		{"Cisco-AVPair", "shell_priv", "Cisco-AVPair"},
		{"Aruba-User-Role", "netadmin", "Aruba-User-Role"},
		{"Fortinet-Group-Name", "NetAdmins", "Fortinet-Group-Name"},
		{"APC-Service-Type", "Admin", "APC-Service-Type"},
		{"Vendor-Specific:25053:3", "00", "Vendor-Specific:25053:3"},
	}
	for _, test := range tests {
		got := serializeOne(t, test.label, test.value).String()
		if got != test.expected {
			t.Fatalf("incorrect attribute name.\nexpected: \t%s\ngot: \t\t%s", test.expected, got)
		}
	}
}

func TestInvalidVendorSpecificAttributes(t *testing.T) {
	badLabels := []string{
		"Vendor-Specific",
		"Vendor-Specific:318",
		"Vendor-Specific:318:1:2",
		"Vendor-Specific:0:1",
		"Vendor-Specific:318:256",
		"Vendor-Specific:notanumber:1",
		"Fortinet-Group-Names",
	}
	for _, l := range badLabels {
		if _, err := AttributeKeyFromString(l); err == nil {
			t.Fatalf("expected an error for attribute label %s", l)
		}
	}

	badValues := []struct {
		label string
		value string
	}{
		{"APC-Service-Type", "SuperAdmin"},
		{"Vendor-Specific:25053:3", "nothexatall"},
		{"Fortinet-Group-Name", strings.Repeat("a", maxVendorAttributeLen+1)},
	}
	for _, test := range badValues {
		k, err := AttributeKeyFromString(test.label)
		if err != nil {
			t.Fatalf("could not resolve attribute label %s: %v", test.label, err)
		}
		if _, err := serializeAttributeMap(AttributeMap{k: {test.value}}); err == nil {
			t.Fatalf("expected an error for %s:%s", test.label, test.value)
		}
	}
}
