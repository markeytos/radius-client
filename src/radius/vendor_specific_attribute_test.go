/*
Copyright © 2024 Keytos alan@keytos.io

Test RADIUS vendor specific attribute encoding
*/
package radius

import (
	"encoding/binary"
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

// packedVendorSpecificAttribute builds the attribute a server sends when it
// packs several vendor attributes of one vendor into a single attribute of
// type Vendor-Specific, which RFC 2865 section 5.26 allows.
func packedVendorSpecificAttribute(id VendorId, vas ...VendorSpecificAttribute) *Attribute {
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, uint32(id))
	for _, va := range vas {
		v = append(v, byte(va.Type), byte(2+len(va.Value)))
		v = append(v, va.Value...)
	}
	return &Attribute{Type: AttributeTypeVendorSpecific, Value: v}
}

func TestPackedVendorSpecificAttributesMatch(t *testing.T) {
	// Fortinet-Group-Name:NetAdmins alongside Fortinet-Vdom-Name:root, vendor
	// type 3, in one attribute of type Vendor-Specific
	recv := packedVendorSpecificAttribute(VendorIdFortinet,
		VendorSpecificAttribute{Type: VendorTypeFortinetGroupName, Value: []byte("NetAdmins")},
		VendorSpecificAttribute{Type: 3, Value: []byte("root")},
	)

	if !recv.matches(serializeOne(t, "Fortinet-Group-Name", "NetAdmins")) {
		t.Fatalf("packed vendor specific attribute did not match the expected attribute")
	}
	if !recv.matches(serializeOne(t, "Vendor-Specific:12356:3", hex.EncodeToString([]byte("root")))) {
		t.Fatalf("second vendor attribute of a packed attribute did not match")
	}
	if recv.matches(serializeOne(t, "Fortinet-Group-Name", "Guests")) {
		t.Fatalf("packed vendor specific attribute matched a different value")
	}
	if recv.matches(serializeOne(t, "Aruba-User-Role", "NetAdmins")) {
		t.Fatalf("packed vendor specific attribute matched a different vendor")
	}

	va := Attributes{recv}.FirstVendorSpecificAttributeOfType(VendorIdFortinet, 3)
	if va == nil || string(va.Value) != "root" {
		t.Fatalf("could not read the second vendor attribute out of the packed attribute")
	}
}

// A single vendor attribute per attribute of type Vendor-Specific is the form
// this client sends, and must keep matching.
func TestUnpackedAttributesMatch(t *testing.T) {
	matching := [][2]string{
		{"APC-Service-Type", "Admin"},
		{"Cisco-AVPair", "shell:priv-lvl=15"},
		{"User-Name", "alice"},
	}
	for _, m := range matching {
		if !serializeOne(t, m[0], m[1]).matches(serializeOne(t, m[0], m[1])) {
			t.Fatalf("%s:%s did not match itself", m[0], m[1])
		}
	}
	if serializeOne(t, "APC-Service-Type", "Admin").matches(serializeOne(t, "APC-Service-Type", "Device")) {
		t.Fatalf("attribute matched a different value")
	}
	if serializeOne(t, "User-Name", "alice").matches(serializeOne(t, "Filter-Id", "alice")) {
		t.Fatalf("attribute matched a different attribute type")
	}
}

// A server reply is not trusted to be well formed, so a vendor length that
// does not fit the attribute must be ignored rather than read past.
func TestMalformedVendorSpecificAttributes(t *testing.T) {
	malformed := []*Attribute{
		{Type: AttributeTypeVendorSpecific, Value: []byte{}},
		{Type: AttributeTypeVendorSpecific, Value: []byte{0x00, 0x00, 0x30, 0x44}},
		// vendor length runs past the end of the attribute
		{Type: AttributeTypeVendorSpecific, Value: []byte{0x00, 0x00, 0x30, 0x44, 0x01, 0x40, 'a', 'b'}},
		// vendor length shorter than the two bytes it covers
		{Type: AttributeTypeVendorSpecific, Value: []byte{0x00, 0x00, 0x30, 0x44, 0x01, 0x00, 'a', 'b'}},
	}
	expected := serializeOne(t, "Fortinet-Group-Name", "ab")
	for _, a := range malformed {
		if a.matches(expected) {
			t.Fatalf("malformed vendor specific attribute matched: %x", a.Value)
		}
		if (Attributes{a}).FirstVendorSpecificAttributeOfType(VendorIdFortinet, VendorTypeFortinetGroupName) != nil {
			t.Fatalf("malformed vendor specific attribute was read: %x", a.Value)
		}
		if a.String() == "" {
			t.Fatalf("malformed vendor specific attribute was not named: %x", a.Value)
		}
	}
}

// A server may also send each vendor attribute in its own attribute of type
// Vendor-Specific, which is how MS-MPPE keys arrive.
func TestVendorAttributesAcrossSeparateAttributes(t *testing.T) {
	as := Attributes{
		packedVendorSpecificAttribute(VendorIdMicrosoft,
			VendorSpecificAttribute{Type: VendorTypeMicrosoftMPPESendKey, Value: []byte("send")}),
		packedVendorSpecificAttribute(VendorIdMicrosoft,
			VendorSpecificAttribute{Type: VendorTypeMicrosoftMPPERecvKey, Value: []byte("recv")}),
	}
	for _, test := range []struct {
		t     VendorType
		value string
	}{
		{VendorTypeMicrosoftMPPESendKey, "send"},
		{VendorTypeMicrosoftMPPERecvKey, "recv"},
	} {
		va := as.FirstVendorSpecificAttributeOfType(VendorIdMicrosoft, test.t)
		if va == nil || string(va.Value) != test.value {
			t.Fatalf("vendor type %d was not found across separate attributes: %v", test.t, va)
		}
	}
	if as.FirstVendorSpecificAttributeOfType(VendorIdCisco, VendorTypeCiscoAVPair) != nil {
		t.Fatalf("a vendor attribute that is not there was found")
	}
}

// The largest value that fits fills an attribute to the 255 byte maximum
// without the vendor length byte wrapping. One byte more is rejected, which
// TestInvalidVendorSpecificAttributes covers.
func TestMaxLengthVendorSpecificAttribute(t *testing.T) {
	a := serializeOne(t, "Fortinet-Group-Name", strings.Repeat("a", maxVendorAttributeLen))
	if got := len(a.Value) + 2; got != 255 {
		t.Fatalf("incorrect attribute length on the wire.\nexpected: \t255\ngot: \t\t%d", got)
	}
	if got := int(a.Value[5]); got != maxVendorAttributeLen+2 {
		t.Fatalf("incorrect vendor length.\nexpected: \t%d\ngot: \t\t%d", maxVendorAttributeLen+2, got)
	}
	if !a.matches(a) {
		t.Fatalf("attribute of the maximum length did not match itself")
	}
}

// A vendor specific attribute is read straight out of a reply, so no value a
// server can send may read past the end of it or fail to terminate.
func FuzzVendorAttributes(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x30, 0x44, 0x01, 0x0b, 'N', 'e', 't'})
	f.Add([]byte{0x00, 0x00, 0x30, 0x44, 0x01, 0x40, 'a', 'b'})
	f.Add([]byte{0x00, 0x00, 0x30, 0x44, 0x01, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		a := &Attribute{Type: AttributeTypeVendorSpecific, Value: b}
		claimed := 0
		for _, va := range a.vendorAttributes() {
			if len(va.Value) > len(b) {
				t.Fatalf("vendor value of %d bytes read out of a %d byte attribute", len(va.Value), len(b))
			}
			claimed += len(va.Value) + 2
		}
		if claimed > len(b) {
			t.Fatalf("vendor attributes claim %d bytes of a %d byte attribute", claimed, len(b))
		}
		_ = a.String()
		_ = a.matches(a)
		_ = (Attributes{a}).FirstVendorSpecificAttributeOfType(VendorIdFortinet, VendorTypeFortinetGroupName)
	})
}
