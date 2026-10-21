/*
Copyright © 2024 Keytos alan@keytos.io

Test RADIUS datagram serialization
*/
package radius

import (
	"bytes"
	"testing"
)

// A vendor specific attribute must survive the trip through the wire format
// and still be matched on the other side.
func TestVendorSpecificAttributeOffTheWire(t *testing.T) {
	packed := packedVendorSpecificAttribute(VendorIdFortinet,
		VendorSpecificAttribute{Type: VendorTypeFortinetGroupName, Value: []byte("NetAdmins")},
		VendorSpecificAttribute{Type: 3, Value: []byte("root")},
	)
	d, err := newDatagram(&Header{Code: CodeAccessAccept, Identifier: 7}, []*Attribute{packed})
	if err != nil {
		t.Fatalf("could not build datagram: %v", err)
	}
	var buf bytes.Buffer
	if _, err := d.WriteTo(&buf); err != nil {
		t.Fatalf("could not write datagram: %v", err)
	}

	rd := &Datagram{}
	if _, err := rd.ReadFrom(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("could not read datagram back: %v", err)
	}
	if len(rd.Attributes) != 1 {
		t.Fatalf("expected a single attribute off the wire, got %d", len(rd.Attributes))
	}
	if !rd.Attributes[0].matches(serializeOne(t, "Fortinet-Group-Name", "NetAdmins")) {
		t.Fatalf("attribute read off the wire did not match the expected attribute")
	}
	if va := rd.Attributes.FirstVendorSpecificAttributeOfType(VendorIdFortinet, 3); va == nil || string(va.Value) != "root" {
		t.Fatalf("second vendor attribute did not survive the wire: %v", va)
	}
}

// A reply from the network is not trusted to be well formed.
func FuzzDatagramReadFrom(f *testing.F) {
	packed := packedVendorSpecificAttribute(VendorIdFortinet,
		VendorSpecificAttribute{Type: VendorTypeFortinetGroupName, Value: []byte("NetAdmins")},
	)
	d, err := newDatagram(&Header{Code: CodeAccessAccept, Identifier: 1}, []*Attribute{packed})
	if err != nil {
		f.Fatalf("could not build datagram: %v", err)
	}
	var buf bytes.Buffer
	if _, err := d.WriteTo(&buf); err != nil {
		f.Fatalf("could not write datagram: %v", err)
	}
	f.Add(buf.Bytes())

	f.Fuzz(func(t *testing.T, b []byte) {
		rd := &Datagram{}
		if _, err := rd.ReadFrom(bytes.NewReader(b)); err != nil {
			return
		}
		for _, a := range rd.Attributes {
			_ = a.String()
			_ = a.matches(a)
		}
	})
}
