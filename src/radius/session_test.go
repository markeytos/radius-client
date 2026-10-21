/*
Copyright © 2024 Keytos alan@keytos.io

Test the received attribute check
*/
package radius

import (
	"strings"
	"testing"
)

// The check a session actually runs, rather than the matching underneath it:
// attributes built from an AttributeMap, compared against a reply whose vendor
// attributes a server packed into one attribute of type Vendor-Specific.
func TestExpectedAttributesAgainstPackedReply(t *testing.T) {
	k, err := AttributeKeyFromString("Fortinet-Group-Name")
	if err != nil {
		t.Fatalf("could not resolve attribute label: %v", err)
	}
	recvattrs, err := serializeAttributeMap(AttributeMap{k: {"NetAdmins"}})
	if err != nil {
		t.Fatalf("could not serialize expected attributes: %v", err)
	}
	s := &session{recvAttributes: recvattrs}

	// the expected vendor attribute sits behind another one of the same vendor
	s.lastReadDatagram = &Datagram{Attributes: Attributes{
		packedVendorSpecificAttribute(VendorIdFortinet,
			VendorSpecificAttribute{Type: 3, Value: []byte("root")},
			VendorSpecificAttribute{Type: VendorTypeFortinetGroupName, Value: []byte("NetAdmins")},
		),
	}}
	if err := s.lastReadDatagramHasExpectedAttributes(); err != nil {
		t.Fatalf("expected attribute was not found in a packed reply: %v", err)
	}

	// a reply holding the same vendor attribute with a different value is
	// reported as missing, and names the vendor attribute
	s.lastReadDatagram = &Datagram{Attributes: Attributes{
		packedVendorSpecificAttribute(VendorIdFortinet,
			VendorSpecificAttribute{Type: VendorTypeFortinetGroupName, Value: []byte("Guests")},
		),
	}}
	err = s.lastReadDatagramHasExpectedAttributes()
	if err == nil {
		t.Fatalf("expected an error for a reply with a different value")
	}
	if !strings.Contains(err.Error(), string(VendorAttributeLabelFortinetGroupName)) {
		t.Fatalf("error did not name the vendor attribute: %v", err)
	}
}
