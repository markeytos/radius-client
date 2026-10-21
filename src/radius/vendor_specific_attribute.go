/*
Copyright © 2024 Keytos alan@keytos.io

Define RADIUS vendor specific attributes of the following format

	 0                   1                   2
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	|     Type      |    Length     |  Value ...
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

where the value holds a single vendor attribute of the following format

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                            Vendor Id                          |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|  Vendor type  | Vendor length |  Vendor value ...
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

The vendor length covers the vendor type and vendor length bytes as well,
so it is the length of the vendor value plus two.
*/
package radius

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

const (
	vendorAttributeHeaderLen = 6
	maxVendorAttributeLen    = maxAttributeLen - vendorAttributeHeaderLen
)

type VendorSpecificAttribute struct {
	Id    VendorId
	Type  VendorType
	Value []byte
}

type VendorId uint32

const (
	VendorIdCisco     VendorId = 9
	VendorIdMicrosoft VendorId = 311
	VendorIdAPC       VendorId = 318
	VendorIdFortinet  VendorId = 12356
	VendorIdAruba     VendorId = 14823
)

// Vendor types are only unique within a vendor, so several of these share a
// value. A vendor attribute is identified by the vendor ID and vendor type
// pair, never by the vendor type on its own.
type VendorType uint8

const (
	VendorTypeCiscoAVPair          VendorType = 1
	VendorTypeMicrosoftMPPESendKey VendorType = 16
	VendorTypeMicrosoftMPPERecvKey VendorType = 17
	VendorTypeAPCServiceType       VendorType = 1
	VendorTypeFortinetGroupName    VendorType = 1
	VendorTypeArubaUserRole        VendorType = 1
)

type VendorAttributeLabel string

const (
	VendorAttributeLabelCiscoAVPair       VendorAttributeLabel = "Cisco-AVPair"
	VendorAttributeLabelAPCServiceType    VendorAttributeLabel = "APC-Service-Type"
	VendorAttributeLabelFortinetGroupName VendorAttributeLabel = "Fortinet-Group-Name"
	VendorAttributeLabelArubaUserRole     VendorAttributeLabel = "Aruba-User-Role"
)

func newVendorAttributeKey(id VendorId, t VendorType) AttributeKey {
	return AttributeKey{Type: AttributeTypeVendorSpecific, VendorId: id, VendorType: t}
}

// vendorAttributeKeyFromLabel resolves the name of one of the vendor
// attributes this client knows about, e.g. `Fortinet-Group-Name`.
func vendorAttributeKeyFromLabel(label string) (AttributeKey, bool) {
	switch VendorAttributeLabel(label) {
	case VendorAttributeLabelCiscoAVPair:
		return newVendorAttributeKey(VendorIdCisco, VendorTypeCiscoAVPair), true
	case VendorAttributeLabelAPCServiceType:
		return newVendorAttributeKey(VendorIdAPC, VendorTypeAPCServiceType), true
	case VendorAttributeLabelFortinetGroupName:
		return newVendorAttributeKey(VendorIdFortinet, VendorTypeFortinetGroupName), true
	case VendorAttributeLabelArubaUserRole:
		return newVendorAttributeKey(VendorIdAruba, VendorTypeArubaUserRole), true
	}
	return AttributeKey{}, false
}

// vendorAttributeKeyFromGenericLabel resolves a vendor attribute addressed by
// number, `Vendor-Specific:<vendor ID>:<vendor type>`, for vendor attributes
// that have no name in this client.
func vendorAttributeKeyFromGenericLabel(label string) (AttributeKey, error) {
	fields := strings.Split(label, ":")
	if len(fields) != 3 {
		return AttributeKey{}, fmt.Errorf("vendor specific attribute must be of the format %s:<vendor ID>:<vendor type>: %s", AttributeTypeLabelVendorSpecific, label)
	}
	id, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil || id == 0 {
		return AttributeKey{}, fmt.Errorf("invalid vendor ID: %s", fields[1])
	}
	t, err := strconv.ParseUint(fields[2], 10, 8)
	if err != nil {
		return AttributeKey{}, fmt.Errorf("invalid vendor type: %s", fields[2])
	}
	return newVendorAttributeKey(VendorId(id), VendorType(t)), nil
}

// serializeVendorSpecificAttribute encodes v as the vendor attribute
// identified by the vendor ID and vendor type pair. Vendor attributes this
// client knows about take the value type listed in RADIUS_ATTRIBUTES.md, any
// other vendor attribute takes a hex string.
func serializeVendorSpecificAttribute(id VendorId, t VendorType, v string) (*Attribute, error) {
	switch {
	case id == VendorIdCisco && t == VendorTypeCiscoAVPair,
		id == VendorIdFortinet && t == VendorTypeFortinetGroupName,
		id == VendorIdAruba && t == VendorTypeArubaUserRole:
		return newVendorSpecificAttribute(id, t, []byte(v))
	case id == VendorIdAPC && t == VendorTypeAPCServiceType:
		e, err := ParseVendorEnumAPCServiceType(v)
		if err != nil {
			return nil, err
		}
		d := make([]byte, 4)
		binary.BigEndian.PutUint32(d, uint32(e))
		return newVendorSpecificAttribute(id, t, d)
	}
	d := make([]byte, len(v)/2)
	_, err := hex.Decode(d, []byte(v))
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	return newVendorSpecificAttribute(id, t, d)
}

func newVendorSpecificAttribute(id VendorId, t VendorType, v []byte) (*Attribute, error) {
	if len(v) > maxVendorAttributeLen {
		return nil, fmt.Errorf("value of vendor specific attribute too big: %d bytes", len(v))
	}
	a := newEmptyAttribute(AttributeTypeVendorSpecific, vendorAttributeHeaderLen+len(v))
	binary.BigEndian.PutUint32(a.Value[:4], uint32(id))
	a.Value[4] = byte(t)
	a.Value[5] = byte(2 + len(v))
	copy(a.Value[vendorAttributeHeaderLen:], v)
	return a, nil
}

// vendorAttributes reads the vendor attributes held in a. A server may pack
// several of them into a single attribute of type Vendor-Specific, so this
// walks the whole value rather than reading only the first. Reading stops at
// the first vendor attribute whose vendor length does not fit, since the ones
// behind it cannot be found without it, and an attribute of any other type
// holds none at all.
func (a *Attribute) vendorAttributes() []*VendorSpecificAttribute {
	if a.Type != AttributeTypeVendorSpecific || len(a.Value) < vendorAttributeHeaderLen {
		return nil
	}
	id := VendorId(binary.BigEndian.Uint32(a.Value[:4]))
	var vas []*VendorSpecificAttribute
	b := a.Value[4:]
	for len(b) >= 2 {
		l := int(b[1])
		if l < 2 || l > len(b) {
			break
		}
		vas = append(vas, &VendorSpecificAttribute{Id: id, Type: VendorType(b[0]), Value: b[2:l]})
		b = b[l:]
	}
	return vas
}

// holdsVendorAttribute reports whether a holds a vendor attribute equal to va.
func (a *Attribute) holdsVendorAttribute(va *VendorSpecificAttribute) bool {
	for _, ava := range a.vendorAttributes() {
		if ava.Id == va.Id && ava.Type == va.Type &&
			subtle.ConstantTimeCompare(ava.Value, va.Value) == 1 {
			return true
		}
	}
	return false
}

func (as Attributes) FirstVendorSpecificAttributeOfType(id VendorId, t VendorType) *VendorSpecificAttribute {
	for _, a := range as {
		for _, va := range a.vendorAttributes() {
			if va.Id == id && va.Type == t {
				return va
			}
		}
	}
	return nil
}

// vendorSpecificString names the vendor attribute held in a, falling back to
// its vendor ID and vendor type when this client has no name for it.
func (a *Attribute) vendorSpecificString() string {
	if len(a.Value) < vendorAttributeHeaderLen {
		return string(AttributeTypeLabelVendorSpecific)
	}
	id := VendorId(binary.BigEndian.Uint32(a.Value[:4]))
	t := VendorType(a.Value[4])
	switch {
	case id == VendorIdCisco && t == VendorTypeCiscoAVPair:
		return string(VendorAttributeLabelCiscoAVPair)
	case id == VendorIdAPC && t == VendorTypeAPCServiceType:
		return string(VendorAttributeLabelAPCServiceType)
	case id == VendorIdFortinet && t == VendorTypeFortinetGroupName:
		return string(VendorAttributeLabelFortinetGroupName)
	case id == VendorIdAruba && t == VendorTypeArubaUserRole:
		return string(VendorAttributeLabelArubaUserRole)
	}
	return fmt.Sprintf("%s:%d:%d", AttributeTypeLabelVendorSpecific, id, t)
}

type VendorEnumAPCServiceType uint32

const (
	VendorEnumAPCServiceTypeAdmin VendorEnumAPCServiceType = iota + 1
	VendorEnumAPCServiceTypeDevice
	VendorEnumAPCServiceTypeReadOnly
	VendorEnumAPCServiceTypeOutlet
	VendorEnumAPCServiceTypeCard
	VendorEnumAPCServiceTypeNetworkOnly
)

func ParseVendorEnumAPCServiceType(v string) (VendorEnumAPCServiceType, error) {
	switch v {
	case "Admin":
		return VendorEnumAPCServiceTypeAdmin, nil
	case "Device":
		return VendorEnumAPCServiceTypeDevice, nil
	case "ReadOnly":
		return VendorEnumAPCServiceTypeReadOnly, nil
	case "Outlet":
		return VendorEnumAPCServiceTypeOutlet, nil
	case "Card":
		return VendorEnumAPCServiceTypeCard, nil
	case "NetworkOnly":
		return VendorEnumAPCServiceTypeNetworkOnly, nil
	default:
		i, err := strconv.ParseUint(v, 10, 0)
		if err == nil {
			return VendorEnumAPCServiceType(i), nil
		}
		return 0, fmt.Errorf("invalid APC service type value: %s", v)
	}
}
