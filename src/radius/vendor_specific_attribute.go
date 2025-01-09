/*
Copyright © 2024 Keytos alan@keytos.io

Define RADIUS vendor specific attributes of the following format

	 0                   1                   2
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	|     Type      |    Length     |  Value ...
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
*/
package radius

import "encoding/binary"

type VendorSpecificAttribute struct {
	Id    VendorId
	Type  VendorType
	Value []byte
}

type VendorId uint32

const (
	VendorIdCisco     VendorId = 9
	VendorIdMicrosoft VendorId = 311
)

type VendorType uint8

const (
	VendorTypeCiscoAVPair          VendorType = 1
	VendorTypeMicrosoftMPPESendKey VendorType = 16
	VendorTypeMicrosoftMPPERecvKey VendorType = 17
)

func (as Attributes) FirstVendorSpecificAttributeOfType(id VendorId, t VendorType) *VendorSpecificAttribute {
	for _, a := range as {
		if a.Type == AttributeTypeVendorSpecific && len(a.Value) > 6 {
			if id == VendorId(binary.BigEndian.Uint32(a.Value[:4])) &&
				t == VendorType(a.Value[4]) {
				return &VendorSpecificAttribute{Id: id, Type: t, Value: a.Value[6 : 4+a.Value[5]]}
			}
		}
	}
	return nil
}
