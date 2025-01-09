/*
Copyright © 2024 Keytos alan@keytos.io

Define Diameter attributes value pair of the following format

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                           AVP Code                            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|V M P r r r r r|                  AVP Length                   |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                        Vendor-ID (opt)                        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|    Data ...
	+-+-+-+-+-+-+-+-+
*/
package diameter

import (
	"encoding/binary"
	"fmt"
	"io"
)

type AttributeValuePair struct {
	Code     Code
	Flags    Flags
	VendorId uint32 // we aint using this, same as VendorId in radius
	Data     []byte
}

type Flags uint8

const (
	FlagsVendorSpecific Flags = 0x8 >> iota
	FlagsMandatory
	FlagsEncrypted
)

func (a *AttributeValuePair) ReadFrom(r io.Reader) (int64, error) {
	b := make([]byte, 5000) // shouldn't get more that these many bytes
	n, err := r.Read(b)
	if err != nil {
		return int64(n), err
	}
	b = b[:n]
	a.Code = Code(binary.BigEndian.Uint32(b[:4]))
	a.Flags = Flags(b[4])
	l := binary.BigEndian.Uint32(b[4:8]) & 0xffffff
	if a.Flags&FlagsVendorSpecific == 0 {
		a.Data = b[8:l]
	} else {
		a.VendorId = binary.BigEndian.Uint32(b[8:12])
		a.Data = b[12:l]
	}
	return int64(n), nil
}

func (a AttributeValuePair) WriteTo(w io.Writer) (int64, error) {
	if len(a.Data) > 0xffffff {
		return 0, fmt.Errorf("data field too long")
	}
	b := make([]byte, ((8+len(a.Data))+3)&(^3))
	binary.BigEndian.PutUint32(b[0:4], uint32(a.Code))
	binary.BigEndian.PutUint32(b[4:8], uint32(8+len(a.Data)))
	b[4] = byte(a.Flags)
	copy(b[8:], a.Data)
	n, err := w.Write(b)
	return int64(n), err
}
