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
	Code  Code
	Flags Flags
	Data  []byte
}

type Flags uint8

const (
	FlagsVendorSpecific Flags = 0x8 >> iota
	FlagsMandatory
	FlagsEncrypted
)

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
