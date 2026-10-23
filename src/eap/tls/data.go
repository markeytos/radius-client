/*
Copyright © 2024 Keytos alan@keytos.io

# Define TLS packet data for EAP

Only hold "Data" section (anything after first `Type`)

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|     Code      |   Identifier  |            Length             |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|     Type      |     Flags     |      TLS Message Length
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|     TLS Message Length        |       TLS Data...
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
package tls

import (
	"encoding/binary"
	"errors"
)

type Data struct {
	Flags            Flags
	TLSMessageLength uint32
	Data             []byte
}

type Flags uint8

const (
	FlagsLength Flags = 0x80 >> iota
	FlagsMore
	FlagsStart
	FlagsTLSMessageLength
)

// TEAP reuses the fourth flag to announce Outer TLVs and carries its version
// in the lowest bits
const (
	FlagsOuterTLVLength = FlagsTLSMessageLength
	FlagsVersionMask    = Flags(0x07)
)

func CreateDataFromBuffer(b []byte) (*Data, error) {
	if len(b) < 1 {
		return nil, errors.New("tls data: missing flags")
	}
	f := Flags(b[0])
	if f&FlagsLength != 0 {
		if len(b) < 5 {
			return nil, errors.New("tls data: missing message length")
		}
		return &Data{
			Flags:            f,
			TLSMessageLength: binary.BigEndian.Uint32(b[1:5]),
			Data:             b[5:],
		}, nil
	} else {

		return &Data{
			Flags: f,
			Data:  b[1:],
		}, nil
	}
}

func (d *Data) ToBinary() []byte {
	var b []byte

	hasTlsLength := d.Flags&FlagsLength != 0
	if hasTlsLength {
		b = make([]byte, 1, 5+len(d.Data))
	} else {
		b = make([]byte, 1, 1+len(d.Data))
	}

	b[0] = byte(d.Flags)
	if hasTlsLength {
		b = binary.BigEndian.AppendUint32(b, d.TLSMessageLength)
	}
	b = append(b, d.Data...)
	return b
}
