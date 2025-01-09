/*
Copyright © 2024 Keytos alan@keytos.io

Define RADIUS datagram of the following format

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|     Code      |  Identifier   |            Length             |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                                                               |
	|                         Authenticator                         |
	|                                                               |
	|                                                               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|  Attributes ...
	+-+-+-+-+-+-+-+-+-+-+-+-+-
*/
package radius

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	headerLen      = 20
	DatagramMaxLen = 4096
)

type Datagram struct {
	Header     *Header
	Attributes Attributes
}

func newDatagram(h *Header, attrs []*Attribute) *Datagram {
	attrs_len := 0
	for _, a := range attrs {
		attrs_len += len(a.Value) + 2
	}
	if attrs_len > DatagramMaxLen-headerLen {
		panic("attribute overflows packet to over max size")
	}
	h.Length = headerLen + uint16(attrs_len)

	return &Datagram{
		Header:     h,
		Attributes: attrs,
	}
}

func (d *Datagram) ReadFrom(r io.Reader) (int64, error) {
	b := make([]byte, DatagramMaxLen)
	rn, err := r.Read(b)
	n := int64(rn)
	if err != nil {
		return n, err
	}
	br := bytes.NewReader(b[:rn])

	h := &Header{}
	err = binary.Read(br, binary.BigEndian, h)
	if err != nil {
		return n, err
	}
	d.Header = h

	var attrs []*Attribute
	if br.Len() != int(h.Length-headerLen) {
		return n, fmt.Errorf("packet length does not match actual packet")
	}
	for br.Len() > 0 {
		tbyte, err := br.ReadByte()
		if err != nil {
			return n, err
		}

		lbyte, err := br.ReadByte()
		if err != nil {
			return n, err
		}

		value := make([]byte, lbyte-2)
		rcount, err := br.Read(value)
		if err != nil {
			return n, err
		}
		if rcount < int(lbyte-2) {
			return n, fmt.Errorf("attribute shorter than noted length")
		}

		attrs = append(attrs, &Attribute{Type: AttributeType(tbyte), Value: value})
	}
	d.Attributes = attrs

	return n, nil
}

func (d Datagram) WriteTo(w io.Writer) (int64, error) {
	b := bytes.NewBuffer(make([]byte, 0, int(d.Header.Length)))
	err := binary.Write(b, binary.BigEndian, d.Header)
	if err != nil {
		return 0, err
	}
	for _, a := range d.Attributes {
		attrlen := len(a.Value) + 2
		err = b.WriteByte(byte(a.Type))
		if err != nil {
			return 0, err
		}
		err = b.WriteByte(byte(attrlen))
		if err != nil {
			return 0, err
		}
		_, err = b.Write(a.Value)
		if err != nil {
			return 0, err
		}
	}
	n, err := w.Write(b.Bytes())
	return int64(n), err
}

type Header struct {
	Code          Code
	Identifier    uint8
	Length        uint16
	Authenticator [16]byte
}

func swap(a, b []byte) {
	for i := 0; i < min(len(a), len(b)); i++ {
		a[i], b[i] = b[i], a[i]
	}
}
