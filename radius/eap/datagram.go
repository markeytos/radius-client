/*
Copyright © 2024 Keytos alan@keytos.io

Define EAP datagram of the following format

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|     Code      |  Identifier   |            Length             |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|    Data ...
	+-+-+-+-+
*/
package eap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	headerLen      = 4
	datagramMaxLen = 3600
)

type Datagram struct {
	Header  *Header
	Content *Content
}

type Header struct {
	Code       Code
	Identifier uint8
	Length     uint16
}

type Content struct {
	Type Type
	Data []byte
}

func newDatagram(h *Header, c *Content) *Datagram {
	clen := 0
	if c != nil {
		clen = 1 + len(c.Data)
		if clen > 65531 {
			panic("eap packet bigger than max for EAP")
		}
	}
	h.Length = uint16(headerLen + clen)
	return &Datagram{
		Header:  h,
		Content: c,
	}
}

func (d *Datagram) ReadFrom(r io.Reader) (int64, error) {
	b := make([]byte, datagramMaxLen)
	rn, err := r.Read(b)
	n := int64(rn)
	if err != nil {
		return n, err
	}
	br := bytes.NewReader(b[:rn])

	h := &Header{}
	err = binary.Read(br, binary.BigEndian, h)
	if err != nil {
		return 0, err
	}
	d.Header = h

	dlen := br.Len()
	if dlen != int(h.Length-headerLen) {
		return n, errors.New("datagram length does not match actual received")
	}
	if dlen > 0 {
		if h.Code != CodeRequest && h.Code != CodeResponse {
			return n, fmt.Errorf("only request and response may have data")
		}

		tbyte, err := br.ReadByte()
		if err != nil {
			return n, err
		}
		d.Content = &Content{
			Type: Type(tbyte),
		}

		if br.Len() > 0 {
			data := make([]byte, dlen-1)
			rcount, err := br.Read(data)
			if err != nil {
				return n, err
			}
			if rcount < dlen-1 {
				return n, errors.New("EAP data shorter than noted length")
			}
			d.Content.Data = data
		}
	}

	return n, nil
}

func (d Datagram) WriteTo(w io.Writer) (int64, error) {
	b := bytes.NewBuffer(make([]byte, 0, int(d.Header.Length)))
	err := binary.Write(b, binary.BigEndian, d.Header)
	if err != nil {
		return 0, err
	}
	if d.Content != nil {
		err = b.WriteByte(byte(d.Content.Type))
		if err != nil {
			return 0, err
		}
		_, err = b.Write(d.Content.Data)
		if err != nil {
			return 0, err
		}
	}
	n, err := w.Write(b.Bytes())
	return int64(n), err
}
