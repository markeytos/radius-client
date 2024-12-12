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
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
)

const (
	headerLen      = 20
	datagramMaxLen = 4096
)

type Datagram struct {
	Header     *Header
	Attributes []*Attribute
}

func CreateDatagram(c Code, id uint8, attrs []*Attribute) (*Datagram, error) {
	// id, err := rand_uint8()
	// if err != nil {
	// 	return nil, err
	// }

	attrs_len := 0
	for _, a := range attrs {
		attrs_len += len(a.buffer)
	}

	h := &Header{
		Code:       c,
		Identifier: id,
		Length:     uint16(headerLen + attrs_len),
	}

	d := &Datagram{
		Header:     h,
		Attributes: attrs,
	}

	_, err := rand.Read(h.Authenticator[:])
	if err != nil {
		return nil, err
	}

	return d, nil
}

func CreateDatagramFromReader(r io.Reader) (*Datagram, error) {
	br := bufio.NewReader(r)

	h := &Header{}
	err := binary.Read(br, binary.BigEndian, h)
	if err != nil {
		return nil, err
	}

	var attrs []*Attribute
	rlen := h.Length - headerLen
	buf := make([]byte, rlen)
	n, err := br.Read(buf)
	if err != nil {
		return nil, err
	}
	if n != len(buf) {
		return nil, errors.New("missing spacing in attributes")
	}
	for len(buf) > 0 {
		if rlen < 2 {
			return nil, errors.New("malformed attribute shape")
		}
		l := buf[1]
		attrs = append(attrs, &Attribute{buffer: buf[:l]})
		buf = buf[l:]
	}

	return &Datagram{Header: h, Attributes: attrs}, nil
}

func (d *Datagram) WriteTo(w io.Writer) (int64, error) {
	written := int64(0)
	bw := bufio.NewWriter(w)
	err := binary.Write(bw, binary.BigEndian, d.Header)
	if err != nil {
		return 0, err
	}
	written += headerLen
	for _, a := range d.Attributes {
		_, err = bw.Write(a.buffer)
		if err != nil {
			return written, err
		}
		written += int64(len(a.buffer))
	}
	return written, bw.Flush()
}

func (d *Datagram) ContainsAttribute(t AttributeType) bool {
	for _, a := range d.Attributes {
		if a.Type() == t {
			return true
		}
	}
	return false
}

func (d *Datagram) AddAttribute(t AttributeType, vlen int) (*Attribute, error) {
	a, err := createAttribute(AttributeTypeMessageAuthenticator, vlen)
	if err != nil {
		return nil, err
	}
	newLen := d.Header.Length + uint16(len(a.buffer))
	if newLen > datagramMaxLen {
		return nil, errors.New("reached maximum size of datagram")
	}
	d.Header.Length = newLen
	d.Attributes = append(d.Attributes, a)
	return a, nil
}

func (d *Datagram) AddRequestMessageAuthenticator(ss string) error {
	for _, a := range d.Attributes {
		if a.Type() == AttributeTypeMessageAuthenticator {
			return errors.New("datagram already has a message authenticator")
		}
	}
	ma, err := d.AddAttribute(AttributeTypeMessageAuthenticator, md5.Size)
	if err != nil {
		return err
	}

	mac := hmac.New(md5.New, []byte(ss))
	_, err = d.WriteTo(mac)
	if err != nil {
		return err
	}
	sum := mac.Sum(nil)

	copy(ma.Value(), sum)
	return nil
}

// Verify datagram's response authenticator, and, if present, the Message-Authenticator
func (d *Datagram) ValidResponseAuthenticatorAndMessageAuthenticator(reqauth [16]byte, ss string) bool {
	swap(d.Header.Authenticator[:], reqauth[:])

	maValid := true
	var ma *Attribute
	for _, a := range d.Attributes {
		if a.Type() == AttributeTypeMessageAuthenticator {
			ma = a
			break
		}
	}
	if ma != nil {
		buff := ma.Value()
		if len(buff) != md5.Size {
			return false
		}
		old := make([]byte, md5.Size)
		for i := 0; i < md5.Size; i++ {
			old[i] = buff[i]
			buff[i] = 0
		}

		mac := hmac.New(md5.New, []byte(ss))
		_, err := d.WriteTo(mac)
		if err != nil {
			return false
		}
		sum := mac.Sum(nil)
		copy(buff, sum)
		maValid = subtle.ConstantTimeCompare(sum, old) == 1
	}

	hash := md5.New()
	_, err := d.WriteTo(hash)
	if err != nil {
		panic(err)
	}
	hash.Write([]byte(ss))
	sum := hash.Sum(nil)
	return maValid && subtle.ConstantTimeCompare(sum, reqauth[:]) == 1
}

// Verify datagram's, if present, the Message-Authenticator
func (d *Datagram) ValidRequestMessageAuthenticator(ss string) bool {
	var attr *Attribute
	for _, a := range d.Attributes {
		if a.Type() == AttributeTypeMessageAuthenticator {
			attr = a
			break
		}
	}
	if attr == nil {
		return true
	}

	buff := attr.Value()
	if len(buff) != md5.Size {
		return false
	}
	old := make([]byte, md5.Size)
	for i := 0; i < md5.Size; i++ {
		old[i] = buff[i]
		buff[i] = 0
	}

	mac := hmac.New(md5.New, []byte(ss))
	_, err := d.WriteTo(mac)
	if err != nil {
		return false
	}
	sum := mac.Sum(nil)
	copy(buff, sum)
	return subtle.ConstantTimeCompare(sum, old) == 1
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
