/*
Copyright © 2024 Keytos alan@keytos.io

Define generic RADIUS session
*/
package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
	"net"
	"time"
)

type baseSession struct {
	net.Conn
	identifier          uint8
	sharedSecret        string
	timeout             time.Duration
	retries             int
	mtuSize             int
	sendAttributes      []*Attribute
	replyOnceAttributes []*Attribute
	lastReadDatagram    *Datagram
	lastWrittenDatagram *Datagram
}

func (s *baseSession) newRequestHeader(c Code) *Header {
	h := &Header{
		Code:       c,
		Identifier: s.identifier,
		Length:     uint16(headerLen),
	}
	_, err := rand.Read(h.Authenticator[:])
	if err != nil {
		panic(err)
	}
	s.identifier++
	return h
}

func (s *baseSession) newRequestDatagram(c Code, attrs ...*Attribute) (*Datagram, error) {
	h := s.newRequestHeader(c)
	return s.newDatagram(h, attrs...)
}

func (s *baseSession) newDatagram(h *Header, attrs ...*Attribute) (*Datagram, error) {
	var err error
	attrs = append(attrs, s.sendAttributes...)
	if s.replyOnceAttributes != nil {
		attrs = append(attrs, s.replyOnceAttributes...)
		s.replyOnceAttributes = nil
	}
	d := newDatagram(h, attrs)
	if ma := d.Attributes.FirstOfType(AttributeTypeMessageAuthenticator); ma != nil {
		err = writeMessageAuthenticator(d, ma, s.sharedSecret)
		if err != nil {
			return nil, err
		}
	}
	return d, nil
}

func (s *baseSession) WriteDatagram(wd *Datagram) (int, error) {
	err := s.SetWriteDeadline(time.Now().Add(s.timeout))
	if err != nil {
		return 0, fmt.Errorf("error setting send deadline: %w", err)
	}
	n, err := wd.WriteTo(s)
	if err != nil {
		return int(n), fmt.Errorf("error sending RADIUS datagram: %w", err)
	}
	s.lastWrittenDatagram = wd
	return int(n), nil
}

func (s *baseSession) ReadDatagram(rd *Datagram) (int, error) {
	err := s.SetReadDeadline(time.Now().Add(s.timeout))
	if err != nil {
		return 0, fmt.Errorf("error setting receive deadline: %w", err)
	}
	n, err := rd.ReadFrom(s)
	if err != nil {
		return int(n), fmt.Errorf("error receiving RADIUS datagram: %w", err)
	}
	s.lastReadDatagram = rd
	for _, a := range rd.Attributes {
		switch a.Type {
		case AttributeTypeState:
			s.replyOnceAttributes = append(s.replyOnceAttributes, a)
		}
	}
	return int(n), nil
}

func (s *baseSession) WriteReadDatagram(wd *Datagram, rd *Datagram) error {
	attempts := 0
retry:
	_, err := s.WriteDatagram(wd)
	if err != nil {
		return err
	}
	_, err = s.ReadDatagram(rd)
	if err != nil {
		attempts++
		if attempts < s.retries {
			goto retry
		}
		return err
	}
	if !validResponseAndMessageAuthenticator(rd, wd.Header.Authenticator, s.sharedSecret) {
		return fmt.Errorf("invalid RADIUS response authenticators")
	}
	return nil
}

func validResponseAndMessageAuthenticator(d *Datagram, reqauth [16]byte, secret string) bool {
	swap(d.Header.Authenticator[:], reqauth[:])

	maValid := true
	if ma := d.Attributes.FirstOfType(AttributeTypeMessageAuthenticator); ma != nil {
		if len(ma.Value) != md5.Size {
			return false
		}
		old := make([]byte, md5.Size)
		for i := 0; i < md5.Size; i++ {
			old[i] = ma.Value[i]
			ma.Value[i] = 0
		}

		mac := hmac.New(md5.New, []byte(secret))
		_, err := d.WriteTo(mac)
		if err != nil {
			return false
		}
		sum := mac.Sum(nil)
		copy(ma.Value, sum)
		maValid = subtle.ConstantTimeCompare(sum, old) == 1
	}

	hash := md5.New()
	_, err := d.WriteTo(hash)
	if err != nil {
		panic(err)
	}
	hash.Write([]byte(secret))
	sum := hash.Sum(nil)
	return maValid && subtle.ConstantTimeCompare(sum, reqauth[:]) == 1
}

// func validRequestMessageAuthenticator(d *Datagram, ss string) bool {
// 	ma := d.FirstAttributeOfType(AttributeTypeMessageAuthenticator)
// 	if ma == nil {
// 		return true
// 	}
//
// 	if len(ma.Value) != md5.Size {
// 		return false
// 	}
// 	old := make([]byte, md5.Size)
// 	for i := 0; i < md5.Size; i++ {
// 		old[i] = ma.Value[i]
// 		ma.Value[i] = 0
// 	}
//
// 	mac := hmac.New(md5.New, []byte(ss))
// 	_, err := d.WriteTo(mac)
// 	if err != nil {
// 		return false
// 	}
// 	sum := mac.Sum(nil)
// 	copy(ma.Value, sum)
// 	return subtle.ConstantTimeCompare(sum, old) == 1
// }

func randUint8() uint8 {
	id, err := rand.Int(rand.Reader, big.NewInt(256))
	if err != nil {
		panic(err)
	}
	return uint8(id.Int64())
}
