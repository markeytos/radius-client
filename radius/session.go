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
	identifier          uint8
	conn                net.Conn
	sharedSecret        string
	timeout             time.Duration
	retries             int
	mtuSize             int
	sendAttributes      []*Attribute
	replyOnceAttributes []*Attribute
	lastReadDatagram    *Datagram
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

func (s *baseSession) newRequestDatagram(c Code, attrs ...*Attribute) *Datagram {
	h := s.newRequestHeader(c)
	return s.newDatagram(h, attrs...)
}

func (s *baseSession) newDatagram(h *Header, attrs ...*Attribute) *Datagram {
	attrs = append(attrs, s.sendAttributes...)
	if s.replyOnceAttributes != nil {
		attrs = append(attrs, s.replyOnceAttributes...)
		s.replyOnceAttributes = nil
	}
	d := newDatagram(h, attrs)
	if ma := d.FirstAttribute(AttributeTypeMessageAuthenticator); ma != nil {
		writeMessageAuthenticator(d, ma, s.sharedSecret)
	}
	return d
}

func (s *baseSession) WriteDatagram(sd *Datagram) (int, error) {
	err := s.conn.SetWriteDeadline(time.Now().Add(s.timeout))
	if err != nil {
		return 0, fmt.Errorf("error setting send deadline: %w", err)
	}
	n, err := sd.WriteTo(s.conn)
	if err != nil {
		return int(n), fmt.Errorf("error sending RADIUS datagram: %w", err)
	}
	return int(n), nil
}

func (s *baseSession) ReadDatagram(rd *Datagram) (int, error) {
	err := s.conn.SetReadDeadline(time.Now().Add(s.timeout))
	if err != nil {
		return 0, fmt.Errorf("error setting receive deadline: %w", err)
	}
	n, err := rd.ReadFrom(s.conn)
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

func (s *baseSession) WriteReadDatagram(sd *Datagram, rd *Datagram) error {
	attempts := 0
retry:
	_, err := s.WriteDatagram(sd)
	if err != nil {
		return err
	}
	_, err = s.ReadDatagram(rd)
	if err != nil {
		attempts++
		if attempts < s.retries {
			println("retry at sending due to no reply")
			goto retry
		}
		return err
	}
	if !validResponseAndMessageAuthenticator(rd, sd.Header.Authenticator, s.sharedSecret) {
		return fmt.Errorf("invalid RADIUS response authenticators")
	}
	return nil
}

func validResponseAndMessageAuthenticator(d *Datagram, reqauth [16]byte, secret string) bool {
	swap(d.Header.Authenticator[:], reqauth[:])

	maValid := true
	if ma := d.FirstAttribute(AttributeTypeMessageAuthenticator); ma != nil {
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

func validRequestMessageAuthenticator(d *Datagram, ss string) bool {
	ma := d.FirstAttribute(AttributeTypeMessageAuthenticator)
	if ma == nil {
		return true
	}

	if len(ma.Value) != md5.Size {
		return false
	}
	old := make([]byte, md5.Size)
	for i := 0; i < md5.Size; i++ {
		old[i] = ma.Value[i]
		ma.Value[i] = 0
	}

	mac := hmac.New(md5.New, []byte(ss))
	_, err := d.WriteTo(mac)
	if err != nil {
		return false
	}
	sum := mac.Sum(nil)
	copy(ma.Value, sum)
	return subtle.ConstantTimeCompare(sum, old) == 1
}

func randUint8() uint8 {
	id, err := rand.Int(rand.Reader, big.NewInt(256))
	if err != nil {
		panic(err)
	}
	return uint8(id.Int64())
}
