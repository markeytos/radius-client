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
	"strings"
	"time"
)

type session struct {
	net.Conn
	identifier          uint8
	sharedSecret        string
	timeout             time.Duration
	minWriteJitter      time.Duration
	maxWriteJitter      time.Duration
	retries             int
	mtuSize             int
	sendAttributes      Attributes
	recvAttributes      Attributes
	replyOnceAttributes Attributes
	lastReadDatagram    *Datagram
	lastWrittenDatagram *Datagram
}

func newSession(conn net.Conn, ss string, timeout, minWriteJitter, maxWriteJitter time.Duration, retries, mtuSize int, sendattrsMap, recvattrsMap AttributeMap) (*session, error) {
	sendattrs, err := serializeAttributeMap(sendattrsMap)
	if err != nil {
		return nil, err
	}
	recvattrs, err := serializeAttributeMap(recvattrsMap)
	if err != nil {
		return nil, err
	}
	return &session{
		Conn:           conn,
		identifier:     randUint8(),
		sharedSecret:   ss,
		timeout:        timeout,
		minWriteJitter: minWriteJitter,
		maxWriteJitter: maxWriteJitter,
		retries:        retries,
		mtuSize:        mtuSize,
		sendAttributes: sendattrs,
		recvAttributes: recvattrs,
	}, nil
}

func (s *session) newRequestHeader(c Code) *Header {
	s.identifier++
	h := &Header{
		Code:       c,
		Identifier: s.identifier,
		Length:     uint16(headerLen),
	}
	_, err := rand.Read(h.Authenticator[:])
	if err != nil {
		panic(err)
	}
	return h
}

func (s *session) newRequestDatagram(c Code, attrs ...*Attribute) (*Datagram, error) {
	h := s.newRequestHeader(c)
	return s.newDatagram(h, attrs...)
}

func (s *session) newDatagram(h *Header, attrs ...*Attribute) (*Datagram, error) {
	attrs = append(attrs, s.sendAttributes...)
	if s.replyOnceAttributes != nil {
		attrs = append(attrs, s.replyOnceAttributes...)
		s.replyOnceAttributes = nil
	}
	d, err := newDatagram(h, attrs)
	if err != nil {
		return nil, err
	}
	if ma := d.Attributes.FirstOfType(AttributeTypeMessageAuthenticator); ma != nil {
		err = writeMessageAuthenticator(d, ma, s.sharedSecret)
		if err != nil {
			return nil, err
		}
	}
	return d, nil
}

func (s *session) WriteDatagram(wd *Datagram) (int, error) {
	time.Sleep(randDuration(s.minWriteJitter, s.maxWriteJitter))
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

func (s *session) ReadDatagram(rd *Datagram) (int, error) {
	var n int64
	var err error
	for range s.retries {
		err = s.SetReadDeadline(time.Now().Add(s.timeout))
		if err != nil {
			return 0, fmt.Errorf("error setting receive deadline: %w", err)
		}
		n, err = rd.ReadFrom(s)
		if err == nil && rd.Header.Identifier == s.identifier {
			break
		}
		_, werr := s.WriteDatagram(s.lastWrittenDatagram)
		if werr != nil {
			return 0, fmt.Errorf("error sending RADIUS datagram in receive retry: %w", werr)
		}
	}
	if rd.Header == nil || rd.Header.Identifier != s.identifier {
		return int(n), fmt.Errorf("did not get response from server")
	}
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
	if !validResponseAndMessageAuthenticator(rd, s.lastWrittenDatagram.Header.Authenticator, s.sharedSecret) {
		return int(n), fmt.Errorf("invalid RADIUS response authenticators")
	}
	return int(n), nil
}

func (s *session) WriteReadDatagram(wd *Datagram, rd *Datagram) error {
	_, err := s.WriteDatagram(wd)
	if err != nil {
		return err
	}
	_, err = s.ReadDatagram(rd)
	if err != nil {
		return err
	}
	return nil
}

func (s *session) lastReadDatagramHasExpectedAttributes() error {
	if s.lastReadDatagram == nil {
		return fmt.Errorf("session has not read a datagram")
	}
	expectedAttrs := make([]string, 0)
	for _, expected := range s.recvAttributes {
		matched := false
		for _, attr := range s.lastReadDatagram.Attributes {
			if expected.Type == attr.Type && subtle.ConstantTimeCompare(expected.Value, attr.Value) == 1 {
				fmt.Printf("G %x\n", expected.Value)
				matched = true
			}
		}
		if !matched {
			fmt.Printf("B %x\n", expected.Value)
			expectedAttrs = append(expectedAttrs, expected.Type.String())
		}
	}
	if len(expectedAttrs) > 0 {
		return fmt.Errorf("expected attributes were missing or had different values: %s", strings.Join(expectedAttrs, ", "))
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
		for i := range md5.Size {
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

func randDuration(min, max time.Duration) time.Duration {
	if min == max {
		return min
	}
	if min > max {
		return max
	}
	if max == 0 {
		return 0
	}
	id, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	if err != nil {
		panic(err)
	}
	return min + time.Duration(id.Int64())
}

func randUint8() uint8 {
	id, err := rand.Int(rand.Reader, big.NewInt(256))
	if err != nil {
		panic(err)
	}
	return uint8(id.Int64())
}
