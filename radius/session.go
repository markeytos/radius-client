/*
Copyright © 2024 Keytos alan@keytos.io

Define generic RADIUS session
*/
package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net"
	"time"
)

type baseSession struct {
	identifier     uint8
	conn           net.Conn
	sharedSecret   string
	timeout        time.Duration
	retries        int
	sendAttributes AttributeMap
}

func (s *baseSession) createDatagram(c Code, attrMap AttributeMap) (*Datagram, error) {
	maps.Copy(attrMap, s.sendAttributes)

	h := &Header{
		Code:       c,
		Identifier: s.identifier,
		Length:     uint16(headerLen),
	}
	_, err := rand.Read(h.Authenticator[:])
	if err != nil {
		return nil, err
	}

	attrs, err := serializeRequestAttributes(attrMap, s.sharedSecret, h.Authenticator[:])
	if err != nil {
		return nil, err
	}

	attrs_len := 0
	for _, a := range attrs {
		attrs_len += len(a.buffer)
	}
	h.Length += uint16(attrs_len)

	d := &Datagram{
		Header:     h,
		Attributes: attrs,
	}

	if _, ok := attrMap[AttributeTypeMessageAuthenticator]; ok {
		ma := d.FirstAttribute(AttributeTypeMessageAuthenticator)
		if ma == nil {
			panic("message authenticator must exist in datagram when constructed")
		}
		mac := hmac.New(md5.New, []byte(s.sharedSecret))
		_, err = d.WriteTo(mac)
		if err != nil {
			return nil, err
		}
		sum := mac.Sum(nil)
		copy(ma.Value(), sum)
	}

	s.identifier++
	return d, nil
}

func (s baseSession) sendReceiveDatagram(sd *Datagram) (*Datagram, error) {
	attempts := 0
	conn := s.conn
	timeout := s.timeout

retry:
	err := conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, fmt.Errorf("error setting send deadline: %w", err)
	}
	_, err = sd.WriteTo(conn)
	if err != nil {
		attempts++
		if attempts > s.retries {
			goto retry
		}
		return nil, fmt.Errorf("error sending datagram: %w", err)
	}
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, fmt.Errorf("error setting receive deadline: %w", err)
	}
	r, err := DeserializeDatagramFromReader(conn)
	if err != nil {
		attempts++
		if attempts > s.retries {
			goto retry
		}
		return nil, fmt.Errorf("error receiving datagram: %w", err)
	}
	if !r.ValidResponseAuthenticatorAndMessageAuthenticator(sd.Header.Authenticator, s.sharedSecret) {
		return nil, errors.New("invalid response authenticators")
	}
	return r, nil
}

func randUint8() uint8 {
	id, err := rand.Int(rand.Reader, big.NewInt(256))
	if err != nil {
		panic(err)
	}
	return uint8(id.Int64())
}
