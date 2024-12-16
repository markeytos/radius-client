/*
Copyright © 2024 Keytos alan@keytos.io

Define EAP authentication session
*/
package eap

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

type Session struct {
	Tunnel            io.ReadWriter
	EAPSendStart      bool
	AnonymousUsername string
	identifier        uint8
	lastReadDatagram  *Datagram
}

func NewSession(tunnel io.ReadWriter, anonymousUname string, eapSendStart bool) Session {
	return Session{
		Tunnel:            tunnel,
		EAPSendStart:      eapSendStart,
		AnonymousUsername: anonymousUname,
		identifier:        randUint8(),
	}
}

func (s *Session) newHeader(c Code) *Header {
	h := &Header{
		Code:       c,
		Identifier: s.identifier,
		Length:     4,
	}
	s.identifier++
	return h
}

func (s *Session) newDatagram(cont *Content) *Datagram {
	h := s.newHeader(CodeResponse)
	return newDatagram(h, cont)
}

func (s *Session) MsCHAPv2(uname, pw string) error {
	err := s.start(TypeMsCHAPv2)
	if err != nil {
		return err
	}
	// use s.lastReadDatagram to get mschapv2 stuff & more
	return errors.New("not implemented")
}

func (s *Session) TLS() error {
	err := s.start(TypeTLS)
	if err != nil {
		return err
	}
	return errors.New("not implemented")
}

func (s *Session) TtlsPAP(uname, pw string) error {
	err := s.start(TypeTTLS)
	if err != nil {
		return err
	}
	return errors.New("not implemented")
}

func (s *Session) TtlsEapMsCHAPv2(uname, pw string) error {
	err := s.start(TypeTTLS)
	if err != nil {
		return err
	}
	return errors.New("not implemented")
}

func (s *Session) TtlsEapTLS() error {
	err := s.start(TypeTTLS)
	if err != nil {
		return err
	}
	return errors.New("not implemented")
}

func (s *Session) PeapMsCHAPv2(uname, pw string) error {
	err := s.start(TypePEAP)
	if err != nil {
		return err
	}
	return errors.New("not implemented")
}

func (s Session) WriteDatagram(sd Datagram) (int, error) {
	n, err := sd.WriteTo(s.Tunnel)
	if err != nil {
		return int(n), fmt.Errorf("error sending EAP datagram: %w", err)
	}
	return int(n), nil
}

func (s Session) ReadDatagram(rd *Datagram) (int, error) {
	n, err := rd.ReadFrom(s.Tunnel)
	if err != nil {
		return int(n), fmt.Errorf("error receiving EAP datagram: %w", err)
	}
	s.lastReadDatagram = rd
	return int(n), nil
}

func (s *Session) WriteReadDatagram(sd Datagram, rd *Datagram) error {
	_, err := s.WriteDatagram(sd)
	if err != nil {
		return err
	}
	_, err = s.ReadDatagram(rd)
	if err != nil {
		return err
	}
	return nil
}

func (s *Session) start(targetType Type) error {
	rd := &Datagram{}
	if s.EAPSendStart {
		_, err := s.Tunnel.Write(nil)
		if err != nil {
			return err
		}
		_, err = s.ReadDatagram(rd)
		if err != nil {
			return err
		}
		if rd.Header.Code != CodeRequest || rd.Content == nil || rd.Content.Type != TypeIdentity {
			return fmt.Errorf("did not receive identity request from server")
		}
	}

	id := &Content{
		Type: TypeIdentity,
		Data: []byte(s.AnonymousUsername),
	}
	sd := s.newDatagram(id)
	err := s.WriteReadDatagram(*sd, rd)
	if err != nil {
		return err
	}
	if rd.Header.Code != CodeRequest {
		return fmt.Errorf("unexpected EAP code in server response")
	}
	if rd.Content == nil {
		return fmt.Errorf("expected EAP content in request")
	}
	if rd.Content.Type != targetType {
		nak := &Content{
			Type: TypeNAK,
			Data: []byte{byte(targetType)},
		}
		sd = s.newDatagram(nak)
		err = s.WriteReadDatagram(*sd, rd)
		if err != nil {
			return err
		}
		if rd.Header.Code != CodeRequest || rd.Content == nil || rd.Content.Type != targetType {
			return fmt.Errorf("got %s: failed to negotiate the target EAP type", sd.Header.Code.String())
		}
	}
	return nil
}

func randUint8() uint8 {
	id, err := rand.Int(rand.Reader, big.NewInt(256))
	if err != nil {
		panic(err)
	}
	return uint8(id.Int64())
}
