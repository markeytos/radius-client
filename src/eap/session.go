/*
Copyright © 2024 Keytos alan@keytos.io

Define EAP authentication session
*/
package eap

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
)

type Session struct {
	Tunnel            net.Conn
	EAPSendStart      bool
	AnonymousUsername string
	identifier        uint8
	lastAction        sessionLastAction
	lastReadDatagram  *Datagram
	RecvKey, SendKey  []byte
}

type sessionLastAction int

const (
	sessionLastActionNone sessionLastAction = iota
	sessionLastActionWriteDatagram
	sessionLastActionReadDatagram
	sessionLastActionError
)

func NewSession(tunnel net.Conn, anonymousUname string, eapSendStart bool) Session {
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

func (s *Session) WriteDatagram(wd *Datagram) (int, error) {
	switch s.lastAction {
	case sessionLastActionNone, sessionLastActionReadDatagram:
		break
	default:
		s.lastAction = sessionLastActionError
		return 0, fmt.Errorf("eap: out of order write: invalid last action")
	}
	n, err := wd.WriteTo(s.Tunnel)
	if err != nil {
		s.lastAction = sessionLastActionError
		return int(n), fmt.Errorf("eap: error sending datagram: %w", err)
	}
	s.lastAction = sessionLastActionWriteDatagram
	return int(n), nil
}

func (s *Session) ReadDatagram(rd *Datagram) (int, error) {
	switch s.lastAction {
	case sessionLastActionNone, sessionLastActionWriteDatagram:
		break
	default:
		s.lastAction = sessionLastActionError
		return 0, fmt.Errorf("eap: out of order read: invalid last action")
	}
	n, err := rd.ReadFrom(s.Tunnel)
	if err != nil {
		s.lastAction = sessionLastActionError
		return int(n), fmt.Errorf("eap: error receiving datagram: %w", err)
	}
	s.lastReadDatagram = rd
	s.lastAction = sessionLastActionReadDatagram
	return int(n), nil
}

func (s *Session) WriteReadDatagram(wd *Datagram, rd *Datagram) error {
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
	wd := s.newDatagram(id)
	err := s.WriteReadDatagram(wd, rd)
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
		wd = s.newDatagram(nak)
		err = s.WriteReadDatagram(wd, rd)
		if err != nil {
			return err
		}
		if rd.Header.Code != CodeRequest || rd.Content == nil || rd.Content.Type != targetType {
			return fmt.Errorf("got %s: failed to negotiate the target EAP type", wd.Header.Code.String())
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
