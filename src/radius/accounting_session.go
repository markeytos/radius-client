/*
Copyright © 2024 Keytos alan@keytos.io

Define RADIUS accounting session
*/
package radius

import (
	"crypto/md5"
	"fmt"
	"net"
	"time"
)

type AccountingSession struct {
	session
	SkipCheckAcctStatusType bool
	SkipCheckAcctSessionId  bool
	SkipCheckAcctNasId      bool
}

func NewAccountingSession(conn net.Conn, ss string, timeout, minWriteJitter, maxWriteJitter time.Duration, retries, mtuSize int, sendattrsMap, recvattrsMap AttributeMap) (*AccountingSession, error) {
	session, err := newSession(conn, ss, timeout, minWriteJitter, maxWriteJitter, retries, mtuSize, sendattrsMap, recvattrsMap)
	if err != nil {
		return nil, err
	}
	return &AccountingSession{session: *session}, nil
}

func (s *AccountingSession) Status() error {
	wd, err := s.newRequestDatagram(
		CodeStatusServer,
		newEmptyMessageAuthenticator(),
	)
	if err != nil {
		return err
	}

	rd := &Datagram{}
	err = s.WriteReadDatagram(wd, rd)
	if err != nil {
		return fmt.Errorf("failed to carry out status round: %w", err)
	}

	if rd.Header.Code != CodeAccountingResponse {
		return fmt.Errorf("invalid status response code: %s", rd.Header.Code.String())
	}
	if !rd.Attributes.ContainsType(AttributeTypeMessageAuthenticator) {
		return fmt.Errorf("missing message authenticator in response")
	}
	return s.lastReadDatagramHasExpectedAttributes()
}

func (s *AccountingSession) Account() error {
	if !s.SkipCheckAcctStatusType &&
		!s.sendAttributes.ContainsType(AttributeTypeAcctStatusType) {
		return fmt.Errorf("acct: missing attribute Acct-Status-Type")
	}
	if !s.SkipCheckAcctSessionId &&
		!s.sendAttributes.ContainsType(AttributeTypeAcctSessionId) {
		return fmt.Errorf("acct: missing attribute Acct-Session-Id")
	}
	if !s.SkipCheckAcctNasId &&
		!s.sendAttributes.ContainsType(AttributeTypeNasIdentifier) &&
		!s.sendAttributes.ContainsType(AttributeTypeNasIpAddress) {
		return fmt.Errorf("acct: missing attribute NAS-Identifier or ")
	}

	sd, err := s.newAccountingRequestDatagram()
	if err != nil {
		return err
	}
	rd := &Datagram{}
	err = s.WriteReadDatagram(sd, rd)
	if err != nil {
		return fmt.Errorf("acct: %w", err)
	}

	if rd.Header.Code != CodeAccountingResponse {
		a := rd.Attributes.FirstOfType(AttributeTypeReplyMessage)
		if a == nil {
			return fmt.Errorf("acct: accounting failed")
		}
		return fmt.Errorf("acct: accounting failed: %s", string(a.Value))
	}
	return s.lastReadDatagramHasExpectedAttributes()
}

func (s *AccountingSession) newAccountingRequestDatagram() (*Datagram, error) {
	h := s.newAccountingRequestHeader()
	d, err := s.newDatagram(h)
	if err != nil {
		return nil, err
	}

	hash := md5.New()
	_, err = d.WriteTo(hash)
	if err != nil {
		return nil, err
	}
	hash.Write([]byte(s.sharedSecret))
	copy(h.Authenticator[:], hash.Sum(nil))

	return d, nil
}

func (s *AccountingSession) newAccountingRequestHeader() *Header {
	s.identifier++
	h := &Header{
		Code:       CodeAccountingRequest,
		Identifier: s.identifier,
		Length:     uint16(headerLen),
	}
	return h
}
