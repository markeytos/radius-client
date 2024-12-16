/*
Copyright © 2024 Keytos alan@keytos.io

Define RADIUS authentication session
*/
package radius

import (
	"errors"
	"fmt"
	"net"
	"time"
)

type AuthenticationSession struct {
	baseSession
}

func NewAuthenticationSession(conn net.Conn, ss string, timeout time.Duration, retries, mtuSize int, sendattrsMap map[AttributeType]string) (*AuthenticationSession, error) {
	sendattrs, err := serializeAttributeMap(sendattrsMap)
	if err != nil {
		return nil, err
	}
	return &AuthenticationSession{
		baseSession: baseSession{
			identifier:     randUint8(),
			conn:           conn,
			sharedSecret:   ss,
			timeout:        timeout,
			retries:        retries,
			mtuSize:        mtuSize,
			sendAttributes: sendattrs,
		},
	}, nil
}

func (s *AuthenticationSession) MAB(macAddress string) error {
	sd := s.newRequestDatagram(
		CodeAccessRequest,
		newAttribute(AttributeTypeUserName, []byte(macAddress)),
	)
	rd := &Datagram{}
	err := s.WriteReadDatagram(sd, rd)
	if err != nil {
		return fmt.Errorf("failed to do MAB round: %w", err)
	}

	if rd.Header.Code != CodeAccessAccept {
		a := rd.FirstAttribute(AttributeTypeReplyMessage)
		if a == nil {
			return fmt.Errorf("MAB authentication failed")
		}
		return fmt.Errorf("MAB authentication failed: %s", string(a.Value))
	}
	return nil
}

func (s *AuthenticationSession) PAP(username, password string) error {
	h := s.newRequestHeader(CodeAccessRequest)
	sd := s.newDatagram(
		h,
		newAttribute(AttributeTypeUserName, []byte(username)),
		newUserPasswordAttribute(password, s.sharedSecret, h.Authenticator[:]),
		newEmptyMessageAuthenticator(),
	)
	rd := &Datagram{}

	err := s.WriteReadDatagram(sd, rd)
	if err != nil {
		return fmt.Errorf("failed to do MAB round: %w", err)
	}

	if rd.Header.Code != CodeAccessAccept {
		a := rd.FirstAttribute(AttributeTypeReplyMessage)
		if a == nil {
			return fmt.Errorf("PAP authentication failed")
		}
		return fmt.Errorf("PAP authentication failed: %s", string(a.Value))
	}
	return nil
}

func (s *AuthenticationSession) Status() error {
	sd := s.newRequestDatagram(
		CodeStatusServer,
		newEmptyMessageAuthenticator(),
	)
	rd := &Datagram{}
	err := s.WriteReadDatagram(sd, rd)
	if err != nil {
		return fmt.Errorf("failed to carry out status round: %w", err)
	}

	if rd.Header.Code != CodeAccessAccept {
		return fmt.Errorf("invalid status response code: %s", rd.Header.Code.String())
	}
	if !rd.ContainsAttribute(AttributeTypeMessageAuthenticator) {
		return errors.New("missing message authenticator in response")
	}
	return nil
}
