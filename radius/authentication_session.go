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

func NewAuthenticationSession(conn net.Conn, ss string, timeout time.Duration, retries int, sendattrs map[AttributeType]string) (*AuthenticationSession, error) {
	return &AuthenticationSession{
		baseSession: baseSession{
			identifier:     randUint8(),
			conn:           conn,
			sharedSecret:   ss,
			timeout:        timeout,
			retries:        retries,
			sendAttributes: sendattrs,
		},
	}, nil
}

func (s *AuthenticationSession) MAB(macAddress string) error {
	attrm := map[AttributeType]string{
		AttributeTypeUserName: macAddress,
	}
	sd, err := s.createDatagram(CodeAccessRequest, attrm)
	if err != nil {
		return fmt.Errorf("failed to create datagram: %w", err)
	}

	rd, err := s.sendReceiveDatagram(sd)
	if err != nil {
		return fmt.Errorf("failed to do MAB round: %w", err)
	}

	if rd.Header.Code != CodeAccessAccept {
		a := rd.FirstAttribute(AttributeTypeReplyMessage)
		if a == nil {
			return fmt.Errorf("MAB authentication failed")
		}
		return fmt.Errorf("MAB authentication failed: %s", string(a.Value()))
	}
	return nil
}

func (s *AuthenticationSession) PAP(username, password string) error {
	attrm := map[AttributeType]string{
		AttributeTypeUserName:     username,
		AttributeTypeUserPassword: password,
	}
	sd, err := s.createDatagram(CodeAccessRequest, attrm)
	if err != nil {
		return fmt.Errorf("failed to create datagram: %w", err)
	}

	rd, err := s.sendReceiveDatagram(sd)
	if err != nil {
		return fmt.Errorf("failed to do MAB round: %w", err)
	}

	if rd.Header.Code != CodeAccessAccept {
		a := rd.FirstAttribute(AttributeTypeReplyMessage)
		if a == nil {
			return fmt.Errorf("PAP authentication failed")
		}
		return fmt.Errorf("PAP authentication failed: %s", string(a.Value()))
	}
	return nil
}

func (s *AuthenticationSession) EapMsChapV2(username, password string) error {
	return errors.New("not implemented EapMsChapV2")
}

// func (s *AuthenticationSession) EapTLS(username, password string) error {
// 	return errors.New("not implemented EapTLS")
// }

func (s *AuthenticationSession) EapTtlsPAP(username, password string) error {
	return errors.New("not implemented EapTtlsPAP")
}

func (s *AuthenticationSession) EapTtlsEapMsChapV2(username, password string) error {
	return errors.New("not implemented EapTtlsEapMsChapV2")
}

// func (s *AuthenticationSession) EapTtlsEapTLS(username, password string) error {
// 	return errors.New("not implemented EapTtlsEapTLS")
// }

// func (s *AuthenticationSession) PeapMsChapV2(username, password string) error {
// 	return errors.New("not implemented PeapMsChapV2")
// }

func (s *AuthenticationSession) Status() error {
	sd, err := s.createDatagram(CodeStatusServer, AttributeMap{AttributeTypeMessageAuthenticator: ""})
	if err != nil {
		return fmt.Errorf("failed to create datagram: %w", err)
	}

	rd, err := s.sendReceiveDatagram(sd)
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
