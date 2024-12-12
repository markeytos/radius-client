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

func NewAuthenticationSession(conn net.Conn, ss string, timeout time.Duration, retries int) *AuthenticationSession {
	return &AuthenticationSession{
		baseSession: baseSession{
			identifier:   randUint8(),
			rounds:       0,
			conn:         conn,
			sharedSecret: ss,
			timeout:      timeout,
			retries:      retries,
		},
	}
}

func (s *AuthenticationSession) Status() error {
	sd, err := CreateDatagram(CodeStatusServer, s.identifier, nil)
	if err != nil {
		return fmt.Errorf("failed to create datagram: %w", err)
	}
	err = sd.AddRequestMessageAuthenticator(s.sharedSecret)
	if err != nil {
		return fmt.Errorf("failed to add message authenticator: %w", err)
	}
	s.identifier++

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
	if !rd.ValidResponseAuthenticatorAndMessageAuthenticator(sd.Header.Authenticator, s.sharedSecret) {
		return errors.New("invalid response authenticators")
	}
	return nil
}
