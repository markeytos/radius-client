/*
Copyright © 2024 Keytos alan@keytos.io

Define RADIUS accounting session
*/
package radius

import (
	"errors"
	"fmt"
	"net"
	"time"
)

type AccountingSession struct {
	baseSession
}

func NewAccountingSession(conn net.Conn, ss string, timeout time.Duration, retries int) *AccountingSession {
	return &AccountingSession{
		baseSession: baseSession{
			identifier:   randUint8(),
			conn:         conn,
			sharedSecret: ss,
			timeout:      timeout,
			retries:      retries,
		},
	}
}

func (s *AccountingSession) Status() error {
	sd := s.newRequestDatagram(
		CodeStatusServer,
		newEmptyMessageAuthenticator(),
	)
	rd := &Datagram{}
	err := s.WriteReadDatagram(sd, rd)
	if err != nil {
		return fmt.Errorf("failed to carry out status round: %w", err)
	}

	if rd.Header.Code != CodeAccountingResponse {
		return fmt.Errorf("invalid status response code: %s", rd.Header.Code.String())
	}
	if !rd.ContainsAttribute(AttributeTypeMessageAuthenticator) {
		return errors.New("missing message authenticator in response")
	}
	return nil
}
