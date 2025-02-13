/*
Copyright © 2024 Keytos alan@keytos.io

Define RADIUS accounting session
*/
package radius

import (
	"fmt"
	"net"
	"time"
)

type AccountingSession struct {
	session
}

func NewAccountingSession(conn net.Conn, ss string, timeout time.Duration, retries, mtuSize int, sendattrsMap, recvattrsMap AttributeMap) (*AccountingSession, error) {
	session, err := newSession(conn, ss, timeout, retries, mtuSize, sendattrsMap, recvattrsMap)
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
