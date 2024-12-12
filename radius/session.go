/*
Copyright © 2024 Keytos alan@keytos.io

Define generic RADIUS session
*/
package radius

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"time"
)

type Session interface {
	Status() error
}

type baseSession struct {
	identifier   uint8
	rounds       int
	conn         net.Conn
	sharedSecret string
	timeout      time.Duration
	retries      int
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
	r, err := CreateDatagramFromReader(conn)
	if err != nil {
		attempts++
		if attempts > s.retries {
			goto retry
		}
		return nil, fmt.Errorf("error receiving datagram: %w", err)
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
