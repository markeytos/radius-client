/*
Copyright © 2025 Keytos alan@keytos.io

Define MD5-Challenge authentication session
*/
package eap

import (
	"crypto/md5"
	"fmt"
)

func (s *Session) MD5(macAddress string) error {
	err := s.start(TypeMD5)
	if err != nil {
		return err
	}

	if s.lastReadDatagram.Content.Type != TypeMD5 {
		return fmt.Errorf("expected EAP packet of type MD5")
	}
	challengeSize := s.lastReadDatagram.Content.Data[0]
	challenge := s.lastReadDatagram.Content.Data[1 : challengeSize+1]

	sum := make([]byte, 1, md5.Size+1)
	sum[0] = md5.Size

	h := md5.New()
	h.Write([]byte{s.identifier})
	h.Write([]byte(macAddress))
	h.Write(challenge)
	sum = h.Sum(sum)

	wd := s.newDatagram(&Content{Type: TypeMD5, Data: sum})
	rd := &Datagram{}
	err = s.WriteReadDatagram(wd, rd)
	if err != nil {
		return err
	}

	if rd.Header.Code != CodeSuccess {
		return fmt.Errorf("authentication failed")
	}
	return nil
}
