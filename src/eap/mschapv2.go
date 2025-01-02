/*
Copyright © 2024 Keytos alan@keytos.io

Define MS-CHAPv2 authentication session
*/
package eap

import (
	"crypto/subtle"
	"fmt"

	"github.com/markeytos/radius-client/src/eap/mschapv2"
)

type MsCHAPv2 struct {
	*Session
	Username, Password string
}

func (s *MsCHAPv2) Authenticate() error {
	err := s.start(TypeMsCHAPv2)
	if err != nil {
		return err
	}

	if s.lastReadDatagram.Content.Type != TypeMsCHAPv2 {
		return fmt.Errorf("expected EAP packet of type MS-CHAPv2")
	}
	c, err := mschapv2.ReadChallenge(s.lastReadDatagram.Content.Data)
	if err != nil {
		return err
	}

	r := mschapv2.CreateEmptyResponse(c, s.Username)
	chall := mschapv2.ChallengeHash(r.PeerChallenge[:], c.Challenge[:], s.Username)
	pwb := mschapv2.Utf16Bytes(s.Password)
	pwh := mschapv2.NTPasswordHash(pwb)
	mschapv2.WriteNTResponse(r.NTResponse[:], pwh, chall)
	pwhh := mschapv2.NTPasswordHash(pwh)

	sd := s.newDatagram(&Content{Type: TypeMsCHAPv2, Data: r.ToBinary()})
	rd := &Datagram{}
	err = s.WriteReadDatagram(sd, rd)
	if err != nil {
		return err
	}

	if rd.Content.Type != TypeMsCHAPv2 {
		return fmt.Errorf("expected EAP packet of type MS-CHAPv2")
	}
	request, err := mschapv2.ReadRequest(rd.Content.Data)
	if err != nil {
		return err
	}
	if request.OpCode == mschapv2.OpCodeSuccess {
		var authenticator []byte
		_, err := fmt.Sscanf(request.Message, "S=%X M=%s", &authenticator, &request.Message)
		if err != nil {
			return err
		}
		authresp := mschapv2.AuthenticatorResponse(pwhh, r.NTResponse[:], chall)
		if subtle.ConstantTimeCompare(authenticator, authresp) == 0 {
			return fmt.Errorf("invalid success authenticator")
		}
	}

	sd = s.newDatagram(&Content{Type: TypeMsCHAPv2, Data: []byte{byte(request.OpCode)}})
	err = s.WriteReadDatagram(sd, rd)
	if err != nil {
		return err
	}

	if rd.Header.Code != CodeSuccess {
		return fmt.Errorf("authentication failed")
	}
	s.RecvKey, s.SendKey = mschapv2.SessionKeys(pwhh, r.NTResponse[:])
	return nil
}
