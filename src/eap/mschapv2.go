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

func (s *Session) MsCHAPv2(uname, pw string) error {
	err := s.start(TypeMsCHAPv2)
	if err != nil {
		return err
	}

	if s.lastReadDatagram.Content.Type != TypeMsCHAPv2 {
		return fmt.Errorf("expected EAP packet of type MS-CHAPv2")
	}
	c, err := mschapv2.CreateChallengeFromBuffer(s.lastReadDatagram.Content.Data)
	if err != nil {
		return err
	}

	r := mschapv2.CreateEmptyResponse(c, uname)
	chall := mschapv2.ChallengeHash(r.PeerChallenge[:], c.Challenge[:], uname)
	pwb := mschapv2.Utf16Bytes(pw)
	pwh := mschapv2.NTPasswordHash(pwb)
	mschapv2.WriteNTResponse(r.NTResponse[:], pwh, chall)
	pwhh := mschapv2.NTPasswordHash(pwh)

	wd := s.newDatagram(&Content{Type: TypeMsCHAPv2, Data: r.ToBinary()})
	rd := &Datagram{}
	err = s.WriteReadDatagram(wd, rd)
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

	wd = s.newDatagram(&Content{Type: TypeMsCHAPv2, Data: []byte{byte(request.OpCode)}})
	_, err = s.WriteDatagram(wd)
	if err != nil {
		return err
	}

	if s.inEncryptedTunnel {
		return s.Tunnel.Close()
	}

	_, err = s.ReadDatagram(rd)
	if err != nil {
		return err
	}
	if rd.Header.Code != CodeSuccess {
		return fmt.Errorf("authentication failed")
	}
	s.RecvKey, s.SendKey = mschapv2.SessionKeys(pwhh, r.NTResponse[:])
	return nil
}
