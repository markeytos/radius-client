/*
Copyright © 2024 Keytos alan@keytos.io

Define RADIUS authentication session
*/
package radius

import (
	"crypto/md5"
	"crypto/subtle"
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

func (s *AuthenticationSession) Status() error {
	sd, err := s.newRequestDatagram(
		CodeStatusServer,
		newEmptyMessageAuthenticator(),
	)
	if err != nil {
		return err
	}

	rd := &Datagram{}
	err = s.WriteReadDatagram(sd, rd)
	if err != nil {
		return fmt.Errorf("failed to carry out status round: %w", err)
	}

	if rd.Header.Code != CodeAccessAccept {
		return fmt.Errorf("invalid status response code: %s", rd.Header.Code.String())
	}
	if !rd.Attributes.ContainsOfType(AttributeTypeMessageAuthenticator) {
		return errors.New("missing message authenticator in response")
	}
	return nil
}

func (s *AuthenticationSession) MAB(macAddress string) error {
	sd, err := s.newRequestDatagram(
		CodeAccessRequest,
		newAttribute(AttributeTypeUserName, []byte(macAddress)),
	)
	if err != nil {
		return err
	}

	rd := &Datagram{}
	err = s.WriteReadDatagram(sd, rd)
	if err != nil {
		return fmt.Errorf("failed to do MAB round: %w", err)
	}

	if rd.Header.Code != CodeAccessAccept {
		a := rd.Attributes.FirstOfType(AttributeTypeReplyMessage)
		if a == nil {
			return fmt.Errorf("MAB authentication failed")
		}
		return fmt.Errorf("MAB authentication failed: %s", string(a.Value))
	}
	return nil
}

func (s *AuthenticationSession) PAP(username, password string) error {
	h := s.newRequestHeader(CodeAccessRequest)
	sd, err := s.newDatagram(
		h,
		newAttribute(AttributeTypeUserName, []byte(username)),
		newUserPasswordAttribute(password, s.sharedSecret, h.Authenticator[:]),
		newEmptyMessageAuthenticator(),
	)
	if err != nil {
		return err
	}

	rd := &Datagram{}
	err = s.WriteReadDatagram(sd, rd)
	if err != nil {
		return fmt.Errorf("failed to do MAB round: %w", err)
	}

	if rd.Header.Code != CodeAccessAccept {
		a := rd.Attributes.FirstOfType(AttributeTypeReplyMessage)
		if a == nil {
			return fmt.Errorf("PAP authentication failed")
		}
		return fmt.Errorf("PAP authentication failed: %s", string(a.Value))
	}
	return nil
}

func (s *AuthenticationSession) VerifyEAP(recvkey, sendkey []byte) error {
	if s.lastReadDatagram.Header.Code != CodeAccessAccept {
		return fmt.Errorf("last read datagram was not an Access-Accept")
	}

	recvkeyAttr := s.lastReadDatagram.Attributes.FirstVendorSpecificAttributeOfType(VendorIdMicrosoft, VendorTypeMicrosoftMPPERecvKey)
	if recvkeyAttr != nil {
		if !s.sessionKeyEqual(recvkey, s.lastWrittenDatagram.Header.Authenticator[:], recvkeyAttr.Value[:2], recvkeyAttr.Value[2:]) {
			return fmt.Errorf("session key (MS-MPPE-Recv-Key) mismatch")
		}
	}

	sendkeyAttr := s.lastReadDatagram.Attributes.FirstVendorSpecificAttributeOfType(VendorIdMicrosoft, VendorTypeMicrosoftMPPESendKey)
	if sendkeyAttr != nil {
		if !s.sessionKeyEqual(sendkey, s.lastWrittenDatagram.Header.Authenticator[:], sendkeyAttr.Value[:2], sendkeyAttr.Value[2:]) {
			return fmt.Errorf("session key (MS-MPPE-Send-Key) mismatch")
		}
	}

	return nil
}

func (s *AuthenticationSession) sessionKeyEqual(key, reqauth, salt, enckey []byte) bool {
	if key == nil {
		return false
	}
	keystr := make([]byte, (16+len(key))&^15)
	keystr[0] = byte(len(key))
	copy(keystr[1:], key)
	ss := []byte(s.sharedSecret)
	enc := make([]byte, 0, len(keystr))

	h := md5.New()
	h.Write(ss)
	h.Write(reqauth)
	h.Write(salt)
	enc = h.Sum(enc)

	for i := 0; i < 16 && i < len(keystr); i++ {
		enc[i] ^= keystr[i]
	}

	for i := 16; i < len(keystr); i += 16 {
		h.Reset()
		h.Write(ss)
		h.Write(enc[i-16 : i])
		enc = h.Sum(enc)
		for j := 0; j < 16; j++ {
			enc[i+j] ^= keystr[i+j]
		}
	}

	return subtle.ConstantTimeCompare(enc, enckey) == 1
}
