/*
Copyright © 2024 Keytos alan@keytos.io

Define RADIUS authentication session
*/
package radius

import (
	"crypto/md5"
	"crypto/subtle"
	"fmt"
	"net"
	"strings"
	"time"
)

type AuthenticationSession struct {
	session
}

func NewAuthenticationSession(conn net.Conn, ss string, timeout time.Duration, retries, mtuSize int, sendattrsMap, recvattrsMap AttributeMap) (*AuthenticationSession, error) {
	session, err := newSession(conn, ss, timeout, retries, mtuSize, sendattrsMap, recvattrsMap)
	if err != nil {
		return nil, err
	}
	return &AuthenticationSession{session: *session}, nil
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
		return fmt.Errorf("status: %w", err)
	}

	if rd.Header.Code != CodeAccessAccept {
		return fmt.Errorf("status: invalid status response code: %s", rd.Header.Code.String())
	}
	if !rd.Attributes.ContainsType(AttributeTypeMessageAuthenticator) {
		return fmt.Errorf("status: missing message authenticator in response")
	}
	return s.lastReadDatagramHasExpectedAttributes()
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
		return fmt.Errorf("mab: %w", err)
	}

	if rd.Header.Code != CodeAccessAccept {
		a := rd.Attributes.FirstOfType(AttributeTypeReplyMessage)
		if a == nil {
			return fmt.Errorf("mab: authentication failed")
		}
		return fmt.Errorf("mab: authentication failed: %s", string(a.Value))
	}
	return s.lastReadDatagramHasExpectedAttributes()
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
		return fmt.Errorf("pap: %w", err)
	}

	if rd.Header.Code != CodeAccessAccept {
		a := rd.Attributes.FirstOfType(AttributeTypeReplyMessage)
		if a == nil {
			return fmt.Errorf("pap: authentication failed")
		}
		return fmt.Errorf("pap: authentication failed: %s", string(a.Value))
	}
	return s.lastReadDatagramHasExpectedAttributes()
}

func (s *AuthenticationSession) VerifyEAP(recvkey, sendkey []byte) error {
	if s.lastReadDatagram.Header.Code != CodeAccessAccept {
		return fmt.Errorf("eap: last read datagram was not an Access-Accept")
	}

	mismatchedKeys := make([]string, 0, 2)
	recvkeyAttr := s.lastReadDatagram.Attributes.FirstVendorSpecificAttributeOfType(VendorIdMicrosoft, VendorTypeMicrosoftMPPERecvKey)
	if recvkeyAttr != nil {
		if !s.sessionKeyEqual(recvkey, s.lastWrittenDatagram.Header.Authenticator[:], recvkeyAttr.Value[:2], recvkeyAttr.Value[2:]) {
			mismatchedKeys = append(mismatchedKeys, "MS-MPPE-Recv-Key")
		}
	}

	sendkeyAttr := s.lastReadDatagram.Attributes.FirstVendorSpecificAttributeOfType(VendorIdMicrosoft, VendorTypeMicrosoftMPPESendKey)
	if sendkeyAttr != nil {
		if !s.sessionKeyEqual(sendkey, s.lastWrittenDatagram.Header.Authenticator[:], sendkeyAttr.Value[:2], sendkeyAttr.Value[2:]) {
			mismatchedKeys = append(mismatchedKeys, "MS-MPPE-Send-Key")
		}
	}

	if len(mismatchedKeys) > 0 {
		return fmt.Errorf("eap: session key (%s) mismatch", strings.Join(mismatchedKeys, ", "))
	}
	return s.lastReadDatagramHasExpectedAttributes()
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
