/*
Copyright © 2024 Keytos alan@keytos.io

Define RADIUS EAP authentication tunnel
*/
package radius

import (
	"bytes"
	"fmt"
)

type eapAuthenticationTunnelLastAction int

const (
	eapAuthenticationTunnelLastActionNone eapAuthenticationTunnelLastAction = iota
	eapAuthenticationTunnelLastActionWritePacket
	eapAuthenticationTunnelLastActionReadPacket
	eapAuthenticationTunnelLastActionError
	eapAuthenticationTunnelLastActionClose
)

type EapAuthenticationTunnel struct {
	session           *AuthenticationSession
	anonymousUsername string
	lastAction        eapAuthenticationTunnelLastAction
}

func NewEapAuthenticationTunnel(session *AuthenticationSession, anonymousUsername string) *EapAuthenticationTunnel {
	session.sendAttributes = append(
		session.sendAttributes,
		newAttribute(AttributeTypeUserName, []byte(anonymousUsername)),
		newEmptyMessageAuthenticator(),
	)
	return &EapAuthenticationTunnel{
		session:           session,
		anonymousUsername: anonymousUsername,
	}
}

func (t *EapAuthenticationTunnel) Read(b []byte) (n int, err error) {
	switch t.lastAction {
	case eapAuthenticationTunnelLastActionNone, eapAuthenticationTunnelLastActionWritePacket:
		break
	default:
		t.lastAction = eapAuthenticationTunnelLastActionError
		return 0, fmt.Errorf("out of order read: invalid last action")
	}
	n = 0
	rd := &Datagram{}
	_, err = t.session.ReadDatagram(rd)
	if err != nil {
		t.lastAction = eapAuthenticationTunnelLastActionError
		return
	}
	for _, a := range rd.Attributes {
		if a.Type != AttributeTypeEapMessage {
			continue
		}
		n += copy(b[n:], a.Value)
	}
	t.lastAction = eapAuthenticationTunnelLastActionReadPacket
	return
}

func (t *EapAuthenticationTunnel) Write(b []byte) (n int, err error) {
	switch t.lastAction {
	case eapAuthenticationTunnelLastActionNone, eapAuthenticationTunnelLastActionReadPacket:
		break
	default:
		t.lastAction = eapAuthenticationTunnelLastActionError
		return 0, fmt.Errorf("out of order read: invalid last action")
	}
	n = 0
	var wd *Datagram
	if len(b) == 0 {
		wd, err = t.session.newRequestDatagram(CodeAccessRequest, newAttribute(AttributeTypeEapMessage, nil))
		if err != nil {
			t.lastAction = eapAuthenticationTunnelLastActionError
			return
		}
		t.lastAction = eapAuthenticationTunnelLastActionWritePacket
		return t.session.WriteDatagram(wd)
	}

	var eapmsgs []*Attribute
	r := bytes.NewReader(b)
	for r.Len() > 0 {
		// TODO: handle too big EAP stuff
		buf := make([]byte, maxAttributeLen)
		rcount, err := r.Read(buf)
		n += rcount
		if err != nil {
			t.lastAction = eapAuthenticationTunnelLastActionError
			return n, err
		}
		eapmsgs = append(eapmsgs, newAttribute(AttributeTypeEapMessage, buf[:rcount]))
	}
	wd, err = t.session.newRequestDatagram(CodeAccessRequest, eapmsgs...)
	if err != nil {
		t.lastAction = eapAuthenticationTunnelLastActionError
		return
	}
	t.lastAction = eapAuthenticationTunnelLastActionWritePacket
	n, err = t.session.WriteDatagram(wd)
	return
}

func (t *EapAuthenticationTunnel) Close() error {
	t.lastAction = eapAuthenticationTunnelLastActionClose
	return nil
}
