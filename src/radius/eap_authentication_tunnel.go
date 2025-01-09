/*
Copyright © 2024 Keytos alan@keytos.io

Define RADIUS EAP authentication tunnel
*/
package radius

import (
	"bytes"
	"fmt"
	"net"
	"time"
)

type EapAuthenticationTunnel struct {
	session           *AuthenticationSession
	anonymousUsername string
	lastAction        eapAuthenticationTunnelLastAction
}

type eapAuthenticationTunnelLastAction int

const (
	eapAuthenticationTunnelLastActionNone eapAuthenticationTunnelLastAction = iota
	eapAuthenticationTunnelLastActionWritePacket
	eapAuthenticationTunnelLastActionReadPacket
	eapAuthenticationTunnelLastActionError
	eapAuthenticationTunnelLastActionClose
)

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

func (tt *EapAuthenticationTunnel) Read(b []byte) (n int, err error) {
	switch tt.lastAction {
	case eapAuthenticationTunnelLastActionNone, eapAuthenticationTunnelLastActionWritePacket:
		break
	case eapAuthenticationTunnelLastActionClose:
		return 0, fmt.Errorf("eap tunnel: out of order read: session ended")
	default:
		tt.lastAction = eapAuthenticationTunnelLastActionError
		return 0, fmt.Errorf("eap tunnel: out of order read: invalid last action: %s", lastActionString(tt.lastAction))
	}
	n = 0
	rd := &Datagram{}
	_, err = tt.session.ReadDatagram(rd)
	if err != nil {
		tt.lastAction = eapAuthenticationTunnelLastActionError
		return
	}
	for _, a := range rd.Attributes {
		if a.Type != AttributeTypeEapMessage {
			continue
		}
		n += copy(b[n:], a.Value)
	}
	tt.lastAction = eapAuthenticationTunnelLastActionReadPacket
	switch rd.Header.Code {
	case CodeAccessAccept, CodeAccessReject:
		tt.lastAction = eapAuthenticationTunnelLastActionClose
	default:
		tt.lastAction = eapAuthenticationTunnelLastActionReadPacket
	}
	return
}

func (tt *EapAuthenticationTunnel) Write(b []byte) (n int, err error) {
	switch tt.lastAction {
	case eapAuthenticationTunnelLastActionNone, eapAuthenticationTunnelLastActionReadPacket:
		break
	case eapAuthenticationTunnelLastActionClose:
		return 0, fmt.Errorf("eap tunnel: out of order write: session ended")
	default:
		tt.lastAction = eapAuthenticationTunnelLastActionError
		return 0, fmt.Errorf("eap tunnel: out of order write: invalid last action: %s", lastActionString(tt.lastAction))
	}
	n = 0
	var wd *Datagram
	if len(b) == 0 {
		wd, err = tt.session.newRequestDatagram(CodeAccessRequest, newAttribute(AttributeTypeEapMessage, nil))
		if err != nil {
			tt.lastAction = eapAuthenticationTunnelLastActionError
			return
		}
		tt.lastAction = eapAuthenticationTunnelLastActionWritePacket
		return tt.session.WriteDatagram(wd)
	}

	var eapmsgs []*Attribute
	r := bytes.NewReader(b)
	for r.Len() > 0 {
		buf := make([]byte, maxAttributeLen)
		rcount, err := r.Read(buf)
		n += rcount
		if err != nil {
			tt.lastAction = eapAuthenticationTunnelLastActionError
			return n, err
		}
		eapmsgs = append(eapmsgs, newAttribute(AttributeTypeEapMessage, buf[:rcount]))
	}
	wd, err = tt.session.newRequestDatagram(CodeAccessRequest, eapmsgs...)
	if err != nil {
		tt.lastAction = eapAuthenticationTunnelLastActionError
		return
	}
	tt.lastAction = eapAuthenticationTunnelLastActionWritePacket
	n, err = tt.session.WriteDatagram(wd)
	return
}

func (tt *EapAuthenticationTunnel) Close() error {
	tt.lastAction = eapAuthenticationTunnelLastActionClose
	return nil
}

func (tt EapAuthenticationTunnel) LocalAddr() net.Addr {
	return tt.session.LocalAddr()
}

func (tt EapAuthenticationTunnel) RemoteAddr() net.Addr {
	return tt.session.RemoteAddr()
}

func (tt *EapAuthenticationTunnel) SetDeadline(t time.Time) error {
	return tt.session.SetDeadline(t)
}

func (tt *EapAuthenticationTunnel) SetReadDeadline(t time.Time) error {
	return tt.session.SetReadDeadline(t)
}

func (tt *EapAuthenticationTunnel) SetWriteDeadline(t time.Time) error {
	return tt.session.SetWriteDeadline(t)
}

func lastActionString(la eapAuthenticationTunnelLastAction) string {
	switch la {
	case eapAuthenticationTunnelLastActionNone:
		return "none"
	case eapAuthenticationTunnelLastActionWritePacket:
		return "write packet"
	case eapAuthenticationTunnelLastActionReadPacket:
		return "read packet"
	case eapAuthenticationTunnelLastActionError:
		return "error"
	case eapAuthenticationTunnelLastActionClose:
		return "close"
	default:
		return "unknown"
	}
}
