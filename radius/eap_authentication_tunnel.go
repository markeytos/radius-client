/*
Copyright © 2024 Keytos alan@keytos.io

Define RADIUS EAP authentication tunnel
*/
package radius

import (
	"bytes"
)

type EapAuthenticationTunnel struct {
	AuthenticationSession
	AnonymousUsername string
}

func NewEapAuthenticationTunnel(session AuthenticationSession, anonymousUsername string) *EapAuthenticationTunnel {
	session.sendAttributes = append(
		session.sendAttributes,
		newAttribute(AttributeTypeUserName, []byte(anonymousUsername)),
		newEmptyMessageAuthenticator(),
	)
	return &EapAuthenticationTunnel{
		AuthenticationSession: session,
		AnonymousUsername:     anonymousUsername,
	}
}

func (t *EapAuthenticationTunnel) Write(b []byte) (n int, err error) {
	n = 0
	var sd *Datagram
	// rd := &Datagram{}

	r := bytes.NewReader(b)
	if r.Len() == 0 {
		sd = t.newRequestDatagram(CodeAccessRequest, newAttribute(AttributeTypeEapMessage, nil))
		return t.WriteDatagram(sd)
	}

	var eapmsgs []*Attribute
	for r.Len() > 0 {
		// TODO: handle too big EAP stuff
		buf := make([]byte, maxAttributeLen)
		rcount, err := r.Read(buf)
		n += rcount
		if err != nil {
			return n, err
		}
		eapmsgs = append(eapmsgs, newAttribute(AttributeTypeEapMessage, buf[:rcount]))
	}
	sd = t.newRequestDatagram(CodeAccessRequest, eapmsgs...)
	n, err = t.WriteDatagram(sd)
	return
}

func (t *EapAuthenticationTunnel) Read(b []byte) (n int, err error) {
	n = 0

	rd := &Datagram{}
	_, err = t.ReadDatagram(rd)
	if err != nil {
		return
	}
	for _, a := range rd.Attributes {
		if a.Type != AttributeTypeEapMessage {
			continue
		}
		n += copy(b[n:], a.Value)
	}
	return
}
